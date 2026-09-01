//! Checking who the coordinator says to pay against who the deposit will pay.
//!
//! A taker learns the Venmo username from the coordinator, because on-chain
//! there is only `payeeDetails`, the curator's opaque hash of it. That lookup
//! used to be trusted outright: whatever string came back went into the Venmo
//! pay URL and the agent clicked send. A hostile or compromised coordinator,
//! or anyone on the wire in front of a plain-http one, could name their own
//! handle for a real deposit. The taker's dollars leave, the proof then fails
//! because the enclave binds `payeeDetails` from the deposit, and the taker
//! eats the loss.
//!
//! The hash is issued by the curator and is not computable locally, so the
//! check is: ask the curator for the hash of the username the coordinator gave,
//! and require it to equal the hash the deposit carries. A wrong username
//! produces a different hash, and the payment is refused before any money moves.

use alloy::primitives::B256;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// zk-p2p's processor name for Venmo.
const VENMO_PROCESSOR: &str = "venmo";

#[derive(Debug, Serialize)]
struct PayeeRequest<'a> {
    #[serde(rename = "processorName")]
    processor_name: &'a str,
    #[serde(rename = "depositData")]
    deposit_data: DepositData<'a>,
}

#[derive(Debug, Serialize)]
struct DepositData<'a> {
    #[serde(rename = "venmoUsername")]
    venmo_username: &'a str,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    message: Option<String>,
    #[serde(rename = "responseObject")]
    response_object: Option<T>,
}

#[derive(Debug, Deserialize)]
struct RegisteredPayee {
    #[serde(rename = "hashedOnchainId")]
    hashed_onchain_id: String,
}

/// Normalize a Venmo username the way the curator expects it.
///
/// Mirrors `zecp2p_coordinator::zkp2p::Zkp2pClient::normalize_venmo_username`.
pub fn normalize_venmo_username(username: &str) -> &str {
    username.trim().trim_start_matches('@')
}

/// Reject a username that could not be a Venmo handle before it reaches a URL.
///
/// The old path put the coordinator's string straight into
/// `https://account.venmo.com/pay?recipients={}` with no check of length or
/// character set.
pub fn validate_username_shape(username: &str) -> Result<&str> {
    let username = normalize_venmo_username(username);

    if username.len() < 2 {
        bail!("the coordinator returned a Venmo username shorter than 2 characters");
    }
    if username.len() > 30 {
        bail!("the coordinator returned a Venmo username longer than 30 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        bail!(
            "the coordinator returned a Venmo username with characters Venmo does not allow: {username:?}"
        );
    }

    Ok(username)
}

/// Parse the curator's `hashedOnchainId` into a bytes32.
pub fn parse_payee_hash(value: &str) -> Result<B256> {
    let hex_str = value.trim().trim_start_matches("0x");
    if hex_str.len() != 64 {
        bail!("curator returned a malformed hashedOnchainId: {value:?}");
    }
    let bytes =
        hex::decode(hex_str).with_context(|| format!("curator returned non-hex hash {value:?}"))?;
    let hash = B256::from_slice(&bytes);
    if hash == B256::ZERO {
        bail!("curator returned a zero hashedOnchainId");
    }
    Ok(hash)
}

/// Ask the curator what `payeeDetails` a username hashes to.
pub async fn curator_hash_for(
    http: &reqwest::Client,
    curator_url: &str,
    username: &str,
) -> Result<B256> {
    let username = validate_username_shape(username)?;
    let url = format!("{}/v2/makers/create", curator_url.trim_end_matches('/'));

    let response = http
        .post(&url)
        .json(&PayeeRequest {
            processor_name: VENMO_PROCESSOR,
            deposit_data: DepositData {
                venmo_username: username,
            },
        })
        .send()
        .await
        .with_context(|| format!("could not reach the zk-p2p curator at {url}"))?;

    let status = response.status();
    let text = response.text().await.context("reading curator response")?;
    if !status.is_success() {
        bail!("curator returned HTTP {status}: {text}");
    }

    let parsed: ApiResponse<RegisteredPayee> = serde_json::from_str(&text)
        .with_context(|| format!("could not parse the curator's response: {text}"))?;
    if !parsed.success {
        bail!(
            "curator refused the username: {}",
            parsed.message.unwrap_or_else(|| text.clone())
        );
    }

    let registered = parsed
        .response_object
        .ok_or_else(|| anyhow::anyhow!("curator response carried no responseObject"))?;

    parse_payee_hash(&registered.hashed_onchain_id)
}

/// Require that `username` is the payee the deposit will actually pay.
///
/// `on_chain` is the deposit's own `payeeDetails`, read from the escrow. If the
/// two hashes differ, the coordinator named someone else and this must not
/// become a Venmo payment.
pub fn require_match(username: &str, resolved: B256, on_chain: B256) -> Result<()> {
    if resolved != on_chain {
        bail!(
            "the coordinator says to pay @{username}, but that is not the payee this deposit \
             will settle against. Its payeeDetails is {on_chain:?} and @{username} hashes to \
             {resolved:?}. Not paying: the proof would fail and the money would be gone."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_at_and_whitespace_come_off() {
        assert_eq!(normalize_venmo_username("  @Alice-Smith "), "Alice-Smith");
        assert_eq!(normalize_venmo_username("bob"), "bob");
    }

    #[test]
    fn usernames_that_could_not_be_venmo_handles_are_refused() {
        // The old path put any of these straight into the pay URL.
        assert!(validate_username_shape("a").is_err(), "too short");
        assert!(validate_username_shape(&"a".repeat(31)).is_err(), "too long");
        assert!(
            validate_username_shape("alice?amount=500").is_err(),
            "query injection into the pay URL"
        );
        assert!(validate_username_shape("alice bob").is_err(), "space");
        assert!(validate_username_shape("alice/../bob").is_err(), "path");
        assert!(validate_username_shape("Alice-Smith_1").is_ok());
    }

    #[test]
    fn a_payee_that_does_not_match_the_deposit_is_refused() {
        let deposit_payee = B256::repeat_byte(0xAA);
        let attacker_payee = B256::repeat_byte(0xBB);

        // The honest case.
        assert!(require_match("alice", deposit_payee, deposit_payee).is_ok());

        // A hostile coordinator naming its own handle for a real deposit.
        let err = require_match("attacker", attacker_payee, deposit_payee)
            .expect_err("must refuse a payee the deposit will not settle against");
        assert!(err.to_string().contains("Not paying"));
    }

    #[test]
    fn a_malformed_curator_hash_is_refused() {
        assert!(parse_payee_hash("0x1234").is_err());
        assert!(parse_payee_hash(&format!("0x{}", "0".repeat(64))).is_err(), "zero hash");
        assert!(parse_payee_hash(&format!("0x{}", "ab".repeat(32))).is_ok());
    }
}
