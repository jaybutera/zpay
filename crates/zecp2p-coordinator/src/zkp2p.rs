//! zk-p2p curator API client
//!
//! zk-p2p does not derive `payeeDetails` on-chain or in its client. Makers
//! register their payout identifier with the curator service, which validates
//! it against the payment platform and returns `hashedOnchainId`. That value is
//! what `DepositPaymentMethodData.payeeDetails` must hold: at fulfillment the
//! attestation witness looks the payee up by this hash and checks it against
//! the taker's payment proof, and `UnifiedPaymentVerifier` requires the
//! witness snapshot's `payeeDetails` to equal the intent's `payeeId`.
//!
//! This mirrors `registerPayeeDetails()` in `@zkp2p/sdk` (0.12.x):
//! `POST {api}/v2/makers/create` with `{ processorName, offchainId }`.
//! For Venmo, `offchainId` is the username without the leading `@`, and the
//! curator checks the exact casing.

#![allow(dead_code)]

use alloy::primitives::B256;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zecp2p_types::config::Zkp2pConfig;

/// Processor name the curator uses for Venmo
pub const VENMO_PROCESSOR: &str = "venmo";

/// Client for the zk-p2p curator API
pub struct Zkp2pClient {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PayeeRequest<'a> {
    processor_name: &'a str,
    offchain_id: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T> {
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default = "default_none")]
    response_object: Option<T>,
}

fn default_none<T>() -> Option<T> {
    None
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisteredPayee {
    hashed_onchain_id: String,
}

impl Zkp2pClient {
    pub fn new(config: &Zkp2pConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config.api_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Normalize a Venmo username the way the curator expects it: no leading
    /// `@`, no surrounding whitespace, casing untouched.
    pub fn normalize_venmo_username(username: &str) -> &str {
        username.trim().trim_start_matches('@')
    }

    /// Ask the curator whether it accepts this Venmo username as a payee.
    ///
    /// `POST /v2/makers/validate` answers `responseObject: true|false`. A
    /// `false` means the curator could not confirm the account (wrong casing,
    /// typo, or the account does not exist).
    pub async fn validate_venmo_payee(&self, username: &str) -> Result<bool> {
        let offchain_id = Self::normalize_venmo_username(username);
        if offchain_id.is_empty() {
            return Ok(false);
        }

        let url = format!("{}/v2/makers/validate", self.base_url);
        let body = PayeeRequest {
            processor_name: VENMO_PROCESSOR,
            offchain_id,
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {} failed", url))?;

        let status = response.status();
        let text = response.text().await.context("reading validate response")?;
        if !status.is_success() {
            bail!("curator validate returned HTTP {}: {}", status, text);
        }

        let parsed: ApiResponse<bool> =
            serde_json::from_str(&text).with_context(|| format!("parsing validate response: {}", text))?;
        if !parsed.success {
            bail!("curator validate failed: {}", parsed.message);
        }

        Ok(parsed.response_object.unwrap_or(false))
    }

    /// Register a Venmo username as a zk-p2p payee and return the curator's
    /// `hashedOnchainId`, which is the value to use as `payeeDetails`.
    pub async fn register_venmo_payee(&self, username: &str) -> Result<B256> {
        let offchain_id = Self::normalize_venmo_username(username);
        if offchain_id.is_empty() {
            bail!("Venmo username is empty");
        }

        let url = format!("{}/v2/makers/create", self.base_url);
        let body = PayeeRequest {
            processor_name: VENMO_PROCESSOR,
            offchain_id,
        };

        tracing::debug!(url = %url, venmo = %offchain_id, "Registering payee with zk-p2p curator");

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {} failed", url))?;

        let status = response.status();
        let text = response.text().await.context("reading create response")?;
        if !status.is_success() {
            // The curator returns JSON error bodies; surface the message if present.
            let message = serde_json::from_str::<ApiResponse<serde_json::Value>>(&text)
                .map(|r| r.message)
                .unwrap_or_default();
            bail!(
                "curator create returned HTTP {}: {}",
                status,
                if message.is_empty() { text } else { message }
            );
        }

        let parsed: ApiResponse<RegisteredPayee> =
            serde_json::from_str(&text).with_context(|| format!("parsing create response: {}", text))?;
        if !parsed.success {
            bail!("curator rejected payee registration: {}", parsed.message);
        }

        let registered = parsed
            .response_object
            .ok_or_else(|| anyhow!("curator create response has no responseObject"))?;

        parse_payee_hash(&registered.hashed_onchain_id)
    }
}

/// Parse the curator's `hashedOnchainId` into a bytes32.
///
/// On-chain `payeeDetails` is a bytes32, so anything other than 32 bytes of hex
/// would revert or, worse, silently create a deposit nobody can fulfill.
pub fn parse_payee_hash(value: &str) -> Result<B256> {
    let hex_str = value.trim().trim_start_matches("0x");
    if hex_str.len() != 64 {
        bail!(
            "curator returned malformed hashedOnchainId (expected 32 bytes of hex, got '{}')",
            value
        );
    }
    let bytes = hex::decode(hex_str)
        .with_context(|| format!("curator returned non-hex hashedOnchainId '{}'", value))?;
    let hash = B256::from_slice(&bytes);
    if hash == B256::ZERO {
        bail!("curator returned a zero hashedOnchainId");
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_leading_at_and_whitespace() {
        assert_eq!(Zkp2pClient::normalize_venmo_username("@Alice-Smith "), "Alice-Smith");
        assert_eq!(Zkp2pClient::normalize_venmo_username("bob"), "bob");
    }

    #[test]
    fn parses_well_formed_hash() {
        let raw = "0x24968a0c92cfc5a596bd27420340cfc9b35a36d2cda8ca82b6beed0f9bb1c51a";
        let parsed = parse_payee_hash(raw).unwrap();
        assert_eq!(format!("{:?}", parsed), raw);
        // Without the 0x prefix is accepted too
        assert_eq!(parse_payee_hash(&raw[2..]).unwrap(), parsed);
    }

    #[test]
    fn rejects_short_zero_and_non_hex() {
        assert!(parse_payee_hash("0x1234").is_err());
        assert!(parse_payee_hash(&format!("0x{}", "0".repeat(64))).is_err());
        assert!(parse_payee_hash(&format!("0x{}", "zz".repeat(32))).is_err());
        assert!(parse_payee_hash("hashed-id-1").is_err());
    }
}
