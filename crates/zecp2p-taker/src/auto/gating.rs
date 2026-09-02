//! The curator's gating signature, and the referral fee that rides with it.
//!
//! `claim.rs::signal_intent` sends an empty `gatingSignature` and an empty
//! `referrers` array. Against a gated deposit both are wrong, and the second is
//! wrong in a way that is easy to miss: the curator injects a **mandatory 95 bps
//! referral fee** and signs a digest that includes it, so a taker who supplies
//! the signature but reconstructs the fee array themselves gets
//! `InvalidSignature()` with everything looking correct.
//!
//! Neither field can be derived locally. The signature is made by
//! `0x396D31055Db28C0C6f36e8b36f18FE7227248a97`, whose key we do not have, and
//! the fee is the curator's policy rather than a contract constant. Both come
//! from one call.
//!
//! # The endpoint
//!
//! `POST {api}/v3/sign`. Probed read-only on 2026-09-02: `/v1/verify/intent`,
//! `/v2/verify/intent` and `/v3/verify/intent` all answer 404 while `/v3/sign`
//! answers a 400 validation error, so it is the live path despite what the
//! published developer docs describe.
//!
//! Its validator reports required fields by count rather than by name, but the
//! count drops by one per field supplied, which recovers the names. Twelve of
//! the thirteen, confirmed that way:
//!
//! ```text
//! depositId  processorName  amount  toAddress  paymentMethod  fiatCurrency
//! conversionRate  chainId  payeeDetails  callerAddress  escrowAddress
//! orchestratorAddress
//! ```
//!
//! `chainId` is a string, and `paymentMethod` and `fiatCurrency` are the bytes32
//! hashes rather than the words "venmo" and "USD".
//!
//! # The one thing this module does not know
//!
//! The thirteenth required field is not identified. [`GatingRequest::extra`]
//! exists to carry it once a live call names it: the 2026-09-01 fill obtained a
//! real signed response by hand, and recording that request verbatim closes
//! this gap without changing anything else here. Until then
//! [`GatingClient::sign`] will get a 400 back and say so plainly rather than
//! failing later at `signalIntent` with gas already spent.

use alloy::primitives::{Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What the taker asks the curator to sign.
#[derive(Debug, Clone, Serialize)]
pub struct GatingRequest {
    #[serde(rename = "depositId")]
    pub deposit_id: String,
    #[serde(rename = "processorName")]
    pub processor_name: String,
    /// Intent amount in 6-decimal USDC units, as a decimal string.
    pub amount: String,
    /// Where the released USDC goes. The taker's own address.
    #[serde(rename = "toAddress")]
    pub to_address: Address,
    #[serde(rename = "paymentMethod")]
    pub payment_method: B256,
    #[serde(rename = "fiatCurrency")]
    pub fiat_currency: B256,
    /// The deposit's real rate, scaled by 1e18, as a decimal string.
    #[serde(rename = "conversionRate")]
    pub conversion_rate: String,
    /// A string, not a number. The validator rejects `8453`.
    #[serde(rename = "chainId")]
    pub chain_id: String,
    /// The deposit's own on-chain payee hash.
    #[serde(rename = "payeeDetails")]
    pub payee_details: String,
    /// The address that will send `signalIntent`. It is inside the signed
    /// digest, so a gating signature cannot be relayed by anyone else.
    #[serde(rename = "callerAddress")]
    pub caller_address: Address,
    #[serde(rename = "escrowAddress")]
    pub escrow_address: Address,
    #[serde(rename = "orchestratorAddress")]
    pub orchestrator_address: Address,
    /// Fields the validator requires that this module has not named yet.
    ///
    /// Flattened into the body as-is. Configured rather than compiled so the
    /// gap can be closed from a config file the first time a live call names
    /// the missing field.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// One entry of the curator's referral fee array.
///
/// The field names match `IOrchestratorWrite::Referrer`, and the values are
/// passed through to `signalIntent` unchanged. Recomputing them locally is the
/// mistake that produces `InvalidSignature()`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReferralFee {
    pub referrer: Address,
    pub fee: U256,
}

/// What the curator signed, and everything `signalIntent` needs to carry it.
#[derive(Debug, Clone, Deserialize)]
pub struct GatingSignature {
    /// The ECDSA signature the orchestrator recovers against the deposit's
    /// `intentGatingService`.
    #[serde(alias = "gatingSignature", alias = "signature")]
    pub signature: Bytes,
    /// Enforced on-chain: `SignatureExpired` carries both timestamps.
    #[serde(alias = "signatureExpiration", alias = "expiration")]
    pub expiration: U256,
    /// The mandatory referral fee, exactly as signed.
    #[serde(alias = "referrers", alias = "referralFees", default)]
    pub referrers: Vec<ReferralFee>,
}

impl GatingSignature {
    /// A deposit with no gating service needs no signature, and the orchestrator
    /// skips the check entirely when `intentGatingService` is the zero address.
    pub fn none() -> Self {
        Self {
            signature: Bytes::new(),
            expiration: U256::ZERO,
            referrers: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.signature.is_empty()
    }
}

/// The curator's envelope. Every endpoint on this API answers in this shape,
/// including its failures, and a failure arrives as HTTP 200 often enough that
/// the status code alone cannot be trusted.
#[derive(Debug, Deserialize)]
struct CuratorEnvelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default = "Option::default")]
    #[serde(rename = "responseObject")]
    response_object: Option<T>,
}

pub struct GatingClient {
    http: reqwest::Client,
    base_url: String,
}

impl GatingClient {
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            http,
            base_url: base_url.into(),
        }
    }

    /// Ask the curator to sign an intent.
    ///
    /// Returns the signature, its expiration, and the referral fees, all of
    /// which go into `SignalIntentParams` untouched.
    pub async fn sign(&self, request: &GatingRequest) -> Result<GatingSignature> {
        let url = format!("{}/v3/sign", self.base_url.trim_end_matches('/'));

        let response = self
            .http
            .post(&url)
            .json(request)
            .send()
            .await
            .with_context(|| format!("could not reach the zk-p2p curator at {url}"))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("the curator's response was not readable")?;

        let envelope: CuratorEnvelope<GatingSignature> = serde_json::from_str(&body)
            .with_context(|| {
                format!("the curator answered {status} with something unparseable: {body}")
            })?;

        // A wrong body answers HTTP 200 with success:false on this API, so the
        // flag is the authority rather than the status code.
        if !envelope.success {
            anyhow::bail!(
                "the curator refused to sign for deposit {}: {} (HTTP {status}). \
                 If this names a missing required field, add it to \
                 [zkp2p.gating_extra] in the taker config; see the module docs \
                 for the twelve fields already known.",
                request.deposit_id,
                envelope.message
            );
        }

        let signed = envelope.response_object.ok_or_else(|| {
            anyhow::anyhow!("the curator reported success but returned no signature")
        })?;

        if signed.signature.is_empty() {
            anyhow::bail!(
                "the curator returned an empty gating signature for deposit {}; \
                 signalIntent would revert with InvalidSignature()",
                request.deposit_id
            );
        }

        tracing::info!(
            deposit_id = %request.deposit_id,
            referrers = signed.referrers.len(),
            expiration = %signed.expiration,
            "curator signed the intent"
        );

        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_serialises_the_field_names_the_validator_wants() {
        let request = GatingRequest {
            deposit_id: "4499".into(),
            processor_name: "venmo".into(),
            amount: "4875437".into(),
            to_address: Address::repeat_byte(1),
            payment_method: B256::repeat_byte(2),
            fiat_currency: B256::repeat_byte(3),
            conversion_rate: "990881148896019200".into(),
            chain_id: "8453".into(),
            payee_details: "0xabc".into(),
            caller_address: Address::repeat_byte(1),
            escrow_address: Address::repeat_byte(4),
            orchestrator_address: Address::repeat_byte(5),
            extra: BTreeMap::new(),
        };
        let json = serde_json::to_value(&request).unwrap();
        for field in [
            "depositId",
            "processorName",
            "amount",
            "toAddress",
            "paymentMethod",
            "fiatCurrency",
            "conversionRate",
            "chainId",
            "payeeDetails",
            "callerAddress",
            "escrowAddress",
            "orchestratorAddress",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
        // chainId is a string; the validator rejects a number.
        assert!(json["chainId"].is_string());
    }

    /// The thirteenth field goes in through `extra` without a code change.
    #[test]
    fn extra_fields_are_flattened_into_the_body() {
        let mut extra = BTreeMap::new();
        extra.insert("someField".to_string(), serde_json::json!("value"));
        let request = GatingRequest {
            deposit_id: "1".into(),
            processor_name: "venmo".into(),
            amount: "1".into(),
            to_address: Address::ZERO,
            payment_method: B256::ZERO,
            fiat_currency: B256::ZERO,
            conversion_rate: "1".into(),
            chain_id: "8453".into(),
            payee_details: "0x".into(),
            caller_address: Address::ZERO,
            escrow_address: Address::ZERO,
            orchestrator_address: Address::ZERO,
            extra,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["someField"], "value");
    }

    #[test]
    fn parses_a_signed_response() {
        let body = r#"{
            "success": true,
            "responseObject": {
                "signature": "0xdeadbeef",
                "expiration": "1789525549",
                "referrers": [
                    {"referrer": "0x0bc26ff515411396dd588abd6ef6846e04470227", "fee": "95"}
                ]
            }
        }"#;
        let envelope: CuratorEnvelope<GatingSignature> = serde_json::from_str(body).unwrap();
        let signed = envelope.response_object.unwrap();
        assert_eq!(signed.referrers.len(), 1);
        assert_eq!(signed.referrers[0].fee, U256::from(95));
        assert!(!signed.is_empty());
    }

    /// The curator's own naming varies between `gatingSignature` and
    /// `signature`; both have to land in the same field or a live response
    /// parses to an empty signature and reverts on chain.
    #[test]
    fn accepts_either_spelling_of_the_signature_field() {
        let body = r#"{"gatingSignature":"0xabcd","signatureExpiration":"1","referralFees":[]}"#;
        let signed: GatingSignature = serde_json::from_str(body).unwrap();
        assert_eq!(signed.signature, Bytes::from(vec![0xab, 0xcd]));
        assert_eq!(signed.expiration, U256::from(1));
    }

    #[test]
    fn an_ungated_deposit_needs_nothing() {
        let none = GatingSignature::none();
        assert!(none.is_empty());
        assert!(none.referrers.is_empty());
    }
}
