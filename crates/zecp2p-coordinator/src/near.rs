//! NEAR Intents 1Click API client
//!
//! This client implements the NEAR Intents 1Click API for cross-chain swaps.
//! API docs: https://docs.near-intents.org/near-intents/integration/distribution-channels/1click-api

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zecp2p_types::config::NearConfig;

/// Smallest ZEC deposit 1Click will quote, in zatoshi.
///
/// Below this the API rejects the quote with
/// `Amount is too low for bridge, try at least 52000`. Checking locally turns a
/// raw 400 into an error the caller can act on.
pub const MIN_ZEC_ZATOSHI: u64 = 52_000;

/// Asset IDs for commonly used tokens in the NEAR Intents network
pub mod assets {
    /// ZEC (Zcash) on the ZEC network
    pub const ZEC: &str = "nep141:zec.omft.near";

    /// USDC on Base mainnet (0x833589fcd6edb6e08f4c7c32d4f71b54bda02913)
    pub const USDC_BASE: &str = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";

    /// USDC on NEAR (Circle's native USDC)
    pub const USDC_NEAR: &str =
        "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
}

/// Client for NEAR Intents 1Click API
pub struct NearIntentsClient {
    client: reqwest::Client,
    base_url: String,
    /// Default timeout for swaps (seconds)
    default_timeout: u64,
}

impl NearIntentsClient {
    pub fn new(config: &NearConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config.api_url.clone(),
            default_timeout: config.default_timeout,
        }
    }

    /// Get a quote for a ZEC → USDC on Base swap
    ///
    /// This uses the 1Click API v0 format with proper asset IDs.
    /// Returns a deposit address and expected output amount.
    pub async fn get_quote(&self, request: QuoteRequest) -> Result<QuoteResponse> {
        request.validate()?;

        let url = format!("{}/v0/quote", self.base_url);

        // Calculate deadline (now + timeout)
        let deadline = Utc::now() + Duration::seconds(self.default_timeout as i64);

        // Build the actual API request
        let api_request = ApiQuoteRequest {
            dry: false,
            swap_type: SwapType::ExactInput,
            slippage_tolerance: request.slippage_bps.unwrap_or(50) as i32,
            origin_asset: request.origin_asset.clone(),
            deposit_type: DepositType::OriginChain,
            destination_asset: request.destination_asset.clone(),
            amount: request.amount.clone(),
            refund_to: request.refund_to.clone(),
            refund_type: RefundType::OriginChain,
            recipient: request.recipient.clone(),
            recipient_type: RecipientType::DestinationChain,
            deadline,
            deposit_mode: Some(DepositMode::Simple),
            quote_waiting_time_ms: Some(5000),
            referral: None,
        };

        let response = self
            .client
            .post(&url)
            .json(&api_request)
            .send()
            .await
            .context("Failed to send quote request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Quote request failed with status {}: {}", status, body);
        }

        let api_response: ApiQuoteResponse = response.json().await.context("Failed to parse quote response")?;

        // Extract the important fields
        let quote = api_response.quote;

        Ok(QuoteResponse {
            deposit_address: quote.deposit_address.ok_or_else(|| {
                anyhow::anyhow!("No deposit address in quote response (dry run?)")
            })?,
            expected_output: quote.amount_out,
            min_output: quote.min_amount_out,
            expires_at: quote.deadline.map(|d| d.timestamp() as u64).unwrap_or(0),
            time_estimate_secs: quote.time_estimate,
        })
    }

    /// Poll status of a deposit by its deposit address
    ///
    /// Returns `Ok(None)` when the service does not (yet) know the address. 1Click
    /// answers 404 in the window between handing out a deposit address and
    /// registering it, so that case is retryable rather than a session failure.
    pub async fn get_status(&self, deposit_address: &str) -> Result<Option<StatusResponse>> {
        let url = format!(
            "{}/v0/status?depositAddress={}",
            self.base_url, deposit_address
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send status request")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Status request failed with status {}: {}", status, body);
        }

        let api_response: ApiStatusResponse = response.json().await.context("Failed to parse status response")?;

        // The transaction hashes and settled amounts live inside `swapDetails`, and
        // the chain hashes are arrays of objects rather than bare strings.
        let details = api_response.swap_details.unwrap_or_default();

        Ok(Some(StatusResponse {
            status: api_response.status,
            source_tx_hash: details.origin_chain_tx_hashes.first().map(|t| t.hash.clone()),
            destination_tx_hash: details
                .destination_chain_tx_hashes
                .first()
                .map(|t| t.hash.clone()),
            output_amount: details.amount_out,
            refunded_amount: details.refunded_amount,
        }))
    }

    /// Helper to create a quote request for ZEC → USDC on Base
    pub fn zec_to_usdc_base_request(
        zec_amount_zatoshi: u64,
        recipient: &str,
        refund_to: &str,
        slippage_bps: Option<u32>,
    ) -> QuoteRequest {
        QuoteRequest {
            origin_asset: assets::ZEC.to_string(),
            destination_asset: assets::USDC_BASE.to_string(),
            amount: zec_amount_zatoshi.to_string(),
            recipient: recipient.to_string(),
            refund_to: refund_to.to_string(),
            slippage_bps,
        }
    }
}

/// Simplified quote request for the NEAR Intents client
#[derive(Debug, Clone)]
pub struct QuoteRequest {
    /// Origin asset ID (e.g., "nep141:zec.omft.near")
    pub origin_asset: String,
    /// Destination asset ID (e.g., "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near")
    pub destination_asset: String,
    /// Amount in smallest unit (zatoshi for ZEC)
    pub amount: String,
    /// Recipient address on destination chain
    pub recipient: String,
    /// Refund address on origin chain (for failed swaps)
    pub refund_to: String,
    /// Slippage tolerance in basis points (e.g., 50 = 0.5%)
    pub slippage_bps: Option<u32>,
}

impl QuoteRequest {
    /// Check the constraints 1Click enforces, before spending a round trip on them.
    ///
    /// Two rejections are worth catching locally because the API's own messages
    /// are hard to act on: amounts under [`MIN_ZEC_ZATOSHI`] come back as a bare
    /// 400, and a shielded `refundTo` reports only `refundTo is not valid`.
    pub fn validate(&self) -> Result<()> {
        if self.origin_asset == assets::ZEC {
            let zatoshi: u64 = self
                .amount
                .parse()
                .with_context(|| format!("ZEC amount {:?} is not an integer", self.amount))?;

            if zatoshi < MIN_ZEC_ZATOSHI {
                anyhow::bail!(
                    "ZEC amount {} zatoshi is below the 1Click minimum of {} zatoshi",
                    zatoshi,
                    MIN_ZEC_ZATOSHI
                );
            }

            validate_zec_refund_address(&self.refund_to)?;
        }

        Ok(())
    }
}

/// 1Click only accepts a transparent Zcash address for refunds.
///
/// Unified (`u1`) and Sapling (`zs`) addresses are rejected by the API, so funds
/// refunded from a swap always land in the transparent pool.
pub fn validate_zec_refund_address(address: &str) -> Result<()> {
    let address = address.trim();

    if address.starts_with("t1") || address.starts_with("t3") {
        // Base58Check t-addresses are 34 or 35 characters. The api.rs copy of
        // this check insisted on exactly 35, which rejected a valid 34.
        if address.len() < 34 || address.len() > 35 {
            anyhow::bail!(
                "refund address {} is not a valid length for a t-address (expected 34 or 35 characters)",
                address
            );
        }
        if !address[1..].chars().all(|c| c.is_ascii_alphanumeric()) {
            anyhow::bail!("refund address {} contains characters base58 does not use", address);
        }
        return Ok(());
    }

    if address.starts_with("u1") || address.starts_with("zs") || address.starts_with("zc") {
        anyhow::bail!(
            "refund address {} is shielded; 1Click only accepts a transparent t1/t3 address",
            address
        );
    }

    anyhow::bail!("refund address {} is not a Zcash transparent address", address)
}

/// Simplified quote response
#[derive(Debug, Clone)]
pub struct QuoteResponse {
    /// Deposit address for source token (ZEC address)
    pub deposit_address: String,
    /// Expected output amount in smallest unit
    pub expected_output: String,
    /// Minimum output amount accounting for slippage
    pub min_output: String,
    /// Quote expiry timestamp (unix seconds)
    pub expires_at: u64,
    /// Estimated time to completion (seconds)
    pub time_estimate_secs: Option<i64>,
}

/// Simplified status response
#[derive(Debug, Clone)]
pub struct StatusResponse {
    /// Current status
    pub status: IntentStatus,
    /// First origin-chain (ZEC) transaction hash, if any
    pub source_tx_hash: Option<String>,
    /// First destination-chain (Base) transaction hash, if any
    pub destination_tx_hash: Option<String>,
    /// Settled output amount (if complete)
    pub output_amount: Option<String>,
    /// Amount of the origin asset returned to `refundTo`, if refunded
    pub refunded_amount: Option<String>,
}

/// Status of a NEAR Intent
///
/// These are exactly the seven values in the 1Click `GetExecutionStatusResponse`
/// schema. There is no `EXPIRED`: a quote whose deadline passes without a
/// matching deposit stays `PENDING_DEPOSIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentStatus {
    /// Waiting for deposit
    PendingDeposit,
    /// Deposit transaction detected
    KnownDepositTx,
    /// Deposit seen but below the quoted amount; refunded by the deadline
    IncompleteDeposit,
    /// Processing the swap
    Processing,
    /// Swap complete, funds delivered
    Success,
    /// Deposit refunded
    Refunded,
    /// Swap failed
    Failed,
}

impl IntentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            IntentStatus::Success | IntentStatus::Failed | IntentStatus::Refunded
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, IntentStatus::Success)
    }

    /// True while the swap can still move on its own.
    ///
    /// `INCOMPLETE_DEPOSIT` is not terminal: 1Click refunds an under-deposit by
    /// the quote deadline, which can be days out, so the session waits rather
    /// than failing.
    pub fn is_pending(&self) -> bool {
        !self.is_terminal()
    }
}

// =============================================================================
// Internal API types (matching the actual 1Click API)
// =============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiQuoteRequest {
    /// Dry run mode (excludes deposit address if true)
    dry: bool,
    /// Swap type
    swap_type: SwapType,
    /// Slippage tolerance in basis points
    slippage_tolerance: i32,
    /// Origin asset ID
    origin_asset: String,
    /// Deposit type
    deposit_type: DepositType,
    /// Destination asset ID
    destination_asset: String,
    /// Amount in smallest unit
    amount: String,
    /// Refund recipient address
    refund_to: String,
    /// Refund type
    refund_type: RefundType,
    /// Recipient address
    recipient: String,
    /// Recipient type
    recipient_type: RecipientType,
    /// Deadline for the swap
    deadline: DateTime<Utc>,
    /// Deposit mode (SIMPLE or MEMO)
    #[serde(skip_serializing_if = "Option::is_none")]
    deposit_mode: Option<DepositMode>,
    /// Time to wait for relay quote (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_waiting_time_ms: Option<i32>,
    /// Referral identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    referral: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SwapType {
    ExactInput,
    ExactOutput,
    FlexInput,
    AnyInput,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DepositType {
    OriginChain,
    Intents,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RefundType {
    OriginChain,
    Intents,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RecipientType {
    DestinationChain,
    Intents,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DepositMode {
    Simple,
    Memo,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiQuoteResponse {
    /// Correlation ID for tracing
    #[allow(dead_code)]
    correlation_id: String,
    /// Quote details
    quote: ApiQuote,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiQuote {
    /// Expected output amount
    amount_out: String,
    /// Minimum output amount (after slippage)
    min_amount_out: String,
    /// Estimated time in seconds
    #[serde(default)]
    time_estimate: Option<i64>,
    /// Deposit address (only if not dry run)
    #[serde(default)]
    deposit_address: Option<String>,
    /// Deadline when address becomes inactive
    #[serde(default)]
    deadline: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiStatusResponse {
    /// Current status
    status: IntentStatus,
    /// Last time the state was updated
    #[serde(default)]
    #[allow(dead_code)]
    updated_at: Option<DateTime<Utc>>,
    /// Details of the actual swaps and withdrawals
    #[serde(default)]
    swap_details: Option<ApiSwapDetails>,
}

/// The `swapDetails` object, where the settled amounts and chain hashes live.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiSwapDetails {
    /// Settled amount of the destination asset
    #[serde(default)]
    amount_out: Option<String>,
    /// Amount of the origin asset returned to `refundTo`
    #[serde(default)]
    refunded_amount: Option<String>,
    /// Transactions on the origin chain
    #[serde(default)]
    origin_chain_tx_hashes: Vec<ApiTransactionDetails>,
    /// Transactions on the destination chain
    #[serde(default)]
    destination_chain_tx_hashes: Vec<ApiTransactionDetails>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiTransactionDetails {
    hash: String,
    #[serde(default)]
    #[allow(dead_code)]
    explorer_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_status_terminal() {
        assert!(!IntentStatus::PendingDeposit.is_terminal());
        assert!(!IntentStatus::KnownDepositTx.is_terminal());
        assert!(!IntentStatus::Processing.is_terminal());
        assert!(IntentStatus::Success.is_terminal());
        assert!(IntentStatus::Failed.is_terminal());
        assert!(IntentStatus::Refunded.is_terminal());
        // An under-deposit is refunded by the quote deadline, so the session waits.
        assert!(!IntentStatus::IncompleteDeposit.is_terminal());
        assert!(IntentStatus::IncompleteDeposit.is_pending());
    }

    /// Every value in the 1Click `GetExecutionStatusResponse` status enum must
    /// deserialize, and nothing outside it should.
    #[test]
    fn test_intent_status_matches_spec_enum() {
        let spec = [
            ("KNOWN_DEPOSIT_TX", IntentStatus::KnownDepositTx),
            ("PENDING_DEPOSIT", IntentStatus::PendingDeposit),
            ("INCOMPLETE_DEPOSIT", IntentStatus::IncompleteDeposit),
            ("PROCESSING", IntentStatus::Processing),
            ("SUCCESS", IntentStatus::Success),
            ("REFUNDED", IntentStatus::Refunded),
            ("FAILED", IntentStatus::Failed),
        ];

        for (name, want) in spec {
            let got: IntentStatus = serde_json::from_str(&format!("\"{}\"", name))
                .unwrap_or_else(|e| panic!("status {} should deserialize: {}", name, e));
            assert_eq!(got, want, "status {} mapped to the wrong variant", name);
        }

        // EXPIRED is not in the 1Click status enum; it belongs to an unrelated
        // order-status enum in the same OpenAPI document.
        assert!(serde_json::from_str::<IntentStatus>("\"EXPIRED\"").is_err());
    }

    /// The hashes and settled amounts live inside `swapDetails`, and the chain
    /// hashes are arrays of objects rather than bare strings.
    #[test]
    fn test_status_response_reads_nested_swap_details() {
        let body = serde_json::json!({
            "correlationId": "550e8400-e29b-41d4-a716-446655440000",
            "status": "SUCCESS",
            "updatedAt": "2026-08-30T18:16:03.374Z",
            "swapDetails": {
                "intentHashes": ["intent-1"],
                "nearTxHashes": ["near-1"],
                "amountOut": "8696004",
                "amountOutFormatted": "8.696004",
                "slippage": 50,
                "originChainTxHashes": [
                    {"hash": "zec-txid-1", "explorerUrl": "https://example.invalid/zec-txid-1"}
                ],
                "destinationChainTxHashes": [
                    {"hash": "0xbase1", "explorerUrl": "https://basescan.org/tx/0xbase1"}
                ]
            }
        });

        let parsed: ApiStatusResponse = serde_json::from_value(body).expect("spec-shaped status");
        let details = parsed.swap_details.expect("swapDetails present");

        assert_eq!(parsed.status, IntentStatus::Success);
        assert_eq!(details.amount_out.as_deref(), Some("8696004"));
        assert_eq!(details.origin_chain_tx_hashes[0].hash, "zec-txid-1");
        assert_eq!(details.destination_chain_tx_hashes[0].hash, "0xbase1");
    }

    /// A pending status carries no `swapDetails` content yet.
    #[test]
    fn test_status_response_pending_has_no_hashes() {
        let body = serde_json::json!({
            "correlationId": "c1",
            "status": "PENDING_DEPOSIT",
            "updatedAt": "2026-08-30T18:16:03.374Z",
            "swapDetails": {}
        });

        let parsed: ApiStatusResponse = serde_json::from_value(body).expect("pending status");
        let details = parsed.swap_details.unwrap_or_default();

        assert_eq!(parsed.status, IntentStatus::PendingDeposit);
        assert!(details.origin_chain_tx_hashes.is_empty());
        assert!(details.destination_chain_tx_hashes.is_empty());
        assert!(details.amount_out.is_none());
    }

    #[test]
    fn test_refunded_status_carries_refunded_amount() {
        let body = serde_json::json!({
            "correlationId": "c2",
            "status": "REFUNDED",
            "updatedAt": "2026-08-30T18:16:03.374Z",
            "swapDetails": {
                "refundedAmount": "5000",
                "refundedAmountFormatted": "0.00005"
            }
        });

        let parsed: ApiStatusResponse = serde_json::from_value(body).expect("refunded status");
        let details = parsed.swap_details.expect("swapDetails present");

        assert_eq!(parsed.status, IntentStatus::Refunded);
        assert_eq!(details.refunded_amount.as_deref(), Some("5000"));
    }

    #[test]
    fn test_validate_rejects_below_minimum() {
        let request = NearIntentsClient::zec_to_usdc_base_request(
            MIN_ZEC_ZATOSHI - 1,
            "0x1234567890123456789012345678901234567890",
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
            Some(50),
        );

        let err = request.validate().expect_err("below the bridge minimum");
        assert!(err.to_string().contains("52000"), "got: {}", err);
    }

    #[test]
    fn test_validate_accepts_exact_minimum() {
        let request = NearIntentsClient::zec_to_usdc_base_request(
            MIN_ZEC_ZATOSHI,
            "0x1234567890123456789012345678901234567890",
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
            Some(50),
        );

        request.validate().expect("52000 zatoshi is quotable");
    }

    #[test]
    fn test_validate_rejects_shielded_refund_address() {
        for shielded in [
            "u1lq6jn3fkgd0dcxpvdnfrhrqrmvdnvzdmhdpvzdshgqe8gksv5x4nzn6vhpwzvz",
            "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
        ] {
            let request = NearIntentsClient::zec_to_usdc_base_request(
                1_000_000,
                "0x1234567890123456789012345678901234567890",
                shielded,
                Some(50),
            );

            let err = request.validate().expect_err("shielded refundTo is rejected");
            assert!(err.to_string().contains("shielded"), "got: {}", err);
        }
    }

    #[test]
    fn test_validate_accepts_transparent_refund_addresses() {
        for transparent in [
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
        ] {
            validate_zec_refund_address(transparent)
                .unwrap_or_else(|e| panic!("{} should be accepted: {}", transparent, e));
        }
    }

    #[test]
    fn test_zec_to_usdc_request() {
        let request = NearIntentsClient::zec_to_usdc_base_request(
            50_000_000, // 0.5 ZEC
            "0x1234567890123456789012345678901234567890",
            "t1abc...", // ZEC refund address
            Some(100),  // 1% slippage
        );

        assert_eq!(request.origin_asset, assets::ZEC);
        assert_eq!(request.destination_asset, assets::USDC_BASE);
        assert_eq!(request.amount, "50000000");
        assert_eq!(request.slippage_bps, Some(100));
    }

    // ---------------------------------------------------------------------
    // Fixtures captured from a real mainnet ZEC -> USDC swap on 2026-08-31
    // (52,000 zatoshi). These pin the deserializer to the shape the live service
    // actually sends, so a schema change breaks a test instead of silently
    // parsing to None.
    //
    // The addresses, transaction hashes, quote signature and correlation ids in
    // them are stand-ins. The originals tied a real ZEC deposit address and its
    // refund address to a real Base EOA, with amounts and timings, which is a
    // linkage this repository has no reason to carry (NEW-6 in the 2026-08-31
    // re-audit). Everything the deserializer is being tested on is structural:
    // field names, nesting, arrays of {hash, explorerUrl} objects rather than
    // bare strings, nulls where a stage has no value yet. None of that depends
    // on the values being anyone's.
    // ---------------------------------------------------------------------

    const LIVE_SUCCESS: &str = include_str!("../tests/fixtures/1click_status_success.json");
    const LIVE_PROCESSING: &str = include_str!("../tests/fixtures/1click_status_processing.json");
    const LIVE_PENDING: &str = include_str!("../tests/fixtures/1click_status_pending_deposit.json");

    /// The settled swap parses, and every field the coordinator records is present.
    #[test]
    fn test_live_success_fixture_parses() {
        let parsed: ApiStatusResponse = serde_json::from_str(LIVE_SUCCESS).expect("live SUCCESS parses");
        assert_eq!(parsed.status, IntentStatus::Success);

        let d = parsed.swap_details.expect("swapDetails present");
        assert_eq!(d.amount_out.as_deref(), Some("443561"));
        // The delivery hash, in the nested array shape the pre-fix
        // deserializer recorded as None.
        assert_eq!(
            d.destination_chain_tx_hashes.first().map(|t| t.hash.as_str()),
            Some("0x2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(
            d.origin_chain_tx_hashes.first().map(|t| t.hash.as_str()),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(d.refunded_amount.as_deref(), Some("0"));
    }

    /// A real swap can reach PROCESSING with `amountOut` already populated and no
    /// destination transaction yet. Settlement must be decided by `status` alone;
    /// treating a populated `amountOut` as "delivered" would fire early here.
    #[test]
    fn test_live_processing_fixture_is_not_settled() {
        let parsed: ApiStatusResponse = serde_json::from_str(LIVE_PROCESSING).expect("live PROCESSING parses");
        assert_eq!(parsed.status, IntentStatus::Processing);
        assert!(!parsed.status.is_success());
        assert!(parsed.status.is_pending());

        let d = parsed.swap_details.expect("swapDetails present");
        assert_eq!(d.amount_out.as_deref(), Some("443561"), "amountOut is set before settlement");
        assert!(
            d.destination_chain_tx_hashes.is_empty(),
            "no destination tx until the swap settles"
        );
    }

    /// PENDING_DEPOSIT carries an all-null swapDetails and must parse cleanly.
    #[test]
    fn test_live_pending_deposit_fixture_parses() {
        let parsed: ApiStatusResponse = serde_json::from_str(LIVE_PENDING).expect("live PENDING parses");
        assert_eq!(parsed.status, IntentStatus::PendingDeposit);
        assert!(parsed.status.is_pending());
        assert!(!parsed.status.is_terminal());

        let d = parsed.swap_details.unwrap_or_default();
        assert!(d.amount_out.is_none());
        assert!(d.origin_chain_tx_hashes.is_empty());
    }

    /// The live run went PENDING_DEPOSIT -> PROCESSING directly, never emitting
    /// KNOWN_DEPOSIT_TX. Both are non-terminal and pending, so nothing may depend
    /// on observing that intermediate state.
    #[test]
    fn test_known_deposit_tx_is_not_required_in_progression() {
        for s in [IntentStatus::PendingDeposit, IntentStatus::KnownDepositTx, IntentStatus::Processing] {
            assert!(s.is_pending(), "{s:?} should be pending");
            assert!(!s.is_terminal(), "{s:?} should not be terminal");
            assert!(!s.is_success(), "{s:?} should not be success");
        }
    }
}
