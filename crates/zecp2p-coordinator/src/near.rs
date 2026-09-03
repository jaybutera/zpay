//! NEAR Intents 1Click API client
//!
//! This client implements the NEAR Intents 1Click API for cross-chain swaps.
//! API docs: https://docs.near-intents.org/near-intents/integration/distribution-channels/1click-api

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zecp2p_types::config::NearConfig;

/// The floor this code assumes when 1Click has not yet told it otherwise.
///
/// This is a starting guess, not a fact. 1Click's real floor tracks the ZEC
/// network fee and moves: it was 52,000 zatoshi when this constant was written
/// and 132,000 on 2026-09-02, a factor of 2.5. Treating the constant as truth
/// is what made every amount under about $1.07 come back as two words of
/// "NEAR Intents error" with the real number thrown away (U1-3).
///
/// The authority is `observed_floor()`, which holds the last floor 1Click
/// actually named in a 400. Quote and open paths read that; this constant only
/// fills in before the first rejection has been seen.
pub const MIN_ZEC_ZATOSHI: u64 = 52_000;

/// The last floor 1Click named in an `Amount is too low for bridge` rejection.
///
/// One number for the process, because the floor is a property of the bridge
/// and not of a caller. Reading it costs no round trip, so the check that used
/// to fire against a stale constant now fires against the last thing the API
/// actually said.
static OBSERVED_FLOOR: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(MIN_ZEC_ZATOSHI);

/// The floor to check an amount against and to advertise.
pub fn observed_floor() -> u64 {
    OBSERVED_FLOOR.load(std::sync::atomic::Ordering::Relaxed)
}

/// Record a floor 1Click named. Monotonic within a run in neither direction:
/// the bridge's floor moves both ways with the fee, so the newest number wins.
fn record_floor(zatoshi: u64) {
    OBSERVED_FLOOR.store(zatoshi, std::sync::atomic::Ordering::Relaxed);
}

/// Pull the floor out of 1Click's rejection text.
///
/// The message is `Amount is too low for bridge, try at least 132000`. Parsing
/// it is unlovely, but the number is the one thing the sender needs and the API
/// offers it nowhere else; a missing or reshaped message just yields `None` and
/// the caller falls back to the category error.
pub fn parse_floor_from_error(body: &str) -> Option<u64> {
    let tail = body.split("try at least").nth(1)?;
    let digits: String = tail
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// An amount 1Click refused as below its bridge floor, carrying that floor.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("amount is below the 1Click bridge floor of {zatoshi} zatoshi")]
pub struct BelowFloor {
    pub zatoshi: u64,
}

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
            // A3-3, still open at the time of the round 1 audit and made worse
            // by the order sweep: none of these calls had a timeout, so one
            // hung status request stalled the entire keeper loop, and with it
            // every live session's credit and fulfilment check. The budget is
            // generous because a real quote asks 1Click to wait 5,000 ms for
            // the relay.
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("the HTTP client's own configuration is valid"),
            base_url: config.api_url.clone(),
            default_timeout: config.default_timeout,
        }
    }

    /// Get a quote for a ZEC → USDC on Base swap
    ///
    /// This uses the 1Click API v0 format with proper asset IDs.
    /// Returns a deposit address and expected output amount.
    pub async fn get_quote(&self, request: QuoteRequest) -> Result<QuoteResponse> {
        self.quote_inner(request, false, 5000).await
    }

    /// Price a swap without reserving a deposit address.
    ///
    /// A quote shown on screen is a price, not a commitment, and `dry` quotes
    /// skip the deposit-address allocation. It also drops the relay waiting
    /// time, which is the whole cost of the call: with `quoteWaitingTimeMs` at
    /// 5000 a priced screen took 5.3 seconds on the ZEC path and 10.6 on the
    /// dollar path, which asks twice. Nobody types an amount and waits ten
    /// seconds to see what it is worth.
    ///
    /// The real quote, with a deposit address and the full waiting time, is
    /// taken when the order opens.
    pub async fn get_dry_quote(&self, request: QuoteRequest) -> Result<QuoteResponse> {
        self.quote_inner(request, true, 600).await
    }

    async fn quote_inner(
        &self,
        request: QuoteRequest,
        dry: bool,
        waiting_ms: i32,
    ) -> Result<QuoteResponse> {
        request.validate()?;

        let url = format!("{}/v0/quote", self.base_url);

        // Calculate deadline (now + timeout)
        let deadline = Utc::now() + Duration::seconds(self.default_timeout as i64);

        // Build the actual API request
        let api_request = ApiQuoteRequest {
            dry,
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
            quote_waiting_time_ms: Some(waiting_ms),
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

            // The one rejection a sender can act on: they asked for less than
            // the bridge takes. Keep the number rather than flattening it into
            // a category, and remember it so the next quote is checked against
            // what 1Click said and not against a constant in this file.
            if let Some(floor) = parse_floor_from_error(&body) {
                record_floor(floor);
                return Err(anyhow::Error::new(BelowFloor { zatoshi: floor }));
            }

            anyhow::bail!("Quote request failed with status {}: {}", status, body);
        }

        let api_response: ApiQuoteResponse = response.json().await.context("Failed to parse quote response")?;

        // Extract the important fields
        let quote = api_response.quote;

        Ok(QuoteResponse {
            // A dry quote returns no deposit address, which is the point of
            // asking for one. Only a real quote is required to carry it.
            deposit_address: match quote.deposit_address {
                Some(a) => a,
                None if dry => String::new(),
                None => anyhow::bail!("1Click returned a quote with no deposit address"),
            },
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

/// Check a Zcash address the way 1Click checks it.
///
/// This used to reject every shielded form on the stated grounds that the API
/// does. Dry quotes on 2026-09-02 say otherwise: 1Click accepts a unified
/// address as both `refundTo` and `recipient`, including a shielded-only one,
/// and refuses a malformed string with `refundTo is not valid`. The evidence
/// is in `docs/plans/ux-simplification.md` section 10.1, and the addresses it
/// was taken with are built by `crates/zecp2p-escrow/examples/ua_probe.rs`.
///
/// So a unified address is accepted here, which is what lets a failed swap
/// refund straight to the address a Zcash user actually has rather than to a
/// transparent hop the page then has to sweep.
///
/// Sapling (`zs`) and Sprout (`zc`) stay refused. Neither has been probed
/// against the live API, and a bare Sapling address is not what any current
/// wallet hands a user to receive with.
pub fn validate_zec_refund_address(address: &str) -> Result<()> {
    let address = address.trim();

    if address.starts_with("t1") || address.starts_with("t3") {
        // U1-4. Length and charset are not a checksum: `t1AAAA…` and the repo's
        // own placeholder with one character changed both passed the old check,
        // and 1Click accepted them too, so a failed swap would have been
        // refunded to a string nothing can pay. Decode it properly instead.
        return validate_transparent_address(address);
    }

    if address.starts_with("u1") {
        // Decode it rather than pattern-match the prefix: `u1` followed by
        // anything is not a unified address, and 1Click would answer 400 for a
        // string that fails its bech32m checksum. Deciding here costs no round
        // trip and names the problem.
        return validate_unified_address(address);
    }

    if address.starts_with("zs") || address.starts_with("zc") {
        anyhow::bail!(
            "refund address {} is a Sapling or Sprout address. Use a unified address \
             (u1...) or a transparent one (t1.../t3...)",
            address
        );
    }

    anyhow::bail!("refund address {} is not a Zcash address", address)
}

/// Check that a `t1` or `t3` string really is a well-formed transparent
/// address: base58check over the right mainnet version bytes.
///
/// `zcash_address` is already a dependency and already decodes the unified case
/// two branches down, so the same decoder does both rather than a hand-rolled
/// length check standing in for a checksum.
fn validate_transparent_address(address: &str) -> Result<()> {
    use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
    use zcash_protocol::consensus::NetworkType;

    /// A witness that the string decoded as a mainnet P2PKH or P2SH address.
    ///
    /// `convert_if_network` calls exactly one of these, and only after
    /// base58check has verified the version bytes and the four-byte checksum,
    /// so reaching a variant is the proof. Everything else falls through to the
    /// blanket errors below.
    struct TransparentOnly;

    impl TryFromAddress for TransparentOnly {
        type Error = &'static str;

        fn try_from_transparent_p2pkh(
            _net: NetworkType,
            _data: [u8; 20],
        ) -> Result<Self, ConversionError<Self::Error>> {
            Ok(TransparentOnly)
        }

        fn try_from_transparent_p2sh(
            _net: NetworkType,
            _data: [u8; 20],
        ) -> Result<Self, ConversionError<Self::Error>> {
            Ok(TransparentOnly)
        }
    }

    let parsed = ZcashAddress::try_from_encoded(address).map_err(|e| {
        anyhow::anyhow!(
            "refund address {address} is not a valid Zcash transparent address \
             (it does not pass base58check): {e}"
        )
    })?;

    parsed
        .convert_if_network::<TransparentOnly>(NetworkType::Main)
        .map_err(|e| {
            anyhow::anyhow!("refund address {address} is not a mainnet t-address: {e}")
        })?;

    Ok(())
}

/// Check that a `u1` string really is a well-formed unified address.
///
/// Bech32m over the `u` HRP, with the ZIP 316 f4jumble and the padding the
/// spec requires. `zcash_address` owns that logic; reimplementing it here is
/// how the first version of this probe ended up testing its own checksum bug
/// instead of the API.
fn validate_unified_address(address: &str) -> Result<()> {
    use zcash_address::unified::Encoding;

    let (network, _ua) = zcash_address::unified::Address::decode(address)
        .map_err(|e| anyhow::anyhow!("refund address {address} is not a valid unified address: {e}"))?;

    if network != zcash_protocol::consensus::NetworkType::Main {
        anyhow::bail!(
            "refund address {} is a {:?} address, not a mainnet one",
            address,
            network
        );
    }

    Ok(())
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
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7",
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
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7",
            Some(50),
        );

        request.validate().expect("52000 zatoshi is quotable");
    }

    /// This test used to assert that every shielded address is refused, on the
    /// stated grounds that 1Click rejects them. Dry quotes on 2026-09-02 show
    /// it accepts a unified address as `refundTo`, so the rule changed and this
    /// test changed with it (`docs/plans/ux-simplification.md`, section 10.1).
    ///
    /// Both strings below are still refused, and the first one shows why the
    /// old test passed for the wrong reason: it is not a valid unified address
    /// at all, so it was failing a checksum rather than a format rule.
    #[test]
    fn test_validate_rejects_malformed_and_sapling_refund_addresses() {
        for bad in [
            "u1lq6jn3fkgd0dcxpvdnfrhrqrmvdnvzdmhdpvzdshgqe8gksv5x4nzn6vhpwzvz",
            "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
        ] {
            let request = NearIntentsClient::zec_to_usdc_base_request(
                1_000_000,
                "0x1234567890123456789012345678901234567890",
                bad,
                Some(50),
            );

            request
                .validate()
                .expect_err("a malformed or Sapling refundTo is rejected");
        }
    }

    /// And the shape that is now accepted, built rather than typed.
    #[test]
    fn test_validate_accepts_a_real_unified_refund_address() {
        use zcash_address::unified::{self, Encoding};
        let ua = unified::Address::try_from_items(vec![
            unified::Receiver::Orchard([3u8; 43]),
            unified::Receiver::P2pkh([7u8; 20]),
        ])
        .unwrap()
        .encode(&zcash_protocol::consensus::NetworkType::Main);

        let request = NearIntentsClient::zec_to_usdc_base_request(
            1_000_000,
            "0x1234567890123456789012345678901234567890",
            &ua,
            Some(50),
        );
        request.validate().expect("a unified refundTo is quotable");
    }

    #[test]
    fn test_validate_accepts_transparent_refund_addresses() {
        for transparent in [
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7",
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

/// The refund validator, after 2026-09-02 widened it to unified addresses.
///
/// The addresses here are built by `zcash_address` rather than typed, which is
/// the lesson from the first probe: hand-written `u1` and `zs` strings failed
/// their own checksum, so the 400s they drew said nothing about the format.
#[cfg(test)]
mod refund_address_tests {
    use super::validate_zec_refund_address;
    use zcash_address::unified::{self, Encoding};

    fn mainnet_ua(items: Vec<unified::Receiver>) -> String {
        unified::Address::try_from_items(items)
            .expect("a legal receiver set")
            .encode(&zcash_protocol::consensus::NetworkType::Main)
    }

    /// The finding that motivated the change: 1Click takes a unified address,
    /// so a refund can go straight to the address a Zcash user actually holds.
    #[test]
    fn a_unified_address_is_accepted() {
        let both = mainnet_ua(vec![
            unified::Receiver::Orchard([3u8; 43]),
            unified::Receiver::P2pkh([7u8; 20]),
        ]);
        validate_zec_refund_address(&both).expect("orchard + transparent UA");

        let shielded_only = mainnet_ua(vec![unified::Receiver::Orchard([3u8; 43])]);
        validate_zec_refund_address(&shielded_only).expect("shielded-only UA");
    }

    /// Transparent addresses still pass, at both valid lengths. This is the
    /// path every existing session used.
    #[test]
    fn transparent_addresses_still_pass() {
        validate_zec_refund_address("t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7").unwrap();
        validate_zec_refund_address("t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd").unwrap();
    }

    /// U1-4. Length and charset are not a checksum. `t1AAAA…` and the repo's
    /// own former placeholder, one character off a real address, were both
    /// accepted here and by 1Click, so a failed swap would have refunded to a
    /// string no wallet can spend from.
    #[test]
    fn a_t_address_that_fails_base58check_is_refused() {
        for bad in [
            // Right prefix, right length, wrong checksum.
            "t1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // The old placeholder: its payload is real, its checksum is not.
            "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
            // Correctly sized, entirely made up.
            "t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "t3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                validate_zec_refund_address(bad).is_err(),
                "{bad} does not pass base58check and must be refused"
            );
        }
    }

    /// A single changed character in a real address must not survive.
    #[test]
    fn a_one_character_corruption_of_a_t_address_is_refused() {
        let good = "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7";
        assert!(validate_zec_refund_address(good).is_ok());
        for i in 2..good.len() {
            let mut broken: Vec<char> = good.chars().collect();
            broken[i] = if broken[i] == 'a' { 'b' } else { 'a' };
            let broken: String = broken.into_iter().collect();
            if broken == good {
                continue;
            }
            assert!(
                validate_zec_refund_address(&broken).is_err(),
                "{broken} is one character off {good} and must be refused"
            );
        }
    }

    /// A `u1` prefix is not a unified address. Deciding this locally is what
    /// turns 1Click's bare "refundTo is not valid" into something actionable,
    /// and it is the exact mistake the first probe made.
    #[test]
    fn a_u1_string_that_fails_its_checksum_is_refused() {
        assert!(validate_zec_refund_address("u1notarealaddressatall").is_err());
        // A real UA with one character changed: the checksum must catch it.
        let good = mainnet_ua(vec![unified::Receiver::Orchard([3u8; 43])]);
        let mut broken = good.clone();
        let last = broken.pop().unwrap();
        broken.push(if last == 'q' { 'p' } else { 'q' });
        assert!(
            validate_zec_refund_address(&broken).is_err(),
            "a one-character corruption of {good} must not pass"
        );
    }

    /// A testnet address would have the funds refunded to a chain the sender is
    /// not on.
    #[test]
    fn a_testnet_unified_address_is_refused() {
        let testnet = unified::Address::try_from_items(vec![unified::Receiver::Orchard([3u8; 43])])
            .unwrap()
            .encode(&zcash_protocol::consensus::NetworkType::Test);
        assert!(validate_zec_refund_address(&testnet).is_err());
    }

    /// Sapling and Sprout stay refused, and say what to use instead.
    #[test]
    fn sapling_and_sprout_are_refused_with_an_actionable_message() {
        for a in ["zs1qqqqqqqqqqqqqqqqqqqq", "zcaaaaaaaaaaaaaaaaaaaa"] {
            let e = validate_zec_refund_address(a).unwrap_err().to_string();
            assert!(e.contains("u1"), "{a} should point at unified addresses: {e}");
        }
    }

    #[test]
    fn nonsense_is_still_nonsense() {
        assert!(validate_zec_refund_address("").is_err());
        assert!(validate_zec_refund_address("bc1qxy2kgdygjrsqtzq2n0yrf249").is_err());
        assert!(validate_zec_refund_address("t1short").is_err());
        assert!(validate_zec_refund_address("0x0000000000000000000000000000000000000000").is_err());
    }
}


