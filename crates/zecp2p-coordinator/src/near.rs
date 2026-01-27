//! NEAR Intents 1Click API client
//!
//! This client implements the NEAR Intents 1Click API for cross-chain swaps.
//! API docs: https://docs.near-intents.org/near-intents/integration/distribution-channels/1click-api

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zecp2p_types::config::NearConfig;

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
    pub async fn get_status(&self, deposit_address: &str) -> Result<StatusResponse> {
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

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Status request failed with status {}: {}", status, body);
        }

        let api_response: ApiStatusResponse = response.json().await.context("Failed to parse status response")?;

        Ok(StatusResponse {
            status: api_response.status,
            source_tx_hash: api_response.source_transaction_hash,
            destination_tx_hash: api_response.destination_transaction_hash,
            output_amount: api_response.amount_out,
            error: api_response.error,
        })
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
    /// Source transaction hash (if known)
    pub source_tx_hash: Option<String>,
    /// Destination transaction hash (if complete)
    pub destination_tx_hash: Option<String>,
    /// Output amount (if complete)
    pub output_amount: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Status of a NEAR Intent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentStatus {
    /// Waiting for deposit
    PendingDeposit,
    /// Deposit transaction detected
    KnownDepositTx,
    /// Processing the swap
    Processing,
    /// Swap complete, funds delivered
    Success,
    /// Swap failed
    Failed,
    /// Deposit refunded
    Refunded,
    /// Quote expired
    Expired,
    /// Incomplete deposit (wrong amount)
    IncompleteDeposit,
}

impl IntentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            IntentStatus::Success
                | IntentStatus::Failed
                | IntentStatus::Refunded
                | IntentStatus::Expired
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, IntentStatus::Success)
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
    /// Source transaction hash
    #[serde(default)]
    source_transaction_hash: Option<String>,
    /// Destination transaction hash
    #[serde(default)]
    destination_transaction_hash: Option<String>,
    /// Output amount
    #[serde(default)]
    amount_out: Option<String>,
    /// Error message
    #[serde(default)]
    error: Option<String>,
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
        assert!(IntentStatus::Expired.is_terminal());
        assert!(!IntentStatus::IncompleteDeposit.is_terminal());
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
}
