//! NEAR Intents 1Click API client

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zecp2p_types::config::NearConfig;

/// Client for NEAR Intents 1Click API
pub struct NearIntentsClient {
    client: reqwest::Client,
    base_url: String,
}

impl NearIntentsClient {
    pub fn new(config: &NearConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: config.api_url.clone(),
        }
    }

    /// Get a quote for ZEC → USDC swap
    ///
    /// Returns a deposit address and expected output amount
    pub async fn get_quote(&self, request: QuoteRequest) -> Result<QuoteResponse> {
        let url = format!("{}/v0/quote", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<QuoteResponse>()
            .await?;

        Ok(response)
    }

    /// Poll status of a deposit
    pub async fn get_status(&self, deposit_address: &str) -> Result<StatusResponse> {
        let url = format!(
            "{}/v0/status?depositAddress={}",
            self.base_url, deposit_address
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json::<StatusResponse>()
            .await?;

        Ok(response)
    }
}

/// Quote request for NEAR Intents
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteRequest {
    /// Source chain (e.g., "zcash")
    pub source_chain: String,
    /// Source token (e.g., "ZEC")
    pub source_token: String,
    /// Source amount in smallest unit (zatoshi for ZEC)
    pub source_amount: String,
    /// Destination chain (e.g., "base")
    pub destination_chain: String,
    /// Destination token (e.g., "USDC")
    pub destination_token: String,
    /// Recipient address on destination chain
    pub recipient: String,
    /// Slippage tolerance in basis points (e.g., 50 = 0.5%)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slippage_bps: Option<u32>,
}

/// Quote response from NEAR Intents
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    /// Deposit address for source token (ZEC address)
    pub deposit_address: String,
    /// Expected output amount (USDC in smallest unit)
    pub expected_output: String,
    /// Minimum output amount accounting for slippage
    pub min_output: String,
    /// Quote expiry timestamp (unix seconds)
    pub expires_at: u64,
    /// Estimated time to completion (seconds)
    #[serde(default)]
    pub estimated_time: Option<u64>,
    /// Fee breakdown
    #[serde(default)]
    pub fees: Option<FeeBreakdown>,
}

/// Fee breakdown in quote
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeBreakdown {
    /// Protocol fee
    pub protocol_fee: Option<String>,
    /// Gas fee on destination
    pub gas_fee: Option<String>,
    /// Bridge fee
    pub bridge_fee: Option<String>,
}

/// Status response for deposit polling
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    /// Current status
    pub status: IntentStatus,
    /// Source transaction hash (if known)
    #[serde(default)]
    pub source_tx_hash: Option<String>,
    /// Destination transaction hash (if complete)
    #[serde(default)]
    pub destination_tx_hash: Option<String>,
    /// Output amount (if complete)
    #[serde(default)]
    pub output_amount: Option<String>,
    /// Error message (if failed)
    #[serde(default)]
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
    }
}
