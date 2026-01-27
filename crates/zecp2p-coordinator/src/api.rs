//! REST API handlers

use std::sync::Arc;

use alloy::primitives::U256;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use zecp2p_types::{OfframpRequest, OfframpResponse, QuoteResponse};

use crate::{error::AppError, state::AppState};

/// Health check
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "zecp2p-coordinator"
    }))
}

/// Quote request query parameters
#[derive(Debug, Deserialize)]
pub struct QuoteQuery {
    /// Amount in ZEC (decimal, e.g., "0.5")
    pub zec_amount: String,
}

/// Get quote for ZEC → Venmo conversion
pub async fn get_quote(
    State(state): State<Arc<AppState>>,
    Query(query): Query<QuoteQuery>,
) -> Result<Json<QuoteResponse>, AppError> {
    // Parse ZEC amount (convert from decimal ZEC to zatoshi)
    let zec_decimal: f64 = query
        .zec_amount
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid ZEC amount".to_string()))?;
    let zatoshi = (zec_decimal * 100_000_000.0) as u64;

    // Get quote from NEAR Intents
    let glue_address = state
        .chain
        .glue_contract()
        .map_err(|e| AppError::Config(e.to_string()))?;

    let quote = state
        .near
        .get_quote(crate::near::QuoteRequest {
            source_chain: "zcash".to_string(),
            source_token: "ZEC".to_string(),
            source_amount: zatoshi.to_string(),
            destination_chain: "base".to_string(),
            destination_token: "USDC".to_string(),
            recipient: glue_address.to_string(),
            slippage_bps: Some(50),
        })
        .await
        .map_err(|e| AppError::NearIntents(e.to_string()))?;

    // Parse USDC amount (6 decimals)
    let usdc_raw: u64 = quote
        .expected_output
        .parse()
        .map_err(|_| AppError::NearIntents("Invalid output amount".to_string()))?;
    let usdc_decimal = usdc_raw as f64 / 1_000_000.0;

    // Estimate Venmo amount (assuming ~1% zk-p2p fee)
    let venmo_amount = usdc_decimal * 0.99;

    // Calculate effective rate
    let rate = usdc_decimal / zec_decimal;

    Ok(Json(QuoteResponse {
        zec_amount: query.zec_amount,
        usdc_amount: format!("{:.6}", usdc_decimal),
        venmo_amount: format!("{:.2}", venmo_amount),
        rate: format!("{:.4}", rate),
        expires_at: Utc::now() + chrono::Duration::seconds(quote.expires_at as i64 - Utc::now().timestamp()),
    }))
}

/// Create offramp request body
#[derive(Debug, Deserialize)]
pub struct CreateOfframpBody {
    /// Amount in ZEC (decimal, e.g., "0.5")
    pub zec_amount: String,
    /// Venmo username (without @)
    pub venmo_username: String,
    /// User's Base address
    pub user_address: String,
    /// Pre-arranged taker address
    pub taker_address: String,
    /// Minimum USDC/ZEC rate (decimal)
    #[serde(default)]
    pub min_rate: Option<String>,
    /// Timeout in seconds
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Create a new offramp
pub async fn create_offramp(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateOfframpBody>,
) -> Result<Json<OfframpResponse>, AppError> {
    // Parse ZEC amount
    let zec_decimal: f64 = body
        .zec_amount
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid ZEC amount".to_string()))?;
    let zatoshi = (zec_decimal * 100_000_000.0) as u64;

    // Parse addresses
    let user_address = body
        .user_address
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid user address".to_string()))?;
    let taker_address = body
        .taker_address
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid taker address".to_string()))?;

    // Parse min rate (default to reasonable value)
    let min_rate = if let Some(rate_str) = body.min_rate {
        let rate: f64 = rate_str
            .parse()
            .map_err(|_| AppError::InvalidState("Invalid min_rate".to_string()))?;
        // Convert to 18-decimal precision
        U256::from((rate * 1e18) as u128)
    } else {
        // Default: 20 USDC per ZEC minimum
        U256::from(20u64) * U256::from(10u64).pow(U256::from(18u64))
    };

    let request = OfframpRequest {
        zec_amount: zatoshi,
        venmo_username: body.venmo_username,
        user_address,
        taker_address,
        min_rate,
        timeout_seconds: body.timeout_seconds.unwrap_or(600),
    };

    let session = state.create_offramp(request).await?;

    Ok(Json(OfframpResponse::from(&session)))
}

/// Get offramp status
pub async fn get_offramp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OfframpResponse>, AppError> {
    let uuid = id
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid session ID".to_string()))?;

    let session = state
        .get_session(uuid)
        .await?
        .ok_or(AppError::SessionNotFound)?;

    Ok(Json(OfframpResponse::from(&session)))
}

/// Manually trigger offramp processing
pub async fn process_offramp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OfframpResponse>, AppError> {
    let uuid = id
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid session ID".to_string()))?;

    let session = state.process_offramp(uuid).await?;

    Ok(Json(OfframpResponse::from(&session)))
}
