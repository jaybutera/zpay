//! REST API handlers

use std::sync::Arc;

use alloy::primitives::U256;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::{info, instrument};
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
#[instrument(skip(state), fields(zec_amount = %query.zec_amount))]
pub async fn get_quote(
    State(state): State<Arc<AppState>>,
    Query(query): Query<QuoteQuery>,
) -> Result<Json<QuoteResponse>, AppError> {
    info!("Quote request for {} ZEC", query.zec_amount);

    // Parse ZEC amount (convert from decimal ZEC to zatoshi)
    let zatoshi = parse_zec_amount(&query.zec_amount)?;

    // Get quote from NEAR Intents
    let glue_address = state
        .chain
        .glue_contract()
        .map_err(|e| AppError::Config(e.to_string()))?;

    // Use the helper to create the ZEC → USDC request
    // For refund address, we use a placeholder since we don't have user's ZEC address yet
    let quote_request = crate::near::NearIntentsClient::zec_to_usdc_base_request(
        zatoshi,
        &glue_address.to_string(),
        "t1placeholder", // User will provide real ZEC refund address during offramp
        Some(50), // 0.5% slippage
    );

    let quote = state
        .near
        .get_quote(quote_request)
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
    let zec_decimal = zatoshi as f64 / 100_000_000.0;
    let rate = if zec_decimal > 0.0 {
        usdc_decimal / zec_decimal
    } else {
        0.0
    };

    info!(
        zec = %query.zec_amount,
        usdc = %format!("{:.6}", usdc_decimal),
        rate = %format!("{:.4}", rate),
        "Quote generated"
    );

    // Calculate expiry safely
    let expires_at = chrono::DateTime::from_timestamp(quote.expires_at as i64, 0)
        .unwrap_or_else(|| Utc::now() + chrono::Duration::minutes(5));

    Ok(Json(QuoteResponse {
        zec_amount: query.zec_amount,
        usdc_amount: format!("{:.6}", usdc_decimal),
        venmo_amount: format!("{:.2}", venmo_amount),
        rate: format!("{:.4}", rate),
        expires_at,
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
    /// User's Zcash address for refunds (t1/t3/zs prefix)
    pub zec_refund_address: String,
    /// Minimum USD per USDC the taker must pay on zk-p2p (decimal, default "1.0")
    #[serde(default)]
    pub min_rate: Option<String>,
    /// Timeout in seconds
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Create a new offramp
#[instrument(skip(state, body), fields(zec_amount = %body.zec_amount, venmo = %body.venmo_username))]
pub async fn create_offramp(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateOfframpBody>,
) -> Result<Json<OfframpResponse>, AppError> {
    info!(
        zec = %body.zec_amount,
        venmo = %body.venmo_username,
        user = %body.user_address,
        taker = %body.taker_address,
        "Creating offramp"
    );

    // Validate Venmo username
    validate_venmo_username(&body.venmo_username)?;

    // Parse ZEC amount
    let zatoshi = parse_zec_amount(&body.zec_amount)?;

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
    let min_rate = parse_min_rate(body.min_rate.as_deref())?;

    // Validate ZEC refund address format (basic check)
    validate_zec_address(&body.zec_refund_address)?;

    let request = OfframpRequest {
        zec_amount: zatoshi,
        venmo_username: body.venmo_username,
        user_address,
        taker_address,
        zec_refund_address: body.zec_refund_address,
        min_rate,
        timeout_seconds: body.timeout_seconds.unwrap_or(600),
    };

    let session = state.create_offramp(request).await?;

    info!(
        session_id = %session.id,
        deposit_address = ?session.near_deposit_address,
        expected_usdc = ?session.expected_usdc,
        "Offramp created"
    );

    Ok(Json(OfframpResponse::from(&session)))
}

/// Get offramp status
#[instrument(skip(state), fields(session_id = %id))]
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
#[instrument(skip(state), fields(session_id = %id))]
pub async fn process_offramp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OfframpResponse>, AppError> {
    info!("Processing offramp for session {}", id);

    let uuid = id
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid session ID".to_string()))?;

    let session = state.process_offramp(uuid).await?;

    info!(
        session_id = %session.id,
        status = ?session.status,
        deposit_id = ?session.zkp2p_deposit_id,
        "Offramp processed"
    );

    Ok(Json(OfframpResponse::from(&session)))
}

/// Rescue funds from GlueContract
/// Returns USDC to user if processOfframp failed
#[instrument(skip(state), fields(session_id = %id))]
pub async fn rescue_offramp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OfframpResponse>, AppError> {
    info!("Rescuing offramp for session {}", id);

    let uuid = id
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid session ID".to_string()))?;

    let session = state.rescue(uuid).await?;

    info!(
        session_id = %session.id,
        status = ?session.status,
        "Offramp rescued"
    );

    Ok(Json(OfframpResponse::from(&session)))
}

/// Withdraw from zk-p2p deposit
/// Withdraws USDC from zk-p2p escrow if no taker signaled intent
#[instrument(skip(state), fields(session_id = %id))]
pub async fn withdraw_offramp(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OfframpResponse>, AppError> {
    info!("Withdrawing offramp for session {}", id);

    let uuid = id
        .parse()
        .map_err(|_| AppError::InvalidState("Invalid session ID".to_string()))?;

    let session = state.withdraw(uuid).await?;

    info!(
        session_id = %session.id,
        status = ?session.status,
        "Offramp withdrawn"
    );

    Ok(Json(OfframpResponse::from(&session)))
}

// === Validation helper functions ===

/// Parse ZEC amount from decimal string to zatoshi
/// Handles up to 8 decimal places (ZEC precision)
fn parse_zec_amount(amount_str: &str) -> Result<u64, AppError> {
    // Remove any whitespace
    let amount_str = amount_str.trim();

    // Split on decimal point
    let parts: Vec<&str> = amount_str.split('.').collect();

    match parts.len() {
        1 => {
            // Integer amount (whole ZEC)
            let whole: u64 = parts[0]
                .parse()
                .map_err(|_| AppError::InvalidState("Invalid ZEC amount".to_string()))?;

            // Check for reasonable bounds (0 < amount <= 21M ZEC)
            if whole == 0 {
                return Err(AppError::InvalidState("ZEC amount must be greater than 0".to_string()));
            }
            if whole > 21_000_000 {
                return Err(AppError::InvalidState("ZEC amount exceeds maximum supply".to_string()));
            }

            whole.checked_mul(100_000_000)
                .ok_or_else(|| AppError::InvalidState("ZEC amount overflow".to_string()))
        }
        2 => {
            // Decimal amount
            let whole: u64 = if parts[0].is_empty() {
                0
            } else {
                parts[0]
                    .parse()
                    .map_err(|_| AppError::InvalidState("Invalid ZEC amount".to_string()))?
            };

            // Pad or truncate fractional part to 8 digits
            let frac_str = parts[1];
            if frac_str.len() > 8 {
                return Err(AppError::InvalidState("ZEC amount has too many decimal places (max 8)".to_string()));
            }

            let padded = format!("{:0<8}", frac_str);
            let frac: u64 = padded
                .parse()
                .map_err(|_| AppError::InvalidState("Invalid ZEC decimal amount".to_string()))?;

            let zatoshi = whole
                .checked_mul(100_000_000)
                .and_then(|w| w.checked_add(frac))
                .ok_or_else(|| AppError::InvalidState("ZEC amount overflow".to_string()))?;

            // Check bounds
            if zatoshi == 0 {
                return Err(AppError::InvalidState("ZEC amount must be greater than 0".to_string()));
            }

            Ok(zatoshi)
        }
        _ => Err(AppError::InvalidState("Invalid ZEC amount format".to_string())),
    }
}

/// Validate Venmo username format
fn validate_venmo_username(username: &str) -> Result<(), AppError> {
    let username = username.trim();

    // Length check (Venmo usernames are 5-30 characters)
    if username.len() < 2 {
        return Err(AppError::InvalidState("Venmo username too short (minimum 2 characters)".to_string()));
    }
    if username.len() > 30 {
        return Err(AppError::InvalidState("Venmo username too long (maximum 30 characters)".to_string()));
    }

    // Character check (alphanumeric, underscore, hyphen)
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(AppError::InvalidState(
            "Venmo username contains invalid characters (only alphanumeric, underscore, hyphen allowed)".to_string()
        ));
    }

    Ok(())
}

/// Validate ZEC address format
fn validate_zec_address(address: &str) -> Result<(), AppError> {
    let address = address.trim();

    // Basic prefix check
    if !address.starts_with("t1")
        && !address.starts_with("t3")
        && !address.starts_with("zs")
    {
        return Err(AppError::InvalidState(
            "Invalid ZEC refund address (must start with t1, t3, or zs)".to_string(),
        ));
    }

    // Length check - t-addresses are 35 chars, z-addresses are longer
    if address.starts_with("t") && address.len() != 35 {
        return Err(AppError::InvalidState(
            "Invalid ZEC t-address length (expected 35 characters)".to_string(),
        ));
    }

    if address.starts_with("zs") && address.len() < 78 {
        return Err(AppError::InvalidState(
            "Invalid ZEC z-address length (too short)".to_string(),
        ));
    }

    Ok(())
}

/// Parse min_rate (USD per USDC the zk-p2p taker must pay) from a decimal
/// string to U256 with 18 decimals
fn parse_min_rate(rate_str: Option<&str>) -> Result<U256, AppError> {
    match rate_str {
        Some(s) => {
            let rate: f64 = s
                .parse()
                .map_err(|_| AppError::InvalidState("Invalid min_rate".to_string()))?;

            if rate <= 0.0 {
                return Err(AppError::InvalidState("min_rate must be positive".to_string()));
            }
            if rate > 1_000_000.0 {
                return Err(AppError::InvalidState("min_rate is unreasonably high".to_string()));
            }

            // Convert to 18-decimal precision safely
            // Split into integer and fractional parts to avoid precision loss
            let int_part = rate.trunc() as u128;
            let frac_part = ((rate.fract()) * 1e18) as u128;

            let scaled = int_part
                .checked_mul(10u128.pow(18))
                .and_then(|i| i.checked_add(frac_part))
                .ok_or_else(|| AppError::InvalidState("min_rate overflow".to_string()))?;

            Ok(U256::from(scaled))
        }
        None => {
            // Default: 1 USD per USDC
            Ok(U256::from(10u64).pow(U256::from(18u64)))
        }
    }
}
