//! The backend-agnostic `/v2` API the main route and the advanced route share.
//!
//! Both routes call these endpoints with the same `OpenRequest`. The advanced
//! route fills `overrides` and supplies its own `session_pubkey`; the main
//! route leaves both at their defaults. There is one code path, so an order
//! opened either way produces the same artefacts for the same inputs.
//!
//! `/offramp` is untouched and becomes the advanced route's own API, so the
//! CLI keeps working exactly as it does.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::{info, instrument};
use zecp2p_types::settlement::{
    Amount, BackendId, Capabilities, OpenRequest, Opened, OrderView, Quote, Rail, ReturnState,
    Stage, Timeline, TimelineEntry,
};

use crate::{
    backend::{oneclick, session_key},
    db::OrderRecord,
    error::AppError,
    state::AppState,
};

/// What the front end needs to render the form before anything is typed.
pub async fn capabilities(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let caps: Vec<Capabilities> = vec![oneclick::capabilities()];
    Json(serde_json::json!({
        "backends": caps,
        // Every rail the enclave enumerates, with the live flag, so the picker
        // can show the product's reach and refuse the rest.
        "rails": Rail::all()
            .iter()
            .map(|r| serde_json::json!({
                "id": r.as_str(),
                "label": r.label(),
                "live": r.is_live(),
            }))
            .collect::<Vec<_>>(),
        "fee": {
            "bps": state.config.fee.bps,
            "label": state.config.fee.label(),
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct QuoteV2Query {
    /// Decimal ZEC, or dollars, according to `unit`.
    pub amount: String,
    #[serde(default = "default_unit")]
    pub unit: String,
    #[serde(default = "default_rail")]
    pub rail: String,
    /// `auto` lets the coordinator pick; the advanced route names one.
    #[serde(default)]
    pub backend: Option<String>,
    /// Advanced route only: the zk-p2p spread floor.
    #[serde(default)]
    pub min_rate: Option<String>,
}

fn default_unit() -> String {
    "zec".to_string()
}
fn default_rail() -> String {
    "venmo".to_string()
}

/// Price an order, net, with the zpay fee as one labelled line.
#[instrument(skip(state), fields(amount = %query.amount, unit = %query.unit))]
pub async fn quote_v2(
    State(state): State<Arc<AppState>>,
    Query(query): Query<QuoteV2Query>,
) -> Result<Json<Quote>, AppError> {
    let rail: Rail = query
        .rail
        .parse()
        .map_err(|e: String| AppError::InvalidRequest(e))?;
    if !rail.is_live() {
        return Err(AppError::InvalidRequest(format!(
            "{} is not live yet",
            rail.label()
        )));
    }

    let backend = resolve_backend(query.backend.as_deref())?;
    let amount = parse_amount(&query.amount, &query.unit)?;
    oneclick::check_amount(amount)?;

    // Dollars are priced by asking what that many dollars of ZEC is, which
    // needs the rate first. One quote at a nominal size gives it, and the real
    // quote is then taken at the ZEC amount that lands on the requested
    // dollars. A sender paying a dinner bill thinks in dollars, so this is the
    // unit the main route defaults to showing.
    let zatoshi = match amount {
        Amount::Zec { zatoshi } => zatoshi,
        Amount::Usd { cents } => zatoshi_for_cents(&state, cents).await?,
    };

    let min_rate = crate::api::parse_min_rate_pub(query.min_rate.as_deref())?;
    let quote = build_live_quote(&state, backend, zatoshi, min_rate).await?;

    Ok(Json(quote))
}

/// Ask 1Click what a nominal ZEC amount is worth, then invert to find the ZEC
/// that lands on the requested dollars.
async fn zatoshi_for_cents(state: &Arc<AppState>, cents: u64) -> Result<u64, AppError> {
    const PROBE_ZATOSHI: u64 = 100_000_000; // 1 ZEC

    let glue = state
        .chain
        .glue_contract()
        .map_err(|e| AppError::Config(e.to_string()))?;

    let probe = crate::near::NearIntentsClient::zec_to_usdc_base_request(
        PROBE_ZATOSHI,
        &glue.to_string(),
        crate::api::QUOTE_REFUND_PLACEHOLDER,
        Some(50),
    );
    let quoted = state
        .near
        .get_quote(probe)
        .await
        .map_err(|e| AppError::NearIntents(e.to_string()))?;

    let units_per_zec: u64 = quoted
        .expected_output
        .parse()
        .map_err(|_| AppError::NearIntents("1Click returned an unparseable output".to_string()))?;

    if units_per_zec == 0 {
        return Err(AppError::NearIntents(
            "1Click priced one ZEC at nothing".to_string(),
        ));
    }

    // cents -> USDC units (6 decimals) -> zatoshi, in integer arithmetic so a
    // rounding error cannot quietly move the sender's money.
    let wanted_units = (cents as u128) * 10_000;
    let zatoshi = wanted_units
        .saturating_mul(PROBE_ZATOSHI as u128)
        .div_ceil(units_per_zec as u128);

    u64::try_from(zatoshi)
        .map_err(|_| AppError::InvalidRequest("that is more ZEC than this route takes".to_string()))
}

/// Take a live 1Click quote and turn it into the net price the sender reads.
async fn build_live_quote(
    state: &Arc<AppState>,
    backend: BackendId,
    zatoshi: u64,
    min_rate: alloy::primitives::U256,
) -> Result<Quote, AppError> {
    if backend != BackendId::OneclickZkp2p {
        return Err(AppError::InvalidRequest(
            "the native escrow backend is not open for orders yet".to_string(),
        ));
    }

    let glue = state
        .chain
        .glue_contract()
        .map_err(|e| AppError::Config(e.to_string()))?;

    let request = crate::near::NearIntentsClient::zec_to_usdc_base_request(
        zatoshi,
        &glue.to_string(),
        crate::api::QUOTE_REFUND_PLACEHOLDER,
        Some(50),
    );

    let quoted = state
        .near
        .get_quote(request)
        .await
        .map_err(|e| AppError::NearIntents(e.to_string()))?;

    let expected_usdc_units: u64 = quoted
        .expected_output
        .parse()
        .map_err(|_| AppError::NearIntents("1Click returned an unparseable output".to_string()))?;

    // The quote's own deadline, or the product's TTL, whichever is sooner. A
    // countdown that outlives the swap's deadline is a countdown that lies.
    let oneclick_expiry = chrono::DateTime::from_timestamp(quoted.expires_at as i64, 0);
    let expires_at = match oneclick_expiry {
        Some(t) => t.min(oneclick::default_expiry()),
        None => oneclick::default_expiry(),
    };

    // The id carries the ZEC it was quoted for, so `POST /v2/orders` knows the
    // size without trusting a separate amount field the caller could vary
    // against the price it was shown.
    oneclick::build_quote(
        format!("{}@{}", uuid::Uuid::new_v4(), zatoshi),
        oneclick::QuoteInputs {
            zec_zatoshi: zatoshi,
            expected_usdc_units,
            min_rate,
            fee_bps: state.config.fee.bps,
        },
        state.config.fee.label(),
        expires_at,
    )
}

fn resolve_backend(named: Option<&str>) -> Result<BackendId, AppError> {
    match named.map(str::trim) {
        None | Some("") | Some("auto") => Ok(BackendId::OneclickZkp2p),
        Some(other) => other
            .parse()
            .map_err(|e: String| AppError::InvalidRequest(e)),
    }
}

fn parse_amount(raw: &str, unit: &str) -> Result<Amount, AppError> {
    match unit.trim().to_ascii_lowercase().as_str() {
        "zec" => Ok(Amount::Zec {
            zatoshi: crate::api::parse_zec_amount_pub(raw)?,
        }),
        "usd" => Ok(Amount::Usd {
            cents: parse_usd_cents(raw)?,
        }),
        other => Err(AppError::InvalidRequest(format!(
            "unit must be zec or usd, not {other:?}"
        ))),
    }
}

/// Dollars to whole cents. Two decimal places at most, because a rail cannot
/// send a fraction of a cent and quoting one would be a promise nothing can
/// keep.
fn parse_usd_cents(raw: &str) -> Result<u64, AppError> {
    let s = raw.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(AppError::InvalidRequest(format!(
            "{s:?} is not a dollar amount"
        )));
    }
    let mut parts = s.split('.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some() || frac.len() > 2 {
        return Err(AppError::InvalidRequest(
            "a dollar amount takes at most two decimal places".to_string(),
        ));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| AppError::InvalidRequest("dollar amount is too large".to_string()))?
    };
    let frac: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<2}")
            .parse()
            .map_err(|_| AppError::InvalidRequest("bad cents".to_string()))?
    };
    let cents = whole
        .checked_mul(100)
        .and_then(|c| c.checked_add(frac))
        .ok_or_else(|| AppError::InvalidRequest("dollar amount is too large".to_string()))?;
    if cents == 0 {
        return Err(AppError::InvalidRequest(
            "amount must be more than zero".to_string(),
        ));
    }
    Ok(cents)
}

/// Open an order.
///
/// Nothing is spent on-chain here. The order is a row and a 1Click deposit
/// address until the ZEC arrives; the keeper sends `createSession` and
/// `creditSession` in the tick that sees it. That is what keeps an unfunded
/// order from costing the keeper gas now that session keys are free.
#[instrument(skip(state, headers, body), fields(rail = %body.destination.rail.as_str()))]
pub async fn open_order(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<OpenRequest>,
) -> Result<Json<Opened>, AppError> {
    let destination = zecp2p_types::settlement::PayoutDestination::new(
        body.destination.rail,
        body.destination.handle.clone(),
    )
    .map_err(AppError::InvalidRequest)?;

    // The session key stands in for the wallet, and the caller has to show it
    // holds the key it names. The signature no longer buys griefing protection,
    // because keys are free, but it still stops a caller naming someone else's
    // address as the one rescue and withdraw will pay.
    let identity = session_key::identity_from_hex(&body.session_pubkey)?;
    let scope = format!(
        "{}:{}:{}",
        body.quote_id,
        destination.rail.as_str(),
        destination.handle
    );
    crate::auth::require_owner(&headers, "open", identity.evm_address, &scope)?;

    let backend = resolve_backend(body.overrides.backend.map(|b| b.as_str()))?;

    // Whose address gets a failed swap back. The sender's own when they named
    // one, and the session key's transparent address otherwise. 1Click accepts
    // both, including a shielded unified address, so a sender who named one
    // needs no sweep at all.
    let refund_address = match body.overrides.refund_address.as_deref() {
        Some(named) => {
            crate::near::validate_zec_refund_address(named)
                .map_err(|e| AppError::InvalidRequest(e.to_string()))?;
            named.to_string()
        }
        None => identity.transparent_address.clone(),
    };

    let min_rate = crate::api::parse_min_rate_pub(body.overrides.min_rate.as_deref())?;

    // Re-quote at open time rather than trusting a quote_id the caller sends
    // back. A quote is a price, not a claim: honouring a stale one would let a
    // caller sit on a good rate and open against it later.
    let quote = build_live_quote(&state, backend, quote_zatoshi(&body)?, min_rate).await?;

    // The rail's payee has to be registered with the curator before a deposit
    // can name it, and a rejection here costs no gas because none has been
    // spent yet.
    let valid = state
        .zkp2p
        .validate_venmo_payee(&destination.handle)
        .await
        .map_err(|e| AppError::Zkp2p(e.to_string()))?;
    if !valid {
        return Err(AppError::InvalidRequest(format!(
            "{} was rejected by the payment network. Check the handle matches the \
             account's exact spelling.",
            destination.describe()
        )));
    }

    let glue = state
        .chain
        .glue_contract()
        .map_err(|e| AppError::Config(e.to_string()))?;

    let swap = crate::near::NearIntentsClient::zec_to_usdc_base_request(
        quote.zec_zatoshi,
        &glue.to_string(),
        &refund_address,
        Some(50),
    );
    let opened_quote = state
        .near
        .get_quote(swap)
        .await
        .map_err(|e| AppError::NearIntents(e.to_string()))?;

    let deposit_expiry = chrono::DateTime::from_timestamp(opened_quote.expires_at as i64, 0)
        .unwrap_or_else(|| Utc::now() + chrono::Duration::minutes(5));

    let deposit = zecp2p_types::settlement::DepositInstruction {
        zip321_uri: zecp2p_types::zip321::payment_uri(
            &opened_quote.deposit_address,
            quote.zec_zatoshi,
            None,
            Some(&format!("zpay to {}", destination.describe())),
        ),
        address: opened_quote.deposit_address.clone(),
        amount_zat: quote.zec_zatoshi,
        memo: None,
        expires_at: deposit_expiry,
        kind: zecp2p_types::settlement::DepositKind::Swap,
    };

    let now = Utc::now();
    let order = OrderRecord {
        id: uuid::Uuid::new_v4(),
        backend,
        destination: destination.clone(),
        session_pubkey: body.session_pubkey.trim().to_string(),
        evm_address: format!("{:?}", identity.evm_address),
        refund_address,
        quote: quote.clone(),
        deposit: Some(deposit.clone()),
        overrides: body.overrides.clone(),
        session_uuid: None,
        stage: Stage::AwaitingZec,
        returns: ReturnState::None,
        error: None,
        created_at: now,
        updated_at: now,
    };

    state
        .db
        .insert_order(&order)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    info!(order_id = %order.id, backend = %backend, "order opened, no gas spent");

    Ok(Json(Opened {
        order_id: order.id,
        backend,
        deposit,
        terms_hash: terms_hash(&order),
        // Backend A needs nothing from the sender after the ZEC is sent.
        client_steps: Vec::new(),
    }))
}

/// The ZEC an open request is for, taken from its own quote.
fn quote_zatoshi(body: &OpenRequest) -> Result<u64, AppError> {
    // The quote id carries no amount, so the caller sends the amount it was
    // quoted for alongside it. `quote_id` stays as the correlation handle.
    body.quote_id
        .split_once('@')
        .and_then(|(_, z)| z.parse().ok())
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "quote_id must be the value /v2/quote returned".to_string(),
            )
        })
}

/// A hash over the terms the order was opened on, so a sender can check the
/// order they are watching is the one they agreed to.
fn terms_hash(order: &OrderRecord) -> String {
    use alloy::primitives::keccak256;
    let preimage = format!(
        "{}|{}|{}|{}|{}|{}",
        order.backend.as_str(),
        order.destination.rail.as_str(),
        order.destination.handle,
        order.quote.zec_zatoshi,
        order.quote.net_cents,
        order.evm_address,
    );
    format!("{:?}", keccak256(preimage.as_bytes()))
}

/// The status view: the ladder, what is coming back, and the receipt.
#[instrument(skip(state), fields(order_id = %id))]
pub async fn get_order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<OrderView>, AppError> {
    let uuid: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::InvalidRequest("that is not an order id".to_string()))?;

    let order = state
        .db
        .get_order(uuid)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::SessionNotFound)?;

    // Raw identifiers live here and nowhere else on the main view. The page
    // shows them only behind a details disclosure.
    let mut details: Vec<(String, String)> = vec![
        ("order id".into(), order.id.to_string()),
        ("route".into(), order.quote.route_label.clone()),
        ("session address".into(), order.evm_address.clone()),
        ("refund destination".into(), order.refund_address.clone()),
    ];
    if let Some(session_uuid) = order.session_uuid {
        details.push(("session id".into(), session_uuid.to_string()));
    }
    if let Some(d) = &order.deposit {
        details.push(("deposit address".into(), d.address.clone()));
    }

    let timeline = Timeline {
        stage: order.stage,
        entries: vec![TimelineEntry {
            stage: order.stage,
            at: order.updated_at,
            note: order.error.clone(),
        }],
        details,
    };

    Ok(Json(OrderView {
        order_id: order.id,
        backend: order.backend,
        destination: order.destination.clone(),
        timeline,
        returns: order.returns.clone(),
        quote: order.quote.clone(),
        deposit: order.deposit.clone(),
        client_steps: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollars_parse_to_whole_cents() {
        assert_eq!(parse_usd_cents("25").unwrap(), 2500);
        assert_eq!(parse_usd_cents("25.00").unwrap(), 2500);
        assert_eq!(parse_usd_cents("25.5").unwrap(), 2550);
        assert_eq!(parse_usd_cents("0.05").unwrap(), 5);
        assert_eq!(parse_usd_cents(" 5.00 ").unwrap(), 500);
    }

    /// A rail cannot send a fraction of a cent, so quoting one would be a
    /// promise nothing can keep.
    #[test]
    fn fractions_of_a_cent_are_refused() {
        assert!(parse_usd_cents("5.001").is_err());
        assert!(parse_usd_cents("5.1.2").is_err());
        assert!(parse_usd_cents("").is_err());
        assert!(parse_usd_cents("0").is_err());
        assert!(parse_usd_cents("0.00").is_err());
        assert!(parse_usd_cents("-5").is_err());
        assert!(parse_usd_cents("1e5").is_err());
        assert!(parse_usd_cents("NaN").is_err());
    }

    #[test]
    fn auto_and_an_empty_backend_both_mean_the_live_one() {
        assert_eq!(resolve_backend(None).unwrap(), BackendId::OneclickZkp2p);
        assert_eq!(resolve_backend(Some("auto")).unwrap(), BackendId::OneclickZkp2p);
        assert_eq!(resolve_backend(Some("")).unwrap(), BackendId::OneclickZkp2p);
        assert_eq!(
            resolve_backend(Some("native-escrow")).unwrap(),
            BackendId::NativeEscrow
        );
        assert!(resolve_backend(Some("something-else")).is_err());
    }

    #[test]
    fn units_are_zec_or_usd_and_nothing_else() {
        assert!(matches!(
            parse_amount("0.5", "zec").unwrap(),
            Amount::Zec { zatoshi: 50_000_000 }
        ));
        assert!(matches!(
            parse_amount("25", "usd").unwrap(),
            Amount::Usd { cents: 2500 }
        ));
        assert!(parse_amount("25", "eur").is_err());
    }
}
