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
    extract::{ConnectInfo, Extension, Path, Query, State},
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

/// Take a token for this caller, or refuse before anything upstream is called.
fn source_for(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
) -> std::net::IpAddr {
    crate::ratelimit::source_of(
        headers,
        peer.map(|Extension(ConnectInfo(addr))| addr),
        state.config.server.behind_trusted_proxy,
    )
}

async fn limit(
    state: &Arc<AppState>,
    limiter: &crate::ratelimit::RateLimiter,
    headers: &HeaderMap,
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
) -> Result<(), AppError> {
    limit_source(limiter, source_for(state, headers, peer)).await
}

/// The same check for a caller that already knows its own source, so the open
/// path can limit and then count the backlog against one address rather than
/// deriving it twice (U3-2).
async fn limit_source(
    limiter: &crate::ratelimit::RateLimiter,
    source: std::net::IpAddr,
) -> Result<(), AppError> {
    limiter
        .check(source)
        .await
        .map_err(|e| AppError::TooManyRequests {
            retry_after_seconds: e.retry_after_seconds,
        })
}

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
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    Query(query): Query<QuoteV2Query>,
) -> Result<Json<Quote>, AppError> {
    limit(&state, &state.quote_limiter, &headers, peer).await?;

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
        // A ZEC amount is not sized from a rate, so there is no rate to name a
        // dollar floor with; the page falls back to the zatoshi figure, which is
        // the unit that caller asked in anyway.
        Amount::Zec { zatoshi } => (zatoshi, None),
        Amount::Usd { cents } => {
            let (zatoshi, units_per_zec) = zatoshi_for_cents(&state, cents).await?;
            // U2-3. The dollar amount is refused here, in dollars, by the same
            // arithmetic that sized it, rather than left for the page to
            // reconstruct from the zatoshi floor at a rate it computed
            // differently. `first_quotable_cents` is the smallest whole-cent
            // amount whose ZEC lands on or above the floor, so a sender told
            // "try $1.09" gets a quote for $1.09.
            let floor = crate::near::observed_floor();
            if zatoshi < floor {
                return Err(AppError::BelowFloor {
                    zatoshi: floor,
                    cents: first_quotable_cents(floor, units_per_zec),
                });
            }
            (zatoshi, Some(units_per_zec))
        }
    };
    let (zatoshi, units_per_zec) = zatoshi;

    let min_rate = crate::api::parse_min_rate_pub(query.min_rate.as_deref())?;
    let quote = build_live_quote(&state, backend, zatoshi, min_rate)
        .await
        // U3-3. The local floor check above uses `observed_floor()`, which is
        // the last floor 1Click named in a rejection and is a guess until the
        // first rejection of the process. On a cold start the guess is low, the
        // sizing passes the local check, and 1Click refuses the real quote; the
        // refusal came back as `BelowFloor { cents: None }` and the page, having
        // asked in dollars, rendered a ZEC amount under a dollar sign. It
        // happened once per process, and the process is restarted to deploy, so
        // the first dollar sender after every deploy got it.
        //
        // The rate is already in hand from the sizing probe, and it is the same
        // number `first_quotable_cents` would be given a moment later on the
        // retry, so the cents are filled here rather than left for the sender to
        // discover by reloading.
        .map_err(|e| fill_in_the_dollar_floor(e, units_per_zec))?;

    // The id is now a thing the coordinator issued, not a string the caller can
    // invent, and opening against it spends it. Because the signature's scope
    // contains the id, that is also what makes the signature single-use (U1-2).
    state
        .quotes
        .issue(&quote.quote_id, quote.zec_zatoshi, quote.expires_at)
        .await;

    Ok(Json(quote))
}

/// Ask 1Click what a nominal ZEC amount is worth, then invert to find the ZEC
/// that lands on the requested dollars.
///
/// Returns the ZEC and the rate it was inverted at, in USDC units per whole
/// ZEC, so a caller who has to refuse the result can quote the floor back in
/// dollars using the same number rather than a second, different one (U2-3).
async fn zatoshi_for_cents(state: &Arc<AppState>, cents: u64) -> Result<(u64, u64), AppError> {
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
        .get_dry_quote(probe)
        .await
        .map_err(AppError::from_quote_error)?;

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

    let zatoshi = u64::try_from(zatoshi).map_err(|_| {
        AppError::InvalidRequest("that is more ZEC than this route takes".to_string())
    })?;
    Ok((zatoshi, units_per_zec))
}

/// The smallest whole-cent amount that `zatoshi_for_cents` would size at or
/// above `floor_zatoshi`, at the rate that was just observed.
///
/// U2-3. The sizing rounds ZEC *up* from cents, so the boundary is not simply
/// the floor converted to dollars: at 132,000 zatoshi and 1Click's rate on
/// 2026-09-03, $1.08 sized to 131,868 zatoshi and was refused while $1.09 sized
/// to 132,920 and quoted. Naming the cent below the boundary is what made the
/// old hint useless, so the boundary is found rather than approximated, and it
/// is found by the same `div_ceil` the sizing uses so the two cannot disagree.
///
/// A rate that puts the floor above what a `u64` of cents can hold, or a zero
/// rate, gives `None` and the page falls back to naming the ZEC amount.
fn first_quotable_cents(floor_zatoshi: u64, units_per_zec: u64) -> Option<u64> {
    if units_per_zec == 0 {
        return None;
    }

    // The candidate: the floor priced at this rate, rounded up to a whole cent.
    // In USDC units, `floor_zatoshi * units_per_zec / PROBE_ZATOSHI`, then up to
    // the next cent, which is 10,000 units.
    const PROBE_ZATOSHI: u128 = 100_000_000;
    let floor_units = (floor_zatoshi as u128)
        .checked_mul(units_per_zec as u128)?
        .div_ceil(PROBE_ZATOSHI);
    let mut cents = u64::try_from(floor_units.div_ceil(10_000)).ok()?;
    if cents == 0 {
        cents = 1;
    }

    // Confirm, and step up if the rounding landed a cent short. One step is
    // always enough at any rate a cent is worth less than the floor's step, and
    // the loop is bounded anyway so a pathological rate cannot hang the
    // handler.
    for _ in 0..4 {
        let sized = (cents as u128)
            .checked_mul(10_000)?
            .checked_mul(PROBE_ZATOSHI)?
            .div_ceil(units_per_zec as u128);
        if sized >= floor_zatoshi as u128 {
            return Some(cents);
        }
        cents = cents.checked_add(1)?;
    }
    None
}

/// Put the dollar floor back into a below-the-floor refusal that lost it.
///
/// U3-3. `from_quote_error` turns 1Click's rejection into `BelowFloor` with the
/// zatoshi figure it named and `cents: None`, because at the point it runs
/// nothing knows what a dollar is worth. A caller who asked in dollars has
/// already paid for a rate probe, so the answer is in hand here; anything that
/// is not a below-the-floor refusal, and any caller who asked in ZEC, passes
/// through untouched.
fn fill_in_the_dollar_floor(err: AppError, units_per_zec: Option<u64>) -> AppError {
    match (err, units_per_zec) {
        (AppError::BelowFloor { zatoshi, cents: None }, Some(rate)) => AppError::BelowFloor {
            zatoshi,
            cents: first_quotable_cents(zatoshi, rate),
        },
        (other, _) => other,
    }
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
        .get_dry_quote(request)
        .await
        .map_err(AppError::from_quote_error)?;

    let expected_usdc_units: u64 = quoted
        .expected_output
        .parse()
        .map_err(|_| AppError::NearIntents("1Click returned an unparseable output".to_string()))?;

    // The quote's own deadline, or the product's TTL, whichever is sooner. A
    // countdown that outlives the swap's deadline is a countdown that lies.
    //
    // A dry quote carries no deadline and `expires_at` comes back as 0, which
    // is the epoch. Taking the minimum against that put every price on screen
    // under a "price expired" label the moment it rendered, so a zero is
    // treated as "not stated" rather than as a timestamp.
    let ttl = oneclick::default_expiry();
    let expires_at = match chrono::DateTime::from_timestamp(quoted.expires_at as i64, 0) {
        Some(t) if quoted.expires_at > 0 => t.min(ttl),
        _ => ttl,
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
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<OpenRequest>,
) -> Result<Json<Opened>, AppError> {
    // Derived once: the limiter buckets on it and the backlog cap counts on it,
    // and the two must agree about who is calling or the cap is bounding a
    // different caller from the one the limiter slowed (U3-2).
    let source = source_for(&state, &headers, peer);
    limit_source(&state.open_limiter, source).await?;

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
            // U3-8. Stored in the one form that decodes everywhere: validation
            // folds case for a unified address, so keeping what was typed would
            // put `U1…` on the row and hand it to 1Click, whose own decoder
            // takes the lower-case form.
            crate::near::canonical_zec_address(named)
        }
        None => identity.transparent_address.clone(),
    };

    let min_rate = crate::api::parse_min_rate_pub(body.overrides.min_rate.as_deref())?;

    // U2-1. An unfunded order costs whoever opened it nothing and costs the
    // keeper a 1Click status call every tick until its window closes. The rate
    // limiter slows the opening; it does not bound how many can be outstanding,
    // and a caller who spends three and a half minutes can fill the sweep's
    // whole budget and hold it. Two caps bound it instead: one per session key,
    // which is what a real sender has one of, and one across the coordinator,
    // which is the number the sweep's budget is actually sized against.
    //
    // Both are checked before the quote is spent, so hitting one costs the
    // caller their price and nothing else.
    check_the_unfunded_backlog(&state, &body.session_pubkey, source).await?;

    // U2-4. The checks that cost no 1Click round trip run *before* the quote is
    // spent. The curator is the one that a sender realistically fails: a
    // mistyped handle came back "check the spelling", and by then the id was
    // burned, so correcting the handle and resubmitting answered "an order has
    // already been opened at that price" and the only way out was to change the
    // amount. The handle is checked here, against the price the sender is still
    // holding, and the id is spent below only once nothing cheap can refuse it.
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

    // Spend the quote. This is the single-use gate: an id the coordinator never
    // issued, one that has expired, and one already opened against are all
    // refused here, before any 1Click round trip. The audit opened 31 orders
    // from one signature and one from an invented id; both stop here (U1-2).
    //
    // It runs after `require_owner` so an unauthenticated caller cannot burn
    // somebody else's price by guessing at ids. Everything from here on either
    // creates the order or fails for a reason a resubmission would not fix, so
    // this is the last point at which the id can be spent without stranding a
    // sender who can still act.
    let zatoshi = state
        .quotes
        .spend(body.quote_id.trim())
        .await
        .map_err(|e| AppError::InvalidRequest(e.message().to_string()))?;

    // Bounds, so an amount 1Click would refuse costs no round trip and comes
    // back as its own number rather than as an upstream category. The open path
    // skipped this entirely, so an open at 1 zatoshi went all the way to 1Click
    // and returned a 502 (U1-3).
    oneclick::check_amount(Amount::Zec { zatoshi })?;

    // Re-quote at open time rather than trusting a quote_id the caller sends
    // back. A quote is a price, not a claim: honouring a stale one would let a
    // caller sit on a good rate and open against it later.
    let quote = build_live_quote(&state, backend, zatoshi, min_rate).await?;

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
        .map_err(AppError::from_quote_error)?;

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
        // The outputs of the quote that minted this deposit address, kept so
        // promotion can bind the session to the swap the sender actually funds
        // instead of taking a second quote (U1-1).
        swap_expected_usdc: Some(opened_quote.expected_output.clone()),
        swap_min_usdc: Some(opened_quote.min_output.clone()),
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
        .insert_order_from_source(&order, Some(&source.to_string()))
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

/// How many orders one session key may have open and unfunded at once.
///
/// A real sender has one. Two is a sender who opened the page twice, or came
/// back to a link and started again; three is a sender being patient with a
/// flaky wallet. Four is nobody, so the cap sits there.
const MAX_UNFUNDED_PER_KEY: i64 = 4;

/// How many unfunded orders one source address may hold open at once.
///
/// U3-2. This is the cap that actually bounds a flood. The per-key cap above
/// bounds nobody, because session keys are free and the page mints a new one on
/// every submit, so two hundred rows from one script look like two hundred
/// senders to it. The source address is the first thing in the request that
/// costs anything to vary.
///
/// Eight, against a global cap of 400, means one address can hold two per cent
/// of the queue and it takes fifty distinct addresses to fill it. It is loose
/// enough for the shape a real sender produces even sharing an address: a
/// household, an office, a mobile carrier NAT. Reaching it is answered as a
/// queue, not as a scolding, because behind a NAT the person refused may well
/// not be the person who filled it.
pub const MAX_UNFUNDED_PER_SOURCE: i64 = 8;

/// How many unfunded orders the coordinator will hold across every caller.
///
/// The number the sweep's budget is sized against: at 1Click's measured status
/// latency of about 0.2 s, a five-second budget covers roughly twenty-five
/// orders, so 400 puts the worst case at sixteen ticks, or four minutes at the
/// default fifteen-second interval, before any order is polled again.
///
/// U3-2. It was 200, and it was the only bound that bit, which made it a
/// lockout: two hundred free-key opens, about five minutes of requests from
/// seven addresses, refused every new sender for the six hours it took the
/// backlog to time out. Three things changed together. The per-source cap above
/// is what a flood now runs into first. `MAX_UNFUNDED_SHED_ABOVE` makes the
/// queue shed its stalest rows instead of sitting full. And this number is a
/// last resort rather than the first one, so it is set where the sweep still
/// keeps its promise rather than where a flood is cheap.
pub const MAX_UNFUNDED_TOTAL: i64 = 400;

/// The level above which the sweep starts retiring the stalest unfunded orders
/// early, instead of waiting for each one's own six-hour window.
///
/// U3-2. Half the cap. Below it nothing is shed and every order gets its full
/// window; above it the queue drains from the oldest end, so a flood ages out
/// in minutes rather than hours and the global cap is reached only by a rush of
/// orders that are all genuinely recent. The shedding still asks 1Click about
/// every order before retiring it (U3-1), so an order somebody has actually
/// paid is never shed.
pub const MAX_UNFUNDED_SHED_ABOVE: i64 = 200;

/// How long an unfunded order is safe from early shedding, however full the
/// queue is.
///
/// The page promises a payment inside twenty minutes and 1Click's deposit
/// windows are longer than that, so an order younger than this is a sender who
/// may still be opening their wallet. Nothing younger is shed, at any depth of
/// queue; a flood large enough to fill 400 rows with orders under an hour old
/// has to keep 400 opens in flight against the per-source cap of eight, which
/// takes fifty addresses sustained rather than seven for five minutes.
pub const SHED_NOTHING_YOUNGER_THAN: chrono::Duration = chrono::Duration::hours(1);

/// Refuse an open that would push the unfunded backlog past what the keeper can
/// sweep in bounded time (U2-1, U3-2).
async fn check_the_unfunded_backlog(
    state: &Arc<AppState>,
    session_pubkey: &str,
    source: std::net::IpAddr,
) -> Result<(), AppError> {
    let mine = state
        .db
        .count_unfunded_orders_for_key(session_pubkey.trim())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if mine >= MAX_UNFUNDED_PER_KEY {
        return Err(AppError::InvalidRequest(format!(
            "you already have {mine} orders waiting for ZEC. Send to one of those, \
             or wait for them to close, before opening another."
        )));
    }

    // U3-2. Per source, and before the global count, so a flood is refused at
    // the address making it rather than at whoever asks next.
    let from_here = state
        .db
        .count_unfunded_orders_from_source(&source.to_string())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if from_here >= MAX_UNFUNDED_PER_SOURCE {
        tracing::warn!(
            unfunded = from_here,
            "one source is holding its whole share of the unfunded backlog"
        );
        return Err(AppError::QueueFull {
            retry_after_seconds: 60,
        });
    }

    let all = state
        .db
        .count_unfunded_orders()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if all >= MAX_UNFUNDED_TOTAL {
        // Reaching this now takes fifty addresses holding eight orders each,
        // all under an hour old, and it says so as a queue rather than as an
        // accusation: the caller refused here has usually opened nothing.
        tracing::warn!(unfunded = all, "the unfunded backlog is full; refusing new orders");
        return Err(AppError::QueueFull {
            retry_after_seconds: 60,
        });
    }

    Ok(())
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

    /// U3-3. A dollar ask that 1Click itself refuses comes back with the floor
    /// and no dollar figure, because `from_quote_error` runs where no rate is
    /// in hand. The caller has one, from the probe that sized the ask, so it
    /// fills the number in.
    ///
    /// The case is not exotic: `observed_floor()` is a guess until 1Click has
    /// rejected something in this process, so on a cold start the local check
    /// passes an amount 1Click will refuse. It happens once per process, and
    /// the process is restarted to deploy, so the first dollar sender after
    /// every deploy is the one who gets it. The page then renders a ZEC amount
    /// under a dollar sign.
    #[test]
    fn a_dollar_ask_refused_upstream_still_names_a_dollar_amount() {
        // The numbers from the audit: 1Click's floor is 132,000 and one ZEC is
        // 819,907,155 units, and the rate is known because the ask was in
        // dollars.
        let filled = fill_in_the_dollar_floor(
            AppError::BelowFloor { zatoshi: 132_000, cents: None },
            Some(819_907_155),
        );
        match filled {
            AppError::BelowFloor { zatoshi, cents } => {
                assert_eq!(zatoshi, 132_000);
                assert_eq!(
                    cents,
                    Some(109),
                    "U3-3: the refusal named no dollar amount, so the page prints \
                     a ZEC figure under a dollar sign"
                );
            }
            other => panic!("the refusal changed shape: {other:?}"),
        }
    }

    /// A ZEC ask has no rate behind it, so there is nothing to name and nothing
    /// is invented. The page falls back to the zatoshi figure, which is the
    /// unit that caller asked in.
    #[test]
    fn a_zec_ask_refused_upstream_is_left_alone() {
        let untouched = fill_in_the_dollar_floor(
            AppError::BelowFloor { zatoshi: 132_000, cents: None },
            None,
        );
        assert!(matches!(
            untouched,
            AppError::BelowFloor { zatoshi: 132_000, cents: None }
        ));
    }

    /// And a refusal that already carries its dollar amount, or is not about
    /// the floor at all, passes through untouched.
    #[test]
    fn only_a_floor_refusal_missing_its_cents_is_filled_in() {
        let already = fill_in_the_dollar_floor(
            AppError::BelowFloor { zatoshi: 132_000, cents: Some(150) },
            Some(819_907_155),
        );
        assert!(matches!(
            already,
            AppError::BelowFloor { cents: Some(150), .. }
        ));

        let other = fill_in_the_dollar_floor(
            AppError::NearIntents("the bridge is down".to_string()),
            Some(819_907_155),
        );
        assert!(matches!(other, AppError::NearIntents(_)));
    }

    /// U2-3, against the day's real numbers. On 2026-09-03 1Click's floor was
    /// 132,000 zatoshi and one ZEC quoted at 819,907,155 USDC units. Through
    /// the coordinator, $1.08 was refused and $1.09 quoted at 132,920 zatoshi,
    /// while the page's own conversion suggested $1.08. The first amount that
    /// quotes is the one this has to name.
    #[test]
    fn the_named_dollar_floor_is_the_first_amount_that_quotes() {
        let cents = first_quotable_cents(132_000, 819_907_155).expect("a rate this size converts");
        assert_eq!(cents, 109, "$1.08 was refused on the day this is taken from");
    }

    /// The same check against the rate on 2026-09-03, taken from live dry
    /// quotes rather than from the audit: the floor was still 132,000 and one
    /// ZEC quoted at 819,767,684 units. $1.08 sizes to 131,745 zatoshi and
    /// 1Click refuses it; $1.09 sizes to 132,965 and 1Click quoted it at
    /// 1,084,699 units out. The rate moved between the two days and the answer
    /// did not, which is the point: the boundary is computed, not pinned.
    #[test]
    fn the_named_dollar_floor_holds_at_a_second_days_rate() {
        assert_eq!(first_quotable_cents(132_000, 819_767_684), Some(109));
    }

    /// The property behind that number: whatever it names must survive the
    /// sizing the quote path actually performs, and the cent below it must not.
    /// Checked across a wide spread of rates, because a hint that is a cent
    /// short is worse than no hint at all: the sender does what it says and is
    /// refused again with the same sentence.
    #[test]
    fn the_named_dollar_floor_always_sizes_at_or_above_the_floor() {
        const PROBE: u128 = 100_000_000;
        let size = |cents: u64, rate: u64| -> u128 {
            (cents as u128 * 10_000 * PROBE).div_ceil(rate as u128)
        };

        for floor in [52_000u64, 100_000, 131_999, 132_000, 250_000, 1_000_000] {
            for rate in [
                10_000_000u64,
                100_000_000,
                819_907_155,
                1_076_169_000,
                3_000_000_000,
            ] {
                let cents = first_quotable_cents(floor, rate)
                    .unwrap_or_else(|| panic!("floor {floor} at rate {rate} named nothing"));
                assert!(
                    size(cents, rate) >= floor as u128,
                    "floor {floor} at rate {rate}: {cents} cents sizes to {} zatoshi, under it",
                    size(cents, rate)
                );
                if cents > 1 {
                    assert!(
                        size(cents - 1, rate) < floor as u128,
                        "floor {floor} at rate {rate}: {} cents also quotes, so {cents} is not the first",
                        cents - 1
                    );
                }
            }
        }
    }

    /// A rate of nothing is not a rate. Naming a dollar amount from it would be
    /// naming a made-up number, so the page is left to say the ZEC instead.
    #[test]
    fn an_impossible_rate_names_no_dollar_amount() {
        assert_eq!(first_quotable_cents(132_000, 0), None);
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

/// Entry points for the funded end-to-end test.
///
/// These call the real handlers with real extractors, so the quote registry,
/// the auth check, the rate limiter and the 1Click round trips are all in the
/// path. They exist because the test drives the coordinator in-process rather
/// than over a socket; they add no behaviour of their own.
#[doc(hidden)]
pub mod test_entry {
    use super::*;

    /// `GET /v2/quote?amount=<zatoshi>&unit=zec`.
    pub async fn quote(state: &Arc<AppState>, zatoshi: u64) -> Result<Quote, AppError> {
        let zec = format!("{}.{:08}", zatoshi / 100_000_000, zatoshi % 100_000_000);
        let Json(q) = quote_v2(
            State(state.clone()),
            None,
            HeaderMap::new(),
            Query(QuoteV2Query {
                amount: zec,
                unit: "zec".to_string(),
                rail: "venmo".to_string(),
                backend: None,
                min_rate: None,
            }),
        )
        .await?;
        Ok(q)
    }

    /// `GET /v2/quote?amount=<dollars>&unit=usd`, the deep link's own path.
    pub async fn quote_usd(state: &Arc<AppState>, cents: u64) -> Result<Quote, AppError> {
        let dollars = format!("{}.{:02}", cents / 100, cents % 100);
        let Json(q) = quote_v2(
            State(state.clone()),
            None,
            HeaderMap::new(),
            Query(QuoteV2Query {
                amount: dollars,
                unit: "usd".to_string(),
                rail: "venmo".to_string(),
                backend: None,
                min_rate: None,
            }),
        )
        .await?;
        Ok(q)
    }

    /// `POST /v2/orders`, with the signature in the header the real route reads.
    pub async fn open(
        state: &Arc<AppState>,
        signature: &str,
        body: OpenRequest,
    ) -> Result<Opened, AppError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::auth::SIGNATURE_HEADER,
            signature.parse().expect("a signature is a valid header value"),
        );
        let Json(opened) = open_order(State(state.clone()), None, headers, Json(body)).await?;
        Ok(opened)
    }
}
