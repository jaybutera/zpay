//! The six endpoints, and nothing else.
//!
//! Every handler is thin on purpose. The decisions live in `driver`, `quote`
//! and the escrow crate; what happens here is parsing, one refusal per
//! precondition, and rendering.
//!
//! Errors go back as `{"error": "..."}` with a 4xx, because the page prints
//! `body.error` straight to the user. So these strings are user-facing: they
//! say what happened to the user's money, in the page's own register.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use zecp2p_escrow::chain::ChainClient;

use crate::order::{Order, Stage};
use crate::state::AppState;
use crate::view;

/// An error the page shows to the user.
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    /// A caller who has asked too often. Finding 4.
    ///
    /// 429 rather than 400, because the request is well formed and the answer
    /// is "not yet" rather than "no": a client that retries later succeeds, and
    /// the status code is what tells it so.
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: Arc<AppState>) -> Router {
    // Long enough for the slowest legitimate handler - `refund`, which
    // broadcasts - under a node that is answering slowly, and far short of
    // holding a connection indefinitely.
    let request_timeout_seconds = state
        .config
        .timeouts
        .node_call_seconds
        .saturating_mul(2)
        .max(30);
    let cors = if state.config.server.allowed_origins.is_empty() {
        tower_http::cors::CorsLayer::new()
    } else {
        let origins: Vec<_> = state
            .config
            .server
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        tower_http::cors::CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    Router::new()
        .route("/health", get(health))
        .route("/escrow/capabilities", get(capabilities))
        .route("/escrow/quote", get(quote))
        .route("/escrow/orders", post(open_order))
        .route("/escrow/orders/{order_id}", get(read_order))
        .route("/escrow/orders/{order_id}/presign", post(presign))
        .route("/escrow/orders/{order_id}/refund", post(refund))
        // Finding 4: no route had a request timeout, so a handler that blocked
        // on a node call under a rate limit held a connection for as long as
        // the node took. The budget is generous - `refund` broadcasts, and a
        // user's refund is the last thing that should be cut short - and its
        // job is to bound the pathological case rather than the slow one.
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            std::time::Duration::from_secs(request_timeout_seconds),
        ))
        // A body bigger than this is not a request this service takes: the
        // largest thing any route accepts is a raw transaction.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1 << 20))
        .layer(cors)
        .with_state(state)
}

/// What this coordinator can actually do right now.
///
/// Finding 7: this returned `{"ok":true}` unconditionally, so the page's own
/// indicator read "responding" through every failure short of the process being
/// gone - a dead node, a signed-out rail, a sweep that had not run in an hour,
/// a payment slot held since yesterday.
///
/// # The status codes
///
/// - **200 `ok`**: everything checked answered, and nothing is stale.
/// - **200 `degraded`**: this coordinator is serving, and something an operator
///   should know about is true - running on a fallback node endpoint, a low
///   float, an unusable fiat rail. A user can still open and fund an order, and
///   still refund one, so this is deliberately not an error: a monitor that
///   pages on 200-vs-not still hears about it through the body.
/// - **503 `unhealthy`**: something users depend on is not working. No node
///   answers, or no sweep has completed in `alerts.sweep_age_minutes`, which
///   means nothing is noticing funding, checking deadlines or offering refunds.
///
/// # Why it costs a node call
///
/// The node read is the cached one, refreshed once per sweep, so polling this
/// does not multiply calls against a provider. A cached head that has gone
/// stale is itself the signal: it means the sweep is not refreshing it.
async fn health(State(state): State<Arc<AppState>>) -> Response {
    let mut checks = serde_json::Map::new();
    let mut unhealthy: Vec<String> = Vec::new();
    let mut degraded: Vec<String> = Vec::new();

    // The node. Cached, for the reason above.
    match state.chain_head().await {
        Ok((height, branch)) => {
            checks.insert(
                "node".into(),
                serde_json::json!({
                    "ok": true,
                    "height": height,
                    "branch_id": format!("{branch:#x}"),
                    "endpoint": crate::nodes::redact(&state.nodes.current().url),
                    "on_fallback": state.nodes.on_fallback(),
                    "endpoints_configured": state.nodes.len(),
                }),
            );
            if state.nodes.on_fallback() {
                degraded.push("node calls are going to a fallback endpoint".into());
            }
        }
        Err(e) => {
            checks.insert(
                "node".into(),
                serde_json::json!({
                    "ok": false,
                    "error": format!("{e:#}"),
                    "endpoints_configured": state.nodes.len(),
                }),
            );
            unhealthy.push("no Zcash node endpoint answered".into());
        }
    }

    // The sweep. Nothing else notices a wedged one: it leaves no log line.
    let sweep_limit = state.config.alerts.sweep_age_minutes;
    match state.since_last_sweep() {
        Some(since) => {
            let minutes = since.as_secs() / 60;
            let stale = sweep_limit > 0 && minutes >= sweep_limit;
            checks.insert(
                "sweep".into(),
                serde_json::json!({
                    "ok": !stale,
                    "minutes_since_last": minutes,
                    "alert_after_minutes": sweep_limit,
                }),
            );
            if stale {
                unhealthy.push(format!("no sweep has completed in {minutes} minutes"));
            }
        }
        None => {
            // Starting up. Not a failure: the first sweep has not run yet.
            checks.insert(
                "sweep".into(),
                serde_json::json!({ "ok": true, "minutes_since_last": null, "note": "no sweep has completed yet" }),
            );
        }
    }

    // The fiat rail. Asked whether it could pay, which is what `preflight`
    // answers; nothing here is specific to any one rail.
    match state.fiat.as_ref() {
        Some(rail) => {
            let budget = std::time::Duration::from_secs(
                state.config.timeouts.node_call_seconds.max(1),
            );
            match tokio::time::timeout(budget, rail.preflight()).await {
                Ok(Ok(())) => {
                    checks.insert("fiat_rail".into(), serde_json::json!({ "ok": true }));
                }
                Ok(Err(e)) => {
                    checks.insert(
                        "fiat_rail".into(),
                        serde_json::json!({ "ok": false, "error": format!("{e:#}") }),
                    );
                    // Degraded, not unhealthy. A user can still open, fund and
                    // refund an order; what they cannot get is paid, and their
                    // escrow comes back to them at T if this does not clear.
                    degraded.push("the fiat rail cannot pay right now".into());
                }
                Err(_) => {
                    checks.insert(
                        "fiat_rail".into(),
                        serde_json::json!({
                            "ok": false,
                            "error": format!("the rail did not answer within {} s", budget.as_secs()),
                        }),
                    );
                    degraded.push("the fiat rail did not answer a health check".into());
                }
            }

            // The float. Reported whenever the rail can say, so an operator
            // reads a number rather than inferring one from refusals.
            match state.fiat_balance_cents().await {
                crate::state::RailBalance::Known(cents) => {
                    let threshold = state.config.float.low_balance_cents;
                    let low = threshold > 0 && cents < threshold;
                    checks.insert(
                        "fiat_float".into(),
                        serde_json::json!({
                            "ok": !low,
                            "balance_cents": cents,
                            "alert_below_cents": threshold,
                            "reserve_cents": state.config.float.reserve_cents,
                        }),
                    );
                    if low {
                        degraded.push("the fiat float is under the configured threshold".into());
                    }
                }
                crate::state::RailBalance::Unknown(why) => {
                    // Not a failure. A rail with no balance concept is a
                    // perfectly good rail; this only says nobody can report it.
                    checks.insert(
                        "fiat_float".into(),
                        serde_json::json!({ "ok": true, "balance_cents": null, "why": why }),
                    );
                }
            }
        }
        None => {
            checks.insert(
                "fiat_rail".into(),
                serde_json::json!({ "ok": true, "note": "no fiat rail is configured" }),
            );
        }
    }

    // The journal: what holds the payment slot, and for how long.
    match state.sweep_journal().await {
        Ok(records) => {
            let now = chrono::Utc::now();
            let mut oldest: Option<(String, i64, String)> = None;
            let mut needs_operator = 0usize;
            for r in records.iter() {
                if matches!(
                    r.state,
                    zecp2p_taker::auto::journal::FillState::NeedsOperator
                ) {
                    needs_operator += 1;
                }
                if !r.state.is_open() {
                    continue;
                }
                let age = (now - r.updated_at).num_minutes();
                if oldest.as_ref().is_none_or(|(_, a, _)| age > *a) {
                    oldest = Some((r.work_id().to_string(), age, format!("{:?}", r.state)));
                }
            }
            let limit = i64::try_from(state.config.alerts.slot_age_minutes).unwrap_or(i64::MAX);
            let held_too_long = state.config.alerts.slot_age_minutes > 0
                && oldest.as_ref().is_some_and(|(_, age, _)| *age >= limit);
            checks.insert(
                "payment_slot".into(),
                serde_json::json!({
                    "ok": !held_too_long && needs_operator == 0,
                    "held_by": oldest.as_ref().map(|(w, _, _)| w.clone()),
                    "held_state": oldest.as_ref().map(|(_, _, s)| s.clone()),
                    "held_minutes": oldest.as_ref().map(|(_, a, _)| *a),
                    "alert_after_minutes": state.config.alerts.slot_age_minutes,
                    "needs_operator": needs_operator,
                }),
            );
            if needs_operator > 0 {
                degraded.push(format!(
                    "{needs_operator} fill(s) need a person before the slot they hold is free"
                ));
            } else if held_too_long {
                degraded.push("the payment slot has been held longer than a trade takes".into());
            }
        }
        Err(e) => {
            checks.insert(
                "payment_slot".into(),
                serde_json::json!({ "ok": false, "error": format!("{e:#}") }),
            );
            degraded.push("the fill journal could not be read".into());
        }
    }

    // Orders paid but not released: the LP's money is out with nothing held
    // against it, and there is no automatic exit.
    let stalled: Vec<serde_json::Value> = state
        .store
        .open_orders()
        .into_iter()
        .filter(|o| o.stage == Stage::Paid)
        .map(|o| {
            serde_json::json!({
                "order_id": o.order_id,
                "minutes": (chrono::Utc::now() - o.updated_at).num_minutes(),
            })
        })
        .collect();
    let paid_limit = i64::try_from(state.config.alerts.paid_age_minutes).unwrap_or(i64::MAX);
    let paid_stall = state.config.alerts.paid_age_minutes > 0
        && stalled
            .iter()
            .any(|o| o["minutes"].as_i64().unwrap_or(0) >= paid_limit);
    checks.insert(
        "paid_orders".into(),
        serde_json::json!({
            "ok": !paid_stall,
            "awaiting_release": stalled,
            "alert_after_minutes": state.config.alerts.paid_age_minutes,
        }),
    );
    if paid_stall {
        degraded.push("an order has been paid without releasing for longer than expected".into());
    }

    let (status, verdict) = if !unhealthy.is_empty() {
        (StatusCode::SERVICE_UNAVAILABLE, "unhealthy")
    } else if !degraded.is_empty() {
        (StatusCode::OK, "degraded")
    } else {
        (StatusCode::OK, "ok")
    };

    let body = serde_json::json!({
        // Kept, and kept meaning what it used to: the page reads it, and a
        // page against an older or newer coordinator should not break on it.
        // `false` now actually happens.
        "ok": status == StatusCode::OK,
        "status": verdict,
        "instance": state.instance_name(),
        "network": state.network_name(),
        "build": crate::version::as_json(),
        "problems": unhealthy.iter().chain(degraded.iter()).collect::<Vec<_>>(),
        "checks": serde_json::Value::Object(checks),
    });

    (status, Json(body)).into_response()
}

/// The USD-per-ZEC rate a quote is built on, spread already applied.
///
/// A pinned `quote.rate_usd_per_zec` wins, because an operator who set one
/// meant it - that is the regtest and rehearsal path. Otherwise the rate comes
/// from the market and the spread is taken off it.
///
/// There is deliberately no third branch. A feed that cannot be read, or that
/// answers something implausible, returns an error and the caller refuses the
/// quote: a service that holds user funds is better off not quoting than
/// quoting a price it cannot stand behind. The old behaviour - a constant
/// serving every request - is exactly what this removes.
async fn rate_for_quote(state: &Arc<AppState>) -> Result<f64, ApiError> {
    if let Some(pinned) = state.config.quote.rate_usd_per_zec {
        return Ok(pinned);
    }
    let spot = crate::price::spot(
        &state.http,
        &state.prices,
        std::time::Duration::from_secs(state.config.quote.price_timeout_seconds),
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "refusing to quote: no trustworthy ZEC price");
        ApiError::unavailable(
            "zpay cannot price a trade right now: no ZEC/USD price it trusts. Try again shortly."
                .to_string(),
        )
    })?;
    Ok(crate::price::apply_spread(
        spot.usd_per_zec,
        state.config.quote.spread_bps,
    ))
}

async fn capabilities(State(state): State<Arc<AppState>>) -> ApiResult<Json<view::Capabilities>> {
    // The branch id comes from the node, never from a constant: it changes at
    // every network upgrade, and a stale one produces a sighash nobody accepts.
    let (_, branch) = state
        .chain_head()
        .await
        .map_err(|e| ApiError::unavailable(format!("zpay cannot reach its Zcash node: {e}")))?;

    // The attestor key the page will pin. On a test network the page accepts
    // whatever is announced, so an empty string is honest; on mainnet the
    // config refuses to start without one.
    let attestor_pubkey = state
        .attestor_pubkey
        .map(|p| hex::encode(p.serialize()))
        .unwrap_or_default();

    Ok(Json(view::Capabilities {
        network: state.network_name().to_string(),
        rails: vec![view::Rail {
            id: "venmo".into(),
            label: "Venmo".into(),
            live: state.fiat.is_some() && state.config.serve.live_payments,
        }],
        fee: view::FeeInfo {
            bps: state.config.quote.fee_bps,
            label: "zpay fee".into(),
        },
        l_pub: hex::encode(state.l_pub),
        attestor_pubkey,
        consensus_branch_id: branch,
        block_seconds: state.config.zec.block_seconds,
        refund_delay_blocks: state.policy.refund_delay_blocks,
        limits: view::Limits {
            min_zat: state.config.quote.min_zat,
            max_zat: state.config.quote.max_zat,
        },
        // The rate the page displays. `None` when no price can be trusted,
        // which the page shows as unavailable rather than as a number; the
        // rest of capabilities is still true and the page needs it.
        rate_usd_per_zec: rate_for_quote(&state).await.ok(),
        spread_bps: state.config.quote.spread_bps,
    }))
}

#[derive(Debug, Deserialize)]
struct QuoteParams {
    amount: Option<String>,
    #[serde(default)]
    unit: Option<String>,
}

async fn quote(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QuoteParams>,
) -> ApiResult<Json<view::QuoteView>> {
    let amount = params
        .amount
        .ok_or_else(|| ApiError::bad_request("Enter a number."))?;
    let unit: crate::quote::Unit = params
        .unit
        .as_deref()
        .unwrap_or("zec")
        .parse()
        .map_err(|_| ApiError::bad_request("Unknown unit."))?;

    let (height, _) = state
        .chain_head()
        .await
        .map_err(|e| ApiError::unavailable(format!("zpay cannot reach its Zcash node: {e}")))?;
    let refund_height = u64::from(state.policy.proposed_refund_height(height));

    let rate = rate_for_quote(&state).await?;

    let quote = crate::quote::quote_for(
        &amount,
        unit,
        &state.config.quote,
        rate,
        state.addr_network(),
        refund_height,
        chrono::Utc::now(),
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?;

    {
        let mut quotes = state.quotes.lock().expect("quote lock");
        // Quotes expire, so unlike orders they can be dropped: an expired one
        // is refused at `/escrow/orders` anyway. Sweeping them here keeps a
        // caller who types in the amount box from growing this map without
        // bound.
        let now = chrono::Utc::now();
        quotes.retain(|_, q| !q.is_expired(now));
        quotes.insert(quote.quote_id.clone(), quote.clone());
    }

    Ok(Json(view::QuoteView::from(&quote)))
}

#[derive(Debug, Deserialize)]
struct OpenOrderRequest {
    quote_id: String,
    u_pub: String,
    destination: DestinationRequest,
}

#[derive(Debug, Deserialize)]
struct DestinationRequest {
    #[serde(default)]
    rail: String,
    handle: String,
}

async fn open_order(
    State(state): State<Arc<AppState>>,
    // Read out of the request's extensions rather than through the
    // `ConnectInfo` extractor. The extractor is a hard requirement: a request
    // that arrives without connection info - which is every request a test
    // drives through `oneshot`, and any future path that is not a TCP listener
    // - fails to extract and the route stops existing. Reading the extension
    // makes the address optional, and `client_key` already has a rule for
    // having none.
    request: axum::extract::Request,
) -> ApiResult<Json<view::OrderView>> {
    let headers = request.headers().clone();
    let connect = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    let body: OpenOrderRequest = {
        let (_, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20)
            .await
            .map_err(|_| ApiError::bad_request("that request body could not be read"))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::bad_request(format!("that request body is not the shape this endpoint takes: {e}")))?
    };
    // Finding 4: the door, before anything is looked up or called out to.
    //
    // Ahead of every other check on purpose. A refused request still costs a
    // quote lookup, a curator call and a scan of the store, so the cheapest
    // possible refusal has to come first or the limit is protecting the
    // expensive work with expensive work.
    let client = crate::ratelimit::client_key(
        connect,
        state
            .config
            .limits
            .client_ip_header
            .as_deref()
            .and_then(|h| headers.get(h))
            .and_then(|v| v.to_str().ok()),
        state.config.limits.client_ip_header.is_some(),
    );
    match state.rate_limiter.check(
        &client,
        state.config.limits.open_rate_per_client,
        state.config.limits.open_rate_global,
        std::time::Duration::from_secs(state.config.limits.rate_window_seconds.max(1)),
    ) {
        crate::ratelimit::LimitVerdict::Allowed => {}
        crate::ratelimit::LimitVerdict::TooManyRequests { retry_after_seconds } => {
            return Err(ApiError::too_many_requests(format!(
                "That is more orders than zpay opens for one caller at a time. Try again in \
                 {retry_after_seconds} seconds."
            )));
        }
        crate::ratelimit::LimitVerdict::ServiceBusy { retry_after_seconds } => {
            return Err(ApiError::too_many_requests(format!(
                "zpay is opening more orders than it can watch right now. Try again in \
                 {retry_after_seconds} seconds."
            )));
        }
        crate::ratelimit::LimitVerdict::TooManyOpenOrders { held, limit } => {
            return Err(ApiError::bad_request(format!(
                "You already have {held} escrows open, and zpay watches {limit} at a time \
                 for one caller. Fund or let those expire before opening another."
            )));
        }
    }

    let per_client = state.config.limits.max_open_per_client;
    if per_client > 0 {
        let held = state.store.open_for_client(&client);
        if held >= per_client {
            return Err(ApiError::bad_request(format!(
                "You already have {held} escrows open, and zpay watches {per_client} at a \
                 time for one caller. Fund or let those expire before opening another."
            )));
        }
    }

    if !body.destination.rail.is_empty() && body.destination.rail != "venmo" {
        return Err(ApiError::bad_request("This coordinator only serves Venmo."));
    }

    // The handle's shape is checked before it reaches a URL or the curator.
    // The old path interpolated it straight into a pay link, so `alice?amount=500`
    // was a query injection into the page the browser would then drive.
    let handle = zecp2p_taker::payee::validate_username_shape(&body.destination.handle)
        .map_err(|_| {
            ApiError::bad_request("Enter their Venmo username: letters, digits, - and _.")
        })?
        .to_string();

    // Whose escrows this coordinator fronts fiat for. Unlike the Base rail's
    // `only_user`, an unconfigured list refuses rather than serving everyone.
    if !state.config.serve.serves(&handle) {
        return Err(ApiError::bad_request(
            "zpay is not taking orders for that account right now.",
        ));
    }

    // Orders cannot be evicted, so the bound is applied here. A caller in a
    // loop would otherwise leave this process scanning an unbounded number of
    // addresses on every sweep, and each of those scans is a node call.
    if state.store.awaiting_count() >= state.config.quote.max_open_orders {
        return Err(ApiError::unavailable(
            "zpay has as many escrows open as it will watch at once. Try again in a \
             few minutes.",
        ));
    }
    if state.store.awaiting_for_handle(&handle) >= state.config.quote.max_open_per_handle {
        return Err(ApiError::bad_request(
            "there are already several escrows open for that Venmo account. Finish or \
             let those refund before opening another.",
        ));
    }

    // Taken, not read. Removing it here under the same lock that found it means
    // one quote mints one order: two requests racing on a single `quote_id`
    // used to both find it, because it was only removed after the order was
    // written. The loser gets the expiry message, which is true - the quote is
    // gone.
    let quote = state
        .quotes
        .lock()
        .expect("quote lock")
        .remove(&body.quote_id)
        .ok_or_else(|| ApiError::bad_request("That quote has expired. Type the amount again."))?;

    if quote.is_expired(chrono::Utc::now()) {
        return Err(ApiError::bad_request(
            "That quote has expired. Type the amount again.",
        ));
    }

    // Everything from here can refuse, and a refusal must give the quote back.
    //
    // Taking it before the refusals run meant a submit refused for any reason -
    // the duplicate guard, the curator, a node that would not answer, the fee
    // moving - consumed the quote as well, so the second click was told "That
    // quote has expired. Type the amount again." rather than the reason it was
    // actually refused. The page re-quotes on input, so the user was a
    // keystroke from recovering, but the message was about the wrong thing.
    //
    // Put back under the same lock that took it, which is what keeps the guard
    // the take exists for. Both obvious repairs - returning it after the write,
    // or taking it only once the order is written - leave a window where two
    // requests hold one quote. This has none: the id is freshly minted per
    // quote so nothing else can be at that key, and a race still ends with one
    // winner holding the quote while the loser is correctly told it is gone.
    //
    // Written as one fallible block rather than a put-back at each refusal, so
    // the next refusal added here cannot forget one.
    let opened = open_order_with_quote(&state, &body, handle, quote.clone(), &client).await;
    let (order, height) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            state
                .quotes
                .lock()
                .expect("quote lock")
                .insert(body.quote_id.clone(), quote);
            return Err(e);
        }
    };

    tracing::info!(
        order = %order.order_id,
        address = %order.address,
        amount_zat = order.quote.amount_zat,
        handle = %order.handle,
        "order opened"
    );

    Ok(Json(view::order_view(&order, height)))
}

/// The part of opening an order that can refuse, with the quote already taken.
///
/// Split out so the caller can put the quote back on any `Err` without a
/// put-back at each refusal site. Returns the written order and the height it
/// was derived against.
async fn open_order_with_quote(
    state: &Arc<AppState>,
    body: &OpenOrderRequest,
    handle: String,
    quote: crate::order::Quote,
    client: &str,
) -> Result<(Order, u32), ApiError> {
    let u_pub_raw = hex::decode(body.u_pub.trim())
        .map_err(|_| ApiError::bad_request("The key this page sent is not hex."))?;
    let u_pub: [u8; 33] = u_pub_raw
        .try_into()
        .map_err(|_| ApiError::bad_request("The key this page sent is not a compressed point."))?;
    secp256k1_zkp::PublicKey::from_slice(&u_pub)
        .map_err(|_| ApiError::bad_request("The key this page sent is not on the curve."))?;

    // The payee hash is the curator's, never computed locally. It is what the
    // enclave binds the attestation to, and it cannot be derived: asking the
    // curator is the only way to learn it.
    let payee_hash = zecp2p_taker::payee::curator_hash_for(
        &state.http,
        &state.config.zkp2p.api_url,
        &handle,
    )
    .await
    .map_err(|e| {
        tracing::warn!(handle = %handle, error = %format!("{e:#}"), "the curator would not resolve a handle");
        ApiError::bad_request(
            "zpay could not confirm that Venmo username. Check the spelling, including \
             capitals, and try again.",
        )
    })?;

    let (height, branch) = state
        .chain_head()
        .await
        .map_err(|e| ApiError::unavailable(format!("zpay cannot reach its Zcash node: {e}")))?;

    let refund_height = u64::from(state.policy.proposed_refund_height(height));

    // The address is derived, and the page derives it again and refuses a
    // mismatch. Both derivations must use the same refund height, which is why
    // the quote was priced against the height this order now uses.
    let plan = zecp2p_escrow::funding::escrow_address(
        &u_pub,
        &state.l_pub,
        refund_height,
        quote.amount_zat,
        state.address_network(),
    )
    .map_err(|e| ApiError::bad_request(format!("could not derive the escrow address: {e}")))?;

    // The miner fee was priced against a redeem script of the same length. If
    // the height moved the encoding into another width, the quote's fee is
    // wrong and the page would refuse the order after the user funded it.
    let priced_len = crate::quote::redeem_script_len(refund_height)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if plan.redeem_script.len() != priced_len {
        return Err(ApiError::bad_request(
            "The quote was priced for a different block height. Type the amount again.",
        ));
    }

    let fee = crate::quote::platform_fee_for(
        quote.amount_zat,
        state.config.quote.fee_bps,
        state.addr_network(),
    );
    // The quote and the order must agree about the fee, or the page's terms
    // hash will not match the coordinator's.
    if fee.zat != quote.platform_fee_zat {
        return Err(ApiError::bad_request(
            "The fee changed while you were typing. Type the amount again.",
        ));
    }

    let order = Order {
        order_id: crate::new_id("esc"),
        opened_by: Some(client.to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        stage: Stage::AwaitingZec,
        reason: None,
        handle,
        quote,
        opened_height: height,
        scanned_through: None,
        mempool_announced_txid: None,
        mempool_announced_vout: None,
        sighting_never_confirmed: false,
        network: state.network_name().to_string(),
        consensus_branch_id: branch,
        u_pub,
        l_pub: state.l_pub,
        refund_height,
        address: plan.address.clone(),
        redeem_script: plan.redeem_script,
        script_pubkey: plan.script_pubkey,
        payee_hash: payee_hash.0,
        treasury_script: fee.treasury_script,
        lp_output_script: state.lp_output_script.clone(),
        funding: None,
        lock_confirmed_ms: None,
        announcement: None,
        pre_signature: None,
        pre_signed_at: None,
        payment: None,
        release_txid: None,
        refund_txid: None,
    };

    // On disk before the address is returned. An order this process has
    // forgotten is an escrow only the user's refund can recover.
    let inserted = state
        .store
        .put_unless_in_flight(&order)
        .map_err(|e| ApiError::unavailable(format!("zpay could not record the order: {e}")))?;

    // One order per handle per number of cents at a time.
    //
    // Two escrows to the same Venmo account for the same cents are the one case
    // `locate_payment` cannot resolve: it looks for a payment of a dollar
    // amount to a handle, two identical entries are indistinguishable, and it
    // refuses rather than guess - after the dollars have gone, with the global
    // payment slot held. Refusing here costs a wait and nothing else: no ZEC has
    // been sent, no escrow exists, no key has been made.
    //
    // The decision and the write happen under one lock inside the store, so two
    // requests arriving together cannot both pass a check and both insert.
    if !inserted {
        return Err(ApiError::bad_request(
            "You already have an escrow open to that Venmo account for exactly this \
             amount. Two identical payments cannot be told apart in the feed, so zpay \
             finishes one before starting another. Wait for that one to complete, or \
             send a slightly different amount.",
        ));
    }

    Ok((order, height))
}

async fn read_order(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<String>,
) -> ApiResult<Json<view::OrderView>> {
    let order = state
        .store
        .get(&order_id)
        .ok_or_else(|| ApiError::not_found("no such order"))?;

    // The height is best-effort: an order still reads when the node is down,
    // because the page needs the escrow's own details to build a refund.
    let height = state.chain_head().await.map(|(h, _)| h).unwrap_or(0);

    // What the journal says about a payment having left, which is not what
    // `order.payment` says. Three of the four `Failed` writers that follow a
    // journal claim leave `payment` null while the journal holds an open
    // `Paying` line, and the page hides its refund form on this answer - the
    // sweep already withholds the promotion on it, and the two have to agree
    // or the `failed` screen offers what the sweep refused.
    //
    // Erring towards "may have left" on an unreadable journal, for the same
    // reason the sweep does: not knowing is not permission to offer a refund.
    let fiat_may_have_left = match order.funding {
        Some(f) => {
            let work = crate::slot::work_id_for(&f.txid, f.vout);
            crate::slot::fiat_may_have_left(&state.journal, &work).unwrap_or(true)
        }
        // No outpoint means no work id and so no journal line: nothing can have
        // been claimed for an escrow the coordinator never saw funded.
        None => false,
    };

    Ok(Json(view::order_view_with_journal(
        &order,
        height,
        fiat_may_have_left,
    )))
}

#[derive(Debug, Deserialize)]
struct PresignRequest {
    pre_signature: String,
    terms_hash: String,
    #[serde(default)]
    u_pub: Option<String>,
}

async fn presign(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<String>,
    Json(body): Json<PresignRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    // Finding 4: does this order exist, before a lock is minted for its id?
    // The lock map is keyed on a caller-supplied string, so taking the lock
    // first meant a request naming an id that had never existed left a
    // permanent entry behind. The real read happens under the lock below; this
    // one only decides whether to take a lock at all, so a race that creates
    // the order between the two costs nothing but a retry.
    if state.store.get(&order_id).is_none() {
        return Err(ApiError::not_found("no such order"));
    }

    // The same lock the driver takes. Two pre-signatures arriving together
    // would both read `needs_presignature`, both pass, and both spawn a
    // settlement task; the second would then be refused by the payment slot,
    // but relying on that is relying on the last line of defence.
    let lock = state.order_lock(&order_id).await;
    let _held = lock.lock().await;

    let mut order = state
        .store
        .get(&order_id)
        .ok_or_else(|| ApiError::not_found("no such order"))?;

    if order.stage != Stage::NeedsPresignature {
        return Err(ApiError::bad_request(format!(
            "not expecting a pre-signature in stage {}",
            order.stage.as_str()
        )));
    }

    // The key must be this order's. A pre-signature is only meaningful against
    // the key the escrow's 2-of-2 names.
    if let Some(claimed) = &body.u_pub {
        if claimed.trim().to_ascii_lowercase() != hex::encode(order.u_pub) {
            return Err(ApiError::bad_request(
                "that pre-signature is for a different key",
            ));
        }
    }

    let announcement = order
        .announcement
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("this escrow has not been announced yet"))?;
    if body.terms_hash.trim().to_ascii_lowercase() != announcement.terms_hash {
        return Err(ApiError::bad_request("terms hash mismatch"));
    }

    // The gate. Everything the LP does after this rests on it.
    crate::driver::verify_pre_signature(&state, &order, &body.pre_signature)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;

    order.pre_signature = Some(body.pre_signature.trim().to_ascii_lowercase());
    order.pre_signed_at = Some(chrono::Utc::now());
    order.stage = Stage::Locked;
    order.touch();
    state
        .store
        .put(&order)
        .map_err(|e| ApiError::unavailable(format!("zpay could not record the lock: {e}")))?;

    tracing::info!(order = %order.order_id, "pre-signature verified, escrow locked");

    // Settle on its own task: the page is waiting on this response and the
    // fiat leg drives a browser.
    let bg = state.clone();
    let id = order.order_id.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::driver::advance(&bg, &id).await {
            tracing::warn!(order = %id, error = %format!("{e:#}"), "settlement stopped");
        }
    });

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct RefundRequest {
    raw_tx: String,
    #[serde(default)]
    txid: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

/// Broadcasts the user's own refund.
///
/// The coordinator is a convenience here and nothing more: the page signed the
/// transaction with a key this process has never seen, shows the bytes on
/// screen, and says any node will take them. A refusal here costs the user
/// nothing but a copy and paste.
///
/// # Why this checks the bytes
///
/// R1-5: it used to parse the transaction only far enough to compare its txid
/// to the one the caller sent alongside it, which is a claim checked against
/// itself. So anyone holding an order id could hand this endpoint any valid
/// transaction, have the coordinator's node broadcast it, and move the order to
/// terminal `refunded` - an open relay that also destroyed the order's own
/// status. It now refuses anything that does not spend this escrow's outpoint,
/// refuses outside the stage where a refund is due, and takes the order lock so
/// it cannot race the settlement path.
async fn refund(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<String>,
    Json(body): Json<RefundRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    // Existence first, for the reason `presign` checks it first: the lock map
    // is keyed on a caller-supplied id. Finding 4.
    if state.store.get(&order_id).is_none() {
        return Err(ApiError::not_found("no such order"));
    }

    // Held across the whole handler, so a refund cannot interleave with the
    // settlement path deciding to pay the same escrow.
    let lock = state.order_lock(&order_id).await;
    let _held = lock.lock().await;

    let mut order = state
        .store
        .get(&order_id)
        .ok_or_else(|| ApiError::not_found("no such order"))?;

    if order.stage.fiat_may_have_left() {
        return Err(ApiError::bad_request(
            "the dollars for this order have already been sent, so zpay will not help \
             broadcast a refund that would race its release",
        ));
    }

    // And the journal, which knows things the stage does not. R2-4: `order.fail`
    // leaves the stage `Failed`, and the failure whose message is "a payment may
    // have left" produced exactly that stage - which the gate above accepts. The
    // journal line is written before the click, so it is the only record that
    // can distinguish a failed order nobody paid for from a failed order that
    // may have been paid.
    //
    // The refusal is deliberately not the end of the road for the user: the page
    // holds the signed bytes and any node will take them after `T`. What this
    // will not do is put the coordinator's own node behind a transaction that
    // may be racing a release for money already sent.
    if let Some(funding) = order.funding {
        let work = crate::slot::work_id_for(&funding.txid, funding.vout);
        let may_have_paid = crate::slot::fiat_may_have_left(&state.journal, &work)
            .map_err(|e| ApiError::unavailable(format!("zpay could not check its own records: {e}")))?;
        if may_have_paid {
            return Err(ApiError::bad_request(
                "zpay's records say a payment for this escrow may already have been sent, \
                 so it will not broadcast a refund that could race the release. The signed \
                 transaction is on your screen and any Zcash node will accept it once the \
                 refund height passes.",
            ));
        }
    }

    // A refund is only due once the escrow is past `T` and unsettled. Outside
    // those stages this endpoint has nothing to broadcast, and answering
    // anyway is what let a caller drive an arbitrary order to `refunded`.
    // `Expired` is here for the same reason `Unpaid` is: an order that stopped
    // counting toward intake can still have coin at its address - somebody who
    // funded late - and that coin is the user's. The checks above still apply,
    // and the escrow's own timeout branch still decides whether the refund is
    // spendable, so this widens who may ask rather than what they may get.
    if !matches!(
        order.stage,
        Stage::Refundable | Stage::Unpaid | Stage::Failed | Stage::Expired
    ) {
        return Err(ApiError::bad_request(format!(
            "this escrow is not refundable yet (it is {}). Your key can spend the timeout \
             branch from block {} and the page will offer it then.",
            order.stage.as_str(),
            order.refund_height
        )));
    }

    let raw = hex::decode(body.raw_tx.trim())
        .map_err(|_| ApiError::bad_request("that is not a transaction"))?;
    if raw.len() < 100 {
        return Err(ApiError::bad_request("that is not a transaction"));
    }

    let parsed_txid = zecp2p_escrow::tx::txid_of_signed(&raw)
        .map_err(|e| ApiError::bad_request(format!("that transaction does not parse: {e}")))?;

    // The bytes must spend *this* escrow. This is the check that keeps the
    // endpoint from being a relay: the signature is the user's own and the node
    // validates it, but nothing except this ties the transaction to the order
    // whose status is about to be overwritten.
    let funding = order.funding.ok_or_else(|| {
        ApiError::bad_request(
            "zpay does not know this escrow's funding transaction, so it cannot tell \
             whether that refund spends it. The signed bytes are on your screen and any \
             Zcash node will take them.",
        )
    })?;
    let spends = zecp2p_escrow::tx::spends_outpoint(&raw, &funding.txid, funding.vout)
        .map_err(|e| ApiError::bad_request(format!("that transaction does not parse: {e}")))?;
    if !spends {
        return Err(ApiError::bad_request(format!(
            "that transaction does not spend this escrow ({}:{}). zpay only broadcasts \
             the refund of the order you asked about.",
            zecp2p_escrow::rpc::txid_to_display(&funding.txid),
            funding.vout
        )));
    }

    if let Some(claimed) = &body.txid {
        if claimed.trim().to_ascii_lowercase()
            != zecp2p_escrow::rpc::txid_to_display(&parsed_txid)
        {
            return Err(ApiError::bad_request(
                "the transaction's id is not the one you sent with it",
            ));
        }
    }

    // Fails over: a user's refund must not be lost because one provider is
    // down, and the pool only moves on when a node is unreachable - a node that
    // *rejected* the transaction has answered, and asking another until one
    // accepts is how a transaction gets broadcast twice.
    let txid = state
        .with_chain(move |chain| chain.broadcast(&raw))
        .await
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;

    let refund_txid = zecp2p_escrow::rpc::txid_to_display(&txid);
    order.refund_txid = Some(refund_txid.clone());
    order.stage = Stage::Refunded;
    order.touch();
    state
        .store
        .put(&order)
        .map_err(|e| ApiError::unavailable(format!("zpay could not record the refund: {e}")))?;

    let to_address = body.address.unwrap_or_default();
    tracing::info!(
        order = %order.order_id,
        txid = %refund_txid,
        address = %to_address,
        "refund broadcast"
    );

    Ok(Json(serde_json::json!({ "txid": refund_txid })))
}
