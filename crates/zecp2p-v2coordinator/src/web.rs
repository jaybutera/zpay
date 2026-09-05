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
        .layer(cors)
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
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
        rate_usd_per_zec: state.config.quote.rate_usd_per_zec,
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

    let quote = crate::quote::quote_for(
        &amount,
        unit,
        &state.config.quote,
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
    Json(body): Json<OpenOrderRequest>,
) -> ApiResult<Json<view::OrderView>> {
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

    let quote = state
        .quotes
        .lock()
        .expect("quote lock")
        .get(&body.quote_id)
        .cloned()
        .ok_or_else(|| ApiError::bad_request("That quote has expired. Type the amount again."))?;

    if quote.is_expired(chrono::Utc::now()) {
        return Err(ApiError::bad_request(
            "That quote has expired. Type the amount again.",
        ));
    }

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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        stage: Stage::AwaitingZec,
        reason: None,
        handle,
        quote,
        opened_height: height,
        scanned_through: None,
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
    state
        .store
        .put(&order)
        .map_err(|e| ApiError::unavailable(format!("zpay could not record the order: {e}")))?;

    // The quote is spent.
    state.quotes.lock().expect("quote lock").remove(&order.quote.quote_id);

    tracing::info!(
        order = %order.order_id,
        address = %order.address,
        amount_zat = order.quote.amount_zat,
        handle = %order.handle,
        "order opened"
    );

    Ok(Json(view::order_view(&order, height)))
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
    Ok(Json(view::order_view(&order, height)))
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
    if !matches!(order.stage, Stage::Refundable | Stage::Unpaid | Stage::Failed) {
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

    let txid = state
        .with_chain(move |chain| {
            chain
                .broadcast(&raw)
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
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
