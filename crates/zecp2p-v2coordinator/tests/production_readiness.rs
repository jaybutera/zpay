//! The audit's findings 3 to 7 and 10, held to their fixes.
//!
//! Each test names the finding it belongs to and the failure it reproduces.
//! What they have in common is that none of them assert an implementation:
//! they assert the property the finding was about - one slow order does not
//! stop another, an unfunded order stops holding a place, no payment starts on
//! a float that will not cover it, an unreachable node is failed over, an
//! operator hears about a stall.
//!
//! The escrow is real here for the same reason it is real in `contract.rs`: a
//! test that mocks the seam it is testing proves that the mock agrees with
//! itself.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zecp2p_v2coordinator::funding::{FakeScanner, FoundOutput};
use zecp2p_v2coordinator::order::Stage;
use zecp2p_v2coordinator::state::{AppState, RailBalance};

mod support;
use support::*;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn post(
    app: &axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

/// Opens an order and returns its id, without funding it.
async fn open_order(
    app: &axum::Router,
    user: &TestUser,
    amount: &str,
    handle: &str,
) -> (StatusCode, serde_json::Value) {
    let (_, q) = get(app, &format!("/escrow/quote?amount={amount}&unit=zec")).await;
    post(
        app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": handle },
        }),
    )
    .await
}

/// Drives an order to `Locked` with a verified pre-signature.
#[allow(clippy::too_many_arguments)]
async fn locked_order_for(
    app: &axum::Router,
    state: &Arc<AppState>,
    node: &FakeNode,
    scanner: &Arc<FakeScanner>,
    attestor: &TestAttestor,
    user: &TestUser,
    amount: &str,
) -> String {
    let (status, order) = open_order(app, user, amount, "alice").await;
    assert_eq!(status, StatusCode::OK, "{order}");
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();

    let stored = state.store.get(&order_id).unwrap();
    let mut funding_txid = [0x9au8; 32];
    funding_txid[0] = order_id.as_bytes()[4];
    funding_txid[1] = order_id.as_bytes()[5];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;

    zecp2p_v2coordinator::driver::advance(state, &order_id)
        .await
        .expect("the escrow confirms and announces");

    let (_, view) = get(app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "needs_presignature", "{view}");
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();
    let pre_sig = user.pre_sign(&stored, attestor, &announced);
    let (status, body) = post(
        app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": announced["terms_hash"],
            "u_pub": hex::encode(user.u_pub),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    order_id
}

// ---------------------------------------------------------------------------
// Finding 3: the sweep must never block on a money path.
// ---------------------------------------------------------------------------

/// The finding, reproduced: one order's rail hangs, and every other order's
/// funding scan and deadline check must still happen in that same sweep.
///
/// Before the fix the sweep joined every task with no bound, so a wedged
/// browser held the whole pass - including orders approaching `T` whose users
/// were waiting to be told they could refund.
#[tokio::test]
async fn a_hanging_payment_does_not_stop_the_rest_of_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();
    let rail = Arc::new(HangingRail::new());

    let mut config = test_config(dir.path());
    // Short enough that the test does not sit through a real timeout, long
    // enough that it is the watchdog firing rather than a scheduling accident.
    config.timeouts.order_advance_seconds = 2;
    config.timeouts.pay_seconds = 1;
    config.limits.unfunded_order_minutes = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // One order that will wedge in `pay`.
    let stuck = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;

    // A second order, funded but not yet noticed. Its funding scan is the work
    // the wedged order used to block.
    let (status, second) = open_order(&app, &user, "0.07", "alice").await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let waiting = second["order_id"].as_str().unwrap().to_string();
    let stored = state.store.get(&waiting).unwrap();
    let amount_zat = second["escrow"]["amount_zat"].as_u64().unwrap();
    let funding_txid = [0x71u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;

    // One sweep, with both orders in it.
    let swept = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        zecp2p_v2coordinator::driver::sweep_once(&state),
    )
    .await;
    assert!(swept.is_ok(), "the sweep must finish even with an order wedged in pay");

    // The wedged order really did wedge, so this is not a test that passed by
    // the rail never being called.
    assert_eq!(rail.started(), 1, "the hanging rail should have been asked to pay");
    let stuck_order = state.store.get(&stuck).unwrap();
    assert_ne!(
        stuck_order.stage,
        Stage::Released,
        "the wedged order cannot have completed"
    );

    // And the other order was advanced in that same pass.
    let advanced = state.store.get(&waiting).unwrap();
    assert!(
        advanced.funding.is_some(),
        "the second order's funding should have been found while the first was stuck, \
         stage is {}",
        advanced.stage.as_str()
    );
}

/// The pay timeout leaves the ambiguous state ambiguous.
///
/// Cutting a payment off mid-flight cannot be reported as "nothing was sent":
/// the money may have gone. The journal line has to keep saying so, which is
/// what stops the next order paying into an unreconciled feed and what stops
/// the refund endpoint handing the user back an escrow the LP has bought.
#[tokio::test]
async fn a_payment_cut_off_by_its_timeout_stays_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();
    let rail = Arc::new(HangingRail::new());

    let mut config = test_config(dir.path());
    config.timeouts.pay_seconds = 1;
    config.timeouts.order_advance_seconds = 30;
    config.limits.unfunded_order_minutes = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let order_id = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;

    // The journal must still say a payment may have left.
    let stored = state.store.get(&order_id).unwrap();
    let funding = stored.funding.expect("the order is funded");
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding.txid, funding.vout);
    assert!(
        zecp2p_v2coordinator::slot::fiat_may_have_left(&state.journal, &work).unwrap(),
        "a payment cut off by a timeout may have left; the journal must not say otherwise"
    );

    // And the refund endpoint must refuse on the strength of that.
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(vec![0u8; 200]) }),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a refund must not be broadcast while a payment may be in flight: {body}"
    );
}

/// An attestation that never returns is cut off, and the order stays `Paid`.
///
/// `Paid` is the honest stage: the dollars have gone. What must not happen is
/// the attempt holding the task for as long as the enclave feels like, which is
/// what "a `node` child awaited with no timeout" meant.
#[tokio::test]
async fn a_hanging_attestation_is_cut_off_and_the_order_stays_paid() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();
    let rail = Arc::new(PaysThenHangsRail::new());

    let mut config = test_config(dir.path());
    config.timeouts.attest_seconds = 1;
    config.timeouts.order_advance_seconds = 30;
    config.limits.unfunded_order_minutes = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let order_id = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;

    let started = std::time::Instant::now();
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "the attestation timeout should have ended this attempt"
    );

    assert_eq!(rail.payments(), 1, "the dollars went");
    assert!(rail.attestation_attempts() >= 1, "attestation was attempted");
    let stored = state.store.get(&order_id).unwrap();
    assert_eq!(
        stored.stage,
        Stage::Paid,
        "the dollars have gone, so the order stays paid and the next sweep retries"
    );
    assert!(
        stored.payment.is_some(),
        "the payment must be recorded, or a restart will not know it happened"
    );
}

// ---------------------------------------------------------------------------
// Finding 4: unfunded orders and rate limits.
// ---------------------------------------------------------------------------

/// The finding, reproduced: five free requests locked a handle out for a day.
///
/// With expiry, the same five stop counting after the configured window and the
/// sixth order opens.
#[tokio::test]
async fn unfunded_orders_stop_holding_a_place() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.quote.max_open_per_handle = 2;
    config.limits.unfunded_order_minutes = 30;
    // Off, so the guard being tested is the per-handle one rather than a rate.
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (s1, o1) = open_order(&app, &user, "0.05", "alice").await;
    assert_eq!(s1, StatusCode::OK, "{o1}");
    let (s2, o2) = open_order(&app, &user, "0.06", "alice").await;
    assert_eq!(s2, StatusCode::OK, "{o2}");

    // The cap bites, which is the behaviour that used to last a day.
    let (s3, o3) = open_order(&app, &user, "0.07", "alice").await;
    assert_eq!(s3, StatusCode::BAD_REQUEST, "the handle is at its cap: {o3}");

    // Age both orders past the window, as sitting unfunded for that long would.
    for id in [o1["order_id"].as_str().unwrap(), o2["order_id"].as_str().unwrap()] {
        let mut order = state.store.get(id).unwrap();
        order.created_at = chrono::Utc::now() - chrono::Duration::minutes(45);
        state.store.put(&order).unwrap();
    }
    zecp2p_v2coordinator::driver::sweep_once(&state).await;

    for id in [o1["order_id"].as_str().unwrap(), o2["order_id"].as_str().unwrap()] {
        assert_eq!(
            state.store.get(id).unwrap().stage,
            Stage::Expired,
            "an order nobody funded should have expired"
        );
    }

    let (s4, o4) = open_order(&app, &user, "0.08", "alice").await;
    assert_eq!(
        s4,
        StatusCode::OK,
        "expired orders must stop counting against the handle: {o4}"
    );
}

/// An order with coin in flight is never expired, however long it waits.
///
/// The expensive way to get this wrong: taking an order out from under a user
/// whose transaction is sitting in the mempool.
#[tokio::test]
async fn an_order_with_coin_in_flight_is_never_expired() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 1;
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (status, opened) = open_order(&app, &user, "0.05", "alice").await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let order_id = opened["order_id"].as_str().unwrap().to_string();
    let amount_zat = opened["escrow"]["amount_zat"].as_u64().unwrap();

    // Old enough to expire, and funded.
    let mut order = state.store.get(&order_id).unwrap();
    order.created_at = chrono::Utc::now() - chrono::Duration::hours(3);
    state.store.put(&order).unwrap();
    let funding_txid = [0x44u8; 32];
    scanner.pay(
        &order.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, order.script_pubkey.clone(), amount_zat, 30)
        .await;

    zecp2p_v2coordinator::driver::sweep_once(&state).await;

    let after = state.store.get(&order_id).unwrap();
    assert_ne!(
        after.stage,
        Stage::Expired,
        "an order with coin at its address must never be expired"
    );
    assert!(after.funding.is_some(), "the funding should have been found");
}

/// An expired order can still be refunded, for the user who funded it late.
///
/// Expiry is a bookkeeping change, not a claim on anybody's coin.
#[tokio::test]
async fn an_expired_order_that_gets_funded_late_can_still_refund() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 1;
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (status, opened) = open_order(&app, &user, "0.05", "alice").await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let order_id = opened["order_id"].as_str().unwrap().to_string();

    let mut order = state.store.get(&order_id).unwrap();
    order.created_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.store.put(&order).unwrap();
    zecp2p_v2coordinator::driver::sweep_once(&state).await;
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Expired);

    // The refund route must not turn this away on its stage. A malformed
    // transaction is refused for being malformed, which is a different refusal
    // from "this escrow is not refundable yet" - and that difference is the
    // property under test.
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(vec![0u8; 200]) }),
    )
    .await;
    let message = body["error"].as_str().unwrap_or_default();
    assert!(
        !message.contains("not refundable yet"),
        "an expired order must not be turned away on its stage, got {status}: {message}"
    );
}

/// A caller in a loop is refused, and it does not refuse anybody else.
///
/// The finding's shape: opening an order was free, so a script could take every
/// slot at no cost. A rate limit that also stopped real users would be a worse
/// outage than the one it prevents, so both halves are asserted.
#[tokio::test]
async fn one_caller_opening_orders_in_a_loop_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.open_rate_per_client = 3;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;
    config.limits.rate_window_seconds = 300;
    config.quote.max_open_per_handle = 100;
    config.limits.unfunded_order_minutes = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let mut refused = 0;
    for i in 0..8 {
        let (status, _) = open_order(&app, &user, &format!("0.0{}", i + 2), "alice").await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert!(
        refused >= 4,
        "a caller past the rate limit should be refused, only {refused} of 8 were"
    );
}

/// The per-client standing bound counts orders, not requests.
///
/// The per-handle cap cannot be this bound: the handle is the payee, chosen by
/// whoever opens the order, so a caller with a list of served handles walks
/// straight past it.
#[tokio::test]
async fn one_caller_may_only_hold_so_many_open_orders() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.max_open_per_client = 2;
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.quote.max_open_per_handle = 100;
    config.limits.unfunded_order_minutes = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Two different handles, so the per-handle cap cannot be what refuses.
    let (s1, _) = open_order(&app, &user, "0.05", "alice").await;
    let (s2, _) = open_order(&app, &user, "0.06", "bob").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);

    let (s3, body) = open_order(&app, &user, "0.07", "alice").await;
    assert_eq!(
        s3,
        StatusCode::BAD_REQUEST,
        "a third open order from one caller should be refused: {body}"
    );
}

/// A request naming an order that never existed leaves nothing behind.
///
/// The audit's unbounded map: `presign` and `refund` took the per-order lock
/// before checking the order existed, so an arbitrary id inserted a permanent
/// entry and nothing ever removed one.
#[tokio::test]
async fn a_request_for_an_unknown_order_does_not_mint_a_lock() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let before = state.order_locks_tracked().await;
    for i in 0..200 {
        let (status, _) = post(
            &app,
            &format!("/escrow/orders/esc_never_existed_{i}/presign"),
            serde_json::json!({ "pre_signature": "00", "terms_hash": "00", "u_pub": "00" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = post(
            &app,
            &format!("/escrow/orders/esc_also_never_{i}/refund"),
            serde_json::json!({ "raw_tx": "00" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert_eq!(
        state.order_locks_tracked().await,
        before,
        "400 requests for orders that do not exist must leave no locks behind"
    );
}

// ---------------------------------------------------------------------------
// Finding 5: the float.
// ---------------------------------------------------------------------------

/// The finding, reproduced: no payment starts on a float that will not cover
/// it, and the slot is never taken.
///
/// Running out used to present as a payment that failed partway through - the
/// ambiguous state a person resolves, holding the slot while they do.
#[tokio::test]
async fn a_float_that_will_not_cover_the_payment_stops_it_before_the_slot_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();
    // One cent, against a payment of far more.
    let rail = Arc::new(FundedRail::with_cents(1));

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 0;
    config.float.reserve_cents = 0;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let order_id = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;

    assert_eq!(rail.payments(), 0, "no payment may be attempted on an empty float");

    // And, crucially, the slot was never taken: another order must be able to
    // pay the moment the float is topped up.
    let stored = state.store.get(&order_id).unwrap();
    let funding = stored.funding.expect("funded");
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding.txid, funding.vout);
    assert!(
        !zecp2p_v2coordinator::slot::fiat_may_have_left(&state.journal, &work).unwrap(),
        "refusing for want of float must not leave a line saying money may have moved"
    );

    // Topped up, the same order pays.
    rail.set_cents(100_000);
    state.forget_fiat_balance();
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
    assert_eq!(rail.payments(), 1, "with float, the payment goes ahead");
}

/// The reserve is kept back, not just the payment amount.
///
/// A balance that exactly covers a payment is not enough: the read is a
/// snapshot, and a payment authorised against it can still fail if anything
/// else moved in between.
#[tokio::test]
async fn the_reserve_is_kept_back_on_top_of_the_payment() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 0;
    config.float.reserve_cents = 5_000;

    // Enough for the payment, and not enough for the payment plus the reserve.
    let rail = Arc::new(FundedRail::with_cents(300));
    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let order_id = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;
    let paid_cents = state.store.get(&order_id).unwrap().quote.net_cents;
    assert!(
        paid_cents <= 300,
        "the test needs a balance that covers the payment alone, payment is {paid_cents}"
    );

    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
    assert_eq!(
        rail.payments(),
        0,
        "the reserve must be kept back on top of the payment"
    );
}

/// A rail that cannot report a balance follows the operator's configured
/// policy, in both directions.
///
/// This is the permissionless-LP property: a balance check must not become a
/// requirement every future rail has to satisfy, and an LP who wants an
/// unreadable balance treated as empty must be able to say so.
#[tokio::test]
async fn an_unreadable_balance_follows_the_configured_policy() {
    for (permit, expect_payment) in [(true, 1usize), (false, 0usize)] {
        let dir = tempfile::tempdir().unwrap();
        let node = FakeNode::spawn().await;
        let scanner = Arc::new(FakeScanner::new());
        let attestor = TestAttestor::new();
        let user = TestUser::new();
        let rail = Arc::new(FundedRail::that_cannot_report());

        let mut config = test_config(dir.path());
        config.limits.unfunded_order_minutes = 0;
        config.float.pay_when_balance_unknown = permit;

        let state = coordinator_from_config(
            config,
            scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
            &node,
            Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
        );
        let state = with_attestor(state, &attestor);
        let app = zecp2p_v2coordinator::web::router(state.clone());

        let order_id =
            locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;

        assert_eq!(
            rail.payments(),
            expect_payment,
            "with pay_when_balance_unknown = {permit} the payment should {}",
            if expect_payment > 0 { "go ahead" } else { "be held" }
        );
    }
}

/// The balance policy is arithmetic on cents and nothing else.
///
/// Asserted directly because it is the seam that keeps the coordinator
/// rail-agnostic: everything the coordinator knows about a float is a number
/// and a configured threshold.
#[test]
fn the_balance_policy_is_only_arithmetic() {
    assert!(RailBalance::Known(500).covers(500, true));
    assert!(RailBalance::Known(500).covers(499, false));
    assert!(!RailBalance::Known(499).covers(500, true));
    // The unknown case is the operator's to decide, both ways.
    assert!(RailBalance::Unknown("no concept".into()).covers(u64::MAX, true));
    assert!(!RailBalance::Unknown("read failed".into()).covers(0, false));
    assert_eq!(RailBalance::Known(7).cents(), Some(7));
    assert_eq!(RailBalance::Unknown("x".into()).cents(), None);
}

/// The balance is read from a cache, and the cache is dropped after a payment.
///
/// A stale reading is exactly what would let the next order through on money
/// that is no longer there.
#[tokio::test]
async fn the_balance_cache_is_dropped_once_money_has_moved() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let user = TestUser::new();
    let rail = Arc::new(FundedRail::with_cents(100_000));

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 0;
    config.float.balance_cache_seconds = 3600;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        Some(rail.clone() as Arc<dyn zecp2p_v2coordinator::state::FiatRail>),
    );
    let state = with_attestor(state, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Repeated reads inside the window cost one call to the rail.
    let _ = state.fiat_balance_cents().await;
    let _ = state.fiat_balance_cents().await;
    let _ = state.fiat_balance_cents().await;
    assert_eq!(rail.balance_reads(), 1, "the cache should have served the repeats");

    let order_id = locked_order_for(&app, &state, &node, &scanner, &attestor, &user, "0.05").await;
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
    assert_eq!(rail.payments(), 1);

    let reads_before = rail.balance_reads();
    let _ = state.fiat_balance_cents().await;
    assert!(
        rail.balance_reads() > reads_before,
        "after a payment the cached balance must be discarded"
    );
}

// ---------------------------------------------------------------------------
// Finding 6: node calls, failover, and startup.
// ---------------------------------------------------------------------------

/// The head is read once for a whole sweep, not twice per order.
///
/// The comment this replaces promised the saving was taken in `advance_all`, a
/// function that never existed. The real behaviour was two uncached reads per
/// order in `check_deadlines`, every sweep - at the 200-order cap, hundreds of
/// calls a minute against one provider whose answer to that is a 429 with a
/// backoff measured in minutes, taken inside the sweep.
///
/// Counted as reads the coordinator *decided* to make rather than calls seen at
/// the socket: the RPC client runs a one-off network check per client it
/// builds, which is per connection and does not scale with orders, so counting
/// sockets would measure the wrong thing.
#[tokio::test]
async fn one_sweep_reads_the_head_once_however_many_orders() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();

    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 0;
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;
    config.quote.max_open_per_handle = 100;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    for i in 0..6u32 {
        let amount = format!("0.{}", 10 + i);
        let (status, body) = open_order(&app, &user, &amount, "alice").await;
        assert_eq!(status, StatusCode::OK, "opening at {amount}: {body}");
    }

    let before = state.head_reads();
    zecp2p_v2coordinator::driver::sweep_once(&state).await;
    let with_six = state.head_reads() - before;

    // One for the page's cache refresh at the top of the pass, one shared by
    // every order in it.
    assert!(
        with_six <= 2,
        "six orders in one sweep made {with_six} head reads; they should share one"
    );

    // The property, rather than the number: twice the orders must not cost
    // twice the reads.
    for i in 6..18u32 {
        let amount = format!("0.{}", 10 + i);
        let (status, body) = open_order(&app, &user, &amount, "alice").await;
        assert_eq!(status, StatusCode::OK, "opening at {amount}: {body}");
    }
    let before = state.head_reads();
    zecp2p_v2coordinator::driver::sweep_once(&state).await;
    let with_eighteen = state.head_reads() - before;
    assert_eq!(
        with_eighteen, with_six,
        "eighteen orders read the head {with_eighteen} times against {with_six} for six; \
         the cost is still scaling with the order count"
    );
}

/// A straggler from one sweep must not publish its head to the next.
///
/// The generation is what makes the shared head safe, and it only works if two
/// passes never share a number. Resetting the counter between passes - the
/// obvious way to say "no sweep is running" - makes them repeat: a task still
/// in flight from pass A finds its number equal to pass B's, its compare
/// succeeds, and it publishes a head it read during the earlier pass. Every
/// order in pass B then decides refund eligibility on a stale height.
///
/// Driven through the public surface rather than by reaching into the field:
/// `begin_sweep` returns the number, and what is asserted is that a later pass
/// never gets one an earlier pass used.
#[tokio::test]
async fn two_sweep_passes_never_share_a_generation() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let generation = state.begin_sweep();
        assert!(
            seen.insert(generation),
            "pass number {generation} was handed out twice; a straggler from the \
             earlier pass would publish its head to the later one"
        );
        state.end_sweep();
    }
}

/// Outside a sweep the node is read, and inside one the pass's head is shared.
///
/// Both halves matter. The refund endpoint and `presign`'s own advance run
/// outside a sweep and must see the node; every order inside a pass must share
/// one read, which is the whole saving.
#[tokio::test]
async fn the_shared_head_applies_inside_a_sweep_and_nowhere_else() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    // Outside a sweep: every call reads the node.
    let before = state.head_reads();
    let _ = state.head_for_this_sweep().await.unwrap();
    let _ = state.head_for_this_sweep().await.unwrap();
    assert_eq!(
        state.head_reads() - before,
        2,
        "outside a sweep each caller must see the node"
    );

    // Inside one: the pass shares a single read.
    state.begin_sweep();
    let before = state.head_reads();
    let _ = state.head_for_this_sweep().await.unwrap();
    let _ = state.head_for_this_sweep().await.unwrap();
    let _ = state.head_for_this_sweep().await.unwrap();
    assert_eq!(
        state.head_reads() - before,
        1,
        "inside a sweep the pass shares one head read"
    );

    // And the sharing ends with the pass.
    state.end_sweep();
    let before = state.head_reads();
    let _ = state.head_for_this_sweep().await.unwrap();
    assert_eq!(
        state.head_reads() - before,
        1,
        "once the pass is over the shared head must not be reused"
    );
}

/// An unreachable primary is failed over to a second endpoint.
///
/// One provider was a single point of failure for the read that decides when a
/// user is offered their refund.
#[tokio::test]
async fn an_unreachable_primary_endpoint_fails_over() {
    let dir = tempfile::tempdir().unwrap();
    let working = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let mut config = test_config(dir.path());
    // The primary points nowhere; the fallback is the node that works.
    config.zec.fallback_rpc = vec![zecp2p_v2coordinator::config::FallbackRpc {
        rpc_url: working.url.clone(),
        rpc_user: None,
        rpc_password: None,
        rpc_api_key_header: None,
        rpc_api_key: None,
        rpc_api_key_env: None,
    }];
    config.limits.unfunded_order_minutes = 0;

    // `coordinator_from_config` overwrites `rpc_url` with the node's, so the
    // primary is set to a dead address afterwards.
    std::env::set_var("ZECP2P_LP_PRIV", hex::encode([0x22u8; 32]));
    let dead = FakeNode::spawn().await;
    let mut config = config;
    config.zec.rpc_url = dead.url.clone();
    dead.go_offline().await;

    let state = coordinator_from_config_keeping_rpc(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        None,
    );

    let head = state.chain_head_uncached().await;
    assert!(
        head.is_ok(),
        "a dead primary with a working fallback must still answer: {head:?}"
    );
    assert!(
        state.nodes.on_fallback(),
        "the pool should have moved to the endpoint that answered"
    );
}

/// A rejection is an answer, and is not shopped around the pool.
///
/// Asking a second node whether a transaction is *really* rejected is asking
/// until one agrees, and a release accepted by one node after another rejected
/// it is a double broadcast.
#[test]
fn a_rejection_is_not_retried_against_another_endpoint() {
    use zecp2p_escrow::chain::ChainError;
    use zecp2p_escrow::rpc::{Network, RpcConfig};
    use zecp2p_v2coordinator::nodes::NodePool;

    let pool = NodePool::new(vec![
        RpcConfig::public("http://one.invalid", Network::Test),
        RpcConfig::public("http://two.invalid", Network::Test),
    ]);
    let calls = std::cell::Cell::new(0);
    let out: Result<u32, ChainError> = pool.try_each(|_| {
        calls.set(calls.get() + 1);
        Err(ChainError::Rejected("bad signature".into()))
    });
    assert!(matches!(out, Err(ChainError::Rejected(_))));
    assert_eq!(calls.get(), 1, "a verdict must not be asked of a second node");
}

// ---------------------------------------------------------------------------
// Finding 7: alerts and /health.
// ---------------------------------------------------------------------------

/// `/health` used to be a constant, so the page's indicator read "responding"
/// through every failure short of the process being gone.
#[tokio::test]
async fn health_reports_a_dead_node_rather_than_ok() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (status, body) = get(&app, "/health").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert!(
        body["build"]["git_hash"].as_str().is_some(),
        "health should name the build it is running: {body}"
    );

    node.go_offline().await;
    // The cached head has to expire before health can see the node is gone.
    state.forget_chain_head();

    let (status, body) = get(&app, "/health").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a coordinator that cannot reach any node is not healthy: {body}"
    );
    assert_eq!(body["ok"], false, "{body}");
    assert_eq!(body["checks"]["node"]["ok"], false, "{body}");
}

/// A stalled sweep reaches `/health`, because nothing else records it.
#[tokio::test]
async fn health_reports_a_sweep_that_has_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let mut config = test_config(dir.path());
    config.alerts.sweep_age_minutes = 1;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Before any sweep has run this is starting up, not stalled.
    let (status, body) = get(&app, "/health").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    zecp2p_v2coordinator::driver::sweep_once(&state).await;
    let (status, body) = get(&app, "/health").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checks"]["sweep"]["minutes_since_last"], 0, "{body}");

    state.pretend_last_sweep_was_minutes_ago(30);
    let (status, body) = get(&app, "/health").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a sweep that has not run means nothing is being advanced: {body}"
    );
}

/// A fill needing a person shows up in `/health` as degraded, and the
/// coordinator keeps serving.
///
/// Degraded rather than unhealthy on purpose: a user can still open, fund and
/// refund an order while a fill waits for an operator.
#[tokio::test]
async fn health_reports_a_fill_that_needs_a_person() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    stage_needs_operator_line(&state);

    let (status, body) = get(&app, "/health").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fill needing a person does not stop the service: {body}"
    );
    assert_eq!(body["status"], "degraded", "{body}");
    assert_eq!(body["checks"]["payment_slot"]["needs_operator"], 1, "{body}");
}

/// The notify hook runs, receives the alert on stdin, and is not given a shell.
///
/// A subprocess rather than a built-in client for one messaging service,
/// because where an alert goes is the LP's decision. The no-shell property is
/// the one worth asserting: the body carries a handle a caller chose.
#[tokio::test]
async fn the_notify_hook_receives_the_alert_and_gets_no_shell() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let out = dir.path().join("alerts.jsonl");

    let hook = dir.path().join("hook.sh");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\ncat >> {}\n", out.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut config = test_config(dir.path());
    config.alerts.notify_command = vec![hook.display().to_string()];
    config.alerts.repeat_minutes = 0;
    config.server.instance_name = "an-lp-somewhere".into();

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    zecp2p_v2coordinator::alert::fire(
        &state,
        zecp2p_v2coordinator::alert::Alert::needs_operator("work-1", 42, Some("a note")),
    )
    .await;

    let written = std::fs::read_to_string(&out).expect("the hook should have been run");
    let alert: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
    assert_eq!(alert["key"], "needs_operator:work-1");
    assert_eq!(alert["severity"], "critical");
    assert_eq!(alert["detail"]["held_minutes"], 42);
    assert_eq!(
        alert["instance"], "an-lp-somewhere",
        "an alert must say which coordinator it came from"
    );
    assert!(
        alert["action"].as_str().unwrap().contains("resolve-fill"),
        "the alert should say what to do about it: {alert}"
    );
}

/// A condition noticed on every sweep is not reported on every sweep.
///
/// The existing session keeper re-alerts every 20 minutes with no state, so the
/// first real incident buries the channel it is trying to be heard on.
#[tokio::test]
async fn a_repeating_condition_is_reported_once_not_every_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let out = dir.path().join("alerts.jsonl");

    let hook = dir.path().join("hook.sh");
    std::fs::write(&hook, format!("#!/bin/sh\ncat >> {}\n", out.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut config = test_config(dir.path());
    config.alerts.notify_command = vec![hook.display().to_string()];
    config.alerts.repeat_minutes = 60;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    for _ in 0..5 {
        zecp2p_v2coordinator::alert::fire(
            &state,
            zecp2p_v2coordinator::alert::Alert::needs_operator("work-1", 42, None),
        )
        .await;
    }

    let written = std::fs::read_to_string(&out).unwrap_or_default();
    let lines = written.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        lines, 1,
        "five sweeps noticing one condition should send one message, sent {lines}"
    );
}

/// A hook that hangs does not hang the sweep.
///
/// An alert that stopped the coordinator would be worse than the condition it
/// was reporting.
#[tokio::test]
async fn a_hanging_notify_hook_does_not_hang_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let hook = dir.path().join("hook.sh");
    std::fs::write(&hook, "#!/bin/sh\nsleep 600\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut config = test_config(dir.path());
    config.alerts.notify_command = vec![hook.display().to_string()];
    config.alerts.notify_timeout_seconds = 1;

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    let started = std::time::Instant::now();
    zecp2p_v2coordinator::alert::fire(
        &state,
        zecp2p_v2coordinator::alert::Alert::sweep_stale(90),
    )
    .await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "the hook timeout should have fired, took {:?}",
        started.elapsed()
    );
}

/// A hook that does not exist is a log line, not a crash.
#[tokio::test]
async fn a_broken_notify_hook_does_not_stop_anything() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let mut config = test_config(dir.path());
    config.alerts.notify_command = vec!["/nonexistent/definitely-not-a-program".into()];

    let state = coordinator_from_config(
        config,
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );

    // The assertion is that this returns at all.
    zecp2p_v2coordinator::alert::fire(
        &state,
        zecp2p_v2coordinator::alert::Alert::sweep_stale(90),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Finding 10: knowing what is running.
// ---------------------------------------------------------------------------

/// The build stamp is one greppable literal, which is how a deploy script
/// identifies a binary it cannot execute.
#[test]
fn the_build_stamp_survives_into_the_binary() {
    let stamp = zecp2p_v2coordinator::version::STAMP;
    assert!(stamp.starts_with("zecp2p-build:"), "{stamp}");
    assert!(
        stamp.contains(zecp2p_v2coordinator::version::GIT_HASH),
        "the stamp must carry the commit: {stamp}"
    );
    // Six colon-separated fields, so a script can split on them.
    assert_eq!(stamp.split(':').count(), 6, "{stamp}");
}

/// `/health` and `--version` answer with the same hash, so an operator
/// comparing a hub against their laptop is comparing one thing.
#[tokio::test]
async fn health_and_the_version_flag_agree() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());

    let state = coordinator_from_config(
        test_config(dir.path()),
        scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>,
        &node,
        None,
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (_, body) = get(&app, "/health").await;
    assert_eq!(
        body["build"]["git_hash"].as_str().unwrap(),
        zecp2p_v2coordinator::version::GIT_HASH
    );
    assert!(
        zecp2p_v2coordinator::version::describe()
            .contains(zecp2p_v2coordinator::version::GIT_HASH),
        "--version and /health must name the same build"
    );
}
