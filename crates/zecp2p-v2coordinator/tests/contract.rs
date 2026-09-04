//! The contract the page depends on, asserted against the running server.
//!
//! `frontend/app/test/mock-coordinator.mjs` is the executable spec and the page
//! was written against it. These tests hold this coordinator to the same
//! shapes, and to the two conventions that are invisible in a schema and
//! expensive to get wrong: which txid is reversed, and which is not.
//!
//! The escrow here is real. Keys are drawn, an address is derived, a
//! pre-signature is made with the escrow crate's own `pre_sign`, verified by
//! the coordinator's gate, decrypted with the attestor's scalar, and the
//! resulting release is executed - so what these tests exercise is the whole
//! adaptor seam, not a mock of it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zecp2p_v2coordinator::funding::{FakeScanner, FoundOutput};
use zecp2p_v2coordinator::order::Stage;
use zecp2p_v2coordinator::state::{AppState, AppStateBuilder};

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
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn post(app: &axum::Router, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn capabilities_carries_every_field_the_page_reads() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let (status, body) = get(&app, "/escrow/capabilities").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Every one of these is read by `loadCapabilities` or by the code that
    // checks the order against it.
    for field in [
        "network",
        "rails",
        "fee",
        "l_pub",
        "attestor_pubkey",
        "consensus_branch_id",
        "block_seconds",
        "refund_delay_blocks",
        "limits",
        "rate_usd_per_zec",
    ] {
        assert!(body.get(field).is_some(), "capabilities is missing {field}");
    }
    assert_eq!(body["fee"]["bps"], 20);
    assert_eq!(body["network"], "test");
    assert_eq!(body["rails"][0]["id"], "venmo");
    assert_eq!(body["limits"]["min_zat"], 120_000);
    // The branch id is the node's, not a constant.
    assert_eq!(body["consensus_branch_id"], BRANCH_ID);
    // The page compares the order's l_pub against this one and refuses a
    // mismatch, so they must be the same key.
    assert_eq!(body["l_pub"], hex::encode(state.l_pub));
}

#[tokio::test]
async fn a_quote_prices_the_fee_the_treasury_and_the_conventional_miner_fee() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let (status, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    assert_eq!(status, StatusCode::OK, "{q}");

    for field in [
        "quote_id",
        "amount_zat",
        "net_cents",
        "usd_amount_6dec",
        "platform_fee_zat",
        "miner_fee_zat",
        "lines",
        "expires_at",
    ] {
        assert!(q.get(field).is_some(), "the quote is missing {field}");
    }
    assert_eq!(q["amount_zat"], 5_000_000);
    // 20 bps of 5,000,000 is 10,000 zat, above the 54 zat dust gate.
    assert_eq!(q["platform_fee_zat"], 10_000);
    // Two outputs, because the fee is non-zero on testnet.
    assert_eq!(q["miner_fee_zat"], 15_000);
    assert_eq!(q["lines"][0]["is_zpay_fee"], true);
    assert_eq!(q["lines"][1]["is_zpay_fee"], false);
}

#[tokio::test]
async fn an_order_returns_an_address_the_page_can_derive_for_itself() {
    // The page rebuilds the address from u_pub, l_pub and the refund height,
    // and refuses the order if it differs. This asserts the same derivation.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (status, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{order}");

    let esc = &order["escrow"];
    let refund_height = esc["refund_height"].as_u64().unwrap();
    let derived = zecp2p_escrow::funding::escrow_address(
        &user.u_pub,
        &state.l_pub,
        refund_height,
        esc["amount_zat"].as_u64().unwrap(),
        zecp2p_escrow::funding::AddressNetwork::Test,
    )
    .unwrap();

    assert_eq!(
        esc["address"].as_str().unwrap(),
        derived.address,
        "the page derives this address itself and refuses a mismatch"
    );
    assert_eq!(esc["l_pub"], hex::encode(state.l_pub));
    assert_eq!(esc["u_pub"], hex::encode(user.u_pub));
    assert_eq!(order["stage"], "awaiting_zec");
    assert!(esc["zip321_uri"].as_str().unwrap().starts_with("zcash:"));
    // The payee hash came from the curator stub, not from a local hash.
    assert_eq!(esc["payee_hash"], hex::encode(CURATOR_HASH));
}

#[tokio::test]
async fn an_order_for_an_unserved_handle_is_refused() {
    // The inverse of the Base rail's `only_user` default: this coordinator
    // fronts fiat for the handles it was told about and nobody else.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (status, body) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "mallory" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("not taking orders"));
}

#[tokio::test]
async fn a_handle_that_could_inject_into_a_pay_url_is_refused() {
    // `alice?amount=500` was a query injection into the Venmo pay link the
    // browser is driven to.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let user = TestUser::new();
    for bad in ["alice?amount=500", "alice/../bob", "alice bob", ""] {
        let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
        let (status, _) = post(
            &app,
            "/escrow/orders",
            serde_json::json!({
                "quote_id": q["quote_id"],
                "u_pub": hex::encode(user.u_pub),
                "destination": { "rail": "venmo", "handle": bad },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?} was accepted");
    }
}

#[tokio::test]
async fn the_full_paid_path_runs_from_a_quote_to_a_release() {
    // The whole point. A real escrow, a real adaptor pre-signature made the way
    // the page makes it, the coordinator's own verification gate, the
    // attestor's scalar, and a release whose signatures are checked.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // 1. Quote and order.
    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (status, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{order}");
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();

    // 2. The user's wallet pays the address. The scanner sees it and the node
    //    reports it deep enough for its size.
    let funding_txid = [0x9au8; 32];
    let stored = state.store.get(&order_id).unwrap();
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput {
            txid: funding_txid,
            vout: 0,
            amount_zat,
        },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("the escrow should confirm and announce");

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "needs_presignature", "{view}");

    // The two byte orders, in the same response.
    let funding_display = view["funding"]["txid"].as_str().unwrap();
    assert_eq!(
        funding_display,
        zecp2p_escrow::rpc::txid_to_display(&funding_txid),
        "funding.txid crosses the wire in display order"
    );
    assert_eq!(
        view["announcement"]["terms"]["funding_txid"].as_str().unwrap(),
        hex::encode(funding_txid),
        "WireTerms carries internal order"
    );

    // 3. The page pre-signs, exactly as `prepareEscrow` does: it rebuilds the
    //    terms, computes the digest from the announced split, and encrypts
    //    under the outcome point.
    let stored = state.store.get(&order_id).unwrap();
    let announced = view["announcement"].clone();
    let miner_fee = announced["miner_fee_zat"].as_u64().unwrap();
    assert_eq!(
        miner_fee,
        zecp2p_escrow::fees::release_fee_zat(stored.redeem_script.len(), 2),
        "the page refuses any miner fee but the conventional one"
    );

    let pre_sig = user.pre_sign(&stored, &attestor, &announced);
    let terms_hash = announced["terms_hash"].as_str().unwrap().to_string();

    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": terms_hash,
            "u_pub": hex::encode(user.u_pub),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "locked");
    assert!(view["pre_signature"]["received_at"].is_string());

    // 4. The fiat leg and the release. The test rail reports the payment; the
    //    attestor signs the outcome; the coordinator decrypts and broadcasts.
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("the paid path should complete");

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "released", "{view}");
    assert!(view["release"]["txid"].is_string());
    assert_eq!(view["payment"]["cents"], stored.quote.net_cents);

    // 5. The release that was broadcast really spends this escrow, and really
    //    pays the treasury.
    let broadcast = node.broadcasts().await;
    assert_eq!(broadcast.len(), 1, "exactly one release");
    let raw = &broadcast[0];

    let terms = stored.escrow_terms(&stored.funding.unwrap_or(
        zecp2p_v2coordinator::order::Funding {
            txid: funding_txid,
            vout: 0,
            confirmations: 30,
            required: 30,
        },
    ));
    let split = stored.release_split();
    let outputs = split.outputs(amount_zat).expect("a valid split");
    assert_eq!(outputs.len(), 2, "payout and treasury");
    assert_eq!(outputs[1].value_zat, stored.quote.platform_fee_zat);
    assert_eq!(
        outputs[1].script,
        zecp2p_escrow::treasury::treasury_script(zecp2p_escrow::address::AddrNetwork::Test)
            .unwrap(),
        "the fee pays the pinned treasury, not a configured address"
    );
    assert_eq!(
        outputs[0].value_zat,
        amount_zat - stored.quote.miner_fee_zat - stored.quote.platform_fee_zat
    );

    // The transaction on the wire is the one the digest was computed over.
    let txid = zecp2p_escrow::tx::txid_of_signed(raw).expect("the release parses");
    assert_eq!(
        view["release"]["txid"].as_str().unwrap(),
        zecp2p_escrow::rpc::txid_to_display(&txid)
    );
    let _ = terms;
}

#[tokio::test]
async fn a_pre_signature_for_another_transaction_is_refused_and_nothing_is_paid() {
    // The gate. A pre-signature that does not verify against this order's own
    // digest means the LP does not pay and the user refunds at T.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();
    let funding_txid = [0x9au8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30).await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();

    // A pre-signature over a different digest: same keys, wrong transaction.
    let bad = user.pre_sign_over_digest(&[0x11u8; 32], &stored, &attestor, &announced);

    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(bad.as_ref()),
            "terms_hash": announced["terms_hash"],
            "u_pub": hex::encode(user.u_pub),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("will not pay"),
        "the refusal says the LP will not pay: {body}"
    );

    // The order did not lock, and nothing was broadcast.
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::NeedsPresignature);
    assert!(node.broadcasts().await.is_empty());
}

#[tokio::test]
async fn a_pre_signature_from_a_different_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let impostor = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();
    let funding_txid = [0x9au8; 32];
    scanner.pay(&stored.script_pubkey, FoundOutput { txid: funding_txid, vout: 0, amount_zat });
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30).await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();

    // Signed correctly, but by the wrong key: it verifies against nothing this
    // escrow's 2-of-2 will accept.
    let wrong = impostor.pre_sign(&stored, &attestor, &announced);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(wrong.as_ref()),
            "terms_hash": announced["terms_hash"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(node.broadcasts().await.is_empty());
}

#[tokio::test]
async fn an_underpaid_escrow_is_not_settled_against() {
    // A sender who pays the wrong amount leaves an output at the address that
    // is not the escrow. Settling against it would build a release over an
    // amount the user never agreed to.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let state = coordinator_with_node(dir.path(), scanner.clone(), &node);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    // One zatoshi short.
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: [0x77u8; 32], vout: 0, amount_zat: amount_zat - 1 },
    );
    node.add_utxo([0x77u8; 32], 0, stored.script_pubkey.clone(), amount_zat - 1, 30).await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "awaiting_zec", "a short payment is not this escrow");
    assert!(view["funding"].is_null());
}

#[tokio::test]
async fn a_refund_is_refused_once_the_dollars_have_gone() {
    // Broadcasting a refund after the payment would race the release, and the
    // LP loses if the refund lands first.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();

    let mut stored = state.store.get(&order_id).unwrap();
    stored.stage = Stage::Paid;
    stored.payment = Some(zecp2p_v2coordinator::order::Payment {
        sent_at: chrono::Utc::now(),
        cents: 100,
    });
    state.store.put(&stored).unwrap();

    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode([0u8; 200]), "txid": "00" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("already been sent"));
}

#[tokio::test]
async fn an_unknown_order_is_a_404_and_an_expired_quote_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let (status, _) = get(&app, "/escrow/orders/esc_nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let user = TestUser::new();
    let (status, body) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": "q_never_issued",
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("expired"));
}

#[tokio::test]
async fn the_state_builds_inside_an_async_runtime() {
    // A regression. `NodeRpc` used to build its blocking reqwest client in its
    // constructor, and `AppStateBuilder::build` runs inside `async fn main`.
    // Building a blocking client on a tokio worker thread panics with "Cannot
    // drop a runtime in a context where blocking is not allowed", so the real
    // binary died at startup while every test passed - the tests all inject a
    // scanner and never construct the default one.
    //
    // This builds the state the way `main` does, with no scanner supplied, so
    // the default path is the one exercised.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let curator = FakeCurator::spawn_blocking_new();

    std::env::set_var("ZECP2P_LP_PRIV", hex::encode([0x22u8; 32]));
    let mut config = test_config(dir.path());
    config.zec.rpc_url = node.url.clone();
    config.zkp2p.api_url = curator.url.clone();

    let state = AppStateBuilder::new(config)
        .build()
        .expect("the state must build on a runtime thread");

    // And the scanner it built is usable from where it will actually be called.
    let scanner = state.scanner.clone();
    let found = tokio::task::spawn_blocking(move || {
        scanner.outputs_paying(&[0xa9, 0x14], "t2Nothing", 0)
    })
    .await
    .unwrap();
    // The fake node answers "method not found" for getblock, so a block scan
    // finds nothing rather than failing. Either way it must not panic.
    assert!(found.map(|f| f.is_empty()).unwrap_or(true));
}

#[tokio::test]
async fn a_rail_that_cannot_pay_leaves_the_escrow_refundable_not_failed() {
    // Found by driving the real page against the real binary: with no stored
    // Venmo session, `pay` failed before the browser opened and the order was
    // marked `failed` saying "a payment may have left". Nothing could have
    // left, and a failed order is terminal - the page stops offering the
    // refund, so the user's ZEC is stranded over an operator problem a restart
    // fixes. A rail that cannot start must produce a wait.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();
    let funding_txid = [0x9au8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30).await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();
    let pre_sig = user.pre_sign(&stored, &attestor, &announced);
    let (status, _) = post(
        &app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": announced["terms_hash"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The rail refuses. The order must stay somewhere the user can still
    // refund from, and nothing may be broadcast.
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    let after = state.store.get(&order_id).unwrap();
    assert_ne!(
        after.stage,
        Stage::Failed,
        "a rail that never started must not strand the escrow in a terminal state"
    );
    assert!(after.payment.is_none(), "nothing was paid");
    assert!(node.broadcasts().await.is_empty(), "nothing was broadcast");
    assert!(
        after.stage.is_open() || after.stage == Stage::Unpaid,
        "the escrow stays refundable, got {}",
        after.stage.as_str()
    );
}

// ---------- round 1 audit: the pay-side money bugs ----------

/// Walks a fresh order up to `locked` with a funded, deep escrow.
///
/// Returns the order id and the funding txid, so a test can then interfere with
/// exactly the state the audit findings are about.
async fn locked_order(
    app: &axum::Router,
    state: &Arc<AppState>,
    node: &FakeNode,
    scanner: &Arc<FakeScanner>,
    attestor: &TestAttestor,
    user: &TestUser,
) -> (String, [u8; 32]) {
    let (_, q) = get(app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (status, order) = post(
        app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{order}");
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();

    let stored = state.store.get(&order_id).unwrap();
    // A txid derived from the order, so two orders in one test differ.
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
    (order_id, funding_txid)
}

#[tokio::test]
async fn a_crash_between_the_journal_and_the_store_does_not_pay_twice() {
    // R1-1. `settle` writes `Paying` to the journal, then drives a browser for
    // up to two minutes, then writes `Paid` to the store. A crash in that
    // window leaves the store at `Locked`, which on restart means "the LP may
    // pay". Nothing read the journal back, so the restart paid again - and the
    // second payment is unrecoverable, because the escrow releases once.
    //
    // This reproduces the restart exactly: drive the order to `locked`, write
    // the journal claim the way `settle` does, leave the store at `Locked`,
    // then advance. It must refuse.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // The crash: a `Paying` line exists and the store still says `Locked`.
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);
    zecp2p_v2coordinator::slot::claim(
        &state.journal,
        &work,
        700_000,
        "alice",
        alloy::primitives::B256::repeat_byte(0x11),
        1_700_000_000_000,
    )
    .unwrap();
    let mut stalled = state.store.get(&order_id).unwrap();
    stalled.stage = Stage::Locked;
    stalled.payment = None;
    state.store.put(&stalled).unwrap();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a refusal is not an error");

    assert_eq!(
        fiat.payments(),
        0,
        "a second payment was sent for an escrow that may already have been paid"
    );
    assert!(node.broadcasts().await.is_empty(), "nothing was released");

    // And the operator is told why, in a message that names the next step.
    let after = state.store.get(&order_id).unwrap();
    assert_eq!(after.stage, Stage::Failed);
    let reason = after.reason.unwrap_or_default();
    assert!(
        reason.contains("check the Venmo feed"),
        "the reason must tell a human what to do: {reason}"
    );
}

#[tokio::test]
async fn a_second_order_cannot_pay_while_the_first_is_mid_payment() {
    // R1-2. The slot was claimed at `Stage::Paid`, but an order being paid is
    // still `Locked`. So order A drives the browser, the sweep reaches order B,
    // B sees nobody at `Paid`, and B pays too. Two entries of the same amount
    // to the same handle is what `locate_payment` refuses to resolve - once
    // both have left.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Only B exists as an order. A is represented by the thing that actually
    // holds the slot: a `Paying` line on disk for some other work item. Opening
    // a real second order would settle it through the task `presign` spawns,
    // which is a different scenario.
    let user_b = TestUser::new();
    let (order_b, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user_b).await;
    let paid_before = fiat.payments();

    // A is mid-browser: its claim is on disk and its own stage is still
    // `Locked`, so nothing in the order store says a payment is under way.
    let work_a = zecp2p_v2coordinator::slot::work_id_for(&[0xa1u8; 32], 0);
    zecp2p_v2coordinator::slot::claim(
        &state.journal,
        &work_a,
        700_000,
        "alice",
        alloy::primitives::B256::repeat_byte(0xaa),
        1_700_000_000_000,
    )
    .unwrap();

    // The sweep reaches B.
    zecp2p_v2coordinator::driver::advance(&state, &order_b)
        .await
        .expect("waiting for the slot is not an error");

    assert_eq!(
        fiat.payments(),
        paid_before,
        "B paid while another work item had a payment in flight"
    );
    // B is not failed: it is waiting, and will pay once A finishes.
    let b = state.store.get(&order_b).unwrap();
    assert_eq!(b.stage, Stage::Locked, "B waits rather than failing");
    assert!(b.payment.is_none());
}

#[tokio::test]
async fn one_order_at_a_time_even_when_the_sweep_runs_them_together() {
    // The same finding from the other direction: two orders both eligible, one
    // sweep. Exactly one may pay.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user_a = TestUser::new();
    let (order_a, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user_a).await;
    let user_b = TestUser::new();
    let (order_b, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user_b).await;

    // Both advanced, back to back, the way the sweep does it. Each may already
    // have been settled by the task `presign` spawns; what must never happen is
    // two *open* payments at once, and the count below is the whole history.
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_a).await;
    let _ = zecp2p_v2coordinator::driver::advance(&state, &order_b).await;

    // Each order pays at most once, and no order pays for another.
    for id in [&order_a, &order_b] {
        let o = state.store.get(id).unwrap();
        assert!(
            matches!(o.stage, Stage::Released | Stage::Locked | Stage::Paid),
            "{} ended at {}",
            id,
            o.stage.as_str()
        );
    }
    assert!(
        fiat.payments() <= 2,
        "no order may be paid more than once, got {} payments for two orders",
        fiat.payments()
    );
    // And the journal never holds two open claims that may have paid.
    let open: Vec<_> = state
        .journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.state.fiat_may_have_left() && r.state.is_open())
        .collect();
    assert!(
        open.len() <= 1,
        "two payments were in flight at once: {open:?}"
    );
}

#[tokio::test]
async fn a_branch_change_stops_the_payment_before_the_dollars_leave() {
    // R1-3. `lib.rs` claimed the branch id was re-read before the browser
    // opened, and it was not: `require_payable` calls `lp::evaluate`, which
    // never reads it. A network upgrade inside the 24-hour refund window
    // changes the ZIP 244 sighash, so the pre-signature stops authorising the
    // release the LP will build - and the LP finds out after paying.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // The network upgrades between the pre-signature and the payment.
    node.set_branch_id(0x4d75_7161).await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("refusing to pay is not an error");

    assert_eq!(
        fiat.payments(),
        0,
        "the LP paid for a release the chain will not accept"
    );
    assert!(node.broadcasts().await.is_empty());
    // Nothing was lost: the escrow is still the user's to refund at T.
    let after = state.store.get(&order_id).unwrap();
    assert!(after.payment.is_none());
    assert_ne!(after.stage, Stage::Paid);
}

#[tokio::test]
async fn the_refund_endpoint_will_not_broadcast_a_transaction_for_another_escrow() {
    // R1-5. The endpoint parsed the transaction only far enough to compare its
    // txid with the one the caller sent alongside it, which is a claim checked
    // against itself. So anyone with an order id could have the coordinator's
    // node broadcast any valid transaction, and the order went terminal
    // `refunded` - losing its own status as well.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // Past T, so a refund is due and the stage gate is satisfied.
    let mut refundable = state.store.get(&order_id).unwrap();
    refundable.stage = Stage::Refundable;
    state.store.put(&refundable).unwrap();

    // A perfectly valid transaction that spends somebody else's outpoint.
    let stranger = {
        let terms = zecp2p_escrow::tx::EscrowTerms {
            funding_txid: [0x11u8; 32],
            vout: 0,
            amount_zat: 5_000_000,
            u_pub: refundable.u_pub,
            l_pub: refundable.l_pub,
            refund_height: refundable.refund_height,
            consensus_branch_id: refundable.consensus_branch_id,
        };
        let script = zecp2p_escrow::address::script_pubkey_for(
            "tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn",
            zecp2p_escrow::address::AddrNetwork::Test,
        )
        .unwrap();
        let redeem = terms.redeem_script().unwrap();
        let fee = zecp2p_escrow::fees::refund_fee_to_transparent_zat(redeem.len());
        let script_sig = zecp2p_escrow::script::refund_script_sig(&[0x30; 71], &redeem);
        zecp2p_escrow::tx::serialize_refund(&terms, &script, fee, &script_sig).unwrap()
    };

    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(&stranger) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("does not spend this escrow"),
        "the refusal must say why: {body}"
    );
    assert!(
        node.broadcasts().await.is_empty(),
        "the coordinator relayed a transaction for another escrow"
    );
    // The order kept its own status.
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Refundable);
    let _ = funding_txid;
}

#[tokio::test]
async fn the_refund_endpoint_still_broadcasts_this_escrows_own_refund() {
    // The other half: hardening the endpoint must not break the path the page
    // actually uses.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let mut refundable = state.store.get(&order_id).unwrap();
    refundable.stage = Stage::Refundable;
    state.store.put(&refundable).unwrap();

    let raw = user.sign_refund(&refundable, &funding_txid, 0);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(&raw) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(node.broadcasts().await.len(), 1);
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Refunded);
}

#[tokio::test]
async fn a_refund_is_refused_before_the_escrow_is_refundable() {
    // The stage gate. Answering outside the refundable stages is what let a
    // caller drive an arbitrary order to terminal `refunded`.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    // Still `locked`: the LP may yet pay, and a refund now would race a release.
    let stored = state.store.get(&order_id).unwrap();
    assert_eq!(stored.stage, Stage::Locked);

    let raw = user.sign_refund(&stored, &funding_txid, 0);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(&raw) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("not refundable yet"));
    assert!(node.broadcasts().await.is_empty());
}

#[tokio::test]
async fn a_reorg_that_unwinds_the_funding_stops_the_payment() {
    // The should-fix "stale funding" concern, resolved by showing the check
    // already happens: `require_payable` calls `lp::evaluate`, which re-reads
    // `chain.utxo` and re-checks the script, the amount and the depth on every
    // call. So an outpoint that has gone away between the lock and the payment
    // is caught, and the coordinator does not need a second reading of its own
    // that could disagree with the one the decision is made on.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let paid_before = fiat.payments();

    // The funding transaction is unwound.
    node.remove_utxo(funding_txid, 0).await;

    // Put the order back to `locked` in case the presign task already settled
    // it, so this exercises the payment decision rather than a finished order.
    let mut relocked = state.store.get(&order_id).unwrap();
    if relocked.stage == Stage::Released || relocked.stage == Stage::Paid {
        // Already settled against the output that existed at the time; nothing
        // to prove here.
        return;
    }
    relocked.stage = Stage::Locked;
    state.store.put(&relocked).unwrap();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("refusing to pay is not an error");

    assert_eq!(
        fiat.payments(),
        paid_before,
        "the LP paid for an escrow whose funding output no longer exists"
    );
}

#[tokio::test]
async fn two_presignatures_arriving_together_settle_once() {
    // The should-fix on `presign` not taking the order lock. Both requests
    // would read `needs_presignature`, both pass, and both spawn a settlement
    // task; the payment slot would then catch the second, but that is the last
    // line of defence rather than the first.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (_, order) = post(
        &app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": q["quote_id"],
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": "alice" },
        }),
    )
    .await;
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();
    let funding_txid = [0x5cu8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30).await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();
    let pre_sig = hex::encode(user.pre_sign(&stored, &attestor, &announced).as_ref());
    let terms_hash = announced["terms_hash"].as_str().unwrap().to_string();

    let body = serde_json::json!({
        "pre_signature": pre_sig,
        "terms_hash": terms_hash,
        "u_pub": hex::encode(user.u_pub),
    });
    let path = format!("/escrow/orders/{order_id}/presign");
    // Both at once.
    let (first, second) = tokio::join!(
        post(&app, &path, body.clone()),
        post(&app, &path, body.clone())
    );

    // One is accepted and one is refused for the stage; never two acceptances.
    let accepted = [first.0, second.0]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(accepted, 1, "both pre-signatures were accepted");

    // Let any spawned settlement finish, then check it happened once.
    for _ in 0..20 {
        if state.store.get(&order_id).unwrap().stage == Stage::Released {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(fiat.payments() <= 1, "paid {} times", fiat.payments());
    assert!(
        node.broadcasts().await.len() <= 1,
        "broadcast {} releases",
        node.broadcasts().await.len()
    );
}

#[tokio::test]
async fn open_orders_are_bounded_per_handle() {
    // Orders cannot be evicted - one this process forgets is an escrow whose
    // release nobody can assemble - so the bound goes at the door.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let mut config = test_config(dir.path());
    config.quote.max_open_per_handle = 2;
    let state = coordinator_from_config(config, Arc::new(FakeScanner::new()), &node, None);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let mut statuses = Vec::new();
    for _ in 0..3 {
        let user = TestUser::new();
        let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
        let (status, body) = post(
            &app,
            "/escrow/orders",
            serde_json::json!({
                "quote_id": q["quote_id"],
                "u_pub": hex::encode(user.u_pub),
                "destination": { "rail": "venmo", "handle": "alice" },
            }),
        )
        .await;
        statuses.push((status, body));
    }

    assert_eq!(statuses[0].0, StatusCode::OK);
    assert_eq!(statuses[1].0, StatusCode::OK);
    assert_eq!(statuses[2].0, StatusCode::BAD_REQUEST, "{:?}", statuses[2].1);
    assert!(statuses[2].1["error"]
        .as_str()
        .unwrap()
        .contains("already several escrows open"));
    assert_eq!(state.store.open_count(), 2);
}
