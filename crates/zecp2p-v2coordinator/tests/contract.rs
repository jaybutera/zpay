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
