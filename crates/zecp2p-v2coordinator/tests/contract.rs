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
    // `rate_usd_per_zec` is nullable now, and `Value::get` returns Some(Null)
    // for a null - so the presence loop above passes even with no price. The
    // page must never render a null as a number, so the contract is that when
    // a rate is present it is a positive number.
    let rate = &body["rate_usd_per_zec"];
    assert!(
        rate.is_null() || rate.as_f64().is_some_and(|r| r > 0.0),
        "rate_usd_per_zec must be null or a positive number, got {rate}"
    );
    // This harness pins a rate, so it must be the pinned one rather than null.
    assert_eq!(rate.as_f64(), Some(40.25));
    assert!(body.get("spread_bps").is_some(), "capabilities is missing spread_bps");

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
async fn a_dollar_quote_pays_the_payee_what_was_typed_and_adds_the_fees_on_top() {
    // The promise the page makes: type $2 and $2.00 lands in their Venmo. The
    // fees are added to the ZEC the sender is asked for, never taken out of
    // what the payee receives. `net_cents` is the number the rail is told to
    // send, so it is the one that must equal what was typed.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let (status, q) = get(&app, "/escrow/quote?amount=2&unit=usd").await;
    assert_eq!(status, StatusCode::OK, "{q}");

    assert_eq!(q["net_cents"], 200, "the payee receives exactly the typed amount");
    assert_eq!(q["usd_amount_6dec"], 2_000_000);
    assert!(
        q["gross_cents"].as_u64().unwrap() > 200,
        "the sender pays more than the payee receives: {q}"
    );

    // The escrow really does hold the payout plus both fees.
    let amount = q["amount_zat"].as_u64().unwrap();
    let fee = q["platform_fee_zat"].as_u64().unwrap();
    let miner = q["miner_fee_zat"].as_u64().unwrap();
    // At the harness's pinned $40.25/ZEC, $2.00 is 4,968,944 zat.
    let payout = ((2.0f64 / 40.25) * 1e8).round() as u64;
    assert_eq!(
        amount - fee - miner,
        payout,
        "the escrow does not leave the payee the typed amount"
    );
}

#[tokio::test]
async fn a_zec_quote_still_prices_what_leaves_the_wallet() {
    // The other unit is unchanged. A sender who types ZEC is choosing against
    // a balance, so that figure is the escrow and the fees come out of it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state);

    let (status, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    assert_eq!(status, StatusCode::OK, "{q}");
    assert_eq!(q["amount_zat"], 5_000_000, "the escrow is what was typed");
    assert!(
        q["net_cents"].as_u64().unwrap() < q["gross_cents"].as_u64().unwrap(),
        "the fees come out of a ZEC-denominated send"
    );
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
async fn an_order_from_a_dollar_quote_escrows_the_grossed_up_amount() {
    // The gross-up has to survive into the order, because the escrow address
    // commits to the amount and the release is built from it. An order that
    // escrowed the un-grossed figure would pay the payee short, and the
    // address the page derived would not match.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let state = coordinator_with_node(dir.path(), Arc::new(FakeScanner::new()), &node);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=2&unit=usd").await;
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
    assert_eq!(
        esc["amount_zat"], q["amount_zat"],
        "the order escrows what the quote priced"
    );
    assert_eq!(order["quote"]["net_cents"], 200, "the payee still gets $2.00");
    assert_eq!(esc["usd_amount_6dec"], 2_000_000);

    // And the address the page will derive is the one for the grossed-up
    // amount, so the ZIP-321 link asks for the right ZEC.
    let derived = zecp2p_escrow::funding::escrow_address(
        &user.u_pub,
        &state.l_pub,
        esc["refund_height"].as_u64().unwrap(),
        q["amount_zat"].as_u64().unwrap(),
        zecp2p_escrow::funding::AddressNetwork::Test,
    )
    .unwrap();
    assert_eq!(esc["address"].as_str().unwrap(), derived.address);
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
        note: None,
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
    locked_order_for(app, state, node, scanner, attestor, user, "0.05").await
}

/// The same, at a chosen amount.
///
/// Two orders to one handle for the same amount are refused at creation, since
/// two identical feed entries cannot be told apart. A test that wants two
/// orders in flight together gives them different amounts, which is what a real
/// pair of users would almost always have.
#[allow(clippy::too_many_arguments)]
async fn locked_order_for(
    app: &axum::Router,
    state: &Arc<AppState>,
    node: &FakeNode,
    scanner: &Arc<FakeScanner>,
    attestor: &TestAttestor,
    user: &TestUser,
    amount: &str,
) -> (String, [u8; 32]) {
    let (_, q) = get(app, &format!("/escrow/quote?amount={amount}&unit=zec")).await;
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
    {
        let reserved = zecp2p_v2coordinator::slot::take(
            &state.journal,
            &work,
            700_000,
            "alice",
        )
        .unwrap()
        .expect("the slot is free");
        zecp2p_v2coordinator::slot::claim(
            &state.journal,
            reserved,
            alloy::primitives::B256::repeat_byte(0x11),
            1_700_000_000_000,
        )
        .unwrap()
        .expect("the claim succeeds");
    }
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
    {
        let reserved = zecp2p_v2coordinator::slot::take(
            &state.journal,
            &work_a,
            700_000,
            "alice",
        )
        .unwrap()
        .expect("the slot is free");
        zecp2p_v2coordinator::slot::claim(
            &state.journal,
            reserved,
            alloy::primitives::B256::repeat_byte(0xaa),
            1_700_000_000_000,
        )
        .unwrap()
        .expect("the claim succeeds");
    }

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
async fn two_orders_advancing_together_never_overlap_a_payment() {
    // R2-1, the reviewer's reproduction. The slot check was a journal *read*
    // with two `await` points before the matching write, and the per-order lock
    // serialises an order only with itself - so two orders advancing
    // concurrently both read an empty journal, both passed, both wrote
    // `Paying`, and both paid. The reviewer measured payments=2, overlap=2.
    //
    // The rail here is slow inside `preflight` and inside `pay`, which is what
    // makes the window certain rather than lucky, and it records the maximum
    // number of payments in flight at once. That number is the invariant: one
    // Venmo balance, and two identical entries in the feed that
    // `locate_payment` cannot tell apart.
    //
    // Note for anyone verifying this test by reverting a fix: there are now
    // **two** independent defences, and removing either one alone leaves this
    // passing. The global mutex serialises within the process, and the `Seen`
    // reservation written before any network call (R3-3) makes the journal
    // check catch the second order. Both have to be disabled to reproduce the
    // original overlap of two. That is belt and braces on purpose - the mutex
    // does nothing across daemons and the journal has no file lock - but it
    // does mean a single-revert check of this test reads as vacuous when it is
    // not.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    // The rail starts closed, so `presign`'s own settlement task cannot pay
    // either order while the other is still being set up. Without this the
    // first order is already `released` by the time the second exists, and
    // there is nothing left to race - which is how the earlier version of this
    // test passed against the broken code.
    let fiat = Arc::new(SlowFiat::closed(150));
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Two orders, both locked, neither paid.
    // Different amounts. Two orders to one handle for the same amount are
    // refused at creation, because two identical feed entries cannot be told
    // apart; the race these tests exercise is between two orders in flight,
    // which is what a real pair of users looks like.
    let user_a = TestUser::new();
    let (order_a, _) =
        locked_order_for(&app, &state, &node, &scanner, &attestor, &user_a, "0.05").await;
    let user_b = TestUser::new();
    let (order_b, _) =
        locked_order_for(&app, &state, &node, &scanner, &attestor, &user_b, "0.06").await;

    // And the sweep, which now spawns each order on its own task, arriving on
    // both at the same moment.
    for id in [&order_a, &order_b] {
        assert_eq!(
            state.store.get(id).unwrap().stage,
            Stage::Locked,
            "both orders must be waiting to be paid before the race starts"
        );
    }

    // Now both become payable at once, and the sweep arrives on both.
    fiat.open_for_business();
    let (sa, sb) = (state.clone(), state.clone());
    let (ia, ib) = (order_a.clone(), order_b.clone());
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { zecp2p_v2coordinator::driver::advance(&sa, &ia).await }),
        tokio::spawn(async move { zecp2p_v2coordinator::driver::advance(&sb, &ib).await }),
    );
    let _ = (ra, rb);

    // Let anything still in flight finish.
    for _ in 0..60 {
        if !state.payment_in_progress() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        fiat.max_overlap() <= 1,
        "two payments were in flight at once (overlap {}), which is the bug the reviewer \
         reproduced",
        fiat.max_overlap()
    );
    assert!(
        fiat.payments() <= 1,
        "{} payments left for two orders sharing one Venmo balance",
        fiat.payments()
    );

    // Exactly one order got the slot; the other is untouched and will be paid
    // on a later sweep.
    let with_payment = [&order_a, &order_b]
        .iter()
        .filter(|id| state.store.get(id).unwrap().payment.is_some())
        .count();
    assert!(
        with_payment <= 1,
        "{with_payment} orders recorded a payment"
    );
}

#[tokio::test]
async fn a_needs_operator_line_keeps_holding_the_slot() {
    // R2-2. When `fiat::pay` failed, `settle` overwrote the `Paying` line with
    // `NeedsOperator` - the state whose entire meaning is "a payment may have
    // left and a human must look" - and the slot check blocked only on `Paying`
    // and `Paid`. So the failure that most needs the slot held was the one that
    // freed it, and the next order for the same handle paid into a feed with an
    // unreconciled entry in it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Another work item failed mid-payment and is waiting for a human.
    let stranded = zecp2p_v2coordinator::slot::work_id_for(&[0xf1u8; 32], 0);
    let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
        stranded.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    record.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
    record.note = Some("the Venmo leg failed".into());
    state.journal.append_unchecked(&record).unwrap();

    let user = TestUser::new();
    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let paid_before = fiat.payments();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("waiting for the slot is not an error");

    assert_eq!(
        fiat.payments(),
        paid_before,
        "an order paid while a stranded payment was still unreconciled"
    );
    // And this order is not failed: it waits for the operator, then pays.
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Locked);
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

    // Different amounts. Two orders to one handle for the same amount are
    // refused at creation, because two identical feed entries cannot be told
    // apart; the race these tests exercise is between two orders in flight,
    // which is what a real pair of users looks like.
    let user_a = TestUser::new();
    let (order_a, _) =
        locked_order_for(&app, &state, &node, &scanner, &attestor, &user_a, "0.05").await;
    let user_b = TestUser::new();
    let (order_b, _) =
        locked_order_for(&app, &state, &node, &scanner, &attestor, &user_b, "0.06").await;

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
async fn confirmations_keep_rising_after_the_scan_cursor_passes_the_funding_block() {
    // The mainnet freeze, as a test. Order esc_1f2809bcb726cd630ff7932c was
    // funded at block 3,472,533 with 214,140 zat and then sat at "2 of 10"
    // while the chain ran 15 blocks past it, because:
    //
    //   - the scan resumes after `scanned_through`, so once the cursor passed
    //     the funding block every later sweep searched only newer blocks;
    //   - `choose_funding` therefore found nothing;
    //   - and `watch_funding` returned on that empty result BEFORE re-reading
    //     the outpoint, so `confirmations` could never be written again.
    //
    // An escrow deep enough to settle stayed `confirming` forever. `forget()`
    // is that exactly: the output is still on chain and still in the node, the
    // scan simply no longer looks at the block holding it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
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
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    // Seen, but not yet in a block: recorded, and below `ANNOUNCE_DEPTH`.
    let funding_txid = [0x5au8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 0)
        .await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("the first sighting is not an error");

    let seen = state.store.get(&order_id).unwrap();
    assert_eq!(seen.stage, Stage::Confirming, "not in a block yet");
    let funding = seen.funding.expect("the outpoint is recorded on first sighting");
    assert_eq!(funding.confirmations, 0);
    assert_eq!(funding.txid, funding_txid);

    // The cursor moves past the funding block: the scan stops reporting it,
    // while the chain keeps burying it.
    scanner.forget();
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a funded order advances from its own outpoint");

    let after = state.store.get(&order_id).unwrap();
    let funding = after.funding.expect("the outpoint does not go away");
    assert_eq!(
        funding.confirmations, 30,
        "confirmations froze at {} - the sweep is still depending on the scan \
         re-finding an output it will never look for again",
        funding.confirmations
    );
    assert_ne!(
        after.stage,
        Stage::Confirming,
        "an escrow 30 deep with 10 required must leave `confirming`"
    );
}

#[tokio::test]
async fn an_escrow_is_signable_one_block_after_funding_not_ten() {
    // The window a key-holding page has to survive.
    //
    // The announcement used to wait for `required_depth` - ten blocks, about
    // thirteen minutes. The page signs by itself but only while it is open, so
    // that was thirteen minutes in which a closed tab meant nobody could ever
    // sign and the escrow could only refund at T. One real order died that way.
    //
    // Announcing at one confirmation is safe because it is a different question
    // from when to pay: the depth guards a reorg double-spend of the funding,
    // and `lp::evaluate` re-checks it at payment time regardless of this.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
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
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    // Exactly one confirmation: in a block, nowhere near the pay depth of ten.
    let funding_txid = [0x11u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 1)
        .await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("one confirmation is enough to announce");

    let after = state.store.get(&order_id).unwrap();
    assert_eq!(
        after.stage,
        Stage::NeedsPresignature,
        "the escrow was funded and in a block, and the page still could not sign"
    );
    assert!(
        after.announcement.is_some(),
        "there is nothing to sign against without an announcement"
    );
    // And the depth it will be paid at is still the real one.
    assert_eq!(after.funding.unwrap().required, 10);
}

#[tokio::test]
async fn signing_early_does_not_let_the_lp_pay_early() {
    // The other half of the trade-off, and the one that would cost money if it
    // were wrong. Announcing at one confirmation must not move the payment
    // gate: `lp::evaluate` re-reads the outpoint and refuses below
    // `required_depth`, so a signature collected at one block buys nothing
    // until the escrow is ten deep.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
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
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    let funding_txid = [0x12u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 1)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("announcing at one confirmation");

    // The user signs immediately, as the page now can.
    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "needs_presignature", "{view}");
    let announced = view["announcement"].clone();
    let stored = state.store.get(&order_id).unwrap();
    let pre_sig = user.pre_sign(&stored, &attestor, &announced);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": announced["terms_hash"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Signed and locked at one confirmation - and still not paid.
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    assert_eq!(
        fiat.payments(),
        0,
        "the LP paid an escrow one block deep because the signature arrived early"
    );
}

#[tokio::test]
async fn a_funded_order_whose_output_vanishes_still_becomes_refundable() {
    // The refund guarantee, on the funded path.
    //
    // Splitting `watch_funding` so a funded order reads its own outpoint moved
    // every funded order off the scan path - and the scan path was where the
    // deadline check lived when nothing was found. Without the check on this
    // side, a reorg that unwound the funding left the order reading
    // "confirming" forever, while the CLTV had made the user's ZEC spendable
    // hours earlier and `refund` asks the stage, not the chain.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
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
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    // Funded and recorded, one confirmation deep.
    let funding_txid = [0x7bu8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 1)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("the first sighting is not an error");
    assert!(state.store.get(&order_id).unwrap().funding.is_some());

    // The funding is unwound, the scan no longer reports it, and the chain
    // runs past T.
    node.remove_utxo(funding_txid, 0).await;
    scanner.forget();
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a vanished output is not an error");

    assert_eq!(
        state.store.get(&order_id).unwrap().stage,
        Stage::Refundable,
        "the user was never offered the refund their ZEC was already entitled to"
    );
}

#[tokio::test]
async fn a_funding_that_never_reaches_depth_still_becomes_refundable() {
    // Same guarantee, the other way in: an output that stays too shallow to
    // settle - a stuck low-fee transaction, or a node that under-reports -
    // must not count confirmations past T forever.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
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
    let order_id = order["order_id"].as_str().unwrap().to_string();
    let amount_zat = order["escrow"]["amount_zat"].as_u64().unwrap();
    let stored = state.store.get(&order_id).unwrap();

    let funding_txid = [0x7cu8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    // Seen but not yet in a block, and it never gets there: below
    // `ANNOUNCE_DEPTH`, so there is nothing to sign against either.
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 0)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("the first sighting is not an error");
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Confirming);

    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a shallow funding is not an error");

    assert_eq!(
        state.store.get(&order_id).unwrap().stage,
        Stage::Refundable,
        "an escrow that never confirmed deep enough counted confirmations past T forever"
    );
}

#[tokio::test]
async fn a_mempool_sighting_is_enough_to_announce_and_sign() {
    // The user's page signs by itself but only while it is open, and the
    // outpoint the release digest commits to exists as soon as the funding
    // transaction is broadcast - seconds after they press send. Waiting for a
    // block meant waiting up to 150 s for something knowable in five.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x21u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a mempool sighting is not an error");

    let after = state.store.get(&order_id).unwrap();
    assert_eq!(after.stage, Stage::NeedsPresignature);
    assert!(after.announcement.is_some());
    assert_eq!(after.mempool_announced_txid, Some(funding_txid));
    assert!(after.funding.is_none(), "a mempool sighting must not count as funding");
}

#[tokio::test]
async fn re_entering_the_scan_does_not_resurrect_a_finished_order() {
    // The re-entry block puts back the stage an order had before it was sent
    // through `find_funding`. That restore must not fire over a stage the
    // deadline check chose: `find_funding` can end in `check_deadlines`, and
    // `check_deadlines` writes `Refundable` past T and `Unpaid` past the pay
    // deadline. `Unpaid` is terminal - `is_open` excludes it - so writing
    // `Locked` back over it makes an abandoned order live again, and writing
    // `Locked` over `Refundable` withholds a refund the chain already permits
    // and the page decides by stage.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    // Announced from the mempool and signed, so the order is `Locked` with no
    // funding outpoint - the exact state the re-entry block acts on.
    let funding_txid = [0x61u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Locked);

    // The transaction confirms only after the chain has run past T - a slow
    // miner, a stuck fee, a restart after an outage. This is the population the
    // mempool announcement exists to serve, not an adversarial case.
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;

    // ONE sweep: the one in which the re-entry block runs and restores.
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    let after_one = state.store.get(&order_id).unwrap();
    assert!(
        !matches!(after_one.stage, Stage::Locked) || after_one.funding.is_none(),
        "the restore wrote `Locked` over a stage the deadline check chose; for a whole \
         sweep the page shows locked and refuses the refund the chain already permits"
    );

    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }

    let end = state.store.get(&order_id).unwrap();
    assert!(
        matches!(end.stage, Stage::Refundable | Stage::Unpaid),
        "past T the order reads {:?}; the user is owed a refund and the page asks the stage",
        end.stage
    );
}

#[tokio::test]
async fn re_entering_the_scan_does_not_undo_a_signed_order() {
    // The re-entry block sends a `Locked` order back through `find_funding` to
    // learn its outpoint, and `find_funding` ends at `NeedsPresignature` as if
    // the order were newly funded. The stage is put back afterwards - this
    // asserts that restoration keeps a signed order signed rather than
    // dropping it a stage and asking the user's page, which may be long gone,
    // to sign again.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x51u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;
    let signed = state.store.get(&order_id).unwrap();
    assert_eq!(signed.stage, Stage::Locked);
    let sig_before = signed.pre_signature.clone().expect("signed");

    // The same transaction confirms, and the order re-enters the scan.
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }

    let after = state.store.get(&order_id).unwrap();
    assert!(after.funding.is_some(), "it never learned the outpoint");
    assert_eq!(
        after.stage,
        Stage::Locked,
        "a signed order was dropped back a stage; the page may be gone and cannot re-sign"
    );
    assert_eq!(
        after.pre_signature.as_deref(),
        Some(sig_before.as_str()),
        "the stored pre-signature changed"
    );
    // And the announcement is the same one the signature is encrypted under.
    assert_eq!(
        after.announcement.as_ref().map(|a| a.r.clone()),
        signed.announcement.as_ref().map(|a| a.r.clone()),
        "R was redrawn, orphaning the signature"
    );
}

#[tokio::test]
async fn a_mempool_announced_order_shows_the_page_an_outpoint_to_sign_over() {
    // The page rebuilds the release digest itself rather than trusting the
    // coordinator for it, and the digest commits the outpoint - so `presign`
    // in `app.js` refuses outright when `view.funding` is absent ("the
    // announcement has not arrived yet").
    //
    // Announcing from the mempool leaves `order.funding` unset by design, so
    // without this the page reached `needs_presignature` and could never sign:
    // an order that announces and is unsignable, which is worse than the delay
    // it was meant to remove. Found on regtest, not by a unit test.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x41u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let (_, view) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "needs_presignature");
    let funding = &view["funding"];
    assert!(
        !funding.is_null(),
        "the page has nothing to build the release digest over, so it cannot sign"
    );
    assert_eq!(
        funding["txid"].as_str().unwrap(),
        zecp2p_escrow::rpc::txid_to_display(&funding_txid),
        "the view must name the outpoint the announcement was drawn against"
    );
    // Unconfirmed, and honest about it.
    assert_eq!(funding["confirmations"].as_u64(), Some(0));
}

#[tokio::test]
async fn a_mempool_announced_order_still_completes_when_the_tx_confirms() {
    // The happy path, all the way through. Its absence is what let a total
    // deadlock pass: every other mempool test stops at or before `Locked`, and
    // the bug only shows once the transaction confirms. `watch_funding` is the
    // only writer of `order.funding`, so an order announced from the mempool
    // must still be able to reach it, or `settle` bails on the missing outpoint
    // every sweep and the escrow sits locked forever.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x31u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // The SAME transaction confirms. Nothing replaced, nothing hostile.
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    for _ in 0..4 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }

    let end = state.store.get(&order_id).unwrap();
    assert!(
        end.funding.is_some(),
        "the order never learned its funding after the tx confirmed; stuck at {:?}",
        end.stage
    );
    assert_eq!(end.funding.unwrap().txid, funding_txid);
}

#[tokio::test]
async fn a_mempool_announced_order_that_never_confirms_leaves_locked() {
    // The other half of the deadlock. `settle` bailing with `?` on a missing
    // outpoint skips the deadline check, so the order never left `Locked` and
    // the page - which asks the stage, not the chain - showed "locked" for ever
    // over a trade that was over.
    //
    // It used to end at `Refundable`, and R5-2 ruled that wrong: the sighted
    // transaction expired unmined and no wallet resent it, so nothing ever
    // reached the address. `Refundable` is the stage that puts the refund form
    // in front of the user, and there is no coin behind it. `Unpaid` is what
    // the chain supports - nobody sent the dollars, and nobody sent the ZEC
    // either - and it takes the order off the sweep list the way R4-2 wants.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x32u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // It never confirms, and the chain runs past T.
    //
    // The mempool sighting is also gone - evicted, as a transaction that never
    // confirms eventually is. So the re-entry path finds nothing and the order
    // reaches `settle` with no outpoint, which is the branch that used to bail
    // with `?` and skip the deadline check entirely.
    scanner.forget();
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }

    let end = state.store.get(&order_id).unwrap();
    assert_ne!(
        end.stage,
        Stage::Locked,
        "the order deadlocked at locked and the page would say so for ever"
    );
    assert_eq!(
        end.stage,
        Stage::Unpaid,
        "nothing ever reached the escrow, so there is no refund to offer"
    );
}

#[tokio::test]
async fn a_mempool_announced_order_pays_once_and_releases_the_sighted_outpoint() {
    // Pre-mainnet condition 1 from the round-6 audit, and the only test that
    // takes a mempool-announced order past the pay gate. Every other
    // `pay_mempool` test either uses a rail that cannot pay or asserts that
    // nothing paid, and the full paid-path test funds through a block - so the
    // whole second half of this branch's flow was uncovered.
    //
    // The seam it guards is the one the lock time opened: `lock_confirmed_ms`
    // is now stamped at the sighting rather than at depth, and it is committed
    // by `terms_hash`. If either moved when the transaction confirmed, the
    // release would be built from terms the page never signed and the
    // pre-signature would not decrypt onto it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    // Broadcast and sighted in the mempool, in no block.
    let funding_txid = [0x71u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    // The page signs while it is still unconfirmed - the whole point of the
    // mempool announcement.
    sign_it(&app, &state, &attestor, &user, &order_id).await;
    let signed = state.store.get(&order_id).unwrap();
    assert_eq!(signed.stage, Stage::Locked);
    assert!(signed.funding.is_none(), "nothing is in a block yet");
    let stamped_lock_ms = signed.lock_confirmed_ms.expect("stamped at the sighting");
    let signed_terms_hash = signed
        .announcement
        .as_ref()
        .expect("announced")
        .terms_hash
        .clone();

    // Nothing may pay while it is unconfirmed.
    for _ in 0..2 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    assert_eq!(fiat.payments(), 0, "it paid for an escrow that is in no block");

    // The same transaction confirms, deep.
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;

    for _ in 0..60 {
        if state.store.get(&order_id).unwrap().stage == Stage::Released {
            break;
        }
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(end.stage, Stage::Released, "it never released");
    assert_eq!(fiat.payments(), 1, "the dollars went {} times", fiat.payments());
    assert_eq!(node.broadcasts().await.len(), 1, "more than one release went out");

    // The release spends the outpoint that was sighted in the mempool, which is
    // the one the page signed over.
    let funding = end.funding.expect("recorded once it confirmed");
    assert_eq!(funding.txid, funding_txid, "it released a different outpoint");
    assert_eq!(funding.vout, 0);

    // And the two values `terms_hash` commits to did not move underneath the
    // signature when the transaction confirmed.
    assert_eq!(
        end.lock_confirmed_ms,
        Some(stamped_lock_ms),
        "the lock time was restamped after the page signed"
    );
    assert_eq!(
        end.announcement.as_ref().map(|a| a.terms_hash.clone()),
        Some(signed_terms_hash),
        "the terms hash moved after the page signed"
    );

    // A refund after the dollars have gone is refused - the LP holds the
    // release and the loss on a race would be its own.
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": "00".repeat(120) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("already been sent")
            || body.to_string().contains("may already have been sent"),
        "expected a refusal naming the payment: {body}"
    );
}

/// Opens an order for a named handle at a USD amount.
async fn open_for_usd(
    app: &axum::Router,
    user: &TestUser,
    handle: &str,
    amount: &str,
) -> (StatusCode, serde_json::Value) {
    let (_, q) = get(app, &format!("/escrow/quote?amount={amount}&unit=usd")).await;
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

/// Opens an order for a named handle at the quoted ZEC amount, returning the
/// HTTP status and body so a test can assert on a refusal.
async fn open_for(
    app: &axum::Router,
    user: &TestUser,
    handle: &str,
    amount: &str,
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

#[tokio::test]
async fn two_usd_orders_for_the_same_dollars_are_refused_across_a_rate_move() {
    // The guard has to key on what the Venmo feed matches on.
    //
    // `locate_payment` searches the feed for a payment of a dollar amount to a
    // handle. Two USD-mode orders for the same dollar figure, quoted either
    // side of a rate move, carry different `amount_zat` and identical
    // `net_cents` - so a guard keyed on zatoshis lets through exactly the pair
    // it exists to refuse, and the second order's payment finds two matching
    // entries, errors, and leaves the global slot held with money out.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (first, body_a) = open_for_usd(&app, &user, "alice", "2").await;
    assert_eq!(first, StatusCode::OK, "{body_a}");
    let first_id = body_a["order_id"].as_str().unwrap().to_string();

    let (second, body_b) = open_for_usd(&app, &user, "alice", "2").await;
    assert_eq!(
        second,
        StatusCode::BAD_REQUEST,
        "a second order for the same dollars was accepted: {body_b}"
    );

    // The harness pins a rate, so those two also share `amount_zat` and a
    // zatoshi key would have caught them. This is the case it would not: the
    // same dollars at a moved rate. Built on the store directly, because the
    // rate cannot be moved between two quotes through the HTTP surface.
    let mut moved = state.store.get(&first_id).unwrap();
    moved.order_id = "esc_rate_moved_since_the_first".into();
    moved.quote.quote_id = "q_rate_moved".into();
    moved.quote.amount_zat += 289; // what a 0.15% rate move does to $2 of ZEC
    assert_ne!(
        moved.quote.amount_zat,
        state.store.get(&first_id).unwrap().quote.amount_zat,
        "the two orders must differ in zatoshis for this to test anything"
    );
    assert_eq!(
        moved.quote.net_cents,
        state.store.get(&first_id).unwrap().quote.net_cents,
        "and agree in cents, which is what the feed matches on"
    );
    assert!(
        !state.store.put_unless_in_flight(&moved).unwrap(),
        "the same dollars at a different rate were accepted, so the feed gets two \
         identical entries and locate_payment cannot attribute either"
    );
}

#[tokio::test]
async fn two_orders_inserted_together_do_not_both_win() {
    // A check followed by an insert is not a guard: two requests that both read
    // an empty store both pass and both write, and the sweep then has two
    // escrows to one handle for one cent figure - the pair `locate_payment`
    // cannot attribute.
    //
    // The store must therefore start EMPTY of anything matching. An earlier
    // version of this test seeded a matching in-flight order first, so both
    // candidates were refused by that one whatever the lock did, and it passed
    // against a check-then-insert. Here the only thing that can refuse the
    // second candidate is the first candidate, which is the property at issue.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    // One order, only to borrow a well-formed shape - then moved to
    // `Refundable`, which the guard ignores by design, so nothing that can
    // refuse either candidate is in the store when the race starts.
    let (status, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let template = state.store.get(body["order_id"].as_str().unwrap()).unwrap();
    let mut parked = template.clone();
    parked.stage = Stage::Refundable;
    state.store.put(&parked).unwrap();
    assert!(
        state.store.open_orders().iter().all(|o| o.stage == Stage::Refundable),
        "nothing that can refuse a candidate may be in the store when the race starts"
    );

    // Both candidates wait on one barrier and are released together, so they
    // are inside the decision at the same moment rather than one after another.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..2u8 {
        let state = state.clone();
        let barrier = barrier.clone();
        let mut candidate = template.clone();
        candidate.order_id = format!("esc_concurrent_{n}");
        tasks.spawn(async move {
            barrier.wait().await;
            tokio::task::spawn_blocking(move || state.store.put_unless_in_flight(&candidate))
                .await
                .unwrap()
                .unwrap()
        });
    }
    let mut accepted = 0;
    while let Some(r) = tasks.join_next().await {
        if r.unwrap() {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, 1,
        "expected exactly one of two simultaneous creations to win, got {accepted}"
    );
    let racers = state
        .store
        .all()
        .into_iter()
        .filter(|o| o.order_id.starts_with("esc_concurrent_"))
        .count();
    assert_eq!(
        racers, 1,
        "{racers} escrows to one handle for one cent figure are in the store"
    );
}

#[tokio::test]
async fn every_order_carries_a_tag_the_feed_can_be_matched_on() {
    // The tag is what tells two payments of the same amount to one handle
    // apart in the feed. It has to reach the leg the rail pays from, it has to
    // differ per order - a tag two orders share discriminates nothing - and it
    // must not print any of the order id, which is the bearer credential for
    // this order's own endpoint and its refund.
    //
    // It does not replace the duplicate refusal. That guard is untouched and
    // still refuses a second order for one handle and one cent figure, so two
    // such orders cannot coexist to be told apart. The tag is what makes the
    // feed unambiguous once the guard is relaxed, and until the live run proves
    // Venmo echoes the note it stays a second line rather than the first.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let mut tags = Vec::new();
    for amount in ["0.05", "0.06", "0.07"] {
        let user = TestUser::new();
        let (id, _, order) = opened_order_for(&app, &state, &user, amount).await;
        let tag = order.payment_tag();
        assert_eq!(tag.len(), 8, "a tag goes in a field a person reads: {tag:?}");
        assert!(
            tag.chars().all(|c| c.is_ascii_hexdigit()),
            "the note round-trips through Venmo, so the tag stays ASCII: {tag:?}"
        );
        assert!(
            !id.contains(&tag),
            "the tag prints part of the order id into a note Venmo shows the \
             payee, and that id is what reads and refunds this order: {tag} in {id}"
        );
        // An unpaid order is matched on the tag it is about to be paid with.
        assert_eq!(order.tag_to_match(), Some(tag.clone()));
        tags.push(tag);
    }

    tags.sort();
    tags.dedup();
    assert_eq!(tags.len(), 3, "two orders shared a tag, which discriminates nothing");
}

#[tokio::test]
async fn a_paid_order_records_the_note_the_rail_typed() {
    // What the feed search looks for has to be what was actually typed, not
    // what the code doing the searching would type now. The attestation runs on
    // a later sweep and can run under a later binary, so the note goes on the
    // order when the payment is made.
    //
    // Without this, an order paid by a build that wrote a bare configured note
    // and attested after a deploy of a build that appends a tag is searched for
    // under a tag its entry does not carry. `locate_payment` finds nothing,
    // refuses, and the driver retries it every sweep with the dollars gone and
    // the one payment slot held.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x73u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    for _ in 0..60 {
        let stage = state.store.get(&order_id).unwrap().stage;
        if matches!(stage, Stage::Paid | Stage::Released) {
            break;
        }
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    let paid = state.store.get(&order_id).unwrap();
    assert_eq!(fiat.payments(), 1, "the dollars went {} times", fiat.payments());
    let payment = paid.payment.as_ref().expect("a paid order records its payment");
    let note = payment
        .note
        .as_deref()
        .expect("the rail reported what it typed, and the order kept it");
    let tag = paid.payment_tag();
    assert!(
        note.contains(&tag),
        "the note that went out does not carry this order's tag: {note:?} vs {tag}"
    );
    // And that is what the feed will be searched for.
    assert_eq!(paid.tag_to_match(), Some(tag));

    // The same order, paid the way the pre-tag build paid it. The recorded note
    // decides, so it is searched for on amount and receiver - the terms it was
    // actually sent under - rather than under a tag that is not in the feed.
    let mut paid_before_the_deploy = paid.clone();
    paid_before_the_deploy.payment.as_mut().unwrap().note = Some("thanks".into());
    assert_eq!(
        paid_before_the_deploy.tag_to_match(),
        None,
        "an order paid before tags existed would be searched for under one, and \
         every sweep would refuse with the dollars already gone"
    );
}

#[tokio::test]
async fn a_second_order_for_the_same_handle_and_amount_is_refused() {
    // Pre-mainnet condition 3 from the round-6 audit, answered by policy rather
    // than by measuring it with real money.
    //
    // Two escrows to the same Venmo account for the same number of cents are
    // the one case `locate_payment` cannot resolve: two identical feed entries
    // are indistinguishable, so it refuses - and that refusal lands after the
    // dollars have gone. Announcing from a mempool sighting widened the window
    // it can happen in, because the feed cut moved from ten confirmations to
    // the sighting.
    //
    // Refused at the door it costs a wait. Refused later it costs an operator
    // reading the feed by hand with a payment already out.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (first, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(first, StatusCode::OK, "{body}");

    let (second, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(
        second,
        StatusCode::BAD_REQUEST,
        "a second identical order was accepted, so two indistinguishable payments \
         can be put in the feed: {body}"
    );
    let text = body.to_string();
    assert!(
        text.contains("already have an escrow open") && text.contains("different amount"),
        "the refusal has to tell the user what to do about it: {body}"
    );
}

#[tokio::test]
async fn the_duplicate_guard_lets_through_everything_that_is_not_ambiguous() {
    // The guard must be narrow. Blocking more than the ambiguous case would
    // lock a user out of their own handle, and there is no cost to the
    // coordinator in any of these: `locate_payment` can tell them apart.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (status, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Same handle, a different amount: two feed entries that differ.
    let (status, body) = open_for(&app, &user, "alice", "0.06").await;
    assert_eq!(status, StatusCode::OK, "a different amount is not ambiguous: {body}");

    // Same amount, a different handle: two feed entries to different people.
    let (status, body) = open_for(&app, &user, "bob", "0.05").await;
    assert_eq!(status, StatusCode::OK, "a different handle is not ambiguous: {body}");
}

#[tokio::test]
async fn a_refundable_order_does_not_block_the_same_handle_and_amount() {
    // A `Refundable` escrow will never be paid - it needs nothing further from
    // this coordinator and the user resolves it from their own page - so it can
    // never collide in the feed. Counting it would lock a handle and amount out
    // for a day at no cost to whoever opened it, which is the same mistake R2-5
    // fixed for the per-handle bound.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (status, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first_id = body["order_id"].as_str().unwrap().to_string();

    // It reaches the point where the user refunds it themselves.
    let mut refundable = state.store.get(&first_id).unwrap();
    refundable.stage = Stage::Refundable;
    state.store.put(&refundable).unwrap();

    let (status, body) = open_for(&app, &user, "alice", "0.05").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a refundable escrow, which will never be paid, blocked a new order: {body}"
    );
}

#[tokio::test]
async fn a_mempool_sighting_never_pays() {
    // The invariant: announcing from the mempool collects a signature early and
    // moves not one cent. `lp::evaluate` re-reads the outpoint with
    // `include_mempool` false and re-checks the depth.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x22u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    assert_eq!(fiat.payments(), 0, "the LP paid for an escrow only in the mempool");
    assert!(state.store.get(&order_id).unwrap().funding.is_none());
}

#[tokio::test]
async fn a_mempool_announcement_is_drawn_once() {
    // A second announcement carries a fresh R - a different outcome point - and
    // the signature already made is not encrypted under it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: [0x23u8; 32], vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    let first = state.store.get(&order_id).unwrap().announcement.clone().unwrap();
    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    let again = state.store.get(&order_id).unwrap().announcement.clone().unwrap();
    assert_eq!(first.event_id, again.event_id);
    assert_eq!(first.r, again.r);
}

#[tokio::test]
async fn one_sweep_reads_the_mempool_once_however_many_orders_are_open() {
    // Audit finding 3. The mempool is the same for every order in a sweep, but
    // it was asked per order: one listing plus one verbose read per entry, each
    // time. At the open-order cap that is the same small mempool fetched two
    // hundred times a minute, and under a provider that rate-limits every one
    // of those reads waits inside a blocking task the sweep then joins.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Three unfunded orders, none of them announced.
    // Distinct amounts so the same-handle-same-amount guard does not refuse the
    // second and third; this test is about how often the mempool is listed.
    let mut ids = Vec::new();
    for amount in ["0.05", "0.06", "0.07"] {
        let user = TestUser::new();
        let (id, _, _) = opened_order_for(&app, &state, &user, amount).await;
        ids.push(id);
    }

    // Advanced CONCURRENTLY on a JoinSet, the way `run` sweeps. Driving them
    // one after another hides the bug: the first read completes and fills the
    // cache before the second order looks. Under the real sweep - and above
    // all under the throttled provider this fix is for, where a read waits up
    // to three times sixty seconds - every order arrives while the first read
    // is still in flight.
    let before = scanner.mempool_reads();
    let mut tasks = tokio::task::JoinSet::new();
    for id in ids.clone() {
        let state = state.clone();
        tasks.spawn(async move {
            zecp2p_v2coordinator::driver::advance(&state, &id).await.ok();
        });
    }
    while tasks.join_next().await.is_some() {}
    let reads = scanner.mempool_reads() - before;

    assert_eq!(
        reads, 1,
        "three orders in one sweep listed the mempool {reads} times; it is the same \
         mempool for all of them"
    );
}

#[tokio::test]
async fn a_failed_order_keeps_its_reason_on_the_way_to_refundable() {
    // R3-2. `check_deadlines` has a second clause that writes `Unpaid` over any
    // stage past the pay deadline that has not seen fiat, and `Failed`
    // satisfies it. A replaced-funding failure lands about a day short of T, so
    // every one of them would be rewritten on its first sweep - and the page's
    // `unpaid` screen shows no reason at all, so the user who was told their
    // funding was replaced would next read "nobody sent the dollars in time".
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x93u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    let mut failed = state.store.get(&order_id).unwrap();
    failed.fail("the funding transaction was replaced after you signed");
    state.store.put(&failed).unwrap();

    // Past the PAY deadline but short of T - the window every such failure
    // lands in.
    let pay_deadline_gap = 20u32;
    node.set_height(u32::try_from(stored.refund_height).unwrap() - pay_deadline_gap)
        .await;
    for o in state.store.open_orders() {
        zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
    }

    let mid = state.store.get(&order_id).unwrap();
    assert_eq!(mid.stage, Stage::Failed, "the failure was rewritten to {:?}", mid.stage);
    assert!(
        mid.reason.as_deref().is_some_and(|r| r.contains("replaced")),
        "the reason the user is owed was lost: {:?}",
        mid.reason
    );

    // And past T it still becomes refundable, reason intact.
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for o in state.store.open_orders() {
        zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
    }
    let end = state.store.get(&order_id).unwrap();
    assert_eq!(end.stage, Stage::Refundable);
    assert!(
        end.reason.as_deref().is_some_and(|r| r.contains("replaced")),
        "the reason did not survive the promotion: {:?}",
        end.reason
    );
}

#[tokio::test]
async fn an_order_nobody_ever_funded_is_not_offered_a_refund() {
    // R4-2. The predicate did not ask whether anything was ever at the address,
    // so an abandoned order went `Unpaid` at the pay deadline and `Refundable`
    // at T with `funding` null. The page then tells the user their ZEC "is in
    // the escrow" and shows the form; the refund builder cannot fill it and the
    // endpoint refuses. The order also stays in the sweep list for good.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, _amount_zat, stored) = opened_order(&app, &state, &user).await;

    // Never funded: no block scan hit, no mempool sighting.
    let mut abandoned = state.store.get(&order_id).unwrap();
    abandoned.stage = Stage::Unpaid;
    state.store.put(&abandoned).unwrap();
    assert!(state.store.get(&order_id).unwrap().funding.is_none());

    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        for o in state.store.open_orders() {
            zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
        }
    }

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(
        end.stage,
        Stage::Unpaid,
        "an order with an empty escrow was promoted to {:?} and handed a refund form",
        end.stage
    );
    assert!(
        !state.store.open_orders().iter().any(|o| o.order_id == order_id),
        "a never-funded order is swept for ever"
    );
}

#[tokio::test]
async fn the_view_tells_the_page_what_the_journal_says() {
    // R5-1. The page cannot decide this from `payment`: three of the four
    // failure writers that follow a journal claim leave it null while the
    // journal holds an open `Paying` line. The sweep already withholds the
    // refund promotion on the journal's answer, and the view has to carry the
    // same answer or the `failed` screen offers the form the sweep refused.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_fiat(
        dir.path(),
        scanner.clone(),
        &node,
        &attestor,
        Arc::new(PayErrorsRail),
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // Clean journal so far: nothing has been claimed for this escrow.
    let (_, before) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(
        before["fiat_may_have_left"], false,
        "nothing has been paid yet: {before}"
    );

    // The payment attempt errors after the claim.
    for _ in 0..2 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    let failed = state.store.get(&order_id).unwrap();
    assert_eq!(failed.stage, Stage::Failed);
    assert!(failed.payment.is_none(), "this writer records no payment");

    let (_, after) = get(&app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(
        after["fiat_may_have_left"], true,
        "the view does not tell the page the journal says a payment may have left, so the \
         page keys its refund form on `payment` and offers it here: {after}"
    );
    // And `payment` is still null, which is exactly why the page cannot use it.
    assert!(after["payment"].is_null());
}

#[tokio::test]
async fn a_venmo_leg_that_errored_is_not_steered_to_a_refund() {
    // R4-1. The R3-3 guard keys on `Order.payment`, and three of the driver's
    // four post-claim `Failed` writers never set it - only the release-failed
    // one does. The committed test built its order by hand with `payment` set,
    // so it exercised the single writer that worked.
    //
    // This drives the real thing: a rail that gets past preflight and then
    // errors inside `pay`. The journal claim is already written, the browser
    // may or may not have sent the dollars, and nothing downstream can tell.
    // The order needs an operator to read the feed. Promoting it to
    // `Refundable` and putting the form in front of the user takes that
    // decision away from them.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_fiat(
        dir.path(),
        scanner.clone(),
        &node,
        &attestor,
        Arc::new(PayErrorsRail),
    );
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    // A funded, signed, locked order - through the driver, not by hand.
    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let stored = state.store.get(&order_id).unwrap();

    // The payment attempt errors after the claim.
    for _ in 0..2 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    let failed = state.store.get(&order_id).unwrap();
    assert_eq!(
        failed.stage,
        Stage::Failed,
        "expected the errored pay to fail the order, got {:?}",
        failed.stage
    );
    assert!(
        failed.payment.is_none(),
        "this writer does not record a payment; the test would not prove anything if it did"
    );

    // Past T, swept the way `run` does.
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        for o in state.store.open_orders() {
            zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
        }
    }

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(
        end.stage,
        Stage::Failed,
        "an order whose journal says the dollars may have left was promoted to {:?}, \
         which is the screen that hands the user a refund form",
        end.stage
    );
}

#[tokio::test]
async fn a_failure_after_the_dollars_left_is_not_steered_to_a_refund() {
    // R3-3. `Failed` is also what the driver writes when the Venmo leg errors
    // after the journal claim, and when the payment left and the release did
    // not broadcast. There the LP has paid and holds a valid release, and on a
    // race the loss is the LP's. Promoting those to `Refundable` puts a screen
    // in front of the user telling them to take a coin the LP has bought -
    // this coordinator instructing its own counterparty to spend against it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x94u8; 32];
    scanner.pay(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
        .await;
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

    // The dollars went, and then something broke.
    let mut paid_then_failed = state.store.get(&order_id).unwrap();
    paid_then_failed.payment = Some(zecp2p_v2coordinator::order::Payment {
        sent_at: chrono::Utc::now(),
        cents: 200,
        note: None,
    });
    paid_then_failed.fail("the dollars were sent and the release did not broadcast");
    state.store.put(&paid_then_failed).unwrap();

    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        for o in state.store.open_orders() {
            zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
        }
    }

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(
        end.stage,
        Stage::Failed,
        "an order the LP already paid for was promoted to {:?}, which is the screen \
         that tells the user to spend against the LP's own release",
        end.stage
    );
    assert!(
        !state
            .store
            .open_orders()
            .iter()
            .any(|o| o.order_id == order_id),
        "a paid-then-failed order is still being swept"
    );
}

#[tokio::test]
async fn an_unpaid_or_failed_order_becomes_refundable_once_the_chain_passes_t() {
    // R2-1. Both stages are terminal - `is_open` excludes them, `open_orders`
    // filters on it, and `advance` returns before `check_deadlines`, which is
    // the only writer of `Refundable`. So an order whose LP never paid, for any
    // reason, sat on a stage the page shows no refund form for, forever.
    //
    // The refund itself carries `nLockTime = T`, so nothing is broadcastable
    // before T whatever the stage says. What has to be true is that once the
    // chain passes T these orders reach `Refundable`, which is the stage the
    // page offers the form on.
    for terminal in [Stage::Unpaid, Stage::Failed] {
        let dir = tempfile::tempdir().unwrap();
        let node = FakeNode::spawn().await;
        let scanner = Arc::new(FakeScanner::new());
        let attestor = TestAttestor::new();
        let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
        let app = zecp2p_v2coordinator::web::router(state.clone());
        let user = TestUser::new();
        let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

        // Funded and confirmed, so there is real ZEC to refund.
        let funding_txid = [0x91u8; 32];
        scanner.pay(
            &stored.script_pubkey,
            FoundOutput { txid: funding_txid, vout: 0, amount_zat },
        );
        node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30)
            .await;
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();

        // Put it in the terminal stage, as `check_deadlines` or `fail` would.
        let mut dead = state.store.get(&order_id).unwrap();
        dead.stage = terminal;
        state.store.put(&dead).unwrap();

        // The chain passes T.
        node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;

        // Swept the way `run` does - over `open_orders`, not by calling
        // `advance` on an id we already have. Calling by id is what let a
        // version of this test pass while the sweep never listed these stages
        // at all, so the fix it was written for did nothing.
        for _ in 0..3 {
            let listed = state.store.open_orders();
            assert!(
                listed.iter().any(|o| o.order_id == order_id),
                "the sweep does not list a {terminal:?} order, so nothing ever moves it"
            );
            for o in listed {
                zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
            }
        }

        assert_eq!(
            state.store.get(&order_id).unwrap().stage,
            Stage::Refundable,
            "an order left at {terminal:?} past T never reaches the stage the page \
             offers a refund on, so the user has no way back to their ZEC"
        );
    }
}

#[tokio::test]
async fn a_replaced_funding_tells_the_user_instead_of_reading_locked() {
    // Audit finding 2. Refusing to pay was already right; saying nothing was
    // not. The signature is over the replaced outpoint and can never authorise
    // the confirmed one, so the trade is dead on the first sweep after the
    // confirmation - but the order read `locked` for the whole pay window,
    // about a day, and the page decides what to offer by stage. Meanwhile every
    // sweep took the global payment lock, read the chain and appended journal
    // lines for an order that could never pay.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let tx_a = [0xa1u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: tx_a, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // A never confirms; B does. Same escrow, same amount, different txid - an
    // ordinary wallet resend after Zcash's 40-block expiry.
    let tx_b = [0xb1u8; 32];
    let mut forced = state.store.get(&order_id).unwrap();
    forced.funding = Some(zecp2p_v2coordinator::order::Funding {
        txid: tx_b,
        vout: 0,
        confirmations: 30,
        required: 10,
    });
    forced.stage = Stage::Locked;
    state.store.put(&forced).unwrap();
    node.add_utxo(tx_b, 0, stored.script_pubkey.clone(), amount_zat, 30).await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(fiat.payments(), 0, "it paid on a signature that cannot release");
    assert_eq!(
        end.stage,
        Stage::Failed,
        "the order still reads {:?}; the user waits a day for a payment that is not coming",
        end.stage
    );
    assert!(
        end.reason.as_deref().is_some_and(|r| r.contains("replaced")),
        "the page shows the reason, so it has to say what happened: {:?}",
        end.reason
    );
    // And the refund endpoint takes `Failed`, so the ZEC is recoverable now
    // rather than at T.
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": "00" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected a refusal about the transaction, not the stage: {body}"
    );
    assert!(
        !body.to_string().contains("not refundable yet"),
        "the stage still blocks the refund: {body}"
    );
}

#[tokio::test]
async fn a_replaced_funding_never_reaches_a_payment() {
    // The user broadcasts A, signs a digest over A, then replaces A with B
    // paying the same escrow the same amount. B confirms. The stored signature
    // will not decrypt onto a transaction spending B, so if the pay gate is
    // satisfied by "a pre-signature exists" rather than "one that matches these
    // terms", the LP sends real dollars for a coin it can never take.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let tx_a = [0xaau8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: tx_a, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // B confirms instead. Forced, because a `Locked` order does not re-scan.
    let tx_b = [0xbbu8; 32];
    let mut forced = state.store.get(&order_id).unwrap();
    forced.funding = Some(zecp2p_v2coordinator::order::Funding {
        txid: tx_b,
        vout: 0,
        confirmations: 30,
        required: 10,
    });
    forced.stage = Stage::Locked;
    state.store.put(&forced).unwrap();
    node.add_utxo(tx_b, 0, stored.script_pubkey.clone(), amount_zat, 30).await;

    for _ in 0..3 {
        zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    }
    assert_eq!(
        fiat.payments(),
        0,
        "the LP paid for an escrow whose release signature is over a replaced outpoint"
    );
    assert!(!state.store.get(&order_id).unwrap().stage.fiat_may_have_left());
}

/// Opens an order and returns its id, amount and stored form.
async fn opened_order(
    app: &axum::Router,
    state: &Arc<AppState>,
    user: &TestUser,
) -> (String, u64, zecp2p_v2coordinator::order::Order) {
    opened_order_for(app, state, user, "0.05").await
}

/// The same, at a chosen amount, for tests that need several orders to the one
/// handle without tripping the same-handle-same-amount guard.
async fn opened_order_for(
    app: &axum::Router,
    state: &Arc<AppState>,
    user: &TestUser,
    amount: &str,
) -> (String, u64, zecp2p_v2coordinator::order::Order) {
    let (_, q) = get(app, &format!("/escrow/quote?amount={amount}&unit=zec")).await;
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
    (order_id, amount_zat, stored)
}

/// Signs the announced terms as the page does, with no user interaction.
async fn sign_it(
    app: &axum::Router,
    state: &Arc<AppState>,
    attestor: &TestAttestor,
    user: &TestUser,
    order_id: &str,
) {
    let (_, view) = get(app, &format!("/escrow/orders/{order_id}")).await;
    assert_eq!(view["stage"], "needs_presignature", "{view}");
    let announced = view["announcement"].clone();
    let stored = state.store.get(order_id).unwrap();
    let pre_sig = user.pre_sign(&stored, attestor, &announced);
    let (status, body) = post(
        app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": announced["terms_hash"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
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
    // Distinct amounts, so this exercises the per-handle bound rather than
    // tripping the same-handle-same-amount guard first. That guard refuses a
    // second order for an amount already in flight; this test is about the
    // count, not the collision.
    for amount in ["0.05", "0.06", "0.07"] {
        let user = TestUser::new();
        let (_, q) = get(&app, &format!("/escrow/quote?amount={amount}&unit=zec")).await;
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

#[tokio::test]
async fn the_refund_endpoint_asks_the_journal_not_the_stage() {
    // R2-4. The guard read `order.stage.fiat_may_have_left()`, and `order.fail`
    // leaves the stage `Failed` - which the endpoint's own stage gate accepts.
    // So the failure whose message is "a payment may have left" produced the
    // one stage that would let a refund through, and the refund would race a
    // release for money already sent.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // Exactly what `settle` leaves behind when the Venmo leg fails after the
    // journal claim: a `NeedsOperator` line, and a `Failed` order.
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);
    let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    record.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
    state.journal.append_unchecked(&record).unwrap();

    let mut failed = state.store.get(&order_id).unwrap();
    failed.fail("the payment could not be completed. Check the Venmo feed.");
    state.store.put(&failed).unwrap();
    // The stage gate alone would let this through.
    assert!(!failed.stage.fiat_may_have_left());

    let raw = user.sign_refund(&failed, &funding_txid, 0);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(&raw) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("may already have been sent"),
        "the refusal must name the reason: {body}"
    );
    assert!(node.broadcasts().await.is_empty());
    // And the user is still told they can broadcast it themselves.
    assert!(body["error"].as_str().unwrap().contains("any Zcash node"));
}

#[tokio::test]
async fn a_refundable_order_stops_counting_against_the_handle_limit() {
    // R2-5. `Refundable` is open - the page must still be able to offer the
    // refund - but it needs nothing further from this coordinator. Counting it
    // meant a handful of abandoned, never-funded orders locked a served handle
    // out permanently, at no cost to whoever opened them.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let mut config = test_config(dir.path());
    config.quote.max_open_per_handle = 2;
    let state = coordinator_from_config(config, Arc::new(FakeScanner::new()), &node, None);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let mut ids = Vec::new();
    // Distinct amounts: this test is about the per-handle count, and identical
    // amounts would trip the same-handle-same-amount guard first.
    for amount in ["0.05", "0.06"] {
        let user = TestUser::new();
        let (_, q) = get(&app, &format!("/escrow/quote?amount={amount}&unit=zec")).await;
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
        assert_eq!(status, StatusCode::OK);
        ids.push(order["order_id"].as_str().unwrap().to_string());
    }

    // Full up. A third amount, so this is refused by the per-handle bound and
    // not by the same-handle-same-cents guard - the two have different messages
    // and this test is about the bound.
    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.07&unit=zec").await;
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
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already several escrows open"),
        "refused by the wrong rule: {body}"
    );

    // Both abandoned escrows reach T. Nobody funded them and nothing was paid.
    for id in &ids {
        let mut o = state.store.get(id).unwrap();
        o.stage = Stage::Refundable;
        state.store.put(&o).unwrap();
    }

    // The handle is served again.
    let user = TestUser::new();
    let (_, q) = get(&app, "/escrow/quote?amount=0.07&unit=zec").await;
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
    assert_eq!(
        status,
        StatusCode::OK,
        "abandoned orders locked the handle out: {body}"
    );
    // And the refundable orders are still readable, so the page can offer the
    // refund. They are never evicted.
    for id in &ids {
        let (status, _) = get(&app, &format!("/escrow/orders/{id}")).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn the_release_still_happens_when_the_journal_cannot_be_written() {
    // R2-3, retested properly. The `Paid` journal write used `?`, so a failure
    // after `fiat::pay` succeeded bailed with the store still at `Locked`. The
    // next sweep read `Paying`, correctly refused to pay twice, and failed the
    // order: the dollars were gone and the release was never attempted.
    //
    // R3-2: the first version of this test was vacuous. It broke the journal
    // from a timer, the timer beat `slot::claim`, the claim failed, no payment
    // left, and the single assertion was inside `if payments > 0`. The rail
    // here breaks the journal from inside `pay` instead, which puts the failure
    // exactly between the dollars leaving and the `Paid` line.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let journal = dir.path().join("fills.jsonl");
    let fiat = Arc::new(PayThenBreakJournal::new(&journal));
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    // `locked_order` posts the pre-signature, which spawns a settlement task,
    // so the payment may already have run by the time this returns.
    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // Let the settlement finish, whichever task is running it.
    for _ in 0..60 {
        let o = state.store.get(&order_id).unwrap();
        if o.stage == Stage::Released || o.stage == Stage::Failed {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // If the presign task did not settle it, drive it here.
    if state.store.get(&order_id).unwrap().stage == Stage::Locked {
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_id).await;
    }

    // The dollars left exactly once.
    assert_eq!(
        fiat.payments(),
        1,
        "the test must actually send a payment, or it proves nothing"
    );

    // And the order says so, so the release is reachable. `Locked` here is the
    // bug: dollars gone, and the next sweep would refuse to pay and fail it.
    let after = state.store.get(&order_id).unwrap();
    assert!(
        matches!(after.stage, Stage::Paid | Stage::Released),
        "the dollars left and the order is {}, which abandons the release",
        after.stage.as_str()
    );
    assert!(
        after.payment.is_some(),
        "the payment was not recorded, so nothing will finish the release"
    );
}

#[tokio::test]
async fn a_finished_trade_releases_the_slot_for_the_next_one() {
    // R3-1. Nothing wrote `Fulfilled`, so the `Paid` line from a completed
    // trade stayed open forever: one finished order blocked every later one.
    // Worse across daemons - the taker refuses to start at all while an open
    // record says the fiat may have left, so a finished coordinator trade would
    // keep the taker from restarting.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // One trade, all the way to released.
    let user_a = TestUser::new();
    let (order_a, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user_a).await;
    for _ in 0..60 {
        if state.store.get(&order_a).unwrap().stage == Stage::Released {
            break;
        }
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_a).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert_eq!(state.store.get(&order_a).unwrap().stage, Stage::Released);
    let paid_after_first = fiat.payments();
    assert_eq!(paid_after_first, 1);

    // The journal must not still be holding the slot.
    let open: Vec<_> = state
        .journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.state.is_open())
        .collect();
    assert!(
        open.is_empty(),
        "a finished trade left the slot held by {open:?}"
    );

    // And the taker's own startup gate, which refuses on any open record whose
    // fiat may have left, is satisfied.
    assert!(
        state.journal.needs_operator().unwrap().is_empty(),
        "a finished coordinator trade would block the taker from starting"
    );

    // The next order pays.
    let user_b = TestUser::new();
    let (order_b, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user_b).await;
    for _ in 0..60 {
        if state.store.get(&order_b).unwrap().stage == Stage::Released {
            break;
        }
        let _ = zecp2p_v2coordinator::driver::advance(&state, &order_b).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert_eq!(
        fiat.payments(),
        2,
        "the second trade never paid: the first one is still holding the slot"
    );
}

#[tokio::test]
async fn the_slot_is_taken_before_any_network_call() {
    // R3-3. The journal is meant to be the slot between daemons, and the window
    // between the read and the `Paying` write spanned a chain round-trip and the
    // rail's preflight - so another daemon reading the file in that window saw
    // it free. The claim now goes down first, as `Seen`, which holds the slot
    // without asserting money may have moved.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    // Slow inside preflight, so the window is wide and observable.
    let fiat = Arc::new(SlowFiat::new(400));
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // Drive the payment and, while it is inside preflight, read the journal the
    // way a second daemon would.
    let driving = {
        let s = state.clone();
        let id = order_id.clone();
        tokio::spawn(async move { zecp2p_v2coordinator::driver::advance(&s, &id).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let seen_by_another_daemon = zecp2p_taker::auto::journal::Journal::open(
        dir.path().join("fills.jsonl"),
    )
    .unwrap()
    .in_flight()
    .unwrap();
    assert!(
        seen_by_another_daemon.is_some(),
        "a second daemon reading the journal mid-preflight saw the slot free"
    );

    let _ = driving.await;
}

#[tokio::test]
async fn a_paid_journal_line_with_a_locked_order_finishes_the_release() {
    // R3-4. `Paid` in the journal and `Locked` in the store is the
    // post-payment store write having failed: the dollars are gone and the
    // order does not say so. Failing that order abandons a release the LP has
    // already paid for.
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

    // Stage the failure exactly: a `Paid` line, and an order still `Locked`
    // with no payment on it.
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);
    let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    record.state = zecp2p_taker::auto::journal::FillState::Paid;
    record.paid = Some("2.00".into());
    state.journal.append_unchecked(&record).unwrap();

    let mut stalled = state.store.get(&order_id).unwrap();
    stalled.stage = Stage::Locked;
    stalled.payment = None;
    stalled.release_txid = None;
    state.store.put(&stalled).unwrap();
    let paid_before = fiat.payments();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("finishing a paid order is not an error");

    let after = state.store.get(&order_id).unwrap();
    assert_ne!(
        after.stage,
        Stage::Failed,
        "the order was failed, abandoning a release the LP paid for"
    );
    assert!(
        after.payment.is_some(),
        "the payment the journal records was not carried onto the order"
    );
    // And no second payment was sent for it.
    assert_eq!(fiat.payments(), paid_before, "it paid again");
}

#[tokio::test]
async fn a_paying_line_still_needs_a_human_rather_than_a_release() {
    // The other side of R3-4, and the reason it is `Paid` only. `Paying` is
    // written before the click, so nobody knows whether money moved. Releasing
    // on it would hand the escrow to the LP for a payment that may never have
    // happened - the user loses the ZEC and got no dollars.
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

    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);
    let reserved =
        zecp2p_v2coordinator::slot::take(&state.journal, &work, 700_000, "alice")
            .unwrap()
            .expect("the slot is free");
    zecp2p_v2coordinator::slot::claim(
        &state.journal,
        reserved,
        alloy::primitives::B256::repeat_byte(0x11),
        1_700_000_000_000,
    )
    .unwrap()
    .expect("the claim succeeds");

    let mut stalled = state.store.get(&order_id).unwrap();
    stalled.stage = Stage::Locked;
    stalled.payment = None;
    stalled.release_txid = None;
    state.store.put(&stalled).unwrap();
    let broadcasts_before = node.broadcasts().await.len();
    let paid_before = fiat.payments();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a refusal is not an error");

    let after = state.store.get(&order_id).unwrap();
    assert_eq!(
        after.stage,
        Stage::Failed,
        "an ambiguous Paying line must stop for a human, not release"
    );
    assert_eq!(node.broadcasts().await.len(), broadcasts_before, "it released");
    assert_eq!(fiat.payments(), paid_before, "it paid again");
}

#[tokio::test]
async fn a_refundable_order_stops_counting_against_the_global_limit() {
    // R3-5. The global bound counted every open order, and `Refundable` is
    // open forever, so abandoned unfunded orders accumulated toward the ceiling
    // and nothing brought them back down.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let mut config = test_config(dir.path());
    config.quote.max_open_orders = 2;
    // Not the per-handle limit under test here.
    config.quote.max_open_per_handle = 50;
    config.serve.handles = vec!["alice".into(), "bob".into(), "carol".into()];
    let state = coordinator_from_config(config, Arc::new(FakeScanner::new()), &node, None);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    let open_one = |handle: &'static str| {
        let app = app.clone();
        async move {
            let user = TestUser::new();
            let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
            post(
                &app,
                "/escrow/orders",
                serde_json::json!({
                    "quote_id": q["quote_id"],
                    "u_pub": hex::encode(user.u_pub),
                    "destination": { "rail": "venmo", "handle": handle },
                }),
            )
            .await
        }
    };

    let (s1, o1) = open_one("alice").await;
    let (s2, o2) = open_one("bob").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    let (s3, _) = open_one("carol").await;
    assert_eq!(s3, StatusCode::SERVICE_UNAVAILABLE, "the global bound holds");

    // Both are abandoned and reach T.
    for body in [&o1, &o2] {
        let id = body["order_id"].as_str().unwrap();
        let mut o = state.store.get(id).unwrap();
        o.stage = Stage::Refundable;
        state.store.put(&o).unwrap();
    }

    let (s4, body) = open_one("carol").await;
    assert_eq!(
        s4,
        StatusCode::OK,
        "abandoned refundable orders filled the global ceiling for good: {body}"
    );
}

#[tokio::test]
async fn a_taker_fill_in_the_shared_journal_stops_the_coordinator_paying() {
    // The other direction of the cross-daemon slot, through the file the two
    // daemons actually share. A Base-rail record is what the taker writes.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // The taker is mid-fill on its own rail.
    let mut takers = zecp2p_taker::auto::journal::FillRecord::new(
        alloy::primitives::U256::from(4499),
        alloy::primitives::B256::repeat_byte(0xaa),
        alloy::primitives::U256::from(4_875_437u64),
        alloy::primitives::U256::from(990_881_148_896_019_200u128),
        "alice".into(),
    );
    takers.state = zecp2p_taker::auto::journal::FillState::Paying;
    state.journal.append_unchecked(&takers).unwrap();

    let user = TestUser::new();
    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let paid_before = fiat.payments();

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("waiting for the slot is not an error");

    assert_eq!(
        fiat.payments(),
        paid_before,
        "the coordinator paid while the taker had a payment in flight, into the same \
         Venmo account"
    );
    // Waiting, not failed: it pays once the taker finishes.
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Locked);
}

#[tokio::test]
async fn the_slot_claim_and_the_check_are_one_step() {
    // R4-3. The check and the claim used to be separate journal calls with the
    // decision between them, so another process could take the slot in the gap.
    // `slot::take` does both under one `flock`, so a caller that succeeds has
    // the slot and one that fails never wrote anything.
    let dir = tempfile::tempdir().unwrap();
    let journal = std::sync::Arc::new(
        zecp2p_taker::auto::journal::Journal::open(dir.path().join("fills.jsonl")).unwrap(),
    );

    // Many claimants for one slot, each a different escrow.
    let mut threads = Vec::new();
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for t in 0..8u8 {
        let journal = journal.clone();
        let winners = winners.clone();
        threads.push(std::thread::spawn(move || {
            let work = zecp2p_v2coordinator::slot::work_id_for(&[t; 32], 0);
            if zecp2p_v2coordinator::slot::take(&journal, &work, 700_000, "alice")
                .unwrap()
                .is_ok()
            {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }

    assert_eq!(
        winners.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "more than one escrow took the one payment slot"
    );
    // And exactly one open record exists, so the file agrees.
    let open = journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.state.is_open())
        .count();
    assert_eq!(open, 1, "{open} open records for one slot");
}

#[tokio::test]
async fn losing_the_slot_before_the_click_gives_the_reservation_back() {
    // R5-1, the coordinator's half of the mutual stall. `take` writes a `Seen`
    // line, then the chain call and the preflight run, then `claim` re-reads
    // and can find somebody else holding the slot. That reservation has to go
    // back: left behind, this order's own `Seen` blocks every other order -
    // including the one that won - and nothing but an operator clears it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    // Slow preflight, so there is a window to take the slot inside.
    let fiat = Arc::new(SlowFiat::new(300));
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    // The order starts paying, and a competing daemon takes the slot while it
    // is inside preflight.
    let driving = {
        let s = state.clone();
        let id = order_id.clone();
        tokio::spawn(async move { zecp2p_v2coordinator::driver::advance(&s, &id).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let mut intruder = zecp2p_taker::auto::journal::FillRecord::new(
        alloy::primitives::U256::from(4499),
        alloy::primitives::B256::repeat_byte(0xaa),
        alloy::primitives::U256::from(4_875_437u64),
        alloy::primitives::U256::from(990_881_148_896_019_200u128),
        "alice".into(),
    );
    intruder.state = zecp2p_taker::auto::journal::FillState::Paying;
    state.journal.append_unchecked(&intruder).unwrap();

    let _ = driving.await;

    // The intruder still holds the slot, and this order left nothing behind.
    let ours = zecp2p_v2coordinator::slot::work_id_for(
        &state.store.get(&order_id).unwrap().funding.unwrap().txid,
        0,
    );
    let open_for_us: Vec<_> = state
        .journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.work_id() == ours && r.state.is_open())
        .collect();
    assert!(
        open_for_us.is_empty(),
        "the reservation was left behind and now blocks every order: {open_for_us:?}"
    );
}

#[tokio::test]
async fn an_order_past_t_becomes_refundable_even_while_the_slot_is_held() {
    // R5-d. The `HeldByAnother` branch returned before the deadline check, so
    // an order past `T` sat at `locked` for as long as another trade took, and
    // the page never offered the refund the user was entitled to.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(CountingFiat::new());
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, _) = locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let mut relocked = state.store.get(&order_id).unwrap();
    relocked.stage = Stage::Locked;
    relocked.payment = None;
    relocked.release_txid = None;
    state.store.put(&relocked).unwrap();

    // Somebody else holds the slot, and the chain passes T.
    let mut other = zecp2p_taker::auto::journal::FillRecord::new(
        alloy::primitives::U256::from(4499),
        alloy::primitives::B256::repeat_byte(0xaa),
        alloy::primitives::U256::from(4_875_437u64),
        alloy::primitives::U256::from(990_881_148_896_019_200u128),
        "alice".into(),
    );
    other.state = zecp2p_taker::auto::journal::FillState::Paying;
    state.journal.append_unchecked(&other).unwrap();
    node.set_height(u32::try_from(relocked.refund_height).unwrap() + 1).await;

    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("waiting for the slot is not an error");

    assert_eq!(
        state.store.get(&order_id).unwrap().stage,
        Stage::Refundable,
        "the user could not be offered their refund because another trade was paying"
    );
    assert_eq!(fiat.payments(), 0, "it paid while the slot was held");
}

#[tokio::test]
async fn a_second_coordinator_cannot_pay_the_same_order() {
    // R5-a. `take` and `claim` skip records for their own work id, which is
    // right for a retry and wrong for a second process on the same state
    // directory: both would treat the other's line as their own and both would
    // write `Paying` for one order.
    let dir = tempfile::tempdir().unwrap();
    let journal =
        zecp2p_taker::auto::journal::Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = zecp2p_v2coordinator::slot::work_id_for(&[0x5c; 32], 0);

    // The first instance reserves and claims.
    let reserved = zecp2p_v2coordinator::slot::take(&journal, &work, 700_000, "alice")
        .unwrap()
        .expect("the slot is free");
    zecp2p_v2coordinator::slot::claim(
        &journal,
        reserved,
        alloy::primitives::B256::repeat_byte(0x11),
        1_700_000_000_000,
    )
    .expect("the journal is readable")
    .expect("the first claim succeeds");

    // A second instance, same order, same journal.
    let second = zecp2p_v2coordinator::slot::take(&journal, &work, 700_000, "alice").unwrap();
    assert!(
        second.is_err(),
        "a second coordinator claimed an order already being paid"
    );

    // And even holding a stale reservation, its claim is refused.
    let stale = zecp2p_taker::auto::journal::FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    let refused = zecp2p_v2coordinator::slot::claim(
        &journal,
        stale,
        alloy::primitives::B256::repeat_byte(0x22),
        1_700_000_000_000,
    )
    .expect("a refusal is a value, not an error");
    // R6-1: the *kind* matters. `ThisOrderMayHavePaid` tells the caller not to
    // touch the journal; `HeldByAnother` tells it to give its reservation back.
    // Collapsing the two into a string is what let a losing instance cancel the
    // winner's `Paying` line while its dollars were in flight.
    assert!(
        matches!(
            refused,
            Err(zecp2p_v2coordinator::slot::SlotRefusal::ThisOrderMayHavePaid { .. })
        ),
        "a second coordinator was not told a payment for this order is under way: {refused:?}"
    );

    // One Paying line, not two.
    let paying = std::fs::read_to_string(dir.path().join("fills.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| l.contains("\"paying\""))
        .count();
    assert_eq!(paying, 1, "{paying} Paying lines for one order");
}

#[tokio::test]
async fn a_losing_instance_does_not_cancel_the_winners_claim() {
    // R6-1, and R7-3: the earlier version of this test never reached the arm it
    // was written for. It put the winner's `Paying` line on disk *before*
    // calling `advance`, so `take` refused first and `claim` was never
    // exercised - the round-6 bug could be re-inserted verbatim and every test
    // stayed green.
    //
    // The line has to land *between* `take` and `claim`, which is the
    // preflight window. A slow rail holds it open long enough for the intruder
    // to claim the same work id, which is what a second coordinator on one
    // state directory does.
    //
    // Verifying by reverting: there are two defences here and both must go to
    // see this fail. R6-1 is the typed refusal that keeps `settle` from
    // retracting on "somebody is already paying"; R7-1 is the compare-and-set
    // inside `retract`, which declines to write over a line that has moved on.
    // Either alone still protects the winner's claim - which is the point of
    // fixing the whole class rather than one arm.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let fiat = Arc::new(SlowFiat::new(400));
    let state = coordinator_with_fiat(dir.path(), scanner.clone(), &node, &attestor, fiat.clone());
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();

    let (order_id, funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);

    // Make sure the order is waiting to be paid, whatever the presign task did.
    let mut relocked = state.store.get(&order_id).unwrap();
    relocked.stage = Stage::Locked;
    relocked.payment = None;
    relocked.release_txid = None;
    state.store.put(&relocked).unwrap();

    // This instance starts paying: it takes the slot, then sits in preflight.
    let driving = {
        let s = state.clone();
        let id = order_id.clone();
        tokio::spawn(async move { zecp2p_v2coordinator::driver::advance(&s, &id).await })
    };

    // While it is in there, a second instance takes the same order - an
    // own-work `Seen` is allowed through, because that is what a retry looks
    // like - and wins the claim. Its dollars are now in flight.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // The intruder is a second coordinator that reserved *before* this one -
    // R8-1 stops it reserving now, which is the earlier and better refusal, so
    // reaching the claim arm means holding a reservation from before. It claims
    // over its own line and is now in the browser.
    let theirs = state
        .journal
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == work)
        .expect("this order holds a reservation");
    zecp2p_v2coordinator::slot::claim(
        &state.journal,
        theirs,
        alloy::primitives::B256::repeat_byte(0xaa),
        1_700_000_000_000,
    )
    .unwrap()
    .expect("the intruder claims");

    // The first instance now reaches its own claim and loses. It must not
    // retract: that writes `Cancelled` over the winner's `Paying` line while
    // the dollars are gone, and the next sweep then reads a free slot.
    let _ = driving.await;

    let latest: Vec<_> = state
        .journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.work_id() == work)
        .collect();
    assert_eq!(latest.len(), 1, "one line per work item");
    assert_eq!(
        latest[0].state,
        zecp2p_taker::auto::journal::FillState::Paying,
        "the loser cancelled the winner's claim while its dollars were in flight; the \
         next sweep would read a free slot and pay again"
    );

    // And the proof of the consequence: another sweep must still refuse.
    let paid_before = fiat.payments();
    let mut relocked = state.store.get(&order_id).unwrap();
    relocked.stage = Stage::Locked;
    relocked.payment = None;
    state.store.put(&relocked).unwrap();
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("refusing is not an error");
    assert_eq!(
        fiat.payments(),
        paid_before,
        "a second payment went out for one escrow"
    );
}


#[tokio::test]
async fn a_coordinator_killed_mid_reservation_heals_and_pays_once() {
    // R10-3. The crash-heal was only covered by a `slot::take` unit test, so a
    // reordering in `settle` - the reservation moving after a network call, or
    // the refusal arm changing - would not be caught. This drives the real
    // `advance`, from an order and a journal in exactly the state a kill
    // between the reservation and the chain read leaves.
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
    let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);

    // The kill: a reservation on disk, and an order still `Locked` because the
    // process died before writing anything else.
    let mut relocked = state.store.get(&order_id).unwrap();
    relocked.stage = Stage::Locked;
    relocked.payment = None;
    relocked.release_txid = None;
    state.store.put(&relocked).unwrap();

    let orphan = zecp2p_taker::auto::journal::FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    state.journal.append_unchecked(&orphan).unwrap();
    assert!(
        !state.journal.open_fills().unwrap().is_empty(),
        "the orphan is not holding the slot, so this proves nothing"
    );

    // The restart. It must displace its own leftover and finish the trade,
    // rather than failing the order and stalling every later one.
    zecp2p_v2coordinator::driver::advance(&state, &order_id)
        .await
        .expect("a restart must not error");

    let after = state.store.get(&order_id).unwrap();
    assert_ne!(
        after.stage,
        Stage::Failed,
        "a crashed reservation stalled the order permanently"
    );
    assert_eq!(after.stage, Stage::Released, "the restart did not finish the trade");

    // Exactly one payment, and exactly one release: healing must not repeat.
    assert_eq!(fiat.payments(), 1, "the restart paid twice");
    assert_eq!(node.broadcasts().await.len(), 1, "the restart released twice");

    // And the slot is free for the next order.
    assert!(
        state.journal.open_fills().unwrap().is_empty(),
        "the finished trade is still holding the slot"
    );
}

#[tokio::test]
async fn a_sighting_that_expired_unmined_is_not_offered_a_refund() {
    // R5-2. `still_owes_a_refund_check` admits a mempool sighting because the
    // coin is usually on its way. When the funding transaction expires unmined
    // and no wallet resends it, nothing ever reaches the address - and the
    // order is still promoted at `T` over an escrow no block holds. The page
    // then says "your ZEC is in the escrow", shows the form, and builds a
    // refund over an outpoint that never confirmed; the endpoint refuses on the
    // unknown funding while the page says any node will take the bytes.
    //
    // One `gettxout` for the sighted outpoint tells this case from finding 7,
    // where the transaction did confirm and the scan cursor merely overtook it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    // Sighted in the mempool, announced, signed while unconfirmed.
    let funding_txid = [0x71u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // It expires. Nothing is added to the node, so `gettxout` on the sighted
    // outpoint answers null: no coin ever left the user's wallet.
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        for o in state.store.open_orders() {
            zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
        }
    }

    let end = state.store.get(&order_id).unwrap();
    assert!(end.funding.is_none(), "nothing confirmed, so there is no funding outpoint");
    assert_ne!(
        end.stage,
        Stage::Refundable,
        "an escrow nothing was ever paid into was offered a refund form"
    );
    assert!(
        !state.store.open_orders().iter().any(|o| o.order_id == order_id),
        "an order over an empty escrow is swept for ever"
    );
}

#[tokio::test]
async fn a_sighting_the_cursor_overtook_is_still_offered_a_refund() {
    // Finding 7, the case R5-2's check must not break. The funding did confirm,
    // but the scan cursor passed its block before the scan found it - a reorg
    // that moved the funding into a height already searched - so `order.funding`
    // is never set. The coin is genuinely in the escrow and the user is owed the
    // refund at `T`.
    //
    // The mempool sighting holds the correct outpoint, and `gettxout` answers
    // with a live output, which is what tells this case from R5-2's.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_that_cannot_pay(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, amount_zat, stored) = opened_order(&app, &state, &user).await;

    let funding_txid = [0x72u8; 32];
    scanner.pay_mempool(
        &stored.script_pubkey,
        FoundOutput { txid: funding_txid, vout: 0, amount_zat },
    );
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.unwrap();
    sign_it(&app, &state, &attestor, &user, &order_id).await;

    // It confirmed - the node holds the output - but no block scan ever
    // reports it, so `funding` stays unset the way finding 7 describes.
    node.add_utxo(funding_txid, 0, stored.script_pubkey.clone(), amount_zat, 30).await;
    node.set_height(u32::try_from(stored.refund_height).unwrap() + 1).await;
    for _ in 0..3 {
        for o in state.store.open_orders() {
            zecp2p_v2coordinator::driver::advance(&state, &o.order_id).await.ok();
        }
    }

    let end = state.store.get(&order_id).unwrap();
    assert_eq!(
        end.stage,
        Stage::Refundable,
        "the coin is in the escrow and past T, and the user was not offered it"
    );

    // Finding 7 proper: the stage says refundable, and the refund the page
    // builds over the sighted outpoint - the only one it has - is refused,
    // because the coordinator never wrote a funding outpoint to check it
    // against. The mempool record held the right one the whole time.
    let raw = user.sign_refund(&end, &funding_txid, 0);
    let (status, body) = post(
        &app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(&raw) }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refund over the outpoint the escrow actually holds was refused: {body}"
    );
    assert_eq!(
        state.store.get(&order_id).unwrap().stage,
        Stage::Refunded,
        "the refund broadcast but the order did not record it"
    );
}

#[tokio::test]
async fn one_sweep_reads_the_journal_once_however_many_orders_are_held_back() {
    // R5-3. `check_refund_deadline_only` read and parsed the whole journal for
    // every `Unpaid` or `Failed` order with an escrow, every sweep, before the
    // head read. For an order the journal holds back that read never stops: the
    // order stays `Failed`, the predicate stays true, and it is listed until an
    // operator writes `Cancelled` or `Fulfilled` for its work. The same
    // per-order-per-sweep shape as the mempool scan of finding 3, and it wants
    // the same treatment - the journal is the same file for every order in a
    // sweep.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());

    // Three failed orders the journal holds back, each with its own escrow.
    // Distinct amounts so the same-handle-same-amount guard does not refuse the
    // second and third; this test is about how often the journal is read.
    let mut ids = Vec::new();
    let mut refund_height = 0u32;
    for amount in ["0.05", "0.06", "0.07"] {
        let user = TestUser::new();
        let (id, funding_txid) =
            locked_order_for(&app, &state, &node, &scanner, &attestor, &user, amount).await;
        let work = zecp2p_v2coordinator::slot::work_id_for(&funding_txid, 0);
        let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
            work.local.clone(),
            alloy::primitives::U256::from(700_000u64),
            alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
            "alice".into(),
        );
        record.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
        state.journal.append_unchecked(&record).unwrap();

        let mut failed = state.store.get(&id).unwrap();
        failed.fail("the payment could not be completed. Check the Venmo feed.");
        refund_height = u32::try_from(failed.refund_height).unwrap();
        state.store.put(&failed).unwrap();
        ids.push(id);
    }
    node.set_height(refund_height + 1).await;

    // Advanced CONCURRENTLY on a JoinSet, the way `run` sweeps. Driving them
    // one after another hides it: the first read fills the cache before the
    // second order looks.
    let before = state.journal_reads();
    let mut tasks = tokio::task::JoinSet::new();
    for id in ids.clone() {
        let state = state.clone();
        tasks.spawn(async move {
            zecp2p_v2coordinator::driver::advance(&state, &id).await.ok();
        });
    }
    while tasks.join_next().await.is_some() {}
    let reads = state.journal_reads() - before;
    assert_eq!(
        reads, 1,
        "three orders in one sweep read the journal {reads} times; it is the same file \
         for all of them"
    );
    // And the answer they shared is the right one: all three are still held.
    for id in &ids {
        assert_eq!(
            state.store.get(id).unwrap().stage,
            Stage::Failed,
            "a shared journal read let an order past the guard that withholds the refund"
        );
    }
}

#[tokio::test]
async fn a_journal_line_written_since_the_shared_read_is_not_missed() {
    // The cost of sharing a read is staleness, and here staleness runs the
    // wrong way. The journal is written *during* a sweep - by this process at
    // the pay gate, and by the taker daemon in another process against the same
    // file - and the line that arrives is the one that withholds the refund. A
    // snapshot taken before it and reused after it promotes an order whose
    // dollars may already have gone, which is exactly what the guard exists to
    // stop.
    //
    // So the cache is keyed on the journal's length rather than on a clock. The
    // file is append-only, so any write by either writer changes it, and a
    // cache that only answers at the length it was read at cannot be behind
    // one. A time window cannot make that promise, and a first cut of this fix
    // used one - this test is what caught it.
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let attestor = TestAttestor::new();
    let state = coordinator_with_everything(dir.path(), scanner.clone(), &node, &attestor);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let user = TestUser::new();
    let (order_id, _funding_txid) =
        locked_order(&app, &state, &node, &scanner, &attestor, &user).await;

    let mut failed = state.store.get(&order_id).unwrap();
    failed.fail("the payment could not be completed. Check the Venmo feed.");
    let refund_height = u32::try_from(failed.refund_height).unwrap();
    state.store.put(&failed).unwrap();
    node.set_height(refund_height + 1).await;

    // A sweep with a clean journal fills the cache, and promotes: nothing says
    // otherwise.
    zecp2p_v2coordinator::driver::advance(&state, &order_id).await.ok();
    assert_eq!(
        state.store.get(&order_id).unwrap().stage,
        Stage::Refundable,
        "a clean journal is permission to offer the refund"
    );

    // Now the line arrives - the taker's, or this process's own at the pay
    // gate - for an order that has already been promoted. A second order in the
    // same store must not be promoted off the snapshot taken before it.
    let user2 = TestUser::new();
    let (second_id, second_txid) =
        locked_order_for(&app, &state, &node, &scanner, &attestor, &user2, "0.06").await;
    let mut second = state.store.get(&second_id).unwrap();
    second.fail("the payment could not be completed. Check the Venmo feed.");
    state.store.put(&second).unwrap();

    let work = zecp2p_v2coordinator::slot::work_id_for(&second_txid, 0);
    let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(700_000u64),
        alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    record.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
    state.journal.append_unchecked(&record).unwrap();

    zecp2p_v2coordinator::driver::advance(&state, &second_id).await.ok();
    assert_eq!(
        state.store.get(&second_id).unwrap().stage,
        Stage::Failed,
        "a journal line written since the shared read was missed, and the order was \
         steered to a refund over an escrow the LP may already have bought"
    );
}
