use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use zecp2p_v2coordinator::funding::{FakeScanner, FoundOutput};
use zecp2p_v2coordinator::order::Stage;
mod support;
use support::*;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}
async fn post(app: &axum::Router, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(Request::builder().method("POST").uri(path).header("content-type", "application/json").body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn audit_sweep_generation_advances() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let state = coordinator_from_config(test_config(dir.path()), scanner as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>, &node, None);
    let g1 = state.begin_sweep(); state.end_sweep();
    let g2 = state.begin_sweep(); state.end_sweep();
    let g3 = state.begin_sweep(); state.end_sweep();
    eprintln!("AUDIT generations: {g1} {g2} {g3}");
    assert!(g1 != g2 && g2 != g3, "generations must differ between passes: {g1} {g2} {g3}");
}

#[tokio::test]
async fn audit_funding_after_expiry_is_discovered() {
    let dir = tempfile::tempdir().unwrap();
    let node = FakeNode::spawn().await;
    let scanner = Arc::new(FakeScanner::new());
    let user = TestUser::new();
    let mut config = test_config(dir.path());
    config.limits.unfunded_order_minutes = 1;
    config.limits.open_rate_per_client = 0;
    config.limits.open_rate_global = 0;
    config.limits.max_open_per_client = 0;
    let state = coordinator_from_config(config, scanner.clone() as Arc<dyn zecp2p_v2coordinator::funding::FundingScanner>, &node, None);
    let app = zecp2p_v2coordinator::web::router(state.clone());
    let (_, q) = get(&app, "/escrow/quote?amount=0.05&unit=zec").await;
    let (status, opened) = post(&app, "/escrow/orders", serde_json::json!({"quote_id": q["quote_id"], "u_pub": hex::encode(user.u_pub), "destination": {"rail": "venmo", "handle": "alice"}})).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let order_id = opened["order_id"].as_str().unwrap().to_string();
    let amount_zat = opened["escrow"]["amount_zat"].as_u64().unwrap();
    let mut order = state.store.get(&order_id).unwrap();
    order.created_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.store.put(&order).unwrap();
    zecp2p_v2coordinator::driver::sweep_once(&state).await;
    assert_eq!(state.store.get(&order_id).unwrap().stage, Stage::Expired);

    // The user funds late: coin lands at the escrow address in a block.
    let funding_txid = [0x55u8; 32];
    scanner.pay(&order.script_pubkey, FoundOutput { txid: funding_txid, vout: 0, amount_zat });
    node.add_utxo(funding_txid, 0, order.script_pubkey.clone(), amount_zat, 30).await;
    for _ in 0..3 { zecp2p_v2coordinator::driver::sweep_once(&state).await; }
    let after = state.store.get(&order_id).unwrap();
    eprintln!("AUDIT after late funding: stage={} funding={:?}", after.stage.as_str(), after.funding.is_some());
    // What does the refund route say to this user?
    let (status, body) = post(&app, &format!("/escrow/orders/{order_id}/refund"), serde_json::json!({"raw_tx": hex::encode(vec![0u8; 200])})).await;
    eprintln!("AUDIT refund answer: {status} {body}");
    assert!(after.funding.is_some(), "coin at the address of an expired order is never discovered");
}
