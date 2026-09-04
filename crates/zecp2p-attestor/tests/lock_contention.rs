//! R6-6: `/announce` must not wait on someone else's chain round trip.
//!
//! The store lock used to be held for the whole `/attest` closure, including
//! `gettxout`. One stalled node call therefore blocked every other request for
//! as long as the RPC timeout, which is 45 s in the daemon. The handler now
//! reads the announcement under the lock, releases it for the network call, and
//! re-takes it to decide and sign.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use secp256k1_zkp::SecretKey;
use serde_json::{json, Value};
use tower::ServiceExt;

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::service::{router, AttestorService, WireTerms};
use zecp2p_attestor::FixedClock;
use zecp2p_escrow::chain::{ChainClient, ChainError, Utxo};
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const TOKEN: &str = "test-bearer-token-16ch";
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];
const REFUND_HEIGHT: u64 = 3_500_000;

/// A node that takes its time answering `utxo`, standing in for a slow or
/// stalled RPC endpoint.
#[derive(Debug)]
struct SlowChain {
    delay: Duration,
}

impl ChainClient for SlowChain {
    fn height(&self) -> Result<u32, ChainError> {
        Ok(3_400_000)
    }
    fn consensus_branch_id(&self) -> Result<u32, ChainError> {
        Ok(0x37a5_165b)
    }
    fn utxo(&self, _txid: &[u8; 32], _vout: u32) -> Result<Option<Utxo>, ChainError> {
        std::thread::sleep(self.delay);
        Ok(Some(Utxo {
            script_pubkey: p2sh_script_pubkey(
                &redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap(),
            ),
            amount_zat: 5_000_000,
            confirmations: 30,
        }))
    }
    fn broadcast(&self, _raw: &[u8]) -> Result<[u8; 32], ChainError> {
        Err(ChainError::Unreachable("not used".into()))
    }
}

fn terms_for(txid: [u8; 32]) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: txid,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: NOW_MS,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    }
}

fn service(delay: Duration) -> Arc<AttestorService<SlowChain, FixedClock>> {
    Arc::new(AttestorService::new(
        SqliteEventStore::in_memory().unwrap(),
        SecretKey::from_slice(&[0xd1; 32]).unwrap(),
        SlowChain { delay },
        FixedClock(NOW_MS),
        TOKEN.to_string(),
        "test".to_string(),
    ))
}

async fn call(
    svc: Arc<AttestorService<SlowChain, FixedClock>>,
    path: &str,
    body: Value,
) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router(svc).oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announce_does_not_wait_on_someone_elses_chain_call() {
    // The chain takes 1.5 s. An announce issued while an attest is waiting on it
    // must not inherit that wait.
    let delay = Duration::from_millis(1500);
    let svc = service(delay);

    let victim = terms_for([0x7a; 32]);
    assert_eq!(
        call(svc.clone(), "/announce", json!({"terms": WireTerms::from_terms(&victim)})).await,
        StatusCode::OK
    );

    // Start an attest that will sit in the chain call. It is refused on the
    // signer afterwards, which is fine: the point is where it spends its time.
    let attest_body = json!({
        "event_id": hex::encode(zecp2p_escrow::dlc::event_id(&victim.funding_txid, 0)),
        "terms": WireTerms::from_terms(&victim),
        "attestation": {
            "intent_hash": hex::encode(victim.intent_hash()),
            "release_amount": "1000000",
            "data_hash": hex::encode([0u8; 32]),
            "signature": hex::encode([0u8; 65]),
            "encoded_payment_details": hex::encode(vec![0u8; 14 * 32]),
        }
    });
    let attesting = tokio::spawn({
        let svc = svc.clone();
        async move { call(svc, "/attest", attest_body).await }
    });

    // Give it time to reach the chain call and be inside it.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let other = terms_for([0x7b; 32]);
    let started = Instant::now();
    let status = call(
        svc.clone(),
        "/announce",
        json!({"terms": WireTerms::from_terms(&other)}),
    )
    .await;
    let waited = started.elapsed();

    assert_eq!(status, StatusCode::OK);
    assert!(
        waited < Duration::from_millis(900),
        "the announce waited {waited:?} on another request's chain call; the store lock is \
         still held across it"
    );

    let _ = attesting.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_announces_still_get_distinct_nonces_under_contention() {
    // Releasing the lock must not let two announcements share a nonce point.
    let svc = service(Duration::from_millis(0));
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let svc = svc.clone();
        let mut txid = [0u8; 32];
        txid[0] = i;
        tasks.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri("/announce")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"terms": WireTerms::from_terms(&terms_for(txid))}))
                        .unwrap(),
                ))
                .unwrap();
            let resp = router(svc).oneshot(req).await.unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            v["r"].as_str().unwrap_or_default().to_string()
        }));
    }

    let mut seen = std::collections::HashSet::new();
    for t in tasks {
        let r = t.await.unwrap();
        assert!(!r.is_empty(), "an announce failed under contention");
        assert!(seen.insert(r), "two announcements shared a nonce point");
    }
    assert_eq!(seen.len(), 16);
}
