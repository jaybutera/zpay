//! The attestor's HTTP surface, spec section 6.
//!
//! Round 4 passed the choke-point functions on the understanding that this
//! layer did not exist yet. These tests are the check that it was written to
//! that guidance: no handler takes a caller's word for a script, an amount, a
//! confirmation depth, a timestamp, a nonce or an event id.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tower::ServiceExt;

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::service::{router, AttestorService, WireTerms};
use zecp2p_attestor::FixedClock;
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::{FakeChain, Utxo};
use zecp2p_escrow::dlc::{event_id, outcome_point, verify_outcome_secret};
use zecp2p_escrow::payment_details::{
    IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;
const TOKEN: &str = "test-bearer-token";
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

/// The real enclave signer cannot be made to sign for terms a test invents, so
/// the service tests use the production `decide` path and expect it to refuse on
/// the signer. What they are testing is the *plumbing*: which facts the handler
/// sources from where. The decision logic itself is covered against genuinely
/// bound attestations in `decide.rs`.
fn test_enclave() -> Sk1 {
    Sk1::from_slice(&[0xe1; 32]).unwrap()
}

fn attest_for(intent: [u8; 32], amount: u128, details: &[u8]) -> (PaymentAttestation, Vec<u8>) {
    let att = PaymentAttestation {
        intent_hash: intent,
        release_amount: amount,
        data_hash: Keccak256::digest(details).into(),
    };
    let sig = Secp1::new()
        .sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &test_enclave());
    let (rec_id, compact) = sig.serialize_compact();
    let mut b = compact.to_vec();
    b.push(i32::from(rec_id) as u8 + 27);
    (att, b)
}

fn word_u(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn details(t: &CanonicalTerms) -> Vec<u8> {
    [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(484),
        USD_FIAT_CURRENCY,
        word_u((t.lock_confirmed_ms + 60_000) as u128),
        [0x55; 32],
        t.intent_hash(),
        word_u(t.usd_amount_6dec as u128),
        VENMO_PAYMENT_METHOD,
        USD_FIAT_CURRENCY,
        t.payee_hash,
        word_u(t.rate_18dec),
        word_u((t.lock_confirmed_ms / 1000) as u128),
        word_u(1_209_600),
    ]
    .concat()
}

fn terms() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: [0x7a; 32],
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

fn funded_chain(confirmations: u32) -> FakeChain {
    let mut c = FakeChain::new(3_400_000, NU6_3);
    c.add_utxo(
        terms().funding_txid,
        0,
        Utxo {
            script_pubkey: p2sh_script_pubkey(
                &redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap(),
            ),
            amount_zat: 5_000_000,
            confirmations,
        },
    );
    c
}

fn service(chain: FakeChain) -> Arc<AttestorService<FakeChain, FixedClock>> {
    Arc::new(AttestorService::new(
        SqliteEventStore::in_memory().unwrap(),
        SecretKey::from_slice(&[0xd1; 32]).unwrap(),
        chain,
        FixedClock(NOW_MS),
        TOKEN.to_string(),
        "test-build".to_string(),
    ))
}

async fn call(
    svc: Arc<AttestorService<FakeChain, FixedClock>>,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router(svc).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn announce_body(t: &CanonicalTerms) -> Value {
    json!({ "terms": WireTerms::from_terms(t) })
}

#[tokio::test]
async fn identity_publishes_the_attestor_key() {
    let svc = service(funded_chain(10));
    let (status, body) = call(svc.clone(), "GET", "/identity", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["p"].as_str().unwrap(),
        hex::encode(svc.public_key().serialize())
    );
    // Phase 7 fills this in; saying so is more honest than omitting the field.
    assert!(body["attestation_document"].is_null());
}

#[tokio::test]
async fn announce_and_attest_require_the_bearer_token() {
    let svc = service(funded_chain(10));
    let t = terms();
    for (path, body) in [
        ("/announce", announce_body(&t)),
        ("/attest", json!({"event_id": hex::encode(event_id(&t.funding_txid, 0)),
                           "terms": WireTerms::from_terms(&t),
                           "attestation": {"intent_hash": hex::encode([0u8;32]),
                                           "release_amount": "1",
                                           "data_hash": hex::encode([0u8;32]),
                                           "signature": "00",
                                           "encoded_payment_details": "00"}})),
    ] {
        let (status, _) = call(svc.clone(), "POST", path, None, Some(body.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} without a token");
        let (status, _) = call(svc.clone(), "POST", path, Some("wrong"), Some(body)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} with a bad token");
    }
}

#[tokio::test]
async fn announce_returns_a_nonce_point_the_caller_did_not_choose() {
    // Round 4 finding 1: `k` is drawn inside the handler. The request has no
    // field for it, and two announcements never share an `R`.
    let svc = service(funded_chain(10));
    let mut t = terms();

    let (status, first) = call(
        svc.clone(),
        "POST",
        "/announce",
        Some(TOKEN),
        Some(announce_body(&t)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first["event_id"].as_str().unwrap(),
        hex::encode(event_id(&t.funding_txid, 0)),
        "the event id is derived from the outpoint, not taken from the request"
    );
    assert_eq!(first["terms_hash"].as_str().unwrap(), hex::encode(t.terms_hash()));
    assert_eq!(first["outcome"].as_str().unwrap(), "paid");

    t.funding_txid = [0x7b; 32];
    let (_, second) = call(
        svc.clone(),
        "POST",
        "/announce",
        Some(TOKEN),
        Some(announce_body(&t)),
    )
    .await;
    assert_ne!(
        first["r"].as_str().unwrap(),
        second["r"].as_str().unwrap(),
        "each announcement must get its own nonce point"
    );
}

/// R6-2: a repeat with the *same* terms returns the announcement that exists,
/// because a lost response otherwise stranded an escrow the user may already
/// have funded. A repeat with different terms is still a 409 - one escrow, one
/// nonce.
#[tokio::test]
async fn a_second_announcement_replays_for_the_same_terms_and_is_refused_otherwise() {
    let svc = service(funded_chain(10));
    let t = terms();

    let (status, first) =
        call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;
    assert_eq!(status, StatusCode::OK);

    let (status, replay) =
        call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;
    assert_eq!(status, StatusCode::OK, "an identical repeat must replay");
    assert_eq!(
        first["r"].as_str().unwrap(),
        replay["r"].as_str().unwrap(),
        "the replay must return the nonce point already announced, not a new one"
    );
    assert_eq!(first["terms_hash"], replay["terms_hash"]);

    // Different terms over the same outpoint: the event id is the same, the
    // terms hash is not, so this is refused.
    let mut other = terms();
    other.usd_amount_6dec = 1;
    let (status, body) = call(
        svc.clone(),
        "POST",
        "/announce",
        Some(TOKEN),
        Some(announce_body(&other)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("announcement"));
}

#[tokio::test]
async fn attest_for_an_unannounced_event_is_refused() {
    let svc = service(funded_chain(10));
    let t = terms();
    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let (status, _) = call(
        svc,
        "POST",
        "/attest",
        Some(TOKEN),
        Some(json!({
            "event_id": hex::encode(event_id(&t.funding_txid, 0)),
            "terms": WireTerms::from_terms(&t),
            "attestation": {
                "intent_hash": hex::encode(att.intent_hash),
                "release_amount": att.release_amount.to_string(),
                "data_hash": hex::encode(att.data_hash),
                "signature": hex::encode(&sig),
                "encoded_payment_details": hex::encode(&det),
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn attest_refuses_an_event_id_that_is_not_the_outpoints() {
    let svc = service(funded_chain(10));
    let t = terms();
    call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (status, body) = call(
        svc,
        "POST",
        "/attest",
        Some(TOKEN),
        Some(json!({
            // A different escrow's event id.
            "event_id": hex::encode(event_id(&[0xa7; 32], 0)),
            "terms": WireTerms::from_terms(&t),
            "attestation": {
                "intent_hash": hex::encode(att.intent_hash),
                "release_amount": att.release_amount.to_string(),
                "data_hash": hex::encode(att.data_hash),
                "signature": hex::encode(&sig),
                "encoded_payment_details": hex::encode(&det),
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("event id"));
}

#[tokio::test]
async fn attest_reads_the_escrow_from_the_attestors_own_node() {
    // The request carries no script, amount or depth. An escrow the node does
    // not have cannot be attested however the request is shaped.
    let svc = service(FakeChain::new(3_400_000, NU6_3));
    let t = terms();
    call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (status, body) = call(
        svc,
        "POST",
        "/attest",
        Some(TOKEN),
        Some(json!({
            "event_id": hex::encode(event_id(&t.funding_txid, 0)),
            "terms": WireTerms::from_terms(&t),
            "attestation": {
                "intent_hash": hex::encode(att.intent_hash),
                "release_amount": att.release_amount.to_string(),
                "data_hash": hex::encode(att.data_hash),
                "signature": hex::encode(&sig),
                "encoded_payment_details": hex::encode(&det),
            }
        })),
    )
    .await;
    // 503, not 400: "the attestor's node has not caught up" is a retry
    // condition, and the LP reaches it whenever its own node is ahead of the
    // attestor's (R5-1).
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"].as_str().unwrap().contains("does not exist"),
        "got {}",
        body["error"]
    );
}

/// The depth the attestor applies is the node's count, not the request's.
///
/// The signer check runs before the depth check, so an end-to-end attest cannot
/// reach the depth branch with a test-signed attestation. What is asserted here
/// is the thing the service actually controls: the observation it builds comes
/// from its own `ChainClient`, and the request has no field that could change
/// it. `decide.rs` covers the depth arithmetic against genuinely bound
/// attestations.
#[tokio::test]
async fn attest_observes_depth_from_the_node_and_not_from_the_request() {
    use zecp2p_attestor::observe_escrow;

    let t = terms();
    for reported in [0u32, 9, 10, 30] {
        let chain = funded_chain(reported);
        let observed = observe_escrow(&chain, &t, NOW_MS).expect("the node has the escrow");
        assert_eq!(
            observed.confirmations, reported,
            "the depth must be the node's number"
        );
        assert_eq!(
            observed.script_pubkey,
            p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap()),
            "the script must be the node's"
        );
        assert_eq!(observed.amount_zat, 5_000_000);
    }

    // And a shallow escrow is refused by the decision path, reached here with
    // the pinned signer supplying the refusal first - which is itself the
    // correct ordering, since an unsigned attestation should never get as far
    // as a chain question.
    let svc = service(funded_chain(9));
    let t = terms();
    call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (status, body) = call(
        svc,
        "POST",
        "/attest",
        Some(TOKEN),
        Some(json!({
            "event_id": hex::encode(event_id(&t.funding_txid, 0)),
            "terms": WireTerms::from_terms(&t),
            "attestation": {
                "intent_hash": hex::encode(att.intent_hash),
                "release_amount": att.release_amount.to_string(),
                "data_hash": hex::encode(att.data_hash),
                "signature": hex::encode(&sig),
                "encoded_payment_details": hex::encode(&det),
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("not the pinned enclave signer"),
        "got {}",
        body["error"]
    );
}

#[tokio::test]
async fn attest_pins_the_real_enclave_signer() {
    // The service has no test-signer path: an attestation signed by anything
    // but the pinned enclave key is refused, whatever the request says.
    let svc = service(funded_chain(30));
    let t = terms();
    call(svc.clone(), "POST", "/announce", Some(TOKEN), Some(announce_body(&t))).await;

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (status, body) = call(
        svc,
        "POST",
        "/attest",
        Some(TOKEN),
        Some(json!({
            "event_id": hex::encode(event_id(&t.funding_txid, 0)),
            "terms": WireTerms::from_terms(&t),
            "attestation": {
                "intent_hash": hex::encode(att.intent_hash),
                "release_amount": att.release_amount.to_string(),
                "data_hash": hex::encode(att.data_hash),
                "signature": hex::encode(&sig),
                "encoded_payment_details": hex::encode(&det),
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("not the pinned enclave signer"),
        "got {}",
        body["error"]
    );
}

#[tokio::test]
async fn the_announcement_binds_a_verifiable_outcome_point() {
    // What the user does with the response: recompute Y from R, P and the terms
    // hash, and encrypt its pre-signature under it. If the published R did not
    // match the nonce the attestor kept, no scalar it ever publishes would
    // decrypt anything.
    let svc = service(funded_chain(10));
    let t = terms();
    let (_, body) = call(
        svc.clone(),
        "POST",
        "/announce",
        Some(TOKEN),
        Some(announce_body(&t)),
    )
    .await;

    let secp = Secp256k1::new();
    let r = secp256k1_zkp::PublicKey::from_slice(
        &hex::decode(body["r"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let p = secp256k1_zkp::PublicKey::from_slice(
        &hex::decode(body["p"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(p, svc.public_key());

    let y = outcome_point(&secp, &r, &p, &event_id(&t.funding_txid, 0), &t.terms_hash())
        .expect("the announcement must yield a usable outcome point");
    // Nobody can produce the scalar yet, which is the whole point.
    assert!(verify_outcome_secret(
        &secp,
        &SecretKey::from_slice(&[0x99; 32]).unwrap(),
        &y
    )
    .is_err());
}
