//! Round 5 review PoCs, against the attestor service layer.
//!
//! Each test asserts the behaviour the spec asks for, and is `#[ignore]`d with
//! the finding it belongs to because the behaviour is not there yet. Run with
//! `cargo test -p zecp2p-attestor --test review_round5_pocs -- --ignored` to
//! see them fail; un-ignore each one when its finding is fixed.
//!
//! See `docs/status/review-round5-findings.md`.

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
use zecp2p_attestor::store::{EventStore, StoreError};
use zecp2p_attestor::{
    handle_announce_with_nonce, handle_attest_against_signer, AttestorError, ChainObservation,
    FixedClock,
};
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::{ChainClient, FakeChain, Utxo};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::payment_details::{
    RatePolicy, IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;
const TOKEN: &str = "test-bearer-token";
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

fn ev(n: u8) -> [u8; 32] {
    [n; 32]
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
    }
}

fn spk() -> Vec<u8> {
    p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap())
}

fn test_enclave() -> (Sk1, [u8; 20]) {
    let secp = Secp1::new();
    let key = Sk1::from_slice(&[0xe1; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let h: [u8; 32] = Keccak256::digest(&pubkey.serialize_uncompressed()[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    (key, addr)
}

fn attest_for(intent: [u8; 32], amount: u128, details: &[u8]) -> (PaymentAttestation, Vec<u8>) {
    let (key, _) = test_enclave();
    let att = PaymentAttestation {
        intent_hash: intent,
        release_amount: amount,
        data_hash: Keccak256::digest(details).into(),
    };
    let sig =
        Secp1::new().sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
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

fn observation() -> ChainObservation {
    ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 10,
        earliest_acceptable_payment_ms: NOW_MS,
    }
}

async fn call(
    app: axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"));
    let req = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            req.body(Body::from(serde_json::to_vec(&b).unwrap())).unwrap()
        }
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn attest_body(t: &CanonicalTerms) -> Value {
    let det = details(t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    json!({
        "event_id": hex::encode(event_id(&t.funding_txid, t.vout)),
        "terms": WireTerms::from_terms(t),
        "attestation": {
            "intent_hash": hex::encode(att.intent_hash),
            "release_amount": att.release_amount.to_string(),
            "data_hash": hex::encode(att.data_hash),
            "signature": hex::encode(&sig),
            "encoded_payment_details": hex::encode(&det),
        }
    })
}

// ---------------------------------------------------------------------------
// R5-1: a SQLite failure that is not a constraint violation is reported as a
// decision. `db.rs` maps every insert error to a Duplicate* variant and every
// update error to UnknownEvent/AlreadySigned, so a locked or unwritable
// database answers 409 "an announcement already exists" and 404 "no
// announcement exists". Spec section 6 and `service.rs` say the LP retries a
// 5xx and stops on a 4xx.
// ---------------------------------------------------------------------------

#[test]
fn r5_1_a_busy_database_is_not_a_duplicate_announcement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestor.sqlite");
    let path = path.to_str().unwrap();
    let mut db = SqliteEventStore::open(path).unwrap();

    // Another process holds the write lock: an operator's sqlite3 shell, a
    // backup, or a second replica.
    let other = rusqlite::Connection::open(path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();

    let err = db
        .announce(ev(1), ev(2), [3; 33], ev(4), ev(5), NOW_MS)
        .unwrap_err();
    assert_ne!(
        err,
        StoreError::DuplicateEvent,
        "a database that could not be written must not be reported as an announcement that \
         already exists; the LP will not retry a 409 and this escrow has no R"
    );
}

#[test]
fn r5_1b_a_busy_database_is_not_an_unknown_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestor.sqlite");
    let path = path.to_str().unwrap();
    let mut db = SqliteEventStore::open(path).unwrap();
    db.announce(ev(1), ev(2), [3; 33], ev(4), ev(5), NOW_MS)
        .unwrap();

    let other = rusqlite::Connection::open(path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();

    let err = db
        .sign_and_record(&ev(1), ev(0xaa), NOW_MS, |_| Ok(ev(0x77)))
        .unwrap_err();
    assert!(
        !matches!(err, StoreError::UnknownEvent | StoreError::AlreadySigned),
        "got {err:?}: a write that could not commit is neither an unknown event nor a signed one; \
         the LP has already paid Venmo and will read a 404 as a verdict"
    );
}

#[tokio::test]
async fn r5_1c_over_http_a_locked_database_answers_409() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestor.sqlite");
    let path = path.to_str().unwrap();
    let db = SqliteEventStore::open(path).unwrap();

    let other = rusqlite::Connection::open(path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();

    let svc = Arc::new(AttestorService::new(
        db,
        SecretKey::from_slice(&[0xd1; 32]).unwrap(),
        FakeChain::new(3_400_000, NU6_3),
        FixedClock(NOW_MS),
        TOKEN.to_string(),
        "test".into(),
    ));
    let (status, body) = call(
        router(svc),
        "POST",
        "/announce",
        Some(json!({ "terms": WireTerms::from_terms(&terms()) })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "got {status} {body}: a database the attestor cannot write is 'the attestor could not \
         look', which is the 5xx class the LP retries"
    );
}

// ---------------------------------------------------------------------------
// R5-2: `k` survives on disk after signing. The row's `k_sealed` is NULL, but
// the bytes remain in the WAL and in freed page space, because neither
// `secure_delete` nor a checkpoint is applied. Anyone with the file after the
// scalar is published recovers `d = (s - k) / e`.
// ---------------------------------------------------------------------------

#[test]
fn r5_2_the_nonce_is_gone_from_disk_after_signing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestor.sqlite");
    let path_s = path.to_str().unwrap();

    // A nonce with a recognisable pattern, so residue is unambiguous.
    let k: [u8; 32] = *b"NONCE-NONCE-NONCE-NONCE-NONCE-k!";
    let read_all = |label: &str| {
        let mut on_disk = std::fs::read(&path).unwrap();
        let wal = std::fs::read(dir.path().join("attestor.sqlite-wal")).unwrap_or_default();
        let wal_len = wal.len();
        on_disk.extend_from_slice(&wal);
        let found = on_disk.windows(k.len()).any(|w| w == k);
        eprintln!("{label}: db {} bytes, wal {wal_len} bytes, nonce residue: {found}", on_disk.len() - wal_len);
        found
    };

    let mut db = SqliteEventStore::open(path_s).unwrap();
    db.announce(ev(1), ev(2), [3; 33], ev(4), k, NOW_MS).unwrap();
    db.sign_and_record(&ev(1), ev(0xaa), NOW_MS, |seen| {
        assert_eq!(seen, &k);
        Ok(ev(0x77))
    })
    .unwrap();
    assert!(!db.holds_nonce(&ev(1)).unwrap(), "the row says k is gone");

    // The service is still running; this is what a copy of the data directory
    // sees at that moment.
    let while_open = read_all("while the service holds the connection");
    drop(db);
    let after_close = read_all("after the connection closed and checkpointed");

    assert!(
        !while_open && !after_close,
        "the nonce bytes are still on disk after the outcome was signed (while open: \
         {while_open}, after close: {after_close}); with the published scalar that is the \
         attestor key"
    );
}

// ---------------------------------------------------------------------------
// R5-3: acceptance criterion 8 says a second `/attest` for one event is
// refused. `handle_attest*` and `attest_over_db` return the stored scalar with
// HTTP 200 instead, before any check on the request. The scalar is public once
// the release is broadcast, so this is not a theft; it is a criterion the run
// will fail as written, and a way to learn `s` for an event whose release has
// not been broadcast yet.
// ---------------------------------------------------------------------------

#[test]
fn r5_3_a_second_attest_for_one_event_is_refused() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms();
    let e = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    handle_announce_with_nonce(&mut store, &secp, &FixedClock(NOW_MS), &e, &t, &k).unwrap();

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let first = handle_attest_against_signer(
        &mut store,
        &secp,
        &d,
        &e,
        &t,
        &att,
        &sig,
        &det,
        &observation(),
        &RatePolicy::production(),
        &signer,
    )
    .expect("the first attest signs");

    // The second call carries garbage: wrong terms, wrong attestation. It is
    // answered with the scalar anyway.
    let mut wrong = t.clone();
    wrong.usd_amount_6dec = 1;
    let second = handle_attest_against_signer(
        &mut store,
        &secp,
        &d,
        &e,
        &wrong,
        &att,
        &[0u8; 65],
        &[0u8; 448],
        &observation(),
        &RatePolicy::production(),
        &signer,
    );
    assert_eq!(
        second,
        Err(AttestorError::AlreadySigned),
        "criterion 8: a second /attest for the same event_id is refused; got {:?}",
        second.as_ref().map(|s| s.secret_bytes() == first.secret_bytes())
    );
}

// ---------------------------------------------------------------------------
// R5-4: the handler calls a blocking HTTP client from a tokio worker while
// holding a std Mutex. With the only real `ChainClient` in the repo
// (`RpcChainClient`, reqwest::blocking) the first `/attest` panics inside
// `observe_escrow`, and the panic poisons the store lock, so every later
// request panics too. The service tests never see this because they use
// `FakeChain`.
// ---------------------------------------------------------------------------

async fn mock_rpc(axum::Json(req): axum::Json<Value>) -> axum::Json<Value> {
    let method = req["method"].as_str().unwrap_or("");
    let result = match method {
        "getblockchaininfo" => json!({
            "chain": "test",
            "blocks": 3_400_000,
            "consensus": { "chaintip": "37a5165b" }
        }),
        "gettxout" => json!({
            "confirmations": 10,
            "value": 0.05,
            "scriptPubKey": { "hex": hex::encode(spk()) }
        }),
        _ => Value::Null,
    };
    axum::Json(json!({ "result": result, "error": null, "id": "zecp2p" }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_4_the_real_rpc_adapter_can_be_driven_from_inside_the_service() {
    use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().route("/", axum::routing::post(mock_rpc)))
            .await
            .unwrap();
    });

    // The adapter itself is fine on a plain thread: it sees the mock's escrow.
    let seen = std::thread::spawn({
        let t = terms();
        move || {
            let c = RpcChainClient::new(RpcConfig::public(
                format!("http://{addr}/"),
                Network::Test,
            ))
            .unwrap();
            c.utxo(&t.funding_txid, 0)
        }
    })
    .join()
    .unwrap()
    .unwrap();
    assert_eq!(
        seen,
        Some(Utxo {
            script_pubkey: spk(),
            amount_zat: 5_000_000,
            confirmations: 10
        })
    );

    // Building the blocking client inside the runtime panics outright, so it
    // is built on a plain thread, as a binary would have to.
    let chain = std::thread::spawn(move || {
        RpcChainClient::new(RpcConfig::public(format!("http://{addr}/"), Network::Test)).unwrap()
    })
    .join()
    .unwrap();

    let svc = Arc::new(AttestorService::new(
        SqliteEventStore::in_memory().unwrap(),
        SecretKey::from_slice(&[0xd1; 32]).unwrap(),
        chain,
        FixedClock(NOW_MS),
        TOKEN.to_string(),
        "test".into(),
    ));
    let t = terms();
    let (status, _) = call(
        router(svc.clone()),
        "POST",
        "/announce",
        Some(json!({ "terms": WireTerms::from_terms(&t) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "announce touches no chain and works");

    // The attest must reach the chain through the adapter and then stop at the
    // pinned signer, which is the expected refusal for a test-signed
    // attestation. Run it as a task so a panic is observed rather than
    // propagated.
    let attest = tokio::spawn({
        let svc = svc.clone();
        let t = t.clone();
        async move { call(router(svc), "POST", "/attest", Some(attest_body(&t))).await }
    });
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), attest).await;
    let panicked = match &outcome {
        Ok(Err(join)) => join.is_panic(),
        _ => false,
    };

    // Whatever happened to that request, the service must still answer the
    // next one. A poisoned Mutex means it does not.
    let next = tokio::spawn({
        let svc = svc.clone();
        async move {
            let mut t2 = terms();
            t2.funding_txid = [0x7b; 32];
            call(router(svc), "POST", "/announce", Some(json!({ "terms": WireTerms::from_terms(&t2) }))).await
        }
    })
    .await;
    let next_panicked = next.as_ref().err().is_some_and(|j| j.is_panic());

    assert!(
        !panicked && !next_panicked,
        "/attest panicked inside the handler: {panicked}; the following /announce panicked on \
         the poisoned store lock: {next_panicked}"
    );
    let (status, body) = outcome.unwrap().unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("not the pinned enclave signer"),
        "{body}"
    );
}
