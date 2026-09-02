//! Round 2 PoCs 2 and 3, ported to the fixed API.

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use zecp2p_attestor::store::EventStore;
use zecp2p_attestor::{
    decide_against_signer, handle_attest_against_signer, AttestorError, ChainObservation,
};
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::payment_details::{
    PaymentDetailsError, RatePolicy, IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY,
    VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const REFUND_HEIGHT: u64 = 3_500_000;
const USER_VENMO_HASH: [u8; 32] = [0x85; 32];
const NOW_MS: u64 = 1_788_315_013_000;
const MONTH_MS: u64 = 30 * 24 * 3600 * 1000;

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
    let sig = Secp1::new()
        .sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
    let (rec_id, compact) = sig.serialize_compact();
    let mut bytes = compact.to_vec();
    bytes.push(i32::from(rec_id) as u8 + 27);
    (att, bytes)
}

fn word_u(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn details(t: &CanonicalTerms, amount: u128, payment_ms: u64, index: u128) -> Vec<u8> {
    let words: [[u8; 32]; 14] = [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(index),
        USD_FIAT_CURRENCY,
        word_u(payment_ms as u128),
        [0x55; 32],
        t.intent_hash(),
        word_u(amount),
        VENMO_PAYMENT_METHOD,
        USD_FIAT_CURRENCY,
        t.payee_hash,
        word_u(t.rate_18dec),
        word_u((t.lock_confirmed_ms / 1000) as u128),
        word_u(1_209_600),
    ];
    words.concat()
}

fn terms_for(txid: [u8; 32], lock_confirmed_ms: u64) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: txid,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: [0x02; 33],
        l_pub: [0x03; 33],
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: USER_VENMO_HASH,
        lock_confirmed_ms,
    }
}

fn spk() -> Vec<u8> {
    p2sh_script_pubkey(&redeem_script(&[0x02; 33], &[0x03; 33], REFUND_HEIGHT).unwrap())
}

/// PoC 2: `lock_confirmed_ms` is the LP's number.
///
/// Setting it a month back made a month-old payment - one the LP genuinely made
/// to this user for an earlier trade - land inside the backdating tolerance,
/// re-proved under this escrow's intent hash. The recency bound now comes from
/// the attestor's own clock, so the LP's claim about when the lock confirmed
/// buys it nothing.
#[test]
fn poc2_a_month_old_payment_is_refused_when_the_attestor_uses_its_own_clock() {
    let t = terms_for([0x7a; 32], NOW_MS - MONTH_MS);
    let old_payment_ms = NOW_MS - MONTH_MS + 60_000;
    let blob = details(&t, 1_000_000, old_payment_ms, 77);
    let (att, sig) = attest_for(t.intent_hash(), 1_000_000, &blob);
    let (_, signer) = test_enclave();

    // The attestor's own view: it first heard of this escrow just now.
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    let err = decide_against_signer(
        &t.terms_hash(),
        false,
        &t,
        &att,
        &sig,
        &blob,
        &obs,
        &signer,
        &RatePolicy::production(),
        false,
    )
    .expect_err("a month-old payment must be refused");
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::PaymentPredatesLock { .. })
        ),
        "got {err}"
    );
}

/// The same escrow with a recent payment still verifies, so the fix is not a
/// blanket refusal.
#[test]
fn poc2b_a_recent_payment_still_verifies() {
    let t = terms_for([0x7a; 32], NOW_MS);
    let blob = details(&t, 1_000_000, NOW_MS + 60_000, 77);
    let (att, sig) = attest_for(t.intent_hash(), 1_000_000, &blob);
    let (_, signer) = test_enclave();
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    decide_against_signer(
        &t.terms_hash(),
        false,
        &t,
        &att,
        &sig,
        &blob,
        &obs,
        &signer,
        &RatePolicy::production(),
        false,
    )
    .expect("a payment made after the attestor announced the escrow is fine");
}

/// Even if the caller passes an observation whose bound is too generous,
/// `handle_attest` narrows it to the store's own announcement time.
#[test]
fn poc2c_the_handler_narrows_a_generous_observation_to_the_stores_own_clock() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms_for([0x7a; 32], NOW_MS - MONTH_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    store
        .announce(
            ev,
            t.terms_hash(),
            k.public_key(&secp).serialize(),
            t.funding_txid,
            k.secret_bytes(),
            NOW_MS, // the attestor announced it now
        )
        .unwrap();

    let old_payment_ms = NOW_MS - MONTH_MS + 60_000;
    let blob = details(&t, 1_000_000, old_payment_ms, 77);
    let (att, sig) = attest_for(t.intent_hash(), 1_000_000, &blob);

    // A caller that passes the LP's own claim as the bound.
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: t.lock_confirmed_ms,
    };

    let err = handle_attest_against_signer(
        &mut store,
        &secp,
        &d,
        &ev,
        &t,
        &att,
        &sig,
        &blob,
        &obs,
        &RatePolicy::production(),
        &signer,
    )
    .expect_err("the handler must use the announcement time, not the caller's bound");
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::PaymentPredatesLock { .. })
        ),
        "got {err}"
    );
    assert!(
        store.holds_nonce(&ev),
        "a refused attestation must not have touched the nonce"
    );
}

/// PoC 3: the nullifier was checked by the caller, after the scalar existed.
///
/// Two handlers both passed `decide`, both computed a scalar, and only the
/// second `mark_signed` refused - by which time the second scalar was in memory
/// and whether it reached the LP was up to a handler nobody had written.
/// `handle_attest` consults the store itself and returns the scalar only after
/// `mark_signed` has committed.
#[test]
fn poc3_the_second_escrow_never_produces_a_scalar_at_all() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let (_, signer) = test_enclave();
    let mut store = EventStore::new();

    let mut events = Vec::new();
    for (i, txid) in [[0x7a; 32], [0x7bu8; 32]].into_iter().enumerate() {
        let t = terms_for(txid, NOW_MS);
        let k = SecretKey::from_slice(&[0x40 + i as u8; 32]).unwrap();
        let ev = event_id(&txid, 0);
        store
            .announce(
                ev,
                t.terms_hash(),
                k.public_key(&secp).serialize(),
                txid,
                k.secret_bytes(),
                NOW_MS,
            )
            .unwrap();
        events.push((t, ev));
    }

    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 10,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    // One Venmo payment, presented against both escrows.
    let mut outcomes = Vec::new();
    for (t, ev) in &events {
        let blob = details(t, 1_000_000, NOW_MS + 60_000, 484);
        let (att, sig) = attest_for(t.intent_hash(), 1_000_000, &blob);
        outcomes.push(handle_attest_against_signer(
            &mut store,
            &secp,
            &d,
            ev,
            t,
            &att,
            &sig,
            &blob,
            &obs,
            &RatePolicy::production(),
            &signer,
        ));
    }

    outcomes[0]
        .as_ref()
        .expect("the first escrow this payment releases is fine");

    // The decisive assertion: the caller gets an error and *no scalar*. Before
    // the fix the second scalar was computed and handed back, and only a
    // separate `mark_signed` refused - after the value existed.
    let err = outcomes[1]
        .as_ref()
        .expect_err("the second call must yield no scalar at all");
    assert_eq!(err, &AttestorError::PaymentAlreadyConsumed);
    assert!(
        outcomes[1].is_err(),
        "no SecretKey may be returned for a payment already consumed"
    );

    // And the refusal happened before any nonce was touched, so nothing was
    // signed even internally.
    assert!(
        store.holds_nonce(&events[1].1),
        "the refused event must still hold its unused nonce"
    );
    assert!(store.signed_outcome(&events[1].1).is_none());
}

/// A repeated `/attest` for an event already signed is refused.
///
/// Round 2 had this returning the stored scalar, and this test asserted that.
/// Round 5 (R5-3) pointed out it fails acceptance criterion 8 as written -
/// "a second /attest for the same event_id is refused" - and that returning the
/// scalar before checking the request let any bearer-token holder read `s` for
/// an event whose release had not been broadcast. The criterion wins; the test
/// now asserts the refusal.
#[test]
fn a_repeated_attest_is_refused_rather_than_signing_twice() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms_for([0x7a; 32], NOW_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    store
        .announce(
            ev,
            t.terms_hash(),
            k.public_key(&secp).serialize(),
            t.funding_txid,
            k.secret_bytes(),
            NOW_MS,
        )
        .unwrap();

    let blob = details(&t, 1_000_000, NOW_MS + 60_000, 484);
    let (att, sig) = attest_for(t.intent_hash(), 1_000_000, &blob);
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 10,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    handle_attest_against_signer(
        &mut store, &secp, &d, &ev, &t, &att, &sig, &blob, &obs,
        &RatePolicy::production(), &signer,
    )
    .expect("the first attest signs");

    let err = handle_attest_against_signer(
        &mut store, &secp, &d, &ev, &t, &att, &sig, &blob, &obs,
        &RatePolicy::production(), &signer,
    )
    .expect_err("a second attest for one event must be refused");
    assert_eq!(err, AttestorError::AlreadySigned);

    assert!(!store.holds_nonce(&ev), "k is gone after the first signing");
}
