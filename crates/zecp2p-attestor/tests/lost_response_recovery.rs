//! R6-2: an LP that loses the response must be able to ask again.
//!
//! The paid path has one exit. The LP sends Venmo, calls `/attest`, and needs
//! `s` to complete the user's pre-signature. If that response is lost - a
//! timeout shorter than the attestor's chain round trip is enough - the sign
//! has already committed, the nonce is gone and the payment is consumed.
//!
//! Round 5 (R5-3) made the repeat a flat 409, and the comment claimed the LP
//! could read `s` off the chain instead. That was wrong: no release reaches the
//! chain without `s`, so the LP was left having paid the fiat with no way to
//! collect, and the user refunded at `T`.
//!
//! The rule now is narrower than "idempotent" and wider than "refused": a
//! repeat that is *the same request* - same announced terms, same payment - and
//! that passes every other check gets the same scalar back. Anything else is
//! still 409. Criterion 8's substance is kept, and the argument is in spec 19.1.

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::{attest_over_db_against_signer, AttestorError, FixedClock};
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::{FakeChain, Utxo};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::payment_details::{
    RatePolicy, IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

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
    let sig = Secp1::new().sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
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

fn details_with(t: &CanonicalTerms, index: u128) -> Vec<u8> {
    [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(index),
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

fn chain(confirmations: u32) -> FakeChain {
    let mut c = FakeChain::new(3_400_000, NU6_3);
    c.add_utxo(
        [0x7a; 32],
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

fn setup() -> (SqliteEventStore, [u8; 32], CanonicalTerms) {
    let secp = Secp256k1::new();
    let mut db = SqliteEventStore::in_memory().unwrap();
    let t = terms();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let ev = event_id(&t.funding_txid, 0);
    db.announce(
        ev,
        t.terms_hash(),
        k.public_key(&secp).serialize(),
        t.funding_txid,
        k.secret_bytes(),
        NOW_MS,
    )
    .unwrap();
    (db, ev, t)
}

#[allow(clippy::too_many_arguments)]
fn attest(
    db: &mut SqliteEventStore,
    ev: &[u8; 32],
    t: &CanonicalTerms,
    att: &PaymentAttestation,
    sig: &[u8],
    det: &[u8],
) -> Result<SecretKey, AttestorError> {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let (_, signer) = test_enclave();
    attest_over_db_against_signer(
        db,
        &chain(30),
        &secp,
        &d,
        &FixedClock(NOW_MS),
        ev,
        t,
        att,
        sig,
        det,
        &RatePolicy::production(),
        &signer,
    )
}

#[test]
fn an_lp_that_lost_the_response_gets_the_same_scalar_back() {
    // The PoC's scenario: the sign committed, the client never saw it, and the
    // LP retries the identical request.
    let (mut db, ev, t) = setup();
    let det = details_with(&t, 484);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let first = attest(&mut db, &ev, &t, &att, &sig, &det).expect("the first attest signs");
    let second = attest(&mut db, &ev, &t, &att, &sig, &det)
        .expect("the identical request must return the same scalar");

    assert_eq!(
        first.secret_bytes(),
        second.secret_bytes(),
        "a replay must yield the value already published, not a new signature"
    );
    // And nothing was signed twice: the nonce is still gone and the stored
    // outcome is unchanged.
    assert!(!db.holds_nonce(&ev).unwrap());
    assert_eq!(db.signed_outcome(&ev).unwrap(), Some(first.secret_bytes()));
}

#[test]
fn a_repeat_with_a_different_payment_is_still_refused() {
    // R5-3's point survives: the replay is gated on the payment, so an LP
    // cannot present a different payment against a signed event.
    let (mut db, ev, t) = setup();
    let det = details_with(&t, 484);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();

    let other_det = details_with(&t, 999);
    let (other_att, other_sig) =
        attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &other_det);
    assert_eq!(
        attest(&mut db, &ev, &t, &other_att, &other_sig, &other_det).unwrap_err(),
        AttestorError::AlreadySigned
    );
}

#[test]
fn a_repeat_with_a_zero_signature_and_a_zero_blob_is_refused() {
    // The exact request R5-3 used to read `s` out of the attestor. It must not
    // work, because the replay is checked *after* the request is validated.
    let (mut db, ev, t) = setup();
    let det = details_with(&t, 484);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();

    let zero_att = PaymentAttestation {
        intent_hash: [0u8; 32],
        release_amount: 0,
        data_hash: [0u8; 32],
    };
    // It is refused. Which refusal it earns depends on where it first diverges:
    // a zero blob hashes to a different payment nullifier than the one recorded,
    // so it is not a replay of this request, and the event is already signed.
    // What matters is that no scalar comes back.
    let err = attest(&mut db, &ev, &t, &zero_att, &[0u8; 65], &vec![0u8; 14 * 32])
        .expect_err("a zero request must not read out the scalar");
    assert_eq!(err, AttestorError::AlreadySigned);

    // And the same on a *fresh* event, where "already signed" cannot be the
    // reason: the request has to stand on its own merits.
    let (mut fresh_db, fresh_ev, fresh_t) = setup();
    let err = attest(
        &mut fresh_db,
        &fresh_ev,
        &fresh_t,
        &zero_att,
        &[0u8; 65],
        &vec![0u8; 14 * 32],
    )
    .expect_err("a zero request is not a valid attestation");
    assert_ne!(err, AttestorError::AlreadySigned, "got {err}");
    assert!(fresh_db.holds_nonce(&fresh_ev).unwrap(), "nothing was signed");
}

#[test]
fn a_repeat_with_different_terms_is_refused() {
    // Criterion 8's substance: a second /attest for this event under terms the
    // announcement did not pin gets nothing.
    let (mut db, ev, t) = setup();
    let det = details_with(&t, 484);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();

    let mut other = t.clone();
    other.usd_amount_6dec = 1;
    let other_det = details_with(&other, 484);
    let (other_att, other_sig) =
        attest_for(other.intent_hash(), other.usd_amount_6dec as u128, &other_det);

    let err = attest(&mut db, &ev, &other, &other_att, &other_sig, &other_det)
        .expect_err("different terms must be refused");
    // The announced terms hash no longer matches, which is the check that bites.
    assert!(
        matches!(err, AttestorError::TermsChanged | AttestorError::AlreadySigned),
        "got {err}"
    );
}

#[test]
fn the_replay_does_not_consume_the_payment_a_second_time() {
    // The nullifier is UNIQUE, so a replay that counted as a fresh consumption
    // would fail on the constraint rather than returning the scalar.
    let (mut db, ev, t) = setup();
    let det = details_with(&t, 484);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();
    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();
    attest(&mut db, &ev, &t, &att, &sig, &det).unwrap();

    // And the payment still cannot release a second escrow.
    let secp = Secp256k1::new();
    let mut t2 = terms();
    t2.funding_txid = [0x7b; 32];
    let k2 = SecretKey::from_slice(&[0x4c; 32]).unwrap();
    let ev2 = event_id(&t2.funding_txid, 0);
    db.announce(
        ev2,
        t2.terms_hash(),
        k2.public_key(&secp).serialize(),
        t2.funding_txid,
        k2.secret_bytes(),
        NOW_MS,
    )
    .unwrap();

    let det2 = details_with(&t2, 484);
    let (att2, sig2) = attest_for(t2.intent_hash(), t2.usd_amount_6dec as u128, &det2);
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let (_, signer) = test_enclave();
    let mut c2 = FakeChain::new(3_400_000, NU6_3);
    c2.add_utxo(
        t2.funding_txid,
        0,
        Utxo {
            script_pubkey: p2sh_script_pubkey(
                &redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap(),
            ),
            amount_zat: 5_000_000,
            confirmations: 30,
        },
    );
    let err = attest_over_db_against_signer(
        &mut db, &c2, &secp, &d, &FixedClock(NOW_MS), &ev2, &t2, &att2, &sig2, &det2,
        &RatePolicy::production(), &signer,
    )
    .expect_err("one payment still releases one escrow");
    assert_eq!(err, AttestorError::PaymentAlreadyConsumed);
}
