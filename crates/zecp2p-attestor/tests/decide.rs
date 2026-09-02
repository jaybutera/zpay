//! The attestor's decision path, spec 5.5 steps 1 to 5.
//!
//! This is the code that decides whether a user's ZEC moves, so each check is
//! tested on its own: the request is otherwise valid and one thing is wrong.
//! Reaching the later checks needs an attestation genuinely bound to the terms
//! under test, which the real enclave key cannot be made to produce, so these
//! tests sign with a key of their own and pin it as the trusted signer. That
//! the *production* signer and domain verify real enclave output is proved
//! separately, in the escrow crate's `attestation_vectors.rs`.

use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use zecp2p_attestor::store::{EventStore, StoreError};
use zecp2p_attestor::{
    decide, decide_against_signer, required_depth, AttestorError, ChainObservation,
};
use zecp2p_escrow::attestation::{eip712_digest, AttestationError, PaymentAttestation};
use zecp2p_escrow::payment_details::{
    PaymentDetailsError, RatePolicy, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];
const REFUND_HEIGHT: u64 = 3_500_000;

fn terms() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_000_000,
        rate_18dec: 990_881_148_896_019_200,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
    }
}

fn script_pubkey() -> Vec<u8> {
    p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap())
}

fn observation() -> ChainObservation {
    ChainObservation {
        script_pubkey: script_pubkey(),
        amount_zat: 5_000_000,
        confirmations: 10,
    }
}

/// A stand-in enclave: a key this test controls, and the address it recovers to.
fn test_enclave() -> (SecretKey, [u8; 20]) {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0xe1; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let h: [u8; 32] = Keccak256::digest(&pubkey.serialize_uncompressed()[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    (key, addr)
}

/// Produces an attestation genuinely signed for `intent` and `amount`, with a
/// `dataHash` that matches the payment details, exactly as the enclave would.
fn attest_for(intent: [u8; 32], amount: u128, details: &[u8]) -> (PaymentAttestation, Vec<u8>) {
    let (key, _) = test_enclave();
    let data_hash: [u8; 32] = Keccak256::digest(details).into();
    let att = PaymentAttestation {
        intent_hash: intent,
        release_amount: amount,
        data_hash,
    };
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
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

/// The enclave's 14-word blob, spec 12.1, describing a genuine payment for
/// these terms: to the user's Venmo, in USD, at the quoted rate, timestamped
/// just after the lock.
fn details_for(t: &CanonicalTerms) -> Vec<u8> {
    details_with(t, |_| {})
}

/// The same, with one field bent by the caller. Every adversarial test below is
/// this: a payment that is genuine in every respect but one.
fn details_with(t: &CanonicalTerms, bend: impl FnOnce(&mut [[u8; 32]; 14])) -> Vec<u8> {
    let payment_ms = t.lock_confirmed_ms + 60_000;
    let mut words: [[u8; 32]; 14] = [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(484),
        USD_FIAT_CURRENCY,
        word_u(payment_ms as u128),
        [0x55; 32],
        t.intent_hash(),
        word_u(t.usd_amount_6dec as u128),
        VENMO_PAYMENT_METHOD,
        USD_FIAT_CURRENCY,
        t.payee_hash,
        word_u(t.rate_18dec),
        word_u((payment_ms / 1000) as u128),
        word_u(1_209_600),
    ];
    bend(&mut words);
    words.concat()
}

/// A fully valid request. Every failing test below is this, with one change.
fn valid() -> (
    CanonicalTerms,
    PaymentAttestation,
    Vec<u8>,
    Vec<u8>,
    ChainObservation,
    [u8; 20],
) {
    let t = terms();
    let d = details_for(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &d);
    let (_, signer) = test_enclave();
    (t, att, sig, d, observation(), signer)
}

#[allow(clippy::too_many_arguments)]
fn run(
    t: &CanonicalTerms,
    announced: &[u8; 32],
    already_signed: bool,
    att: &PaymentAttestation,
    sig: &[u8],
    det: &[u8],
    obs: &ChainObservation,
    signer: &[u8; 20],
) -> Result<[u8; 32], AttestorError> {
    run_with(t, announced, already_signed, att, sig, det, obs, signer,
             &RatePolicy::Exact(t.rate_18dec), false)
}

#[allow(clippy::too_many_arguments)]
fn run_with(
    t: &CanonicalTerms,
    announced: &[u8; 32],
    already_signed: bool,
    att: &PaymentAttestation,
    sig: &[u8],
    det: &[u8],
    obs: &ChainObservation,
    signer: &[u8; 20],
    rate: &RatePolicy,
    consumed: bool,
) -> Result<[u8; 32], AttestorError> {
    decide_against_signer(
        announced,
        already_signed,
        t,
        att,
        sig,
        det,
        obs,
        &script_pubkey(),
        signer,
        rate,
        consumed,
    )
}

#[test]
fn a_valid_request_is_accepted() {
    // Without this the negative tests could all be passing for the wrong
    // reason.
    let (t, att, sig, det, obs, signer) = valid();
    run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer)
        .expect("a well-formed, paid, confirmed escrow must be signable");
}

#[test]
fn an_attestation_for_a_different_intent_is_refused() {
    // The central binding of the design. The enclave signs whatever 32 bytes it
    // is handed, so if the attestor did not recompute the intent from the terms
    // an LP could present an attestation for a payment it made to someone else.
    let (t, _, _, det, obs, signer) = valid();
    let (att, sig) = attest_for([0xAB; 32], t.usd_amount_6dec as u128, &det);

    assert_eq!(
        run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::IntentMismatch
    );
}

#[test]
fn an_underpayment_is_refused() {
    // Spec 5.5 step 4. The LP must not release a 1 USD escrow with a 0.99 USD
    // payment.
    let (t, _, _, det, obs, signer) = valid();
    let (att, sig) = attest_for(t.intent_hash(), (t.usd_amount_6dec - 1) as u128, &det);

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::Attestation(AttestationError::InsufficientAmount { .. })
        ),
        "got {err}"
    );
}

#[test]
fn an_overpayment_is_accepted() {
    // The rule is `releaseAmount >= usd_amount_6dec`, so paying more is fine.
    let (t, _, _, det, obs, signer) = valid();
    let (att, sig) = attest_for(t.intent_hash(), (t.usd_amount_6dec + 1) as u128, &det);
    run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap();
}

#[test]
fn an_attestation_signed_by_another_key_is_refused() {
    // The production path pins the real enclave signer; here the request is
    // otherwise perfect and only the signer is wrong.
    let (t, att, sig, det, obs, _) = valid();
    let wrong_signer = [0x11u8; 20];

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &wrong_signer).unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::Attestation(AttestationError::WrongSigner { .. })
        ),
        "got {err}"
    );
}

#[test]
fn payment_details_that_do_not_match_the_signed_data_hash_are_refused() {
    let (t, att, sig, _, obs, signer) = valid();
    let tampered = vec![0xcd; 14 * 32];

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &tampered, &obs, &signer).unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::Attestation(AttestationError::DataHashMismatch)
        ),
        "got {err}"
    );
}

#[test]
fn terms_altered_after_the_announcement_are_refused() {
    // Spec 5.5 step 1. The announcement pins the terms hash, so an LP cannot
    // announce at one price and attest at another.
    let (t, att, sig, det, obs, signer) = valid();
    let announced = t.terms_hash();

    let mut altered = t.clone();
    altered.usd_amount_6dec = 1;

    assert_eq!(
        run(&altered, &announced, false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::TermsChanged
    );
}

#[test]
fn a_second_attestation_for_a_signed_event_is_refused() {
    // Acceptance criterion 8.
    let (t, att, sig, det, obs, signer) = valid();
    assert_eq!(
        run(&t, &t.terms_hash(), true, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::AlreadySigned
    );
}

#[test]
fn an_escrow_paying_a_different_script_is_refused() {
    // The attestor confirms on its own node that the output it is signing for
    // is the escrow the terms describe, not some other output the LP controls.
    let (t, att, sig, det, mut obs, signer) = valid();
    obs.script_pubkey = p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, 9_999_999).unwrap());

    assert_eq!(
        run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::WrongScriptPubkey
    );
}

#[test]
fn an_escrow_holding_the_wrong_amount_is_refused() {
    let (t, att, sig, det, mut obs, signer) = valid();
    obs.amount_zat = 4_999_999;

    assert_eq!(
        run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::WrongAmount {
            found: 4_999_999,
            expected: 5_000_000
        }
    );
}

#[test]
fn an_insufficiently_confirmed_escrow_is_refused() {
    // The attestor applies the depth table independently of the LP, because it
    // is the party protecting the user against a reorg unwinding the lock.
    let (t, att, sig, det, mut obs, signer) = valid();
    obs.confirmations = 9;

    assert_eq!(
        run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::InsufficientDepth {
            found: 9,
            required: 10
        }
    );

    // And exactly at the threshold it passes, so the boundary is not off by one.
    obs.confirmations = 10;
    run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap();
}

#[test]
fn a_larger_escrow_demands_a_deeper_confirmation() {
    // A 100 USD escrow needs 30 confirmations, so the 10 that sufficed for 1
    // USD must not be enough here.
    let mut t = terms();
    t.usd_amount_6dec = 100_000_000;
    let det = details_for(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let mut obs = observation();
    obs.confirmations = 10;
    assert_eq!(
        run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap_err(),
        AttestorError::InsufficientDepth {
            found: 10,
            required: 30
        }
    );

    obs.confirmations = 30;
    run(&t, &t.terms_hash(), false, &att, &sig, &det, &obs, &signer).unwrap();
}

#[test]
fn the_production_path_pins_the_real_enclave_signer() {
    // `decide` must not accept the test key. This is the check that the
    // injectable signer above is a testing affordance and not a hole.
    let (t, att, sig, det, obs, _) = valid();
    let err = decide(
        &t.terms_hash(),
        false,
        &t,
        &att,
        &sig,
        &det,
        &obs,
        &script_pubkey(),
        &RatePolicy::Exact(t.rate_18dec),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::Attestation(AttestationError::WrongSigner { .. })
        ),
        "the default decide() must only trust the real enclave, got {err}"
    );
}

#[test]
fn the_depth_table_matches_spec_section_7() {
    assert_eq!(required_depth(0), 10);
    assert_eq!(required_depth(1_000_000), 10, "1 USD");
    assert_eq!(required_depth(50_000_000), 10, "50 USD is in the first tier");
    assert_eq!(required_depth(50_000_001), 30);
    assert_eq!(required_depth(500_000_000), 30, "500 USD is in the second tier");
    assert_eq!(required_depth(500_000_001), 100);
    assert_eq!(required_depth(u64::MAX), 100);
}

// --- The store's two rules. ---

#[test]
fn the_store_refuses_a_second_announcement_for_one_event() {
    let mut store = EventStore::new();
    store.announce([1; 32], [2; 32], [3; 33], [4; 32], [5; 32]).unwrap();
    assert_eq!(
        store.announce([1; 32], [9; 32], [9; 33], [9; 32], [9; 32]),
        Err(StoreError::DuplicateEvent),
        "a second announcement would mean a second nonce for one escrow"
    );
}

#[test]
fn the_store_refuses_a_second_announcement_for_one_funding_transaction() {
    let mut store = EventStore::new();
    store.announce([1; 32], [2; 32], [3; 33], [4; 32], [5; 32]).unwrap();
    assert_eq!(
        store.announce([9; 32], [2; 32], [3; 33], [4; 32], [6; 32]),
        Err(StoreError::DuplicateFundingTx)
    );
}

#[test]
fn the_nonce_is_destroyed_when_the_outcome_is_signed() {
    // The rule that stops `d` leaking. The escrow crate's dlc tests show what
    // reusing a nonce actually costs.
    let mut store = EventStore::new();
    store.announce([1; 32], [2; 32], [3; 33], [4; 32], [5; 32]).unwrap();

    assert!(store.holds_nonce(&[1; 32]));
    let bound = store.take_nonce_for_signing(&[1; 32]).unwrap();
    assert_eq!(bound.secret_for(&[1; 32]), Some(&[5u8; 32]));
    assert_eq!(
        bound.secret_for(&[2; 32]),
        None,
        "a nonce must not be usable for an event it was not drawn for"
    );

    store.mark_signed(&[1; 32], [7; 32], [0x9a; 32]).unwrap();

    assert!(!store.holds_nonce(&[1; 32]), "k must be gone once signed");
    assert_eq!(
        store.take_nonce_for_signing(&[1; 32]),
        Err(StoreError::AlreadySigned),
        "a second signing attempt must find no nonce to reuse"
    );
    assert_eq!(
        store.mark_signed(&[1; 32], [8; 32], [0x9a; 32]),
        Err(StoreError::AlreadySigned)
    );
}

#[test]
fn a_signed_event_returns_the_same_scalar_rather_than_signing_again() {
    // Criterion 8 refuses a second /attest. Returning the scalar already
    // published is safe, since it is public once the release is broadcast;
    // signing again under a fresh nonce would not be.
    let mut store = EventStore::new();
    store.announce([1; 32], [2; 32], [3; 33], [4; 32], [5; 32]).unwrap();
    store.mark_signed(&[1; 32], [7; 32], [0x9a; 32]).unwrap();

    assert_eq!(store.signed_outcome(&[1; 32]), Some([7; 32]));
    assert_eq!(store.signed_outcome(&[2; 32]), None);
}

#[test]
fn signing_an_unannounced_event_is_refused() {
    let mut store = EventStore::new();
    assert_eq!(
        store.take_nonce_for_signing(&[1; 32]),
        Err(StoreError::UnknownEvent)
    );
    assert_eq!(
        store.mark_signed(&[1; 32], [7; 32], [0x9a; 32]),
        Err(StoreError::UnknownEvent)
    );
}

// --- Review finding 1, critical: the attestor must read what the payment
// --- details actually say, not merely that the enclave signed them.
//
// The enclave signs whatever payment the caller proved. Checking only that
// keccak256(details) equals the signed dataHash proves the bytes are authentic
// and nothing about what they claim. Each test below is a payment that is
// genuine in every respect except one, signed by a real key, with a matching
// dataHash - exactly what an LP could produce.

#[test]
fn a_payment_to_the_lps_own_venmo_is_refused() {
    // The headline attack: the LP pays itself, proves it honestly, and claims
    // the escrow. Before the fix every check passed.
    let t = terms();
    let det = details_with(&t, |w| {
        w[1] = [0x11; 32]; // payeeDetails
        w[10] = [0x11; 32]; // and its second copy
    });
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::WrongPayee { .. })
        ),
        "a payment to an account that is not the user's must be refused, got {err}"
    );
}

#[test]
fn a_payment_whose_two_payee_copies_disagree_is_refused() {
    // The blob carries the payee twice. An LP that bent only the copy the
    // attestor happened to read would otherwise slip through.
    let t = terms();
    let det = details_with(&t, |w| w[10] = [0x11; 32]);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::InternalDisagreement {
                field: "payeeDetails"
            })
        ),
        "got {err}"
    );
}

#[test]
fn a_payment_made_long_before_the_lock_is_refused() {
    // The PoC used a payment a month old. A payment that predates the escrow
    // cannot be a payment for it.
    let t = terms();
    let stale = t.lock_confirmed_ms - 30 * 24 * 3600 * 1000;
    let det = details_with(&t, |w| {
        w[4] = word_u(stale as u128);
        w[12] = word_u((stale / 1000) as u128);
    });
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::PaymentPredatesLock { .. })
        ),
        "got {err}"
    );
}

#[test]
fn a_payment_slightly_before_the_lock_is_still_accepted() {
    // Not slack for its own sake: the captured 1.00 USD attestation carries a
    // payment timestamped 155 s before its own intent timestamp, because
    // Venmo's clock and the prover's snapshot are different clocks. A strict
    // comparison would reject genuine attestations.
    let t = terms();
    let slightly_early = t.lock_confirmed_ms - 155_000;
    let det = details_with(&t, |w| w[4] = word_u(slightly_early as u128));
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .expect("155 s of clock skew is what real attestations look like");
}

#[test]
fn a_payment_at_a_rate_the_lp_chose_is_refused() {
    // The PoC set conversionRate to 1 wei. Under an Exact policy the rate must
    // be the one the terms quoted.
    let t = terms();
    let det = details_with(&t, |w| w[11] = word_u(1));
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::RateMismatch { .. })
        ),
        "got {err}"
    );
}

#[test]
fn the_rate_policy_can_be_relaxed_but_says_so_explicitly() {
    // Finding 6: word 11's semantics for a ZEC escrow are not settled by
    // anything captured, so the policy is a value rather than a silent
    // omission. Unenforced is the development stance; Exact is production.
    let t = terms();
    let det = details_with(&t, |w| w[11] = word_u(1));
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    run_with(
        &t,
        &t.terms_hash(),
        false,
        &att,
        &sig,
        &det,
        &observation(),
        &signer,
        &RatePolicy::Unenforced,
        false,
    )
    .expect("an explicitly unenforced rate policy accepts any rate");
}

#[test]
fn a_payment_in_another_currency_is_refused() {
    let t = terms();
    let det = details_with(&t, |w| {
        w[3] = [0x77; 32];
        w[9] = [0x77; 32];
    });
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::WrongFiatCurrency)
        ),
        "got {err}"
    );
}

#[test]
fn a_payment_on_another_platform_is_refused() {
    let t = terms();
    let det = details_with(&t, |w| {
        w[0] = [0x66; 32];
        w[8] = [0x66; 32];
    });
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::WrongPaymentMethod)
        ),
        "got {err}"
    );
}

#[test]
fn the_intent_inside_the_payment_details_must_match_too() {
    // The signed typedDataValue carries an intentHash, and so does word 6 of
    // the details. Checking only the former leaves the payment itself unbound.
    let t = terms();
    let det = details_with(&t, |w| w[6] = [0xAB; 32]);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::IntentMismatch { .. })
        ),
        "got {err}"
    );
}

#[test]
fn a_details_blob_of_the_wrong_length_is_refused_rather_than_panicking() {
    let t = terms();
    let det = vec![0xab; 13 * 32];
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    let err = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::WrongLength(416))
        ),
        "got {err}"
    );
}

// --- Review finding 5: one Venmo payment releases one escrow.

#[test]
fn a_payment_already_used_for_another_escrow_is_refused() {
    let t = terms();
    let det = details_for(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);
    let (_, signer) = test_enclave();

    // First use succeeds and yields the nullifier the caller records.
    let nullifier = run(&t, &t.terms_hash(), false, &att, &sig, &det, &observation(), &signer)
        .expect("the first escrow this payment releases is fine");

    // Presented again, with the caller reporting the payment as consumed.
    let err = run_with(
        &t,
        &t.terms_hash(),
        false,
        &att,
        &sig,
        &det,
        &observation(),
        &signer,
        &RatePolicy::Exact(t.rate_18dec),
        true,
    )
    .unwrap_err();
    assert_eq!(err, AttestorError::PaymentAlreadyConsumed);
    assert_ne!(nullifier, [0u8; 32], "the nullifier must be a real value");
}

#[test]
fn two_different_payments_have_different_nullifiers() {
    // The nullifier must distinguish payments, or a second genuine payment
    // would be refused as a replay.
    let t = terms();
    let a = details_for(&t);
    let b = details_with(&t, |w| w[2] = word_u(485)); // a different payment index
    let (_, signer) = test_enclave();

    let (att_a, sig_a) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &a);
    let (att_b, sig_b) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &b);

    let na = run(&t, &t.terms_hash(), false, &att_a, &sig_a, &a, &observation(), &signer).unwrap();
    let nb = run(&t, &t.terms_hash(), false, &att_b, &sig_b, &b, &observation(), &signer).unwrap();
    assert_ne!(na, nb, "two distinct payments must not share a nullifier");
}

#[test]
fn the_store_refuses_to_consume_one_payment_for_two_events() {
    use zecp2p_attestor::store::EventStore;
    let mut store = EventStore::new();
    let nullifier = [0x9a; 32];

    store.announce([1; 32], [2; 32], [3; 33], [4; 32], [5; 32]).unwrap();
    store.announce([6; 32], [7; 32], [8; 33], [9; 32], [10; 32]).unwrap();

    store.mark_signed(&[1; 32], [7; 32], nullifier).unwrap();
    assert!(store.payment_is_consumed(&nullifier));
    assert_eq!(store.payment_consumed_by(&nullifier), Some([1; 32]));

    assert_eq!(
        store.mark_signed(&[6; 32], [8; 32], nullifier),
        Err(StoreError::PaymentAlreadyConsumed),
        "one payment must not release a second escrow"
    );
}
