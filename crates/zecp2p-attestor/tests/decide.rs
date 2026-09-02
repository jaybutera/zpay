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

/// Payment details standing in for the enclave's 14-word ABI blob.
fn details() -> Vec<u8> {
    vec![0xab; 14 * 32]
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
    let d = details();
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
) -> Result<(), AttestorError> {
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
    let det = details();
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
    assert_eq!(store.take_nonce_for_signing(&[1; 32]).unwrap(), [5; 32]);

    store.mark_signed(&[1; 32], [7; 32]).unwrap();

    assert!(!store.holds_nonce(&[1; 32]), "k must be gone once signed");
    assert_eq!(
        store.take_nonce_for_signing(&[1; 32]),
        Err(StoreError::AlreadySigned),
        "a second signing attempt must find no nonce to reuse"
    );
    assert_eq!(
        store.mark_signed(&[1; 32], [8; 32]),
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
    store.mark_signed(&[1; 32], [7; 32]).unwrap();

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
        store.mark_signed(&[1; 32], [7; 32]),
        Err(StoreError::UnknownEvent)
    );
}
