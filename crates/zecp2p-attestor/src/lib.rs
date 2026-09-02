//! The outcome attestor of spec section 6.
//!
//! What this service can and cannot do is the whole point of the design, so it
//! is worth stating at the top. It holds a long-lived key `d` and a per-event
//! nonce `k`. It never sees a Zcash sighash, never holds an escrow key, and the
//! only thing it emits is a scalar `s = k + e*d`. That scalar releases exactly
//! one escrow, and only in combination with a pre-signature the user made and
//! the LP's own signature.
//!
//! What it *can* do, stated as plainly as the spec does: signing a `paid`
//! outcome for an escrow that was never paid hands the LP the user's ZEC. That
//! is why `decide` below is a pure function of the request and the pinned
//! constants, with no manual override and no path that skips the enclave check.

pub mod store;

use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use zecp2p_escrow::attestation::{
    verify_with_signer, AttestationError, PaymentAttestation, ENCLAVE_SIGNER,
};
use zecp2p_escrow::payment_details::{
    payment_nullifier, PaymentDetails, PaymentDetailsError, RatePolicy,
};
use zecp2p_escrow::dlc::{outcome_point, sign_outcome, DlcError};
use zecp2p_escrow::terms::CanonicalTerms;

/// A funded escrow output as the attestor's own node reports it (spec 5.5
/// step 5), together with the attestor's own view of when this escrow could
/// first have been paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainObservation {
    pub script_pubkey: Vec<u8>,
    pub amount_zat: u64,
    pub confirmations: u32,
    /// The earliest wall-clock time, in milliseconds, at which a payment for
    /// this escrow could plausibly have been made.
    ///
    /// This must come from something the attestor observed: the moment it
    /// issued the announcement (`events.announced_at_ms`), or the funding
    /// block's own timestamp read from its node. It must never be
    /// `terms.lock_confirmed_ms`, which the LP writes - bounding recency
    /// against a number the adversary chose bounds nothing (round 2 finding 2).
    pub earliest_acceptable_payment_ms: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestorError {
    #[error("no announcement exists for this event")]
    UnknownEvent,
    #[error("this event has already been signed")]
    AlreadySigned,
    #[error("an announcement already exists for this funding transaction")]
    DuplicateAnnouncement,
    #[error("the terms do not hash to the value pinned at announcement")]
    TermsChanged,
    #[error("the attestation is for a different intent than these terms")]
    IntentMismatch,
    #[error("attestation rejected: {0}")]
    Attestation(#[from] AttestationError),
    #[error("the escrow output does not pay the expected script")]
    WrongScriptPubkey,
    #[error("the escrow holds {found} zat, the terms say {expected}")]
    WrongAmount { found: u64, expected: u64 },
    #[error("the escrow has {found} confirmations, {required} are required for this size")]
    InsufficientDepth { found: u32, required: u32 },
    #[error("dlc error: {0}")]
    Dlc(#[from] DlcError),
    #[error("payment details rejected: {0}")]
    PaymentDetails(#[from] PaymentDetailsError),
    #[error(
        "this Venmo payment has already released another escrow; one payment releases one escrow"
    )]
    PaymentAlreadyConsumed,
}

/// The confirmation depth table of spec section 7, applied by the attestor
/// independently of the LP.
///
/// The LP applying it protects the LP. The attestor applying it protects the
/// user, because the attestor is the party that will not sign. Both call the
/// same function so the two cannot drift apart.
pub use zecp2p_escrow::depth::required_depth;

/// The verification of spec 5.5 steps 1 to 5, as a pure function.
///
/// Keeping this free of I/O is deliberate: the whole security argument for the
/// attestor is that its signing path is a few hundred lines that can be read,
/// and in Phase 7 measured. A branch that depended on hidden state could not be
/// audited from the outside.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    announced_terms_hash: &[u8; 32],
    already_signed: bool,
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    rate: &RatePolicy,
    payment_already_consumed: bool,
) -> Result<[u8; 32], AttestorError> {
    decide_inner(
        announced_terms_hash,
        already_signed,
        terms,
        attestation,
        signature,
        encoded_payment_details,
        observation,
        &ENCLAVE_SIGNER,
        rate,
        payment_already_consumed,
    )
}

/// As [`decide`], but against a caller-supplied trusted enclave signer.
///
/// Gated behind `test-signer` so a production build has no path that trusts
/// anything but the pinned enclave key.
#[cfg(feature = "test-signer")]
#[allow(clippy::too_many_arguments)]
pub fn decide_against_signer(
    announced_terms_hash: &[u8; 32],
    already_signed: bool,
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    trusted_signer: &[u8; 20],
    rate: &RatePolicy,
    payment_already_consumed: bool,
) -> Result<[u8; 32], AttestorError> {
    decide_inner(
        announced_terms_hash,
        already_signed,
        terms,
        attestation,
        signature,
        encoded_payment_details,
        observation,
        trusted_signer,
        rate,
        payment_already_consumed,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_inner(
    announced_terms_hash: &[u8; 32],
    already_signed: bool,
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    trusted_signer: &[u8; 20],
    rate: &RatePolicy,
    payment_already_consumed: bool,
) -> Result<[u8; 32], AttestorError> {
    // 1. The terms must be the ones the announcement committed to. Without
    //    this the LP could announce against one escrow and attest against
    //    another.
    if already_signed {
        return Err(AttestorError::AlreadySigned);
    }
    if &terms.terms_hash() != announced_terms_hash {
        return Err(AttestorError::TermsChanged);
    }

    // 2. The attestation must be for the intent these terms describe.
    let intent = terms.intent_hash();
    if attestation.intent_hash != intent {
        return Err(AttestorError::IntentMismatch);
    }

    // 3 and 4. The enclave signature, the pinned signer and domain, and the
    //    amount. `verify` also re-derives dataHash from the payment details, so
    //    a caller cannot present values that disagree with what was signed.
    verify_with_signer(
        attestation,
        signature,
        encoded_payment_details,
        &intent,
        terms.usd_amount_6dec as u128,
        trusted_signer,
    )?;

    // 3b. The signature above proves the enclave signed *these bytes*. It says
    //     nothing about what the bytes claim. Until the payment itself is
    //     checked against the terms, an LP could prove a payment to its own
    //     Venmo, at a rate it chose, made long before this escrow existed, and
    //     every earlier check would still pass. Decode the payment and compare
    //     it field by field.
    let details = PaymentDetails::decode(encoded_payment_details)?;
    details.check_against_terms(
        &intent,
        &terms.payee_hash,
        terms.usd_amount_6dec as u128,
        attestation.release_amount,
        // The attestor's own clock, not the LP's claim. See round 2 finding 2.
        observation.earliest_acceptable_payment_ms,
        terms.lock_confirmed_ms,
        rate,
    )?;

    // 3c. One Venmo payment releases one escrow. Without this, an LP that made
    //     a single payment could announce several escrows for the same user and
    //     present the same attestation against each of them.
    if payment_already_consumed {
        return Err(AttestorError::PaymentAlreadyConsumed);
    }

    // 5. The escrow itself, on the attestor's own node. The script is derived
    //    from the terms here rather than taken from the caller (round 2
    //    finding 8): a caller that passes both the terms and the script it
    //    expects them to produce can pass a matching pair that is not this
    //    escrow.
    let derived =
        zecp2p_escrow::script::redeem_script(&terms.u_pub, &terms.l_pub, terms.refund_height)
            .map_err(|_| AttestorError::WrongScriptPubkey)?;
    let expected_script_pubkey = zecp2p_escrow::script::p2sh_script_pubkey(&derived);
    if observation.script_pubkey != expected_script_pubkey {
        return Err(AttestorError::WrongScriptPubkey);
    }
    if observation.amount_zat != terms.amount_zat {
        return Err(AttestorError::WrongAmount {
            found: observation.amount_zat,
            expected: terms.amount_zat,
        });
    }
    let required = required_depth(terms.usd_amount_6dec);
    if observation.confirmations < required {
        return Err(AttestorError::InsufficientDepth {
            found: observation.confirmations,
            required,
        });
    }

    // The caller records this against the event so the payment cannot be
    // presented again for a different escrow.
    Ok(payment_nullifier(&details))
}

/// Produces the outcome scalar once `decide` has passed.
///
/// The caller must delete `k` immediately afterwards and mark the event signed.
/// Signing twice under one `k` with two different challenges exposes `d`, which
/// is demonstrated in the escrow crate's `dlc` tests.
pub fn sign_decided_outcome(
    secp: &Secp256k1<secp256k1_zkp::All>,
    k: &SecretKey,
    d: &SecretKey,
    event_id: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<SecretKey, AttestorError> {
    Ok(sign_outcome(secp, k, d, event_id, terms_hash)?)
}

/// The outcome point the user checks its pre-signature against.
pub fn announced_outcome_point(
    secp: &Secp256k1<secp256k1_zkp::All>,
    r: &PublicKey,
    p: &PublicKey,
    event_id: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<PublicKey, AttestorError> {
    Ok(outcome_point(secp, r, p, event_id, terms_hash)?)
}

/// The whole `/attest` handler, spec 5.5, as one operation over the store.
///
/// Round 2 finding 4: `decide` returning a nullifier that the *caller* then
/// checked left a window in which two handlers both passed, both computed a
/// scalar, and only the second `mark_signed` refused. By then the second scalar
/// existed in memory, and whether it reached the LP was up to a handler that
/// had not been written. The ordering here removes the question:
///
/// 1. read the announcement from the store,
/// 2. run every check, consulting the store's own consumed-payment set,
/// 3. take the nonce, sign, and record - returning the scalar only once
///    `mark_signed` has committed.
///
/// The store is borrowed mutably for the whole call, so the sequence is atomic
/// against anything else holding it. A persistent implementation must take the
/// equivalent lock across the same span.
#[allow(clippy::too_many_arguments)]
pub fn handle_attest(
    store: &mut store::EventStore,
    secp: &Secp256k1<secp256k1_zkp::All>,
    d: &SecretKey,
    event_id: &[u8; 32],
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    rate: &RatePolicy,
) -> Result<SecretKey, AttestorError> {
    handle_attest_with_signer(
        store,
        secp,
        d,
        event_id,
        terms,
        attestation,
        signature,
        encoded_payment_details,
        observation,
        rate,
        &ENCLAVE_SIGNER,
    )
}

/// As [`handle_attest`], against a caller-supplied enclave signer. Test only.
#[cfg(feature = "test-signer")]
#[allow(clippy::too_many_arguments)]
pub fn handle_attest_against_signer(
    store: &mut store::EventStore,
    secp: &Secp256k1<secp256k1_zkp::All>,
    d: &SecretKey,
    event_id: &[u8; 32],
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    rate: &RatePolicy,
    trusted_signer: &[u8; 20],
) -> Result<SecretKey, AttestorError> {
    handle_attest_with_signer(
        store,
        secp,
        d,
        event_id,
        terms,
        attestation,
        signature,
        encoded_payment_details,
        observation,
        rate,
        trusted_signer,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_attest_with_signer(
    store: &mut store::EventStore,
    secp: &Secp256k1<secp256k1_zkp::All>,
    d: &SecretKey,
    event_id: &[u8; 32],
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    rate: &RatePolicy,
    trusted_signer: &[u8; 20],
) -> Result<SecretKey, AttestorError> {
    // An event already signed returns what it published rather than signing
    // again. The scalar is public the moment the release is broadcast, so this
    // is idempotent, not a leak.
    if let Some(existing) = store.signed_outcome(event_id) {
        return SecretKey::from_slice(&existing)
            .map_err(|e| AttestorError::Dlc(DlcError::Secp(e.to_string())));
    }

    let event = store.get(event_id).ok_or(AttestorError::UnknownEvent)?.clone();

    // The recency bound is the attestor's own announcement time, not anything
    // the LP wrote. An observation claiming an earlier bound than the store
    // knows is narrowed to the store's (round 2 finding 2).
    let observation = ChainObservation {
        earliest_acceptable_payment_ms: observation
            .earliest_acceptable_payment_ms
            .max(event.announced_at_ms),
        ..observation.clone()
    };

    // `already_signed` and the announced terms hash come from the store, not
    // from the caller (round 2 finding 8).
    let nullifier = decide_inner(
        &event.terms_hash,
        event.signed_s.is_some(),
        terms,
        attestation,
        signature,
        encoded_payment_details,
        &observation,
        trusted_signer,
        rate,
        store.payment_is_consumed(&payment_nullifier(&PaymentDetails::decode(
            encoded_payment_details,
        )?)),
    )?;

    // Only now is a nonce touched.
    let bound = store
        .take_nonce_for_signing(event_id)
        .map_err(map_store_error)?;
    let k_bytes = bound
        .secret_for(event_id)
        .ok_or(AttestorError::UnknownEvent)?;
    let k = SecretKey::from_slice(k_bytes)
        .map_err(|e| AttestorError::Dlc(DlcError::Secp(e.to_string())))?;

    let s = sign_outcome(secp, &k, d, event_id, &event.terms_hash)?;

    // Record before returning. If this refuses, the scalar never leaves.
    store
        .mark_signed(event_id, s.secret_bytes(), nullifier)
        .map_err(map_store_error)?;

    Ok(s)
}

fn map_store_error(e: store::StoreError) -> AttestorError {
    match e {
        store::StoreError::UnknownEvent => AttestorError::UnknownEvent,
        store::StoreError::AlreadySigned => AttestorError::AlreadySigned,
        store::StoreError::PaymentAlreadyConsumed => AttestorError::PaymentAlreadyConsumed,
        store::StoreError::DuplicateEvent | store::StoreError::DuplicateFundingTx => {
            AttestorError::DuplicateAnnouncement
        }
    }
}
