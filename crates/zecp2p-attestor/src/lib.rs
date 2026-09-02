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
    verify_against_signer, AttestationError, PaymentAttestation, ENCLAVE_SIGNER,
};
use zecp2p_escrow::dlc::{outcome_point, sign_outcome, DlcError};
use zecp2p_escrow::terms::CanonicalTerms;

/// A funded escrow output as the attestor's own node reports it (spec 5.5
/// step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainObservation {
    pub script_pubkey: Vec<u8>,
    pub amount_zat: u64,
    pub confirmations: u32,
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
    expected_script_pubkey: &[u8],
) -> Result<(), AttestorError> {
    decide_against_signer(
        announced_terms_hash,
        already_signed,
        terms,
        attestation,
        signature,
        encoded_payment_details,
        observation,
        expected_script_pubkey,
        &ENCLAVE_SIGNER,
    )
}

/// As [`decide`], but against a caller-supplied trusted enclave signer. Spec
/// section 8 treats signer rotation as configuration, and tests need to build
/// attestations bound to terms they control.
#[allow(clippy::too_many_arguments)]
pub fn decide_against_signer(
    announced_terms_hash: &[u8; 32],
    already_signed: bool,
    terms: &CanonicalTerms,
    attestation: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    observation: &ChainObservation,
    expected_script_pubkey: &[u8],
    trusted_signer: &[u8; 20],
) -> Result<(), AttestorError> {
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
    verify_against_signer(
        attestation,
        signature,
        encoded_payment_details,
        &intent,
        terms.usd_amount_6dec as u128,
        trusted_signer,
    )?;

    // 5. The escrow itself, on the attestor's own node.
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

    Ok(())
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
) -> Result<SecretKey, AttestorError> {
    Ok(sign_outcome(secp, k, d, event_id)?)
}

/// The outcome point the user checks its pre-signature against.
pub fn announced_outcome_point(
    secp: &Secp256k1<secp256k1_zkp::All>,
    r: &PublicKey,
    p: &PublicKey,
    event_id: &[u8; 32],
) -> Result<PublicKey, AttestorError> {
    Ok(outcome_point(secp, r, p, event_id)?)
}
