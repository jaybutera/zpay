//! The adaptor / DLC layer of spec section 5: the attestor's announcement, the
//! outcome point `Y`, and the pre-signature the user hands the LP.
//!
//! The shape of the trust here is worth stating once. The attestor never sees a
//! Zcash sighash and never holds a key over the escrow. It publishes a nonce
//! point `R` before the user funds, and later publishes one scalar
//! `s = k + e*d`. That scalar is the discrete log of `Y = R + e*P`, which is
//! exactly the secret the user's pre-signature was encrypted under. So the
//! attestor's signature *is* the decryption key, and nothing else it holds
//! moves money.

use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1_zkp::{
    ecdsa::Signature, EcdsaAdaptorSignature, Message, PublicKey, Scalar, Secp256k1, SecretKey,
    Signing, Verification,
};

/// There is exactly one outcome. A `not paid` outcome is never signed, because
/// the refund path is CLTV; that removes any possibility of the attestor
/// equivocating between two signable outcomes (spec 5.1).
pub const OUTCOME_PAID: &str = "paid";

const OUTCOME_TAG: &[u8] = b"zecp2p-outcome-v1";
const EVENT_TAG: &[u8] = b"zecp2p-escrow-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DlcError {
    #[error("the attestor's scalar s does not satisfy s*G == Y")]
    WrongOutcomeSecret,
    #[error("the pre-signature does not verify against u_pub and Y")]
    InvalidPreSignature,
    #[error("the decrypted signature is not a valid signature by u_pub")]
    DecryptionFailed,
    #[error("secp256k1 error: {0}")]
    Secp(String),
}

impl From<secp256k1_zkp::Error> for DlcError {
    fn from(e: secp256k1_zkp::Error) -> Self {
        DlcError::Secp(e.to_string())
    }
}

impl From<secp256k1_zkp::UpstreamError> for DlcError {
    fn from(e: secp256k1_zkp::UpstreamError) -> Self {
        DlcError::Secp(e.to_string())
    }
}

/// BIP 340 style tagged hash: `sha256(sha256(tag) || sha256(tag) || data)`.
///
/// Tagging is not decoration. It stops a value hashed for one purpose in this
/// protocol from being reinterpreted as a value hashed for another.
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(data);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// `event_id = sha256("zecp2p-escrow-v1" || funding_txid || vout)` (spec 5.1).
///
/// The event is bound to the outpoint, so an attestor announcement cannot be
/// reused for a different escrow.
pub fn event_id(funding_txid: &[u8; 32], vout: u32) -> [u8; 32] {
    let mut eng = sha256::Hash::engine();
    eng.input(EVENT_TAG);
    eng.input(funding_txid);
    eng.input(&vout.to_le_bytes());
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// `e = tagged_hash("zecp2p-outcome-v1", R || P || event_id || terms_hash || "paid") mod n`.
///
/// `terms_hash` is in the preimage so that `Y` commits to the terms, not merely
/// to the outpoint. Without it the outcome point is the same for any terms over
/// one escrow, so a scalar released for a 1 USD claim would decrypt a
/// pre-signature the user made expecting a 100 USD one. With it, changing any
/// term changes `Y`, and a pre-signature made under the user's terms cannot be
/// completed by a scalar signed for different ones.
pub fn outcome_challenge(
    r: &PublicKey,
    p: &PublicKey,
    event_id: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<Scalar, DlcError> {
    let mut data = Vec::with_capacity(33 + 33 + 32 + 32 + OUTCOME_PAID.len());
    data.extend_from_slice(&r.serialize());
    data.extend_from_slice(&p.serialize());
    data.extend_from_slice(event_id);
    data.extend_from_slice(terms_hash);
    data.extend_from_slice(OUTCOME_PAID.as_bytes());

    let e = tagged_hash(OUTCOME_TAG, &data);
    // A hash that is zero or >= n is negligibly unlikely, but it must not be
    // silently reduced to zero: e = 0 would make Y = R, so the attestor's nonce
    // alone would release the escrow.
    Scalar::from_be_bytes(e).map_err(|_| DlcError::Secp("challenge out of range".into()))
}

/// The outcome point `Y = R + e*P`, computed by everyone from public data.
///
/// The user encrypts its pre-signature under `Y` before it funds. Nobody knows
/// `y = k + e*d` until the attestor publishes it.
pub fn outcome_point<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    r: &PublicKey,
    p: &PublicKey,
    event_id: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<PublicKey, DlcError> {
    let e = outcome_challenge(r, p, event_id, terms_hash)?;
    let e_p = p.mul_tweak(secp, &e)?;
    Ok(r.combine(&e_p)?)
}

/// The attestor's outcome signature `s = k + e*d mod n` (spec 5.5 step 6).
///
/// After this the attestor deletes `k`. Publishing a second `s` for the same
/// `k` under a different `e` would leak `d`, which is why 5.1 refuses a second
/// announcement per event and 5.5 refuses a second signing.
pub fn sign_outcome<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    k: &SecretKey,
    d: &SecretKey,
    event_id: &[u8; 32],
    terms_hash: &[u8; 32],
) -> Result<SecretKey, DlcError> {
    let r = k.public_key(secp);
    let p = d.public_key(secp);
    let e = outcome_challenge(&r, &p, event_id, terms_hash)?;
    // s = k + e*d
    let e_d = d.mul_tweak(&e)?;
    Ok(k.add_tweak(&Scalar::from_be_bytes(e_d.secret_bytes()).map_err(|_| {
        DlcError::Secp("e*d out of range".into())
    })?)?)
}

/// Checks `s*G == Y` before the LP spends anything on it (spec 5.6 step 1).
pub fn verify_outcome_secret<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    s: &SecretKey,
    y: &PublicKey,
) -> Result<(), DlcError> {
    if s.public_key(secp) == *y {
        Ok(())
    } else {
        Err(DlcError::WrongOutcomeSecret)
    }
}

/// The user's pre-signature over the release digest, encrypted under `Y`
/// (spec 5.3 step 3).
///
/// It carries a DLEQ proof, so the LP can verify it against `u_pub` and `Y`
/// without learning `y`. That verification is what lets the LP pay Venmo
/// knowing the release will work once the attestor answers.
pub fn pre_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    digest: &[u8; 32],
    u_priv: &SecretKey,
    y: &PublicKey,
) -> EcdsaAdaptorSignature {
    EcdsaAdaptorSignature::encrypt(secp, &Message::from_digest(*digest), u_priv, y)
}

/// The LP's check before it pays (spec 5.3 step 5). A failure here means the
/// LP does not proceed and the user refunds at `T`.
pub fn verify_pre_signature<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    pre_sig: &EcdsaAdaptorSignature,
    digest: &[u8; 32],
    u_pub: &PublicKey,
    y: &PublicKey,
) -> Result<(), DlcError> {
    pre_sig
        .verify(secp, &Message::from_digest(*digest), u_pub, y)
        .map_err(|_| DlcError::InvalidPreSignature)
}

/// Completes the user's signature with the attestor's scalar (spec 5.6 step 2).
///
/// The result may be high-S; the caller must normalise before encoding, because
/// Zcash enforces low-S as a standardness rule.
pub fn decrypt_pre_signature(
    pre_sig: &EcdsaAdaptorSignature,
    s: &SecretKey,
) -> Result<Signature, DlcError> {
    pre_sig
        .decrypt(s)
        .map_err(|_| DlcError::DecryptionFailed)
}

/// Re-derives `s` from the on-chain signature (spec 5.6, last paragraph).
///
/// Not needed by the protocol, but it is the check that the released signature
/// really was the encrypted one, and acceptance criterion 6 asks for it.
pub fn recover_outcome_secret<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    pre_sig: &EcdsaAdaptorSignature,
    sig: &Signature,
    y: &PublicKey,
) -> Result<SecretKey, DlcError> {
    Ok(pre_sig.recover(secp, sig, y)?)
}
