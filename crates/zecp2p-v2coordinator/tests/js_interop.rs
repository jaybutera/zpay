//! The seam between the page's JavaScript and this coordinator's Rust.
//!
//! The page computes its pre-signature with `frontend/app/escrow.js`, a
//! from-scratch implementation of the libsecp256k1-zkp adaptor format. The
//! coordinator verifies it with libsecp256k1-zkp itself. Nothing but a vector
//! shows that those two agree, and if they do not, the failure arrives as "the
//! LP will not pay" on every single order.
//!
//! The vector below was produced by running `escrow.js` in node. The generator
//! is in the doc comment on `THE_VECTOR` so it can be reproduced, and the whole
//! point is that the bytes here were **not** produced by any Rust code.

use secp256k1_zkp::{EcdsaAdaptorSignature, PublicKey, Secp256k1, SecretKey};

/// A pre-signature made by the browser's `escrow.js`.
///
/// Reproduce with:
///
/// ```js
/// const E = require('frontend/app/escrow.js');
/// const uPriv = E.scalarFromBytes(E.fromHex('11'.repeat(32)));
/// const d = E.scalarFromBytes(E.fromHex('d1'.repeat(32)));
/// const k = E.scalarFromBytes(E.fromHex('7a'.repeat(32)));
/// const R = E.mulG(k), P = E.pubkey(d);
/// const digest = E.sha256(E.ascii('a release digest for the interop check'));
/// const eventId = E.sha256(E.ascii('event'));
/// const termsHash = E.sha256(E.ascii('terms'));
/// const Y = E.outcomePoint(R, E.pointFromBytes(P), eventId, termsHash);
/// E.toHex(E.adaptorEncrypt(uPriv, digest, Y));
/// ```
struct Vector {
    pre_signature: &'static str,
    digest: &'static str,
    u_pub: &'static str,
    outcome_point: &'static str,
    outcome_secret: &'static str,
    r: &'static str,
    p: &'static str,
    event_id: &'static str,
    terms_hash: &'static str,
}

const THE_VECTOR: Vector = Vector {
    pre_signature: "035cc7ff5ddc88c8b3a52f608bd92a3c66851034de3deca607531c22f6862b4f15023b88186316673d5c51efb0af29655cfe722971d49656625aaab8db61feeb16d2aef76997985fe5d02e989291bb86c4c85e826cfa79032cbd1d508413df6e9dc4d644fc548b82e028da5606415be3254b7c4322581efde67fed132002f61a132cdbe8b7340d545702b7f0ad9cf30c621eb48c39cb1ec497b2f4072085c4bee76a",
    digest: "a9a76172edcae0d2cd955ca752e3783c43cbaa2e7f3071f3647fe1e8a22ea9b0",
    u_pub: "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
    outcome_point: "02d89ea11ed474f9990b3696ebbe6d6bf664e4abc19cba7a696d699dc4fb45966f",
    outcome_secret: "019138530d6d693b61b1c4c8b683366a31ab2188f5db107db3777848451cf90a",
    r: "03e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baac",
    p: "020612c5e8c98a9677a2ddd13770e26f5f1e771a088c88ce519a1e1b65872423f9",
    event_id: "b8e1f80bd70ae0784c7855a451731b745fddb67749d23f637be9082b75e9575b",
    terms_hash: "51d2361f4faea3bc8f9facdbc7d99abb555596a2e51f7b25fd3b41c93587e616",
};

fn bytes32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn a_pre_signature_from_the_page_is_162_bytes_and_parses() {
    // The JS builds `R || R' || s' || e || s` by hand. libsecp256k1-zkp's
    // serialization is the same 162 bytes in the same order, and this is the
    // only thing that says so.
    let raw = hex::decode(THE_VECTOR.pre_signature).unwrap();
    assert_eq!(raw.len(), 162, "an adaptor signature is 162 bytes");
    EcdsaAdaptorSignature::from_slice(&raw).expect("the page's bytes parse in libsecp256k1-zkp");
}

#[test]
fn the_coordinator_verifies_a_pre_signature_the_page_made() {
    // The gate, against bytes no Rust code produced. If this fails, every
    // order stalls at `needs_presignature` and the user refunds at T.
    let secp = Secp256k1::new();
    let pre = EcdsaAdaptorSignature::from_slice(&hex::decode(THE_VECTOR.pre_signature).unwrap())
        .unwrap();
    let u_pub = PublicKey::from_slice(&hex::decode(THE_VECTOR.u_pub).unwrap()).unwrap();
    let y = PublicKey::from_slice(&hex::decode(THE_VECTOR.outcome_point).unwrap()).unwrap();
    let digest = bytes32(THE_VECTOR.digest);

    zecp2p_escrow::dlc::verify_pre_signature(&secp, &pre, &digest, &u_pub, &y)
        .expect("the page's pre-signature must verify here");
}

#[test]
fn the_outcome_point_the_page_computed_is_the_one_the_crate_computes() {
    // `Y = R + e*P` with `e` a tagged hash over R, P, the event and the terms.
    // The page derives it from the announcement this coordinator relays, so a
    // disagreement here means the pre-signature is encrypted under a point the
    // attestor's scalar cannot open.
    let secp = Secp256k1::new();
    let r = PublicKey::from_slice(&hex::decode(THE_VECTOR.r).unwrap()).unwrap();
    let p = PublicKey::from_slice(&hex::decode(THE_VECTOR.p).unwrap()).unwrap();

    let y = zecp2p_escrow::dlc::outcome_point(
        &secp,
        &r,
        &p,
        &bytes32(THE_VECTOR.event_id),
        &bytes32(THE_VECTOR.terms_hash),
    )
    .unwrap();

    assert_eq!(
        hex::encode(y.serialize()),
        THE_VECTOR.outcome_point,
        "the two implementations of the outcome challenge disagree"
    );
}

#[test]
fn the_scalar_the_page_expects_decrypts_its_own_pre_signature() {
    // The end of the protocol, from the other side: the attestor's `s` opens
    // the page's pre-signature into a signature that verifies against `u_pub`.
    // This is what makes the release spendable, and it crosses the language
    // boundary in the opposite direction from the check above.
    let secp = Secp256k1::new();
    let pre = EcdsaAdaptorSignature::from_slice(&hex::decode(THE_VECTOR.pre_signature).unwrap())
        .unwrap();
    let s = SecretKey::from_slice(&bytes32(THE_VECTOR.outcome_secret)).unwrap();
    let y = PublicKey::from_slice(&hex::decode(THE_VECTOR.outcome_point).unwrap()).unwrap();

    // The scalar really is this outcome's.
    zecp2p_escrow::dlc::verify_outcome_secret(&secp, &s, &y)
        .expect("s*G must equal Y");

    let sig = zecp2p_escrow::dlc::decrypt_pre_signature(&pre, &s)
        .expect("the pre-signature decrypts");

    let u_pub = PublicKey::from_slice(&hex::decode(THE_VECTOR.u_pub).unwrap()).unwrap();
    let digest = bytes32(THE_VECTOR.digest);
    secp.verify_ecdsa(&secp256k1_zkp::Message::from_digest(digest), &sig, &u_pub)
        .expect("the decrypted signature verifies against the user's key");

    // And the scalar can be recovered from the completed signature, which is
    // acceptance criterion 6.
    let recovered = zecp2p_escrow::dlc::recover_outcome_secret(&secp, &pre, &sig, &y)
        .expect("the scalar recovers");
    assert_eq!(recovered.secret_bytes(), s.secret_bytes());
}

#[test]
fn a_pre_signature_under_a_different_outcome_point_does_not_verify() {
    // The property the LP's safety rests on: a pre-signature only means
    // something against the exact Y the announcement produced. Changing a term
    // changes the terms hash, changes Y, and invalidates the pre-signature.
    let secp = Secp256k1::new();
    let pre = EcdsaAdaptorSignature::from_slice(&hex::decode(THE_VECTOR.pre_signature).unwrap())
        .unwrap();
    let u_pub = PublicKey::from_slice(&hex::decode(THE_VECTOR.u_pub).unwrap()).unwrap();
    let digest = bytes32(THE_VECTOR.digest);

    // One byte of the terms differs.
    let mut other_terms = bytes32(THE_VECTOR.terms_hash);
    other_terms[0] ^= 0x01;
    let r = PublicKey::from_slice(&hex::decode(THE_VECTOR.r).unwrap()).unwrap();
    let p = PublicKey::from_slice(&hex::decode(THE_VECTOR.p).unwrap()).unwrap();
    let other_y = zecp2p_escrow::dlc::outcome_point(
        &secp,
        &r,
        &p,
        &bytes32(THE_VECTOR.event_id),
        &other_terms,
    )
    .unwrap();

    assert!(
        zecp2p_escrow::dlc::verify_pre_signature(&secp, &pre, &digest, &u_pub, &other_y).is_err(),
        "a pre-signature must not verify under terms the user did not sign"
    );
}
