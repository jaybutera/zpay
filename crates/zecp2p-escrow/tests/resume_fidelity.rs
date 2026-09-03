//! R9-1: a resumed run must reproduce the exact pre-signature it first made.
//!
//! `EcdsaAdaptorSignature::encrypt` draws fresh auxiliary randomness on every
//! call, so a resume that pre-signed again produced a *different* pre-signature
//! from the one it recorded. The release still spent - the decrypted signature
//! is valid either way - but the recorded pre-signature no longer matched the
//! mined transaction, so `recover(sig_u, pre_sig, Y)` failed and criterion 6
//! could not be checked. A mined release then looks exactly like one signed
//! directly with `u_priv`, which is the R8-1 failure reached by another route.
//!
//! These tests are off-chain because the property is about bytes, not about a
//! node: what matters is that recovery works against the signature that ends up
//! in the scriptSig, and that it fails for a direct signature.

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{EcdsaAdaptorSignature, Secp256k1, SecretKey};

use zecp2p_escrow::dlc::{
    decrypt_pre_signature, event_id, outcome_point, pre_sign, recover_outcome_secret,
    sign_outcome, verify_pre_signature,
};
use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::tx::{build_release, encode_signature, serialize_release, EscrowTerms};

const NU6_3: u32 = 0x37a5_165b;
const TXID: [u8; 32] = [0x7a; 32];
const REFUND_HEIGHT: u64 = 3_500_000;
const TERMS_HASH: [u8; 32] = [0x7c; 32];

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

struct Run {
    secp: Secp256k1<secp256k1_zkp::All>,
    u_priv: SecretKey,
    l_priv: SecretKey,
    terms: EscrowTerms,
    redeem: Vec<u8>,
    fee: u64,
    lp_script: Vec<u8>,
    digest: [u8; 32],
    y: secp256k1_zkp::PublicKey,
    s: SecretKey,
}

fn run() -> Run {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let terms = EscrowTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: 200_000,
        u_pub: u_priv.public_key(&secp).serialize(),
        l_pub: l_priv.public_key(&secp).serialize(),
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: NU6_3,
    };
    let redeem = terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp_script = p2pkh([0x09; 20]);
    let digest = build_release(&terms, &lp_script, fee).unwrap().sighash().unwrap();

    let ev = event_id(&TXID, 0);
    let y = outcome_point(&secp, &k.public_key(&secp), &d.public_key(&secp), &ev, &TERMS_HASH)
        .unwrap();
    let s = sign_outcome(&secp, &k, &d, &ev, &TERMS_HASH).unwrap();

    Run { secp, u_priv, l_priv, terms, redeem, fee, lp_script, digest, y, s }
}

/// Assembles the release the way the runner does, and returns the scriptSig as
/// it would appear on chain.
fn assemble(r: &Run, pre_sig: &EcdsaAdaptorSignature) -> (Vec<u8>, Vec<u8>) {
    let sig_u_zkp = decrypt_pre_signature(pre_sig, &r.s).unwrap();
    let sig_u = secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
    let secp1 = Secp1::new();
    let sig_l = secp1.sign_ecdsa(
        &Message::from_digest(r.digest),
        &Sk1::from_slice(&r.l_priv.secret_bytes()).unwrap(),
    );
    let ss = release_script_sig(&encode_signature(&sig_u), &encode_signature(&sig_l), &r.redeem);
    let raw = serialize_release(&r.terms, &r.lp_script, r.fee, &ss).unwrap();
    (ss, raw)
}

/// `sig_u` as a verifier would take it out of a mined scriptSig.
fn sig_u_from_script_sig(ss: &[u8]) -> secp256k1_zkp::ecdsa::Signature {
    // OP_0 <sig_u> <sig_l> OP_1 <redeem>
    let len = ss[1] as usize;
    let der = &ss[2..2 + len - 1]; // drop the trailing sighash byte
    secp256k1_zkp::ecdsa::Signature::from_der(der).expect("sig_u")
}

#[test]
fn pre_signing_twice_gives_two_different_pre_signatures() {
    // The root cause. If this ever stops being true the bug below cannot
    // happen, and this test says so rather than the fix looking unmotivated.
    let r = run();
    let a = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);
    let b = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);
    assert_ne!(
        a.as_ref(),
        b.as_ref(),
        "encrypt draws fresh auxiliary randomness; a resume must not call it again"
    );
}

#[test]
fn a_recorded_pre_signature_recovers_s_from_the_release_it_produced() {
    // The property criterion 6 rests on.
    let r = run();
    let pre_sig = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);
    let recorded = hex::encode(pre_sig.as_ref());

    let (ss, _raw) = assemble(&r, &pre_sig);

    // The verifier's path: the record's pre-signature, the chain's signature.
    let replayed = EcdsaAdaptorSignature::from_slice(&hex::decode(&recorded).unwrap()).unwrap();
    let sig_u = sig_u_from_script_sig(&ss);
    let recovered = recover_outcome_secret(&r.secp, &replayed, &sig_u, &r.y)
        .expect("recovery must work against the mined signature");
    assert_eq!(recovered.secret_bytes(), r.s.secret_bytes());
}

#[test]
fn a_resume_that_pre_signs_again_makes_criterion_6_unverifiable() {
    // The bug, demonstrated. The release is built from a *second* pre-signature
    // while the record still holds the first, which is exactly what the old
    // resume did.
    let r = run();
    let recorded = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);
    let resumed = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);

    let (ss, _raw) = assemble(&r, &resumed);
    let sig_u = sig_u_from_script_sig(&ss);

    // The release is perfectly valid on chain...
    let secp1 = Secp1::new();
    let der = secp256k1::ecdsa::Signature::from_der(&sig_u.serialize_der()).unwrap();
    secp1
        .verify_ecdsa(
            &Message::from_digest(r.digest),
            &der,
            &secp256k1::PublicKey::from_slice(&r.terms.u_pub).unwrap(),
        )
        .expect("the release still spends; that is what makes this dangerous");

    // ...and the recorded pre-signature cannot prove where it came from.
    let recovered = recover_outcome_secret(&r.secp, &recorded, &sig_u, &r.y);
    let matches = recovered
        .map(|k| k.secret_bytes() == r.s.secret_bytes())
        .unwrap_or(false);
    assert!(
        !matches,
        "if this passes, the resume bug is harmless and the fix is unnecessary"
    );
}

#[test]
fn a_replayed_pre_signature_reproduces_the_release_byte_for_byte() {
    // What the fix buys: decoding the record and decrypting gives the same
    // transaction as the first run, so a resumed broadcast is the same txid.
    let r = run();
    let pre_sig = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);
    let (_ss1, raw1) = assemble(&r, &pre_sig);

    let replayed =
        EcdsaAdaptorSignature::from_slice(&hex::decode(hex::encode(pre_sig.as_ref())).unwrap())
            .unwrap();
    verify_pre_signature(
        &r.secp,
        &replayed,
        &r.digest,
        &r.u_priv.public_key(&r.secp),
        &r.y,
    )
    .expect("the replayed pre-signature must still verify");
    let (_ss2, raw2) = assemble(&r, &replayed);

    assert_eq!(raw1, raw2, "a resumed run must rebuild the same bytes");
}

#[test]
fn a_direct_user_signature_fails_recovery() {
    // The check that makes criterion 6 meaningful: a release signed with
    // `u_priv` rather than by decrypting is exactly what the verify subcommand
    // has to reject, and it does.
    let r = run();
    let pre_sig = pre_sign(&r.secp, &r.digest, &r.u_priv, &r.y);

    let secp1 = Secp1::new();
    let direct = secp1.sign_ecdsa(
        &Message::from_digest(r.digest),
        &Sk1::from_slice(&r.u_priv.secret_bytes()).unwrap(),
    );
    let sig_l = secp1.sign_ecdsa(
        &Message::from_digest(r.digest),
        &Sk1::from_slice(&r.l_priv.secret_bytes()).unwrap(),
    );
    let ss = release_script_sig(
        &encode_signature(&direct),
        &encode_signature(&sig_l),
        &r.redeem,
    );
    let sig_u = sig_u_from_script_sig(&ss);

    let recovered = recover_outcome_secret(&r.secp, &pre_sig, &sig_u, &r.y);
    let matches = recovered
        .map(|k| k.secret_bytes() == r.s.secret_bytes())
        .unwrap_or(false);
    assert!(
        !matches,
        "a directly signed release must not pass criterion 6"
    );
}
