//! The whole protocol in one place: terms, announcement, pre-signature, Venmo
//! attestation, outcome scalar, decryption, and a scriptSig that the consensus
//! interpreter accepts.
//!
//! The unit tests elsewhere check each layer against its own spec section. This
//! file checks that the layers *fit*: the digest the user signed is the digest
//! the release commits to, the signature the attestor's scalar produces is the
//! one CHECKMULTISIG wants, and the fabricated-secret case fails at the script,
//! not merely at a library call.

use secp256k1::{Message, Secp256k1, SecretKey};
use zcash_script::interpreter::{CallbackTransactionSignatureChecker, Flags, SignatureChecker};
use zcash_script::script::{self, Code};
use zcash_script::Script;

use zecp2p_escrow::attestation::{verify, PaymentAttestation};
use zecp2p_escrow::dlc::{
    decrypt_pre_signature, event_id, outcome_point, pre_sign, recover_outcome_secret, sign_outcome,
    verify_outcome_secret, verify_pre_signature,
};
use zecp2p_escrow::fees::{refund_fee_to_shielded_zat, release_fee_to_transparent_zat};
use zecp2p_escrow::script::{
    p2sh_script_pubkey, refund_script_sig, release_script_sig,
};
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::{build_refund, build_release, encode_signature, EscrowTerms};

const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;

fn consensus_flags() -> Flags {
    Flags::P2SH
        | Flags::StrictEnc
        | Flags::LowS
        | Flags::NullDummy
        | Flags::SigPushOnly
        | Flags::MinimalData
        | Flags::CleanStack
        | Flags::CHECKLOCKTIMEVERIFY
}

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn eval_at_height(
    script_sig: &[u8],
    script_pubkey: &[u8],
    digest: [u8; 32],
    height: i64,
) -> bool {
    let cb: &'static dyn Fn(&Code, &zcash_script::signature::HashType) -> Option<[u8; 32]> =
        Box::leak(Box::new(move |_: &Code, _: &zcash_script::signature::HashType| {
            Some(digest)
        }));
    let checker = CallbackTransactionSignatureChecker {
        sighash: cb,
        lock_time: height,
        is_final: false,
    };
    let sig = match script::Component::parse(&Code(script_sig.to_vec())) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = match script::Component::parse(&Code(script_pubkey.to_vec())) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let s: Script<zcash_script::opcode::PossiblyBad, zcash_script::opcode::PossiblyBad> =
        Script { sig, pub_key: pk };
    s.eval(consensus_flags(), &checker as &dyn SignatureChecker)
        .unwrap_or(false)
}

struct Parties {
    secp: Secp256k1<secp256k1::All>,
    zkp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    u_priv: SecretKey,
    l_priv: SecretKey,
    terms: EscrowTerms,
}

fn parties() -> Parties {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let u_pub = secp256k1::PublicKey::from_secret_key(&secp, &u_priv).serialize();
    let l_pub = secp256k1::PublicKey::from_secret_key(&secp, &l_priv).serialize();

    Parties {
        secp,
        zkp: secp256k1_zkp::Secp256k1::new(),
        u_priv,
        l_priv,
        terms: EscrowTerms {
            funding_txid: [0x7a; 32],
            vout: 0,
            amount_zat: 5_000_000,
            u_pub,
            l_pub,
            refund_height: REFUND_HEIGHT,
            consensus_branch_id: NU6_3,
        },
    }
}

/// The canonical terms for the same escrow, whose hash the outcome point now
/// commits to (review finding 3).
fn canonical(t: &EscrowTerms) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: t.funding_txid,
        vout: t.vout,
        amount_zat: t.amount_zat,
        u_pub: t.u_pub,
        l_pub: t.l_pub,
        refund_height: t.refund_height,
        usd_amount_6dec: 1_000_000,
        rate_18dec: 1_000_000_000_000_000_000,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
    }
}

/// The attestor's keys, and the user's view of them.
fn attestor() -> (SecretKey, SecretKey) {
    (
        SecretKey::from_slice(&[0xd1; 32]).unwrap(), // d, long-lived
        SecretKey::from_slice(&[0x4b; 32]).unwrap(), // k, per event
    )
}

#[test]
fn the_paid_path_releases_the_escrow() {
    let p = parties();
    let (d, k) = attestor();

    // --- Announcement, before the user funds (spec 5.1).
    let event = event_id(&p.terms.funding_txid, p.terms.vout);
    let r = secp256k1_zkp::SecretKey::from_slice(&k.secret_bytes())
        .unwrap()
        .public_key(&p.zkp);
    let big_p = secp256k1_zkp::SecretKey::from_slice(&d.secret_bytes())
        .unwrap()
        .public_key(&p.zkp);
    let y = outcome_point(&p.zkp, &r, &big_p, &event, &canonical(&p.terms).terms_hash()).unwrap();

    // --- The user builds the release exactly as the LP will, and pre-signs.
    let redeem = p.terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp_script = p2pkh([0x09; 20]);
    let digest = build_release(&p.terms, &lp_script, fee)
        .unwrap()
        .sighash()
        .unwrap();

    let u_priv_zkp = secp256k1_zkp::SecretKey::from_slice(&p.u_priv.secret_bytes()).unwrap();
    let pre_sig = pre_sign(&p.zkp, &digest, &u_priv_zkp, &y);

    // --- The LP verifies before it pays a cent (spec 5.3 step 5).
    let u_pub_zkp = u_priv_zkp.public_key(&p.zkp);
    verify_pre_signature(&p.zkp, &pre_sig, &digest, &u_pub_zkp, &y)
        .expect("the LP must verify the pre-signature before paying Venmo");

    // --- The LP pays, gets an enclave attestation, and the attestor checks it.
    //     The real attestation is exercised in attestation_vectors.rs; here the
    //     point is that a passing check is what unlocks the outcome signature.
    let attested = attestor_would_sign();
    assert!(attested, "the attestor signs only when the enclave check passes");

    let s = sign_outcome(
        &p.zkp,
        &secp256k1_zkp::SecretKey::from_slice(&k.secret_bytes()).unwrap(),
        &secp256k1_zkp::SecretKey::from_slice(&d.secret_bytes()).unwrap(),
        &event,
        &canonical(&p.terms).terms_hash(),
    )
    .unwrap();

    // --- The LP checks s*G == Y, then decrypts (spec 5.6).
    verify_outcome_secret(&p.zkp, &s, &y).unwrap();
    let sig_u_zkp = decrypt_pre_signature(&pre_sig, &s).unwrap();

    // The decrypted signature is an ordinary ECDSA signature; move it across
    // crate versions by its DER bytes.
    let sig_u = secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
    let sig_l = p.secp.sign_ecdsa(&Message::from_digest(digest), &p.l_priv);

    let script_sig = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &redeem,
    );
    let spk = p2sh_script_pubkey(&redeem);

    // --- The release spends, well before T.
    assert!(
        eval_at_height(&script_sig, &spk, digest, 1_000),
        "the released signatures must satisfy the 2-of-2 branch"
    );

    // --- And s is recoverable from the on-chain signature (criterion 6).
    let recovered = recover_outcome_secret(&p.zkp, &pre_sig, &sig_u_zkp, &y).unwrap();
    assert_eq!(recovered, s);
}

/// Stands in for the attestor's step 3 of 5.5, which is verified for real
/// against production signatures in `attestation_vectors.rs`.
fn attestor_would_sign() -> bool {
    let raw = std::fs::read_to_string("tests/fixtures/attestation_1000000.json").unwrap();
    let j: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let att = &j["attestation"];
    let tv = &att["typedDataValue"];

    let mut intent = [0u8; 32];
    intent.copy_from_slice(
        &hex::decode(tv["intentHash"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
    );
    let mut data_hash = [0u8; 32];
    data_hash.copy_from_slice(
        &hex::decode(tv["dataHash"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
    );
    let details = hex::decode(
        att["encodedPaymentDetails"].as_str().unwrap().trim_start_matches("0x"),
    )
    .unwrap();
    let sig =
        hex::decode(att["signature"].as_str().unwrap().trim_start_matches("0x")).unwrap();

    verify(
        &PaymentAttestation {
            intent_hash: intent,
            release_amount: tv["releaseAmount"].as_str().unwrap().parse().unwrap(),
            data_hash,
        },
        &sig,
        &details,
        &intent,
        1_000_000,
    )
    .is_ok()
}

#[test]
fn the_refund_path_returns_the_escrow_at_t_without_the_lp() {
    // Property 1, end to end: the user needs nobody after T.
    let p = parties();
    let redeem = p.terms.redeem_script().unwrap();
    let fee = refund_fee_to_shielded_zat(redeem.len());
    let user_script = p2pkh([0x0b; 20]);

    let refund = build_refund(&p.terms, &user_script, fee).unwrap();
    let digest = refund.sighash().unwrap();
    assert_eq!(refund.lock_time(), REFUND_HEIGHT as u32);

    let sig_u = p.secp.sign_ecdsa(&Message::from_digest(digest), &p.u_priv);
    let script_sig = refund_script_sig(&encode_signature(&sig_u), &redeem);
    let spk = p2sh_script_pubkey(&redeem);

    assert!(
        eval_at_height(&script_sig, &spk, digest, REFUND_HEIGHT as i64),
        "the user must reclaim the escrow at T with its key alone"
    );
    assert!(
        !eval_at_height(&script_sig, &spk, digest, REFUND_HEIGHT as i64 - 1),
        "and must not be able to before T"
    );
}

#[test]
fn a_fabricated_outcome_secret_produces_a_release_the_script_rejects() {
    // Acceptance criterion 12. The LP has a valid pre-signature and its own
    // key, and invents `s` rather than obtaining it. The resulting scriptSig
    // must fail, and fail at the script - not at a library error the LP could
    // route around.
    let p = parties();
    let (d, k) = attestor();

    let event = event_id(&p.terms.funding_txid, p.terms.vout);
    let r = secp256k1_zkp::SecretKey::from_slice(&k.secret_bytes())
        .unwrap()
        .public_key(&p.zkp);
    let big_p = secp256k1_zkp::SecretKey::from_slice(&d.secret_bytes())
        .unwrap()
        .public_key(&p.zkp);
    let y = outcome_point(&p.zkp, &r, &big_p, &event, &canonical(&p.terms).terms_hash()).unwrap();

    let redeem = p.terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp_script = p2pkh([0x09; 20]);
    let digest = build_release(&p.terms, &lp_script, fee).unwrap().sighash().unwrap();

    let u_priv_zkp = secp256k1_zkp::SecretKey::from_slice(&p.u_priv.secret_bytes()).unwrap();
    let pre_sig = pre_sign(&p.zkp, &digest, &u_priv_zkp, &y);

    let spk = p2sh_script_pubkey(&redeem);
    let sig_l = p.secp.sign_ecdsa(&Message::from_digest(digest), &p.l_priv);

    // Several fabrications, none of which is the attestor's scalar.
    for fabricated in [[0x01u8; 32], [0x99; 32], [0xfe; 32]] {
        let fake = secp256k1_zkp::SecretKey::from_slice(&fabricated).unwrap();
        assert!(
            verify_outcome_secret(&p.zkp, &fake, &y).is_err(),
            "a fabricated scalar must fail the s*G == Y check"
        );

        // Unconditional: decryption succeeds structurally for any scalar, so a
        // `let ... else { continue }` here would skip the only assertion the
        // moment that changed, and the test would pass having checked nothing.
        let sig_u_zkp = decrypt_pre_signature(&pre_sig, &fake)
            .expect("decryption is structurally possible with any scalar");
        let sig_u =
            secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
        let script_sig = release_script_sig(
            &encode_signature(&sig_u),
            &encode_signature(&sig_l),
            &redeem,
        );

        assert!(
            !eval_at_height(&script_sig, &spk, digest, 1_000),
            "a release built from a fabricated secret must be rejected by the script"
        );
    }
}

#[test]
fn the_lp_cannot_move_the_payout_after_the_user_pre_signs() {
    // The user pre-signs a release paying the script the LP stated. If the LP
    // then builds a release paying somewhere else, the user's decrypted
    // signature does not match that transaction's digest, so it does not spend.
    let p = parties();
    let (d, k) = attestor();

    let event = event_id(&p.terms.funding_txid, p.terms.vout);
    let r = secp256k1_zkp::SecretKey::from_slice(&k.secret_bytes()).unwrap().public_key(&p.zkp);
    let big_p = secp256k1_zkp::SecretKey::from_slice(&d.secret_bytes()).unwrap().public_key(&p.zkp);
    let y = outcome_point(&p.zkp, &r, &big_p, &event, &canonical(&p.terms).terms_hash()).unwrap();

    let redeem = p.terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());

    let agreed = build_release(&p.terms, &p2pkh([0x09; 20]), fee).unwrap().sighash().unwrap();
    let diverted = build_release(&p.terms, &p2pkh([0xaa; 20]), fee).unwrap().sighash().unwrap();
    assert_ne!(agreed, diverted);

    let u_priv_zkp = secp256k1_zkp::SecretKey::from_slice(&p.u_priv.secret_bytes()).unwrap();
    let pre_sig = pre_sign(&p.zkp, &agreed, &u_priv_zkp, &y);
    let s = sign_outcome(
        &p.zkp,
        &secp256k1_zkp::SecretKey::from_slice(&k.secret_bytes()).unwrap(),
        &secp256k1_zkp::SecretKey::from_slice(&d.secret_bytes()).unwrap(),
        &event,
        &canonical(&p.terms).terms_hash(),
    )
    .unwrap();
    let sig_u_zkp = decrypt_pre_signature(&pre_sig, &s).unwrap();
    let sig_u = secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
    let sig_l = p.secp.sign_ecdsa(&Message::from_digest(diverted), &p.l_priv);

    let script_sig =
        release_script_sig(&encode_signature(&sig_u), &encode_signature(&sig_l), &redeem);
    let spk = p2sh_script_pubkey(&redeem);

    assert!(
        !eval_at_height(&script_sig, &spk, diverted, 1_000),
        "a release paying a script the user never signed for must not spend"
    );
}
