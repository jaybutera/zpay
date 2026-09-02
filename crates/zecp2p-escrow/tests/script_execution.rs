//! Executes the escrow redeem script through the consensus interpreter that
//! zebrad uses, so the spec's security properties are demonstrated rather than
//! asserted.
//!
//! The properties under test, from spec section 1:
//!
//! 1. after `T` the user's key alone spends the escrow;
//! 2. before `T` the refund branch does not run;
//! 3. the release branch needs both signatures, so the LP cannot claim alone;
//! 4. a signature over the wrong digest, which is what a fabricated attestor
//!    secret produces, does not spend.

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use zcash_script::interpreter::{
    CallbackTransactionSignatureChecker, Flags, SignatureChecker,
};
use zcash_script::script::{self, Code};
use zcash_script::Script;

use zecp2p_escrow::script::{
    p2sh_script_pubkey, redeem_script, refund_script_sig, release_script_sig, CompressedPubkey,
};

const REFUND_HEIGHT: u64 = 3_000_000;

/// The consensus flags a Zcash node applies to a P2SH spend. `CleanStack`
/// and `LowS` are standardness rules that the mempool enforces, and the spec
/// calls out low-S explicitly in section 4.6.
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

struct Keys {
    secp: Secp256k1<secp256k1::All>,
    u_priv: SecretKey,
    l_priv: SecretKey,
    u_pub: CompressedPubkey,
    l_pub: CompressedPubkey,
}

fn keys() -> Keys {
    let secp = Secp256k1::new();
    // Fixed keys so a failure is reproducible rather than flaky.
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let u_pub = PublicKey::from_secret_key(&secp, &u_priv).serialize();
    let l_pub = PublicKey::from_secret_key(&secp, &l_priv).serialize();
    Keys { secp, u_priv, l_priv, u_pub, l_pub }
}

/// Signs `digest` and appends the SIGHASH_ALL byte, normalising to low-S the
/// way section 4.6 requires. `secp256k1` normalises on signing, so this is the
/// same encoding the release path produces after adaptor decryption.
fn sign(secp: &Secp256k1<secp256k1::All>, digest: &[u8; 32], key: &SecretKey) -> Vec<u8> {
    let msg = Message::from_digest(*digest);
    let mut sig = secp.sign_ecdsa(&msg, key);
    sig.normalize_s();
    let mut der = sig.serialize_der().to_vec();
    der.push(0x01); // SIGHASH_ALL
    der
}

/// A checker that reports a fixed sighash and a fixed block height, standing in
/// for the transaction being verified.
fn checker(digest: [u8; 32], height: i64) -> CallbackTransactionSignatureChecker<'static> {
    // The escrow signs a single digest for the whole input, so the script_code
    // the interpreter passes back is not consulted.
    let cb: &'static dyn Fn(&Code, &zcash_script::signature::HashType) -> Option<[u8; 32]> =
        Box::leak(Box::new(move |_: &Code, _: &zcash_script::signature::HashType| Some(digest)));
    CallbackTransactionSignatureChecker {
        sighash: cb,
        lock_time: height,
        // The refund input sets nSequence = 0xfffffffe precisely so it is not
        // final; a final input disables CLTV entirely.
        is_final: false,
    }
}

fn eval(script_sig: &[u8], script_pubkey: &[u8], checker: &dyn SignatureChecker) -> bool {
    let sig = script::Component::parse(&Code(script_sig.to_vec()));
    let pk = script::Component::parse(&Code(script_pubkey.to_vec()));
    let (sig, pk) = match (sig, pk) {
        (Ok(s), Ok(p)) => (s, p),
        _ => return false,
    };
    let s: Script<zcash_script::opcode::PossiblyBad, zcash_script::opcode::PossiblyBad> =
        Script { sig, pub_key: pk };
    s.eval(consensus_flags(), checker).unwrap_or(false)
}

#[test]
fn release_branch_spends_with_both_signatures() {
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let sig_l = sign(&k.secp, &digest, &k.l_priv);
    let ss = release_script_sig(&sig_u, &sig_l, &rs);

    // Well before T, so this is not the refund path succeeding by accident.
    assert!(
        eval(&ss, &spk, &checker(digest, 1_000)),
        "the 2-of-2 release must spend when both parties have signed"
    );
}

#[test]
fn release_branch_rejects_lp_signature_alone() {
    // Property: the LP cannot claim the escrow without the user's signature,
    // which it only obtains by decrypting the pre-signature with the attestor's
    // secret. Here it substitutes its own signature for the user's.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    let sig_l = sign(&k.secp, &digest, &k.l_priv);
    let ss = release_script_sig(&sig_l, &sig_l, &rs);

    assert!(
        !eval(&ss, &spk, &checker(digest, 1_000)),
        "the LP must not be able to claim with two copies of its own signature"
    );
}

#[test]
fn release_branch_rejects_fabricated_user_signature() {
    // Property: a signature the LP forges without a valid attestation, which is
    // what decrypting the pre-signature with a fabricated `s` yields, does not
    // spend. This is acceptance criterion 12 at the script level.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    // A signature by an unrelated key, standing in for a decryption under a
    // fabricated secret: structurally a valid DER signature, wrong key.
    let fake = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let sig_fake = sign(&k.secp, &digest, &fake);
    let sig_l = sign(&k.secp, &digest, &k.l_priv);
    let ss = release_script_sig(&sig_fake, &sig_l, &rs);

    assert!(
        !eval(&ss, &spk, &checker(digest, 1_000)),
        "a signature not made by u_priv must not satisfy the release branch"
    );
}

#[test]
fn release_branch_rejects_signature_over_a_different_digest() {
    // A digest disagreement between the client and the LP is the silent
    // funds-lock the spec warns about in 4.6. It must fail closed.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);

    let signed_digest = [0x42u8; 32];
    let verified_digest = [0x43u8; 32];

    let sig_u = sign(&k.secp, &signed_digest, &k.u_priv);
    let sig_l = sign(&k.secp, &signed_digest, &k.l_priv);
    let ss = release_script_sig(&sig_u, &sig_l, &rs);

    assert!(
        !eval(&ss, &spk, &checker(verified_digest, 1_000)),
        "signatures over the wrong digest must not spend"
    );
}

#[test]
fn refund_branch_spends_at_t_with_the_user_key_alone() {
    // Property 1: after T the user needs nobody.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let ss = refund_script_sig(&sig_u, &rs);

    assert!(
        eval(&ss, &spk, &checker(digest, REFUND_HEIGHT as i64)),
        "the user must be able to refund at exactly T with no other party"
    );
    assert!(
        eval(&ss, &spk, &checker(digest, REFUND_HEIGHT as i64 + 500)),
        "the refund must remain spendable after T"
    );
}

#[test]
fn refund_branch_is_rejected_before_t() {
    // The mirror of property 1: the user cannot take the money back early,
    // which is what makes the LP willing to pay.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let ss = refund_script_sig(&sig_u, &rs);

    assert!(
        !eval(&ss, &spk, &checker(digest, REFUND_HEIGHT as i64 - 1)),
        "CHECKLOCKTIMEVERIFY must reject the refund one block before T"
    );
}

#[test]
fn refund_branch_rejects_the_lp_key() {
    // The ELSE branch checks u_pub only; the LP has no unilateral path at all.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    let sig_l = sign(&k.secp, &digest, &k.l_priv);
    let ss = refund_script_sig(&sig_l, &rs);

    assert!(
        !eval(&ss, &spk, &checker(digest, REFUND_HEIGHT as i64 + 100)),
        "the LP must not be able to sweep the escrow through the refund branch"
    );
}

#[test]
fn a_redeem_script_for_other_keys_does_not_satisfy_the_p2sh_commitment() {
    // P2SH binds the spend to this exact script, including T and both keys.
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];

    // Same parties, different T: a different script, so a different address.
    let rs_other = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT - 1).unwrap();
    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let sig_l = sign(&k.secp, &digest, &k.l_priv);
    let ss = release_script_sig(&sig_u, &sig_l, &rs_other);

    assert!(
        !eval(&ss, &spk, &checker(digest, 1_000)),
        "a redeem script with a different T must not satisfy the committed hash"
    );
}

/// Guards the negative tests above. Every one of them asserts that `eval`
/// returns false; if `eval` returned false because the harness could not parse
/// or run the script at all, those assertions would pass while proving nothing.
/// This test pins the discriminating behaviour: identical inputs differing only
/// in the one field under test flip the result.
#[test]
fn the_harness_distinguishes_pass_from_fail() {
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];
    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let sig_l = sign(&k.secp, &digest, &k.l_priv);

    // Release: correct order passes, swapped order fails. CHECKMULTISIG pops
    // signatures in the order the pubkeys appear, so this also pins the spec's
    // "u_pub then l_pub" requirement.
    assert!(eval(&release_script_sig(&sig_u, &sig_l, &rs), &spk, &checker(digest, 1_000)));
    assert!(
        !eval(&release_script_sig(&sig_l, &sig_u, &rs), &spk, &checker(digest, 1_000)),
        "signature order must matter, or the multisig test above proves nothing"
    );

    // Refund: the only difference between these two calls is the height.
    let refund = refund_script_sig(&sig_u, &rs);
    assert!(eval(&refund, &spk, &checker(digest, REFUND_HEIGHT as i64)));
    assert!(!eval(&refund, &spk, &checker(digest, REFUND_HEIGHT as i64 - 1)));
}

/// A final `nSequence` disables CLTV, which is why section 4.4 sets
/// `0xfffffffe` on the refund input. If the client ever emitted a final input
/// the refund would be spendable immediately, so pin the interpreter's rule.
#[test]
fn a_final_input_disables_the_timelock() {
    let k = keys();
    let rs = redeem_script(&k.u_pub, &k.l_pub, REFUND_HEIGHT).unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = [0x42u8; 32];
    let sig_u = sign(&k.secp, &digest, &k.u_priv);
    let refund = refund_script_sig(&sig_u, &rs);

    let mut final_input = checker(digest, REFUND_HEIGHT as i64 - 1);
    final_input.is_final = true;

    assert!(
        !eval(&refund, &spk, &final_input),
        "CLTV must still reject a pre-T refund; if this ever passes, the client \
         must never be allowed to set nSequence = 0xffffffff on a refund input"
    );
}
