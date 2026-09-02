//! The adaptor protocol of spec section 5, tested for the properties the design
//! rests on rather than for line coverage.
//!
//! The claim being tested is narrow and total: the LP cannot produce the user's
//! release signature without the attestor's scalar, and the attestor's scalar
//! is worthless for anything else.

use secp256k1_zkp::{Message, PublicKey, Scalar, Secp256k1, SecretKey};

use zecp2p_escrow::dlc::{
    decrypt_pre_signature, event_id, outcome_challenge, outcome_point, pre_sign,
    recover_outcome_secret, sign_outcome, tagged_hash, verify_outcome_secret,
    verify_pre_signature, DlcError,
};

struct Setup {
    secp: Secp256k1<secp256k1_zkp::All>,
    u_priv: SecretKey,
    u_pub: PublicKey,
    /// The attestor's long-lived key.
    d: SecretKey,
    p: PublicKey,
    /// The attestor's per-event nonce.
    k: SecretKey,
    r: PublicKey,
    event: [u8; 32],
    digest: [u8; 32],
}

fn setup() -> Setup {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let u_pub = u_priv.public_key(&secp);
    let p = d.public_key(&secp);
    let r = k.public_key(&secp);
    Setup {
        secp,
        u_priv,
        u_pub,
        d,
        p,
        k,
        r,
        event: event_id(&[0x7a; 32], 0),
        digest: [0x42; 32],
    }
}

#[test]
fn the_attestor_scalar_is_the_discrete_log_of_the_outcome_point() {
    // The whole construction reduces to this: s*G == Y = R + e*P. If it did not
    // hold, the attestor's signature would not decrypt anything.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let secret = sign_outcome(&s.secp, &s.k, &s.d, &s.event).unwrap();
    verify_outcome_secret(&s.secp, &secret, &y).expect("s*G must equal Y");
}

#[test]
fn the_full_paid_path_produces_a_valid_user_signature() {
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();

    // User pre-signs before funding, LP verifies before paying.
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);
    verify_pre_signature(&s.secp, &pre_sig, &s.digest, &s.u_pub, &y)
        .expect("the LP must be able to verify the pre-signature before it pays");

    // Attestor signs the outcome; LP decrypts.
    let secret = sign_outcome(&s.secp, &s.k, &s.d, &s.event).unwrap();
    let sig = decrypt_pre_signature(&pre_sig, &secret).unwrap();

    // The result is an ordinary ECDSA signature by the user's key. On chain it
    // is indistinguishable from any other 2-of-2 spend, which is property 4.
    s.secp
        .verify_ecdsa(&Message::from_digest(s.digest), &sig, &s.u_pub)
        .expect("the decrypted signature must verify under u_pub");
}

#[test]
fn the_lp_cannot_decrypt_without_the_attestors_scalar() {
    // Property 3 in its operational form: an attestor that refuses or is down
    // means the LP cannot claim. Every wrong scalar here stands for a guess.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);

    for (label, wrong) in [
        ("the attestor's long-lived key", s.d),
        ("the attestor's nonce alone", s.k),
        ("an unrelated scalar", SecretKey::from_slice(&[0x99; 32]).unwrap()),
    ] {
        assert_eq!(
            verify_outcome_secret(&s.secp, &wrong, &y),
            Err(DlcError::WrongOutcomeSecret),
            "{label} must not pass the s*G == Y check"
        );

        // decrypt() will still return *a* signature for a wrong key, because it
        // is just subtraction; what matters is that it does not verify.
        if let Ok(sig) = decrypt_pre_signature(&pre_sig, &wrong) {
            assert!(
                s.secp
                    .verify_ecdsa(&Message::from_digest(s.digest), &sig, &s.u_pub)
                    .is_err(),
                "decrypting with {label} must not yield a signature valid under u_pub"
            );
        }
    }
}

#[test]
fn a_fabricated_scalar_yields_a_signature_that_does_not_verify() {
    // Acceptance criterion 12 at the cryptographic layer: the pre-signature is
    // inert without the attestor. The script-level counterpart is in
    // script_execution.rs, and the mempool-level one is the testnet gate.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);

    let mut fabricated = [0u8; 32];
    for i in 0..32u8 {
        fabricated[i as usize] = i.wrapping_mul(7).wrapping_add(3);
    }
    let fabricated = SecretKey::from_slice(&fabricated).unwrap();

    assert_eq!(
        verify_outcome_secret(&s.secp, &fabricated, &y),
        Err(DlcError::WrongOutcomeSecret)
    );
    if let Ok(sig) = decrypt_pre_signature(&pre_sig, &fabricated) {
        assert!(s
            .secp
            .verify_ecdsa(&Message::from_digest(s.digest), &sig, &s.u_pub)
            .is_err());
    }
}

#[test]
fn the_pre_signature_does_not_verify_under_the_wrong_outcome_point() {
    // The user must encrypt under the Y that the announcement commits to. If a
    // pre-signature verified under some other Y, an LP could get an attestation
    // for a different event and still release.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);

    let other_event = event_id(&[0x7b; 32], 0);
    let other_y = outcome_point(&s.secp, &s.r, &s.p, &other_event).unwrap();
    assert_ne!(y, other_y);

    assert_eq!(
        verify_pre_signature(&s.secp, &pre_sig, &s.digest, &s.u_pub, &other_y),
        Err(DlcError::InvalidPreSignature)
    );
}

#[test]
fn the_pre_signature_does_not_verify_for_a_different_digest() {
    // The digest is the release transaction. A pre-signature that verified for
    // any digest would let the LP pay itself from a transaction the user never
    // agreed to.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);

    assert_eq!(
        verify_pre_signature(&s.secp, &pre_sig, &[0x43; 32], &s.u_pub, &y),
        Err(DlcError::InvalidPreSignature)
    );
}

#[test]
fn the_pre_signature_does_not_verify_under_another_users_key() {
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);

    let other = SecretKey::from_slice(&[0x12; 32]).unwrap().public_key(&s.secp);
    assert_eq!(
        verify_pre_signature(&s.secp, &pre_sig, &s.digest, &other, &y),
        Err(DlcError::InvalidPreSignature)
    );
}

#[test]
fn the_outcome_secret_is_recoverable_from_the_on_chain_signature() {
    // Acceptance criterion 6 asks for this. It also means the attestor's scalar
    // becomes public the moment the LP broadcasts, which is a property of every
    // adaptor scheme and worth being explicit about: s is not a secret after
    // release, it is a receipt.
    let s = setup();
    let y = outcome_point(&s.secp, &s.r, &s.p, &s.event).unwrap();
    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);
    let secret = sign_outcome(&s.secp, &s.k, &s.d, &s.event).unwrap();
    let sig = decrypt_pre_signature(&pre_sig, &secret).unwrap();

    let recovered = recover_outcome_secret(&s.secp, &pre_sig, &sig, &y).unwrap();
    assert_eq!(recovered, secret, "recover() must reproduce the attestor's s");
}

#[test]
fn each_escrow_gets_a_distinct_event_id_and_outcome_point() {
    // The event is bound to the outpoint, so an announcement cannot be replayed
    // onto another escrow.
    let s = setup();
    let a = event_id(&[0x7a; 32], 0);
    let b = event_id(&[0x7a; 32], 1);
    let c = event_id(&[0x7b; 32], 0);
    assert_ne!(a, b, "a different vout is a different event");
    assert_ne!(a, c, "a different funding tx is a different event");

    let ya = outcome_point(&s.secp, &s.r, &s.p, &a).unwrap();
    let yb = outcome_point(&s.secp, &s.r, &s.p, &b).unwrap();
    assert_ne!(ya, yb);
}

#[test]
fn the_outcome_challenge_binds_the_nonce_the_attestor_key_and_the_event() {
    // If e ignored any of these, an attestor could reuse one scalar across
    // escrows.
    let s = setup();
    let base = outcome_challenge(&s.r, &s.p, &s.event).unwrap();

    let other_r = SecretKey::from_slice(&[0x4c; 32]).unwrap().public_key(&s.secp);
    let other_p = SecretKey::from_slice(&[0xd2; 32]).unwrap().public_key(&s.secp);

    assert_ne!(base.to_be_bytes(), outcome_challenge(&other_r, &s.p, &s.event).unwrap().to_be_bytes());
    assert_ne!(base.to_be_bytes(), outcome_challenge(&s.r, &other_p, &s.event).unwrap().to_be_bytes());
    assert_ne!(
        base.to_be_bytes(),
        outcome_challenge(&s.r, &s.p, &event_id(&[0x7b; 32], 0)).unwrap().to_be_bytes()
    );
}

#[test]
fn tagged_hashes_are_domain_separated() {
    assert_ne!(
        tagged_hash(b"zecp2p-outcome-v1", b"x"),
        tagged_hash(b"zecp2p-announce-v1", b"x"),
        "two tags must not collide, or a value signed for one purpose could be \
         reused for the other"
    );
}

#[test]
fn a_reused_nonce_across_two_events_leaks_the_attestor_key() {
    // This is not a feature; it is the reason spec 5.1 refuses a second
    // announcement per event and 5.5 deletes `k` on signing. Demonstrating the
    // consequence is the argument for why that rule is load-bearing.
    //
    // From s_a = k + e_a*d and s_b = k + e_b*d the nonce cancels:
    //     s_a - s_b = (e_a - e_b) * d
    // so d = (s_a - s_b) * (e_a - e_b)^-1 mod n. The arithmetic below uses
    // secp256k1's own scalar operations rather than a hand-rolled bignum.
    let s = setup();
    let event_a = event_id(&[0x7a; 32], 0);
    let event_b = event_id(&[0x7b; 32], 0);

    let s_a = sign_outcome(&s.secp, &s.k, &s.d, &event_a).unwrap();
    let s_b = sign_outcome(&s.secp, &s.k, &s.d, &event_b).unwrap();

    let e_a = sk(&outcome_challenge(&s.r, &s.p, &event_a).unwrap().to_be_bytes());
    let e_b = sk(&outcome_challenge(&s.r, &s.p, &event_b).unwrap().to_be_bytes());

    // Negating a SecretKey negates it mod n, so `a - b` is `a + (-b)`.
    let num = add(&s_a, &s_b.negate());
    let den = add(&e_a, &e_b.negate());

    let recovered = mul(&num, &invert(&den));

    assert_eq!(
        recovered.secret_bytes(),
        s.d.secret_bytes(),
        "reusing k across two events must be shown to expose d, which is why \
         the attestor may never do it"
    );
}

fn sk(bytes: &[u8; 32]) -> SecretKey {
    SecretKey::from_slice(bytes).expect("scalar is in range")
}

fn add(a: &SecretKey, b: &SecretKey) -> SecretKey {
    a.add_tweak(&Scalar::from_be_bytes(b.secret_bytes()).unwrap())
        .expect("the sum is nonzero for the values used here")
}

fn mul(a: &SecretKey, b: &SecretKey) -> SecretKey {
    a.mul_tweak(&Scalar::from_be_bytes(b.secret_bytes()).unwrap())
        .expect("a product of nonzero scalars is nonzero")
}

/// Multiplicative inverse mod the group order, by Fermat's little theorem:
/// `x^(n-2)`. `mul_tweak` is multiplication mod n, so square-and-multiply over
/// it needs no bignum of our own.
fn invert(x: &SecretKey) -> SecretKey {
    // n - 2 for secp256k1.
    const N_MINUS_2: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x3f,
    ];

    // Most-significant bit first. `acc` begins at the first set bit, so no
    // representation of the scalar one is needed.
    let mut acc: Option<SecretKey> = None;
    for byte in N_MINUS_2.iter() {
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 == 1;
            acc = match acc {
                None => set.then_some(*x),
                Some(a) => {
                    let squared = mul(&a, &a);
                    Some(if set { mul(&squared, x) } else { squared })
                }
            };
        }
    }
    acc.expect("n-2 is nonzero")
}
