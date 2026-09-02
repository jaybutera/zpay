//! Verifies the Rust attestation verifier against two real enclave signatures
//! captured from production.
//!
//! These are the Phase 0 vectors that close open item 1. They matter because
//! the attestor signs an outcome, and therefore moves a user's ZEC, on the
//! strength of this check alone.

use serde_json::Value;

use zecp2p_escrow::attestation::{
    domain_separator, eip712_digest, recover_signer, type_hash, verify, AttestationError,
    PaymentAttestation, ENCLAVE_SIGNER,
};

struct Vector {
    name: &'static str,
    attestation: PaymentAttestation,
    signature: Vec<u8>,
    encoded_payment_details: Vec<u8>,
    domain_separator: [u8; 32],
    type_hash: [u8; 32],
}

fn h32(v: &Value, key: &str) -> [u8; 32] {
    let s = v[key].as_str().expect("hex string").trim_start_matches("0x");
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(s).expect("valid hex"));
    out
}

fn load(name: &'static str, path: &str) -> Vector {
    let raw = std::fs::read_to_string(path).expect("fixture is present");
    let j: Value = serde_json::from_str(&raw).expect("fixture parses");
    let att = &j["attestation"];
    let tv = &att["typedDataValue"];

    Vector {
        name,
        attestation: PaymentAttestation {
            intent_hash: h32(tv, "intentHash"),
            release_amount: tv["releaseAmount"]
                .as_str()
                .expect("releaseAmount is a decimal string")
                .parse()
                .expect("releaseAmount parses"),
            data_hash: h32(tv, "dataHash"),
        },
        signature: hex::decode(
            att["signature"].as_str().unwrap().trim_start_matches("0x"),
        )
        .unwrap(),
        encoded_payment_details: hex::decode(
            att["encodedPaymentDetails"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap(),
        domain_separator: h32(att, "domainSeparator"),
        type_hash: h32(att, "typeHash"),
    }
}

fn vectors() -> Vec<Vector> {
    vec![
        load(
            "1.00 USD",
            "tests/fixtures/attestation_1000000.json",
        ),
        load(
            "4.875437 USD",
            "tests/fixtures/attestation_4875437.json",
        ),
    ]
}

#[test]
fn the_pinned_domain_reproduces_the_recorded_domain_separator() {
    // If this fails, the enclave changed its domain and every attestation the
    // attestor accepts afterwards would be verified against the wrong one.
    for v in vectors() {
        assert_eq!(
            domain_separator(),
            v.domain_separator,
            "domain separator mismatch on the {} vector",
            v.name
        );
    }
}

#[test]
fn the_pinned_type_hash_reproduces_the_recorded_type_hash() {
    for v in vectors() {
        assert_eq!(type_hash(), v.type_hash, "type hash mismatch on {}", v.name);
    }
}

#[test]
fn the_data_hash_is_keccak_of_the_encoded_payment_details() {
    // The Phase 0 derivation. Three other candidates were tried and rejected.
    use sha3::{Digest, Keccak256};
    for v in vectors() {
        let mut h = Keccak256::new();
        h.update(&v.encoded_payment_details);
        let computed: [u8; 32] = h.finalize().into();
        assert_eq!(
            computed, v.attestation.data_hash,
            "dataHash derivation is wrong for {}",
            v.name
        );
    }
}

#[test]
fn both_live_attestations_recover_to_the_pinned_enclave_signer() {
    for v in vectors() {
        let signer = recover_signer(&eip712_digest(&v.attestation), &v.signature)
            .expect("a production signature must recover");
        assert_eq!(
            signer, ENCLAVE_SIGNER,
            "the {} vector did not recover to the pinned signer",
            v.name
        );
    }
}

#[test]
fn full_verification_accepts_both_live_attestations() {
    for v in vectors() {
        verify(
            &v.attestation,
            &v.signature,
            &v.encoded_payment_details,
            &v.attestation.intent_hash,
            v.attestation.release_amount,
        )
        .unwrap_or_else(|e| panic!("the {} vector must verify, got {e}", v.name));
    }
}

// --- The rejections. A verifier that accepts everything passes the tests
// --- above, so each check has to be shown to actually bite.

#[test]
fn verification_rejects_an_attestation_for_a_different_intent() {
    // The attack this stops: an LP replaying a real payment it made for some
    // other purpose against this escrow's intentHash.
    let v = &vectors()[0];
    let err = verify(
        &v.attestation,
        &v.signature,
        &v.encoded_payment_details,
        &[0xAB; 32],
        v.attestation.release_amount,
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::WrongIntent { .. }), "got {err}");
}

#[test]
fn verification_rejects_an_underpayment() {
    let v = &vectors()[0];
    let err = verify(
        &v.attestation,
        &v.signature,
        &v.encoded_payment_details,
        &v.attestation.intent_hash,
        v.attestation.release_amount + 1,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestationError::InsufficientAmount { .. }),
        "got {err}"
    );
}

#[test]
fn verification_rejects_a_tampered_release_amount() {
    // Raising the amount changes the struct hash, so the signature no longer
    // recovers to the enclave. This is the check that stops an LP claiming a
    // larger escrow than it paid for.
    let v = &vectors()[0];
    let mut tampered = v.attestation.clone();
    tampered.release_amount += 1_000_000;
    let err = verify(
        &tampered,
        &v.signature,
        &v.encoded_payment_details,
        &tampered.intent_hash,
        0,
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::WrongSigner { .. }), "got {err}");
}

#[test]
fn verification_rejects_payment_details_that_do_not_match_the_data_hash() {
    // dataHash is what binds the signature to the actual Venmo payment. If a
    // caller could supply arbitrary details, the attestor's inspection of the
    // payment would be meaningless.
    let v = &vectors()[0];
    let mut details = v.encoded_payment_details.clone();
    details[0] ^= 0xff;
    let err = verify(
        &v.attestation,
        &v.signature,
        &details,
        &v.attestation.intent_hash,
        0,
    )
    .unwrap_err();
    assert_eq!(err, AttestationError::DataHashMismatch);
}

#[test]
fn verification_rejects_a_signature_from_another_key() {
    // A forged attestation from an attacker's own key: structurally perfect,
    // wrong signer.
    use secp256k1::{Message, Secp256k1, SecretKey};
    let v = &vectors()[0];
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0x5a; 32]).unwrap();
    let digest = eip712_digest(&v.attestation);
    let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(digest), &key);
    let (rec_id, compact) = sig.serialize_compact();
    let mut bytes = compact.to_vec();
    bytes.push(i32::from(rec_id) as u8 + 27);

    let err = verify(
        &v.attestation,
        &bytes,
        &v.encoded_payment_details,
        &v.attestation.intent_hash,
        0,
    )
    .unwrap_err();
    assert!(matches!(err, AttestationError::WrongSigner { .. }), "got {err}");
}

#[test]
fn verification_rejects_a_malformed_signature() {
    let v = &vectors()[0];
    let err = verify(
        &v.attestation,
        &v.signature[..64],
        &v.encoded_payment_details,
        &v.attestation.intent_hash,
        0,
    )
    .unwrap_err();
    assert_eq!(err, AttestationError::BadSignatureLength(64));
}

#[test]
fn the_intent_hash_and_release_amount_appear_in_the_signed_payment_details() {
    // Phase 0 decoded encodedPaymentDetails as 14 abi words, with intentHash at
    // word 6 and releaseAmount at word 7. That binding is what lets the attestor
    // trust the payment matches the intent, rather than trusting typedDataValue
    // alone, so pin it.
    for v in vectors() {
        assert_eq!(v.encoded_payment_details.len(), 14 * 32);
        assert_eq!(
            &v.encoded_payment_details[6 * 32..7 * 32],
            &v.attestation.intent_hash,
            "intentHash must sit at word 6 for {}",
            v.name
        );
        let mut amount_word = [0u8; 32];
        amount_word[16..].copy_from_slice(&v.attestation.release_amount.to_be_bytes());
        assert_eq!(
            &v.encoded_payment_details[7 * 32..8 * 32],
            &amount_word,
            "releaseAmount must sit at word 7 for {}",
            v.name
        );
    }
}
