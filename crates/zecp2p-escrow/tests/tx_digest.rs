//! The ZIP 244 digest and the transaction shapes of spec 4.3 and 4.4.
//!
//! Spec 4.6 names the failure this file exists to prevent: if the user client
//! and the LP compute different digests, the decrypted signature is invalid,
//! the release cannot be broadcast, and the LP has already sent the dollars.
//! Nothing reports the mismatch. So the tests below check that the digest moves
//! when any committed field moves, and does not move otherwise.

use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::script::CompressedPubkey;
use zecp2p_escrow::tx::{
    build_refund, build_release, encode_signature, EscrowTerms, TxError, REFUND_SEQUENCE,
    RELEASE_SEQUENCE,
};

/// NU6.3 / Ironwood, the branch in force on mainnet. Read from the node in
/// production; fixed here so the vectors are reproducible.
const NU6_3: u32 = 0x37a5_165b;

const U_PUB: CompressedPubkey = [0x02; 33];
const L_PUB: CompressedPubkey = [0x03; 33];

/// A P2PKH output script, standing in for the LP's t1 address.
fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn terms() -> EscrowTerms {
    EscrowTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: 3_500_000,
        consensus_branch_id: NU6_3,
    }
}

fn release_digest(t: &EscrowTerms) -> [u8; 32] {
    let fee = release_fee_to_transparent_zat(t.redeem_script().unwrap().len());
    build_release(t, &p2pkh([0x09; 20]), fee)
        .unwrap()
        .sighash()
        .unwrap()
}

#[test]
fn the_release_digest_is_deterministic() {
    // The user and the LP never exchange the transaction; each builds it from
    // the terms. If this were not stable, the protocol would not work at all.
    let t = terms();
    let a = release_digest(&t);
    let b = release_digest(&t);
    assert_eq!(a, b);
    assert_ne!(a, [0u8; 32], "a zero digest would mean nothing was hashed");
}

#[test]
fn every_committed_field_changes_the_release_digest() {
    // ZIP 244 commits the transparent input to the prevout, value, spent
    // scriptPubKey and nSequence. A field that did not move the digest would be
    // a field an LP could alter after the user pre-signed.
    let base = release_digest(&terms());

    let mut t = terms();
    t.funding_txid = [0x7b; 32];
    assert_ne!(base, release_digest(&t), "funding txid must be committed");

    let mut t = terms();
    t.vout = 1;
    assert_ne!(base, release_digest(&t), "vout must be committed");

    let mut t = terms();
    t.amount_zat = 5_000_001;
    assert_ne!(base, release_digest(&t), "input value must be committed");

    let mut t = terms();
    t.refund_height = 3_500_001;
    assert_ne!(
        base,
        release_digest(&t),
        "T changes the redeem script, so it changes the scriptPubKey and the digest"
    );

    let mut t = terms();
    t.l_pub = [0x04; 33];
    assert_ne!(base, release_digest(&t), "l_pub is in the redeem script");

    let mut t = terms();
    t.consensus_branch_id = 0x5437_f330; // NU6.2
    assert_ne!(
        base,
        release_digest(&t),
        "the branch id is mixed into the sighash personalization"
    );
}

#[test]
fn the_output_script_and_fee_change_the_release_digest() {
    // The LP names its own payout script. The user builds the release from that
    // stated script, so a later change by the LP invalidates the signature it
    // holds rather than redirecting the money.
    let t = terms();
    let fee = release_fee_to_transparent_zat(t.redeem_script().unwrap().len());
    let base = build_release(&t, &p2pkh([0x09; 20]), fee).unwrap().sighash().unwrap();

    let other_script = build_release(&t, &p2pkh([0x0a; 20]), fee).unwrap().sighash().unwrap();
    assert_ne!(base, other_script, "the payout script must be committed");

    let other_fee = build_release(&t, &p2pkh([0x09; 20]), fee + 5_000)
        .unwrap()
        .sighash()
        .unwrap();
    assert_ne!(base, other_fee, "the output value must be committed");
}

#[test]
fn the_release_and_refund_digests_differ() {
    // They spend the same outpoint. If their digests collided, a signature
    // meant for one would spend the other.
    let t = terms();
    let fee = release_fee_to_transparent_zat(t.redeem_script().unwrap().len());
    let release = build_release(&t, &p2pkh([0x09; 20]), fee).unwrap();
    let refund = build_refund(&t, &p2pkh([0x0b; 20]), fee).unwrap();

    assert_ne!(release.sighash().unwrap(), refund.sighash().unwrap());
}

#[test]
fn the_refund_sets_locktime_to_t_and_a_non_final_sequence() {
    // Spec 4.4. A final input disables CLTV outright, which would make the
    // escrow refundable the moment it is funded.
    let t = terms();
    let refund = build_refund(&t, &p2pkh([0x0b; 20]), 20_000).unwrap();
    assert_eq!(refund.lock_time(), 3_500_000);
    assert_ne!(REFUND_SEQUENCE, 0xffff_ffff, "the refund input must not be final");
    assert_eq!(REFUND_SEQUENCE, 0xffff_fffe);
}

#[test]
fn the_release_sets_locktime_zero_and_a_final_sequence() {
    let t = terms();
    let release = build_release(&t, &p2pkh([0x09; 20]), 15_000).unwrap();
    assert_eq!(release.lock_time(), 0);
    assert_eq!(RELEASE_SEQUENCE, 0xffff_ffff);
}

#[test]
fn both_transactions_are_version_5() {
    // Phase 0 finding 12.2: under NU6.3 the library builder would default to
    // V6. Version is part of the sighash, so a party that took the default
    // would compute a different digest.
    use zcash_primitives::transaction::TxVersion;
    let t = terms();
    assert_eq!(
        build_release(&t, &p2pkh([0x09; 20]), 15_000).unwrap().version(),
        TxVersion::V5
    );
    assert_eq!(
        build_refund(&t, &p2pkh([0x0b; 20]), 20_000).unwrap().version(),
        TxVersion::V5
    );
}

#[test]
fn an_escrow_that_cannot_cover_its_fee_is_refused_rather_than_underpaying() {
    let mut t = terms();
    t.amount_zat = 10_000;
    match build_release(&t, &p2pkh([0x09; 20]), 15_000) {
        Err(TxError::BelowFee { amount, fee }) => {
            assert_eq!((amount, fee), (10_000, 15_000));
        }
        Err(other) => panic!("expected a BelowFee refusal, got {other}"),
        Ok(_) => panic!("an escrow below its fee must not build a release"),
    }
}

#[test]
fn signatures_are_encoded_low_s_with_the_sighash_byte() {
    // Zcash enforces low-S as a standardness rule (spec 4.6). Adaptor
    // decryption can produce a high-S signature, which consensus accepts and
    // the mempool refuses, so the encoder must normalise unconditionally.
    use secp256k1::{Message, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0x11; 32]).unwrap();

    for i in 0..32u8 {
        let mut digest = [0u8; 32];
        digest[0] = i;
        let sig = secp.sign_ecdsa(&Message::from_digest(digest), &key);
        let encoded = encode_signature(&sig);

        assert_eq!(*encoded.last().unwrap(), 0x01, "SIGHASH_ALL must be appended");
        assert_eq!(encoded[0], 0x30, "DER sequence tag");

        // Re-parse and normalise again: for an already-low-S signature this
        // must be a no-op, so the bytes are unchanged.
        let parsed =
            secp256k1::ecdsa::Signature::from_der(&encoded[..encoded.len() - 1]).unwrap();
        let mut again = parsed;
        again.normalize_s();
        assert_eq!(
            again.serialize_der().to_vec(),
            encoded[..encoded.len() - 1].to_vec(),
            "the encoded signature must already be low-S"
        );
    }
}

#[test]
fn an_empty_output_script_is_refused() {
    // A zero-length output script is an unspendable output, and would burn the
    // escrow rather than pay anyone.
    let t = terms();
    assert!(matches!(
        build_release(&t, &[], 15_000),
        Err(TxError::EmptyOutputScript)
    ));
}
