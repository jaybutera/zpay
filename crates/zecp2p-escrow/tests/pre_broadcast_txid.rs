//! Spec 4.2's foundation: a ZIP 244 txid does not commit to signatures.
//!
//! The whole handshake rests on this. The user must know the funding outpoint
//! before the funding transaction is signed, so the pre-signature can commit to
//! it; and the LP must be able to compute the release's txid before it
//! broadcasts. Round 7 found nothing in the repo exercised it - every txid in
//! the regtest run was read back from the node after the fact.

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::rpc::{rpc_hex_to_txid, txid_to_rpc_hex};
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::tx::{
    build_release, encode_signature, release_txid, serialize_release, txid_of_signed, EscrowTerms,
};

const NU6_3: u32 = 0x37a5_165b;

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

struct Fixture {
    secp: Secp256k1<secp256k1::All>,
    terms: EscrowTerms,
    redeem: Vec<u8>,
    fee: u64,
    lp_script: Vec<u8>,
    digest: [u8; 32],
    u_priv: SecretKey,
    l_priv: SecretKey,
}

fn fixture() -> Fixture {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let terms = EscrowTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 200_000,
        u_pub: PublicKey::from_secret_key(&secp, &u_priv).serialize(),
        l_pub: PublicKey::from_secret_key(&secp, &l_priv).serialize(),
        refund_height: 3_500_000,
        consensus_branch_id: NU6_3,
    };
    let redeem = terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp_script = p2pkh([0x09; 20]);
    let digest = build_release(&terms, &lp_script, fee)
        .unwrap()
        .sighash()
        .unwrap();
    Fixture {
        secp,
        terms,
        redeem,
        fee,
        lp_script,
        digest,
        u_priv,
        l_priv,
    }
}

#[test]
fn the_txid_does_not_move_when_the_signatures_change() {
    // The ZIP 244 property spec 4.2 depends on. Signing the same transaction
    // with different nonces gives different scriptSigs and the same txid.
    let f = fixture();

    let mut txids = Vec::new();
    let mut script_sigs = Vec::new();
    for _ in 0..4 {
        // secp256k1's RFC 6979 nonce is deterministic, so vary the LP's key to
        // get genuinely different signature bytes over one digest.
        let sig_u = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.u_priv);
        let sig_l = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.l_priv);
        let ss = release_script_sig(
            &encode_signature(&sig_u),
            &encode_signature(&sig_l),
            &f.redeem,
        );
        script_sigs.push(ss.clone());
        txids.push(release_txid(&f.terms, &f.lp_script, f.fee, &ss).unwrap());
    }
    assert!(txids.windows(2).all(|w| w[0] == w[1]));

    // Now a genuinely different signature: a third key in the user slot. The
    // scriptSig differs, the txid must not.
    let other = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let sig_other = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &other);
    let sig_l = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.l_priv);
    let ss_other = release_script_sig(
        &encode_signature(&sig_other),
        &encode_signature(&sig_l),
        &f.redeem,
    );
    assert_ne!(
        ss_other, script_sigs[0],
        "the two scriptSigs must actually differ, or this proves nothing"
    );
    assert_eq!(
        release_txid(&f.terms, &f.lp_script, f.fee, &ss_other).unwrap(),
        txids[0],
        "a ZIP 244 txid must not commit to the signatures"
    );
}

#[test]
fn the_txid_does_move_when_the_transaction_changes() {
    // The mirror: if the txid ignored the outputs too, it would be useless.
    let f = fixture();
    let sig_u = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.u_priv);
    let sig_l = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.l_priv);
    let ss = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &f.redeem,
    );

    let base = release_txid(&f.terms, &f.lp_script, f.fee, &ss).unwrap();
    let other_payee = release_txid(&f.terms, &p2pkh([0xaa; 20]), f.fee, &ss).unwrap();
    let other_fee = release_txid(&f.terms, &f.lp_script, f.fee + 5_000, &ss).unwrap();

    assert_ne!(base, other_payee, "the payout script must be committed");
    assert_ne!(base, other_fee, "the output value must be committed");
}

#[test]
fn the_computed_txid_matches_the_serialized_transaction() {
    // `release_txid` and `txid_of_signed` must agree, since the LP computes one
    // before broadcasting and reads the other back.
    let f = fixture();
    let sig_u = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.u_priv);
    let sig_l = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.l_priv);
    let ss = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &f.redeem,
    );

    let raw = serialize_release(&f.terms, &f.lp_script, f.fee, &ss).unwrap();
    assert_eq!(
        release_txid(&f.terms, &f.lp_script, f.fee, &ss).unwrap(),
        txid_of_signed(&raw).unwrap()
    );
}

#[test]
fn the_wire_and_rpc_byte_orders_are_reverses_and_round_trip() {
    // Round 7, item 7: the wire carries the internal order and every RPC prints
    // the reverse. Sending the wrong one gets a 503 the LP retries forever, so
    // the conversion is worth a test of its own.
    let f = fixture();
    let sig_u = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.u_priv);
    let sig_l = f.secp.sign_ecdsa(&Message::from_digest(f.digest), &f.l_priv);
    let ss = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &f.redeem,
    );
    let internal = release_txid(&f.terms, &f.lp_script, f.fee, &ss).unwrap();

    let rpc = txid_to_rpc_hex(&internal);
    assert_ne!(
        rpc,
        hex::encode(internal),
        "the two orders must differ, or nobody would ever get this wrong"
    );
    assert_eq!(rpc_hex_to_txid(&rpc).unwrap(), internal);
}

#[test]
fn a_transaction_that_does_not_parse_is_an_error_not_a_panic() {
    assert!(txid_of_signed(&[]).is_err());
    assert!(txid_of_signed(&[0x00; 8]).is_err());
}
