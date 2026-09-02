//! Byte-level properties of the redeem script and the P2SH commitment.
//! `script_execution.rs` proves the script *behaves* correctly; these pin how it
//! is *encoded*, because both parties must derive the identical address.

use zecp2p_escrow::script::{
    encode_script_num, hash160, p2sh_script_pubkey, redeem_script, ScriptError,
};

const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

#[test]
fn script_numbers_are_minimally_encoded() {
    // CLTV requires minimal encoding under the MinimalData rule; a non-minimal
    // push makes the refund unspendable.
    assert_eq!(encode_script_num(0).unwrap(), Vec::<u8>::new());
    assert_eq!(encode_script_num(1).unwrap(), vec![0x01]);
    assert_eq!(encode_script_num(0x7f).unwrap(), vec![0x7f]);
    // 0x80 has the sign bit set, so a zero byte is appended rather than the
    // value being read as negative.
    assert_eq!(encode_script_num(0x80).unwrap(), vec![0x80, 0x00]);
    assert_eq!(encode_script_num(0xff).unwrap(), vec![0xff, 0x00]);
    assert_eq!(encode_script_num(3_000_000).unwrap(), vec![0xc0, 0xc6, 0x2d]);
    // Just below and just above the 3-to-4 byte boundary.
    assert_eq!(encode_script_num(8_388_607).unwrap(), vec![0xff, 0xff, 0x7f]);
    assert_eq!(encode_script_num(8_388_608).unwrap(), vec![0x00, 0x00, 0x80, 0x00]);
}

#[test]
fn the_redeem_script_has_the_shape_of_spec_section_4_1() {
    let rs = redeem_script(&U_PUB, &L_PUB, 3_000_000).unwrap();

    assert_eq!(rs[0], 0x63, "OP_IF");
    assert_eq!(rs[1], 0x52, "OP_2");
    assert_eq!(rs[2], 33, "push u_pub");
    assert_eq!(&rs[3..36], &U_PUB, "u_pub comes first");
    assert_eq!(rs[36], 33, "push l_pub");
    assert_eq!(&rs[37..70], &L_PUB, "l_pub comes second");
    assert_eq!(rs[70], 0x52, "OP_2");
    assert_eq!(rs[71], 0xae, "OP_CHECKMULTISIG");
    assert_eq!(rs[72], 0x67, "OP_ELSE");
    assert_eq!(rs[73], 3, "push a 3-byte height");
    assert_eq!(&rs[74..77], &[0xc0, 0xc6, 0x2d]);
    assert_eq!(rs[77], 0xb1, "OP_CHECKLOCKTIMEVERIFY");
    assert_eq!(rs[78], 0x75, "OP_DROP");
    assert_eq!(rs[79], 33, "push u_pub again");
    assert_eq!(&rs[80..113], &U_PUB, "the refund branch checks the user only");
    assert_eq!(rs[113], 0xac, "OP_CHECKSIG");
    assert_eq!(rs[114], 0x68, "OP_ENDIF");
    assert_eq!(rs.len(), 115);
}

#[test]
fn the_key_order_in_checkmultisig_is_user_then_lp() {
    // CHECKMULTISIG requires the signatures in the same order as the pubkeys,
    // so swapping the parties must produce a different script and address.
    let a = redeem_script(&U_PUB, &L_PUB, 3_000_000).unwrap();
    let b = redeem_script(&L_PUB, &U_PUB, 3_000_000).unwrap();
    assert_ne!(a, b);
    assert_ne!(p2sh_script_pubkey(&a), p2sh_script_pubkey(&b));
}

#[test]
fn the_p2sh_script_pubkey_commits_to_the_redeem_script() {
    let rs = redeem_script(&U_PUB, &L_PUB, 3_000_000).unwrap();
    let spk = p2sh_script_pubkey(&rs);

    assert_eq!(spk.len(), 23);
    assert_eq!(spk[0], 0xa9, "OP_HASH160");
    assert_eq!(spk[1], 20, "push 20 bytes");
    assert_eq!(&spk[2..22], &hash160(&rs));
    assert_eq!(spk[22], 0x87, "OP_EQUAL");
}

#[test]
fn every_term_of_the_escrow_changes_the_address() {
    // The address is the user's only commitment to the terms it agreed to. If
    // any of these collided, an LP could fund a different escrow than the one
    // the user signed a pre-signature for.
    let base = p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, 3_000_000).unwrap());

    let other_u = p2sh_script_pubkey(&redeem_script(&[0x04; 33], &L_PUB, 3_000_000).unwrap());
    let other_l = p2sh_script_pubkey(&redeem_script(&U_PUB, &[0x04; 33], 3_000_000).unwrap());
    let other_t = p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, 3_000_001).unwrap());

    for (label, spk) in [("u_pub", other_u), ("l_pub", other_l), ("T", other_t)] {
        assert_ne!(base, spk, "changing {label} must change the escrow address");
    }
}

#[test]
fn hash160_matches_the_known_bitcoin_test_vector() {
    // RIPEMD160(SHA256("")), so a wrong hash function is caught rather than
    // being merely self-consistent.
    assert_eq!(
        hex::encode(hash160(b"")),
        "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
    );
}

#[test]
fn an_out_of_range_refund_height_is_refused() {
    assert_eq!(
        redeem_script(&U_PUB, &L_PUB, u64::MAX),
        Err(ScriptError::BadHeight(u64::MAX))
    );
}
