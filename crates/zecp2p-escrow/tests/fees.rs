//! The escrow computes its own ZIP 317 fee because the library rule cannot size
//! a P2SH input. That makes the arithmetic ours to get right, so these tests
//! cross-check it against `zcash_primitives`' own rule on the inputs that rule
//! *can* size, and pin the escrow's actual numbers.

use zcash_primitives::transaction::fees::transparent::InputSize;
use zcash_primitives::transaction::fees::{zip317, FeeRule as _};
use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

use zecp2p_escrow::fees::{
    conventional_fee_zat, refund_fee_to_shielded_zat, refund_input_size,
    release_fee_to_transparent_zat, release_input_size, P2PKH_STANDARD_OUTPUT_SIZE,
};
use zecp2p_escrow::script::redeem_script;

fn escrow_redeem_len() -> usize {
    let u_pub = [0x02u8; 33];
    let l_pub = [0x03u8; 33];
    // A mainnet-scale height, which encodes as 4 script bytes.
    redeem_script(&u_pub, &l_pub, 3_000_000).unwrap().len()
}

/// Runs the library's ZIP 317 rule for the same shape, with the transparent
/// input size supplied explicitly as `Known`, which is the part the library
/// declines to infer for P2SH.
fn library_fee(t_in: usize, t_out: Vec<usize>, orchard_actions: usize) -> u64 {
    let fee = zip317::FeeRule::standard()
        .fee_required(
            &MAIN_NETWORK,
            BlockHeight::from_u32(3_000_000),
            vec![InputSize::Known(t_in)],
            t_out,
            0,
            0,
            orchard_actions,
            0,
        )
        .expect("a known-size input is always priceable");
    u64::from(fee)
}

#[test]
fn the_escrow_fee_matches_the_library_rule_for_the_release() {
    let rs_len = escrow_redeem_len();
    let mine = release_fee_to_transparent_zat(rs_len);
    let theirs = library_fee(
        release_input_size(rs_len),
        vec![P2PKH_STANDARD_OUTPUT_SIZE],
        0,
    );
    assert_eq!(
        mine, theirs,
        "the escrow's own ZIP 317 arithmetic must agree with zcash_primitives"
    );
}

#[test]
fn the_escrow_fee_matches_the_library_rule_for_the_shielded_refund() {
    let rs_len = escrow_redeem_len();
    let mine = refund_fee_to_shielded_zat(rs_len);
    let theirs = library_fee(refund_input_size(rs_len), vec![], 2);
    assert_eq!(mine, theirs);
}

#[test]
fn the_release_costs_three_logical_actions_not_two() {
    // Phase 0 finding, and a correction to spec section 3 and criterion 6: the
    // escrow's scriptSig carries two signatures and a 116-byte redeem script,
    // so the input is 311 bytes. ZIP 317 divides by the 150-byte nominal P2PKH
    // input, giving 3 logical actions and a 15000 zat fee, not the 10000 zat a
    // 1-in 1-out P2PKH spend would pay.
    let rs_len = escrow_redeem_len();
    // 115 bytes at a height that encodes in 3 script bytes; 116 once heights
    // pass 8388608 and need a fourth. Both land in the same fee bracket, which
    // the next test pins.
    assert_eq!(rs_len, 115, "the redeem script size feeds every fee below");
    assert_eq!(release_input_size(rs_len), 310);
    assert_eq!(
        release_fee_to_transparent_zat(rs_len),
        15_000,
        "a release paying 10000 zat would underpay, and Zcash has no RBF"
    );
}

#[test]
fn the_shielded_refund_costs_four_logical_actions() {
    let rs_len = escrow_redeem_len();
    assert_eq!(refund_input_size(rs_len), 233);
    // 2 transparent-input actions + 2 Orchard actions.
    assert_eq!(refund_fee_to_shielded_zat(rs_len), 20_000);
}

/// `T` grows over the life of the chain, and at height 8388608 it needs a
/// fourth script byte. A fee that changed at that boundary would silently
/// underpay every escrow written against the old constant, so pin that the
/// bracket is unchanged across it.
#[test]
fn the_fee_is_unchanged_when_the_refund_height_needs_a_fourth_byte() {
    let u_pub = [0x02u8; 33];
    let l_pub = [0x03u8; 33];

    let three_byte = redeem_script(&u_pub, &l_pub, 8_388_607).unwrap();
    let four_byte = redeem_script(&u_pub, &l_pub, 8_388_608).unwrap();
    assert_eq!(three_byte.len() + 1, four_byte.len(), "the height must gain a byte here");

    assert_eq!(
        release_fee_to_transparent_zat(three_byte.len()),
        release_fee_to_transparent_zat(four_byte.len()),
    );
    assert_eq!(
        refund_fee_to_shielded_zat(three_byte.len()),
        refund_fee_to_shielded_zat(four_byte.len()),
    );
}

/// R7-2: a transparent refund is two logical actions, not four.
///
/// The node probed in round 7 refused a 5000 zat transparent refund and
/// accepted 10000, which is what this computes. The shielded number is
/// double, because an Orchard bundle is padded to two actions.
#[test]
fn a_transparent_refund_costs_less_than_a_shielded_one() {
    use zecp2p_escrow::fees::refund_fee_to_transparent_zat;
    let rs_len = escrow_redeem_len();

    assert_eq!(refund_fee_to_transparent_zat(rs_len), 10_000);
    assert_eq!(refund_fee_to_shielded_zat(rs_len), 20_000);
    assert!(
        refund_fee_to_transparent_zat(rs_len) < refund_fee_to_shielded_zat(rs_len),
        "paying the shielded fee on a transparent refund overpays for actions the \
         transaction does not have"
    );

    // And it agrees with the library rule for the same shape.
    let theirs = library_fee(
        refund_input_size(rs_len),
        vec![P2PKH_STANDARD_OUTPUT_SIZE],
        0,
    );
    assert_eq!(refund_fee_to_transparent_zat(rs_len), theirs);
}

#[test]
fn the_fee_never_falls_below_the_grace_floor() {
    assert_eq!(conventional_fee_zat(0, 0, 0), 10_000);
    assert_eq!(conventional_fee_zat(1, 1, 0), 10_000);
}

#[test]
fn the_fee_is_monotone_in_input_size() {
    // A fee that could shrink as the transaction grows would be a way to
    // underpay a release; ZIP 317 is monotone and so must our copy be.
    let mut last = 0;
    for bytes in (0..2_000).step_by(37) {
        let f = conventional_fee_zat(bytes, P2PKH_STANDARD_OUTPUT_SIZE, 0);
        assert!(f >= last, "fee decreased at {bytes} bytes: {f} < {last}");
        last = f;
    }
}
