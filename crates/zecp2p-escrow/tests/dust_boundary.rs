//! The dust threshold, derived from the node's own rule rather than assumed.
//!
//! `treasury::DUST_THRESHOLD_ZAT` is 54. Being wrong about it in either
//! direction has a cost, and they are different costs:
//!
//! - too **low**, and a treasury output at the constant is under the node's
//!   real threshold, so the whole release is non-standard and the trade fails
//!   rather than merely going unbilled;
//! - too **high**, and the dust gate drops fees the node would have accepted.
//!
//! # Why this is arithmetic and not a live probe
//!
//! An earlier version of this file broadcast a 53 zat and a 54 zat output to a
//! node and compared the verdicts. Round 2 found it could not work against
//! Zebra, which is the node this project runs: Zebra's transaction verifier
//! rejects a missing transparent input UTXO *before* it reaches the
//! standardness rules, so both probes came back "missing input" and the test
//! failed blaming the constant. Reaching the dust check would need a real
//! spendable outpoint, which means funding one, which is not something a unit
//! test should do.
//!
//! So the check is that our constant reproduces the node's formula, evaluated
//! here from the same inputs the node uses. That is a weaker claim than "a node
//! accepted it", and the difference is worth naming: this catches a wrong
//! constant and a wrong formula, and it would not catch a node that departed
//! from the formula. The live-fire run in the ship order is what covers that
//! last case, on a funded escrow, where the release is a real transaction and
//! the node's answer means something.

use zecp2p_escrow::treasury::{platform_fee_zat, DUST_THRESHOLD_ZAT, PLATFORM_FEE_BPS};
use zecp2p_escrow::tx::{EscrowTerms, ReleaseSplit, TxError};

/// Zcash's minimum relay fee, in zatoshi per 1000 bytes.
///
/// 100 since zcashd v1.0.7-1, down from the 1000 that gave the widely quoted
/// 546 zat threshold and the 5000 that gave the older 2730.
const MIN_RELAY_FEE_ZAT_PER_KB: u64 = 100;

/// The size of the input needed to spend a transparent output, in bytes.
///
/// The inherited Bitcoin figure: a 148-byte P2PKH input. A P2SH input is
/// smaller per byte of output, so using the P2PKH number makes the threshold
/// the conservative side of the boundary for either script type.
const SPEND_INPUT_SIZE: u64 = 148;

/// A serialized P2PKH output: 8 value bytes, 1 length byte, 25 script bytes.
const P2PKH_OUTPUT_SIZE: u64 = 34;

/// A serialized P2SH output: 8 value bytes, 1 length byte, 23 script bytes.
const P2SH_OUTPUT_SIZE: u64 = 32;

/// The node's rule: an output is dust if spending it would cost more than a
/// third of its value at the minimum relay rate.
///
/// `3 * minRelayTxFee.GetFee(output_size + spend_input_size)`, with `GetFee`
/// being `size * rate / 1000`.
fn dust_threshold_for(output_size: u64) -> u64 {
    3 * (MIN_RELAY_FEE_ZAT_PER_KB * (output_size + SPEND_INPUT_SIZE) / 1000)
}

#[test]
fn the_constant_reproduces_the_nodes_formula() {
    // 3 * (100 * (34 + 148) / 1000) = 3 * 18 = 54.
    assert_eq!(dust_threshold_for(P2PKH_OUTPUT_SIZE), 54);
    assert_eq!(
        DUST_THRESHOLD_ZAT,
        dust_threshold_for(P2PKH_OUTPUT_SIZE),
        "the pinned constant must be the number the node computes for a P2PKH output"
    );
}

#[test]
fn the_constant_is_the_conservative_side_for_a_p2sh_treasury() {
    // A t3 treasury address pays a P2SH output, which is two bytes smaller and
    // therefore cheaper to spend, so its threshold is no higher. Using the
    // P2PKH number for both means a P2SH treasury output at the constant clears
    // its own rule with room to spare, rather than sitting one byte under it.
    let p2sh = dust_threshold_for(P2SH_OUTPUT_SIZE);
    assert_eq!(p2sh, 54, "3 * (100 * (32 + 148) / 1000) = 3 * 18");
    assert!(
        DUST_THRESHOLD_ZAT >= p2sh,
        "the constant must not be below the P2SH threshold"
    );
}

/// The rate history, so a future change to `minRelayTxFee` is caught here
/// rather than in a release nobody can broadcast.
#[test]
fn the_older_relay_rates_give_the_thresholds_they_are_remembered_for() {
    // These are not what Zcash uses now; they are here because the 546 and 2730
    // figures are what a search turns up, and a reader who finds one of them
    // should be able to see immediately which rate it came from.
    let at_rate = |rate: u64| 3 * (rate * (P2PKH_OUTPUT_SIZE + SPEND_INPUT_SIZE) / 1000);
    assert_eq!(at_rate(1_000), 546, "the pre-v1.0.7-1 rate");
    assert_eq!(at_rate(5_000), 2_730, "the launch rate");
    assert_eq!(at_rate(MIN_RELAY_FEE_ZAT_PER_KB), 54, "the current rate");
}

/// The escrow's own gate must sit exactly on the boundary: it must refuse what
/// the node would refuse, and accept what the node would accept.
///
/// A gate stricter than the node drops fees; a gate looser than it builds
/// releases that cannot be broadcast, which the LP discovers after paying.
#[test]
fn the_escrows_gate_sits_on_the_boundary_in_both_directions() {
    let terms = EscrowTerms {
        funding_txid: [0xd5; 32],
        vout: 0,
        amount_zat: 200_000,
        u_pub: [0x02; 33],
        l_pub: [0x03; 33],
        refund_height: 3_471_833,
        consensus_branch_id: 0xc8e7_1055,
    };
    let treasury =
        zecp2p_escrow::treasury::treasury_script(zecp2p_escrow::address::AddrNetwork::Test)
            .expect("the testnet treasury is pinned");

    let split = |fee: u64| ReleaseSplit {
        payout_script: vec![
            0x76, 0xa9, 20, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0x88,
            0xac,
        ],
        miner_fee_zat: 15_000,
        platform_fee_zat: fee,
        treasury_script: treasury.clone(),
    };

    // One zatoshi under: refused, and the error names the value and the
    // threshold rather than merely failing.
    match split(DUST_THRESHOLD_ZAT - 1).outputs(terms.amount_zat) {
        Err(TxError::DustOutput { value, threshold, .. }) => {
            assert_eq!(value, 53);
            assert_eq!(threshold, 54);
        }
        other => panic!("a 53 zat treasury output must be refused as dust, got {other:?}"),
    }

    // At the threshold: accepted, and the treasury output carries exactly that.
    let outs = split(DUST_THRESHOLD_ZAT)
        .outputs(terms.amount_zat)
        .expect("54 zat clears the threshold");
    assert_eq!(outs.len(), 2);
    assert_eq!(outs[1].value_zat, 54);

    // And the payout leg is held to the same rule, not just the treasury one.
    let starved = ReleaseSplit {
        miner_fee_zat: terms.amount_zat - 500,
        platform_fee_zat: 447,
        ..split(447)
    };
    assert!(
        matches!(
            starved.outputs(terms.amount_zat),
            Err(TxError::DustOutput { index: 0, value: 53, .. })
        ),
        "a 53 zat payout leg is as unbroadcastable as a 53 zat fee"
    );
}

/// The fee policy never hands the transaction builder something the builder
/// will refuse.
///
/// Two gates on the same boundary is one gate too many if they disagree:
/// `treasury::platform_fee_zat` drops a sub-dust fee to zero, and
/// `ReleaseSplit::outputs` refuses one. They must not be able to disagree about
/// where the line is, or a quote would succeed and the release it implies would
/// fail to build.
#[test]
fn the_fee_policy_and_the_transaction_builder_agree_on_the_line() {
    for amount in [36_000u64, 35_999, 120_000, 200_000, 1_000_000] {
        let fee = platform_fee_zat(amount, PLATFORM_FEE_BPS);
        assert!(
            fee == 0 || fee >= DUST_THRESHOLD_ZAT,
            "a {amount} zat escrow yielded a {fee} zat fee, which is neither zero nor \
             above the dust threshold, so the quote would build a release that cannot"
        );
    }

    // And at a rate low enough for the gate to fire, the fee is zero rather
    // than a value the builder would reject.
    assert_eq!(platform_fee_zat(120_000, 1), 0);
}
