//! ZIP 317 fees for the escrow's own transactions.
//!
//! `zcash_primitives`' `zip317::FeeRule` refuses to size a custom P2SH input:
//! only the spender knows how long the scriptSig will be, so the rule reports
//! `UnknownP2shInputs` rather than guessing (see
//! `tests/phase0_librustzcash.rs`). The escrow does know, because it builds the
//! scriptSig itself, so it computes the conventional fee directly.
//!
//! ZIP 317: `fee = marginal_fee * max(grace_actions, logical_actions)`, where
//! the transparent contribution is `ceil(total_input_bytes / 150)` against
//! `ceil(total_output_bytes / 34)`.

/// 5000 zat per logical action.
pub const MARGINAL_FEE_ZAT: u64 = 5_000;
/// A transaction is charged for at least this many actions.
pub const GRACE_ACTIONS: usize = 2;
/// ZIP 317's nominal P2PKH input size, the divisor for transparent inputs.
pub const P2PKH_STANDARD_INPUT_SIZE: usize = 150;
/// ZIP 317's nominal P2PKH output size.
pub const P2PKH_STANDARD_OUTPUT_SIZE: usize = 34;

/// The largest DER-encoded ECDSA signature, plus the trailing sighash byte.
///
/// A DER signature is at most 72 bytes; low-S normalisation (spec 4.6) can only
/// shrink it. Sizing for the maximum means the fee is never underpaid, which
/// matters because Zcash has no RBF and a stuck release cannot be bumped.
pub const MAX_SIG_WITH_HASHTYPE: usize = 73;

/// The serialized size of a `push` of `n` bytes, including the opcode.
fn push_len(n: usize) -> usize {
    if n < 0x4c {
        1 + n
    } else if n <= 0xff {
        2 + n
    } else {
        3 + n
    }
}

/// The size of a CompactSize prefix for `n`.
fn compact_size_len(n: usize) -> usize {
    if n < 253 {
        1
    } else if n <= 0xffff {
        3
    } else {
        5
    }
}

/// Upper bound on the serialized size of the release input, whose scriptSig is
/// `OP_0 <sig_u> <sig_l> OP_1 <redeemScript>`.
pub fn release_input_size(redeem_script_len: usize) -> usize {
    let script_sig = 1 // OP_0
        + push_len(MAX_SIG_WITH_HASHTYPE)
        + push_len(MAX_SIG_WITH_HASHTYPE)
        + 1 // OP_1
        + push_len(redeem_script_len);
    txin_size(script_sig)
}

/// Upper bound on the serialized size of the refund input, whose scriptSig is
/// `<sig_u> OP_0 <redeemScript>`.
pub fn refund_input_size(redeem_script_len: usize) -> usize {
    let script_sig =
        push_len(MAX_SIG_WITH_HASHTYPE) + 1 /* OP_0 */ + push_len(redeem_script_len);
    txin_size(script_sig)
}

/// outpoint (32-byte txid + 4-byte index) + scriptSig length prefix + scriptSig
/// + nSequence.
fn txin_size(script_sig_len: usize) -> usize {
    36 + compact_size_len(script_sig_len) + script_sig_len + 4
}

/// The ZIP 317 conventional fee, in zatoshis.
///
/// `shielded_actions` is the Orchard (or Ironwood) action count; a shielded
/// refund output costs the ZIP 317 minimum of 2 actions, because an Orchard
/// bundle is padded to two actions.
pub fn conventional_fee_zat(
    transparent_input_bytes: usize,
    transparent_output_bytes: usize,
    shielded_actions: usize,
) -> u64 {
    let t_in = transparent_input_bytes.div_ceil(P2PKH_STANDARD_INPUT_SIZE);
    let t_out = transparent_output_bytes.div_ceil(P2PKH_STANDARD_OUTPUT_SIZE);
    let logical_actions = t_in.max(t_out) + shielded_actions;
    MARGINAL_FEE_ZAT * logical_actions.max(GRACE_ACTIONS) as u64
}

/// The fee for a release paying a single transparent (t1) output.
pub fn release_fee_to_transparent_zat(redeem_script_len: usize) -> u64 {
    release_fee_zat(redeem_script_len, 1)
}

/// The fee for a refund paying a single shielded output.
pub fn refund_fee_to_shielded_zat(redeem_script_len: usize) -> u64 {
    conventional_fee_zat(refund_input_size(redeem_script_len), 0, 2)
}

/// The fee for a refund paying a single transparent output.
///
/// R7-2: the runner used the shielded number on a transparent refund and
/// overpaid by 10000 zat. A regtest node's floor for that shape is two logical
/// actions. The shielded number becomes the right one when the refund of spec
/// 4.4 actually pays a shielded output, which needs the wallet tooling
/// `funding.rs` describes; until then paying it is paying for actions the
/// transaction does not have.
pub fn refund_fee_to_transparent_zat(redeem_script_len: usize) -> u64 {
    conventional_fee_zat(
        refund_input_size(redeem_script_len),
        P2PKH_STANDARD_OUTPUT_SIZE,
        0,
    )
}

/// The fee for a release paying `n_outputs` transparent (t1) outputs.
///
/// The design's arithmetic, recomputed rather than asserted: the release input
/// is 310 bytes of scriptSig plus framing, which ZIP 317 divides by its 150-byte
/// nominal input to get 3 input actions. Outputs are 34 bytes each, so the
/// output side contributes `n_outputs` actions and the logical count is the
/// larger of the two. The input therefore dominates through three outputs, and
/// the treasury output the platform fee needs is free. The fourth output is the
/// first one that costs anything, and `tests/fees.rs` pins that cliff.
///
/// `n_outputs` of zero is not a transaction anyone can broadcast; it is priced
/// at the grace floor rather than special-cased, because `tx::build_vout`
/// refuses it before a fee is ever needed.
pub fn release_fee_zat(redeem_script_len: usize, n_outputs: usize) -> u64 {
    conventional_fee_zat(
        release_input_size(redeem_script_len),
        n_outputs * P2PKH_STANDARD_OUTPUT_SIZE,
        0,
    )
}
