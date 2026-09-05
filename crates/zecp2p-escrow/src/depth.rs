//! The confirmation depth table of spec section 7.
//!
//! Both the LP and the attestor apply it, independently and to the same
//! numbers. It lives here so the two cannot drift: the LP applying it protects
//! the LP, and the attestor applying it protects the user.

/// Confirmations required before the LP pays, by USD size of the escrow.
///
/// The 100-block tier is the reorg-finality depth from section 3, at which a
/// double-spend of the funding input is not merely expensive but refused by
/// zcashd and zebrad.
pub fn required_depth(usd_amount_6dec: u64) -> u32 {
    match usd_amount_6dec {
        // up to 50 USD
        0..=50_000_000 => 10,
        // 50 to 500 USD
        50_000_001..=500_000_000 => 30,
        // over 500 USD
        _ => 100,
    }
}

/// Confirmations required before the escrow is announced and the user's
/// pre-signature is collected.
///
/// This is **not** the depth the LP pays at - `required_depth` is, and
/// `lp::evaluate` re-checks it independently at payment time. This is only how
/// deep the funding must be before the terms are fixed enough to sign over.
///
/// One confirmation, because that is the point at which the outpoint exists and
/// stops changing. The release digest commits to the outpoint (ZIP 244 S.2g),
/// so a signature cannot be made before the funding is in a block; it does not
/// need to wait any longer than that.
///
/// Waiting for full depth here cost users an escrow. The page holds the key and
/// signs by itself, but only while it is open: between funding and ten
/// confirmations there are about thirteen minutes in which a closed tab means
/// nobody can ever sign, and the escrow can only refund at T. Announcing at one
/// confirmation cuts that window to about one block.
///
/// Nothing is paid earlier because of this. A reorg that unwinds the funding
/// after the signature exists is caught by `lp::evaluate`, which re-reads the
/// outpoint and refuses; the signature is then simply never decrypted, and the
/// user refunds at T exactly as before.
pub const ANNOUNCE_DEPTH: u32 = 1;
