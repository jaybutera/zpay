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
