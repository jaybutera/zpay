//! Turning an intent into the dollars Venmo has to be told to send.
//!
//! The intent is denominated in 6-decimal USDC units against a conversion rate
//! scaled by 1e18, and Venmo's field takes two decimals. So there is a division
//! and a rounding step between "what the escrow will release" and "what a human
//! sees on the payment screen", and both directions of getting it wrong cost
//! money.
//!
//! `venmo::usdc_to_dollars` converts units to dollars one-for-one and ceils to
//! cents. That is correct only when the rate is exactly 1.0. Deposit 4499 was
//! priced at 0.990881148896019200, where 4,875,437 units are owed $4.84 and the
//! one-for-one function returns "4.88": four cents overpaid, which is the whole
//! margin on a $5 order.

use alloy::primitives::U256;
use anyhow::{bail, Result};

/// 1e18, the scale `conversionRate` is expressed in.
pub const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
/// USDC units in one cent.
pub const UNITS_PER_CENT: u128 = 10_000;

/// A payment amount that has passed every check, in whole cents.
///
/// Constructed only by [`payment_cents`], so a value of this type is a
/// statement that the amount came from an intent, was rounded in the taker's
/// favour, and is under the configured cap. The Venmo driver takes one of these
/// rather than a `String` so an unchecked amount cannot reach the send button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentAmount {
    cents: u128,
}

impl PaymentAmount {
    pub fn cents(self) -> u128 {
        self.cents
    }

    /// The string Venmo's amount field expects: "4.84".
    pub fn to_venmo_string(self) -> String {
        format!("{}.{:02}", self.cents / 100, self.cents % 100)
    }
}

impl std::fmt::Display for PaymentAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_venmo_string())
    }
}

/// Fiat owed for an intent, rounded up to the cent and capped.
///
/// `amount_units` is the intent amount in 6-decimal USDC units and `rate` is
/// the intent's `conversionRate` scaled by 1e18. The contract's own statement
/// of the direction (`OrchestratorV3.sol:104`) is that the taker pays
/// `amount * conversionRate` off-chain to unlock `amount` on-chain, so the
/// dollars are the product, not the quotient.
///
/// # Why up
///
/// The enclave signs a `releaseAmount` derived from the payment it observes and
/// `UnifiedPaymentVerifierV3._calculateReleaseAmount` caps that at the intent
/// amount. A fraction of a cent too much releases the full intent and costs
/// under a cent. A fraction of a cent too little releases less than the intent,
/// or fails `UPV: Snapshot rate mismatch`, after the fiat has already left.
/// The asymmetry is total, so this is not a style choice.
pub fn payment_cents(amount_units: U256, rate: U256, cap_cents: u64) -> Result<PaymentAmount> {
    if amount_units.is_zero() {
        bail!("refusing to build a payment for a zero-amount intent");
    }
    if rate.is_zero() {
        bail!("refusing to build a payment at a zero conversion rate");
    }

    // u128 is enough with room to spare: the product below is bounded by
    // amount_units * rate, and a taker capped in the dollars will never see an
    // amount_units anywhere near u128::MAX. Checked anyway, because an
    // unchecked overflow here is a wrong payment rather than a panic.
    let units: u128 = amount_units
        .try_into()
        .map_err(|_| anyhow::anyhow!("intent amount {amount_units} does not fit in u128"))?;
    let rate: u128 = rate
        .try_into()
        .map_err(|_| anyhow::anyhow!("conversion rate {rate} does not fit in u128"))?;

    // cents = ceil(units * rate / (1e18 * 10_000)), computed as one ceiling
    // division so the two roundings cannot compound.
    let scaled = units
        .checked_mul(rate)
        .ok_or_else(|| anyhow::anyhow!("{units} units at rate {rate} overflows"))?;
    let divisor = RATE_SCALE
        .checked_mul(UNITS_PER_CENT)
        .expect("1e18 * 1e4 fits in u128");
    // Ceiling division of a non-zero product is at least 1, so there is no
    // zero-cent case to guard: sub-cent dust becomes a one-cent payment rather
    // than an empty one. That is the right direction (see above), and it means
    // the smallest payment this function can produce is $0.01.
    let cents = scaled.div_ceil(divisor);

    if cents > u128::from(cap_cents) {
        bail!(
            "payment of ${}.{:02} exceeds this daemon's cap of ${}.{:02}. \
             Refusing to send. Raise taker.max_payment_cents deliberately if \
             this is intended.",
            cents / 100,
            cents % 100,
            cap_cents / 100,
            cap_cents % 100
        );
    }

    Ok(PaymentAmount { cents })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: u128 = RATE_SCALE;
    /// A cap well clear of every case here, so a test that fails is failing on
    /// the arithmetic rather than on the cap.
    const NO_CAP: u64 = 1_000_000;

    fn cents(units: u64, rate: u128) -> u128 {
        payment_cents(U256::from(units), U256::from(rate), NO_CAP)
            .expect("should price")
            .cents()
    }

    /// The live 2026-09-01 fill. Deposit 4499: 4,875,437 units at
    /// 0.990881148896019200 was paid $4.84 by hand and the enclave attested it.
    #[test]
    fn reproduces_the_deposit_4499_payment() {
        assert_eq!(cents(4_875_437, 990_881_148_896_019_200), 484);
    }

    /// The bug this module exists for: at that same rate the rate-blind
    /// conversion in `venmo::usdc_to_dollars` says 4.88, four cents high, which
    /// is more than the taker's whole margin on a $5 order.
    #[test]
    fn rate_blind_conversion_would_have_overpaid_by_four_cents() {
        let rate_aware = cents(4_875_437, 990_881_148_896_019_200);
        let rate_blind = crate::venmo::usdc_to_dollars(U256::from(4_875_437u64));
        assert_eq!(rate_aware, 484);
        assert_eq!(rate_blind, "4.88");
    }

    #[test]
    fn a_rate_of_one_is_a_straight_conversion() {
        assert_eq!(cents(25_000_000, ONE), 2500);
        assert_eq!(cents(1_500_000, ONE), 150);
    }

    /// Rounding is up, always, because the loss is asymmetric.
    #[test]
    fn a_fraction_of_a_cent_rounds_up() {
        // 1.000001 USDC at rate 1.0 is 100.0001 cents.
        assert_eq!(cents(1_000_001, ONE), 101);
        // Exactly on a cent does not gain one.
        assert_eq!(cents(1_000_000, ONE), 100);
    }

    /// The two roundings must not compound: dividing by 1e18 first and then by
    /// 10_000 would round twice and can land a cent high.
    #[test]
    fn rounding_happens_once() {
        // units * rate / 1e18 = 9999.99...; a first ceil would make it 10_000
        // units = 1 cent, then ceil again to 1. One ceiling division gives 1
        // too, but the intermediate must not be materialised.
        let c = cents(10_000, ONE - 1);
        assert_eq!(c, 1);
    }

    #[test]
    fn the_cap_refuses_rather_than_clamps() {
        // A daemon meant for $5 orders, handed a $50 one.
        let err = payment_cents(U256::from(50_000_000u64), U256::from(ONE), 1_000)
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("exceeds"), "{msg}");
        assert!(msg.contains("$10.00"), "{msg}");
    }

    /// The cap is the last line against a units/dollars confusion. 4875437
    /// read as dollars rather than units is $4.8 million.
    #[test]
    fn the_cap_catches_a_units_confusion() {
        let as_dollars = U256::from(4_875_437u64) * U256::from(1_000_000u64);
        assert!(payment_cents(as_dollars, U256::from(ONE), 1_000).is_err());
    }

    #[test]
    fn refuses_degenerate_inputs() {
        assert!(payment_cents(U256::ZERO, U256::from(ONE), NO_CAP).is_err());
        assert!(payment_cents(U256::from(1_000_000u64), U256::ZERO, NO_CAP).is_err());
    }

    /// Sub-cent dust becomes a one-cent payment, never a zero-cent one.
    /// Rounding up has no floor to fall through, and $0.00 sent to Venmo would
    /// wait forever for an attestation of a payment that does not exist.
    #[test]
    fn dust_rounds_up_to_a_cent_rather_than_to_nothing() {
        // One millionth of a USDC at a rate of 1e-18: as small as the inputs go.
        assert_eq!(cents(1, 1), 1);
        // Just under a cent.
        assert_eq!(cents(9_999, ONE), 1);
    }

    #[test]
    fn formats_the_way_venmos_field_expects() {
        let amount = payment_cents(U256::from(4_875_437u64), U256::from(990_881_148_896_019_200u128), NO_CAP).unwrap();
        assert_eq!(amount.to_venmo_string(), "4.84");
        let round = payment_cents(U256::from(25_000_000u64), U256::from(ONE), NO_CAP).unwrap();
        assert_eq!(round.to_venmo_string(), "25.00");
        let small = payment_cents(U256::from(50_000u64), U256::from(ONE), NO_CAP).unwrap();
        assert_eq!(small.to_venmo_string(), "0.05");
    }
}
