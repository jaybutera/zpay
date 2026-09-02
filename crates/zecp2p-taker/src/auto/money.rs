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
    // The arithmetic itself is shared with the coordinator, which sizes the
    // intent this function prices. Two implementations of it would be two
    // chances to disagree about the number on the Venmo screen.
    let cents = zecp2p_types::pricing::payment_cents_for(amount_units, rate)?;

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

/// The intent size whose payment lands on exactly `target_cents`.
///
/// This is [`payment_cents`] run backwards, and it exists because the two
/// directions answer different questions. `payment_cents` asks "given an intent
/// somebody already created, what do I owe?". This asks "the user requested
/// $5.00 and must see $5.00 on Venmo; how big does the intent have to be?".
///
/// # Why the intent must be grossed up
///
/// The Venmo number is `units * rate`, and `rate` is below 1.0 by the spread
/// that pays the taker. Sizing the intent at the requested amount therefore
/// pays the spread *out of the requested amount*: the 2026-09-01 fill sized
/// 4,875,437 units against a $5.00 request at rate 0.990881148896019200 and the
/// payment came out $4.84. The fee has to be added on top of the request, not
/// taken out of it, which means solving for the units rather than assuming them.
///
/// # Why floor, and why the readback
///
/// `payment_cents` ceils. Inverting a ceiling gives a *range* of admissible
/// intent sizes, not a point: at the rate above, anything in
/// `(5_035_921, 5_046_013]` prices to exactly 500 cents. Taking the floor of
/// `target * scale / rate` picks the top of that range, which is the largest
/// intent the requested payment can honestly buy, so the user receives the most
/// USDC consistent with paying exactly what they asked to pay. One unit more
/// prices to 501 cents.
///
/// The result is fed back through `payment_cents` before it is returned. That is
/// not defensive decoration: it is the property the caller actually needs, and
/// an off-by-one in this arithmetic is a payment that is a cent wrong on a live
/// Venmo screen. If the readback disagrees, this refuses rather than returning a
/// size that prices to something other than what was requested.
pub fn intent_units_for_payment(
    target_cents: u64,
    rate: U256,
    cap_cents: u64,
) -> Result<(U256, PaymentAmount)> {
    if target_cents > cap_cents {
        bail!(
            "requested payment of ${}.{:02} exceeds this daemon's cap of ${}.{:02}. \
             Refusing to size an intent for it. Raise taker.max_payment_cents \
             deliberately if this is intended.",
            target_cents / 100,
            target_cents % 100,
            cap_cents / 100,
            cap_cents % 100
        );
    }

    let units = zecp2p_types::pricing::intent_units_for_cents(target_cents, rate)?;
    let payment = payment_cents(units, rate, cap_cents)?;

    Ok((units, payment))
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

    /// The bug this run exists to fix. A $5.00 request at deposit 4499's rate
    /// produced a $4.84 Venmo payment because the intent was sized at the
    /// requested amount and the spread came out of it. Sized the other way, the
    /// payment is exactly $5.00 and the spread is added on top.
    #[test]
    fn a_five_dollar_request_pays_exactly_five_dollars() {
        let rate = U256::from(990_881_148_896_019_200u128);
        let (units, payment) = intent_units_for_payment(500, rate, NO_CAP).expect("should size");

        assert_eq!(payment.cents(), 500);
        assert_eq!(payment.to_venmo_string(), "5.00");

        // The gross-up is real: the intent is larger than the request, not equal
        // to it, and the difference is the spread paid on top.
        assert_eq!(units, U256::from(5_046_013u64));
        assert!(units > U256::from(5_000_000u64));

        // The old sizing, for contrast: the requested amount as the intent.
        let old = payment_cents(U256::from(4_875_437u64), rate, NO_CAP).unwrap();
        assert_eq!(old.to_venmo_string(), "4.84");
    }

    /// The round trip is the guarantee, across the whole range of sizes and
    /// spreads this daemon will see. Whatever is requested is what gets paid.
    #[test]
    fn every_sized_intent_prices_back_to_what_was_requested() {
        let rates = [
            RATE_SCALE,                    // 1.0, no spread
            990_881_148_896_019_200,       // deposit 4499
            988_652_000_000_000_000,       // the economics doc's $5 recommendation
            998_000_000_000_000_000,       // deposit 4496
            950_000_000_000_000_000,       // a wide spread
        ];
        for rate in rates {
            for target in [1u64, 5, 99, 100, 484, 500, 501, 1_000, 2_500] {
                let (units, payment) =
                    intent_units_for_payment(target, U256::from(rate), NO_CAP)
                        .unwrap_or_else(|e| panic!("rate {rate} target {target}: {e}"));
                assert_eq!(
                    payment.cents(),
                    u128::from(target),
                    "rate {rate} target {target} sized {units}"
                );
            }
        }
    }

    /// Floor, not ceil: the sized intent is the largest one that still prices to
    /// the request, and one unit more overshoots by a cent.
    #[test]
    fn the_sized_intent_is_the_top_of_the_admissible_range() {
        let rate = U256::from(990_881_148_896_019_200u128);
        let (units, _) = intent_units_for_payment(500, rate, NO_CAP).unwrap();

        assert_eq!(payment_cents(units, rate, NO_CAP).unwrap().cents(), 500);
        assert_eq!(
            payment_cents(units + U256::from(1u64), rate, NO_CAP)
                .unwrap()
                .cents(),
            501,
            "one unit more must overshoot, or this is not the top of the range"
        );
    }

    /// A rate of exactly 1.0 needs no gross-up, and must not invent one.
    #[test]
    fn a_rate_of_one_sizes_the_intent_at_the_request() {
        let (units, payment) = intent_units_for_payment(500, U256::from(ONE), NO_CAP).unwrap();
        assert_eq!(units, U256::from(5_000_000u64));
        assert_eq!(payment.to_venmo_string(), "5.00");
    }

    /// The cap is checked against the request itself, before any arithmetic, so
    /// an oversized order is refused rather than silently sized.
    #[test]
    fn sizing_refuses_a_request_over_the_cap() {
        let err = intent_units_for_payment(5_000, U256::from(ONE), 1_000).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("exceeds"), "{msg}");
        assert!(msg.contains("$10.00"), "{msg}");
    }

    #[test]
    fn sizing_refuses_degenerate_inputs() {
        assert!(intent_units_for_payment(0, U256::from(ONE), NO_CAP).is_err());
        assert!(intent_units_for_payment(500, U256::ZERO, NO_CAP).is_err());
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
