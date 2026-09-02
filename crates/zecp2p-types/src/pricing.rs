//! The arithmetic that decides the number on the Venmo screen.
//!
//! Two parties need this and they must agree to the cent. The coordinator sizes
//! a deposit's intent so the payment comes out at what the user requested; the
//! taker prices the intent it is about to fill. If those two disagree, either
//! the payment is wrong or the escrow refuses to release, and by then the fiat
//! has left. So both directions live here, in the crate both already depend on,
//! rather than being written twice.
//!
//! The relation, from `OrchestratorV3`: the taker pays `amount * conversionRate`
//! off-chain to unlock `amount` on-chain. Dollars are the product, not the
//! quotient.

use alloy::primitives::U256;

/// 1e18, the scale `conversionRate` is expressed in.
pub const RATE_SCALE: u128 = 1_000_000_000_000_000_000;
/// USDC units in one cent.
pub const UNITS_PER_CENT: u128 = 10_000;

/// Why a price or a size could not be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PricingError {
    ZeroAmount,
    ZeroRate,
    ZeroTarget,
    /// The value does not fit the machine word the arithmetic uses.
    TooLarge(String),
    /// The sized intent did not price back to the requested payment.
    RoundTrip { requested: u64, priced: u128 },
}

impl std::fmt::Display for PricingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PricingError::ZeroAmount => {
                write!(f, "refusing to price a zero-amount intent")
            }
            PricingError::ZeroRate => {
                write!(f, "refusing to price at a zero conversion rate")
            }
            PricingError::ZeroTarget => {
                write!(f, "refusing to size an intent for a zero-dollar payment")
            }
            PricingError::TooLarge(what) => write!(f, "{what}"),
            PricingError::RoundTrip { requested, priced } => write!(
                f,
                "sized an intent for a payment of {requested} cents, but it prices to \
                 {priced} cents. Refusing: the number on Venmo must be the number that \
                 was requested"
            ),
        }
    }
}

impl std::error::Error for PricingError {}

/// Whole cents owed for an intent of `amount_units` at `rate`.
///
/// Ceiled, and the rounding direction is not a style choice. The enclave signs a
/// `releaseAmount` derived from the payment it observes and the verifier caps
/// that at the intent amount, so a fraction of a cent too much releases the full
/// intent and costs under a cent, while a fraction of a cent too little releases
/// less than the intent or fails the snapshot rate check, after the fiat has
/// already left. The asymmetry is total.
pub fn payment_cents_for(amount_units: U256, rate: U256) -> Result<u128, PricingError> {
    if amount_units.is_zero() {
        return Err(PricingError::ZeroAmount);
    }
    if rate.is_zero() {
        return Err(PricingError::ZeroRate);
    }

    let units: u128 = amount_units
        .try_into()
        .map_err(|_| PricingError::TooLarge(format!("intent amount {amount_units} does not fit in u128")))?;
    let rate: u128 = rate
        .try_into()
        .map_err(|_| PricingError::TooLarge(format!("conversion rate {rate} does not fit in u128")))?;

    // One ceiling division, so the two roundings cannot compound.
    let scaled = units
        .checked_mul(rate)
        .ok_or_else(|| PricingError::TooLarge(format!("{units} units at rate {rate} overflows")))?;
    let divisor = RATE_SCALE
        .checked_mul(UNITS_PER_CENT)
        .expect("1e18 * 1e4 fits in u128");

    Ok(scaled.div_ceil(divisor))
}

/// The intent size whose payment is exactly `target_cents`.
///
/// This is [`payment_cents_for`] run backwards, and it is the fix for a $5.00
/// request that paid $4.84. Sizing the intent at the requested amount pays the
/// spread *out of* the request, because the Venmo number is `units * rate` and
/// `rate` is below 1.0 by that spread. Solving for the units instead puts the
/// spread on top, where the user asked for it to be.
///
/// # Why floor
///
/// Inverting a ceiling gives a range, not a point: at rate
/// 0.990881148896019200 every size in `(5_035_921, 5_046_013]` prices to exactly
/// 500 cents. The floor of `target * scale / rate` is the top of that range, so
/// the user receives the most USDC consistent with paying exactly what they
/// asked. One unit more prices a cent high.
///
/// The result is fed back through [`payment_cents_for`] before it is returned.
/// An off-by-one here is a wrong number on a live payment screen, so the
/// property is asserted rather than assumed.
pub fn intent_units_for_cents(target_cents: u64, rate: U256) -> Result<U256, PricingError> {
    if target_cents == 0 {
        return Err(PricingError::ZeroTarget);
    }
    if rate.is_zero() {
        return Err(PricingError::ZeroRate);
    }

    let rate_u: u128 = rate
        .try_into()
        .map_err(|_| PricingError::TooLarge(format!("conversion rate {rate} does not fit in u128")))?;

    let numerator = u128::from(target_cents)
        .checked_mul(RATE_SCALE)
        .and_then(|v| v.checked_mul(UNITS_PER_CENT))
        .ok_or_else(|| PricingError::TooLarge(format!("target of {target_cents} cents overflows")))?;

    let units = numerator / rate_u;
    if units == 0 {
        return Err(PricingError::ZeroTarget);
    }
    let units = U256::from(units);

    let priced = payment_cents_for(units, rate)?;
    if priced != u128::from(target_cents) {
        return Err(PricingError::RoundTrip {
            requested: target_cents,
            priced,
        });
    }

    Ok(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: u128 = RATE_SCALE;

    /// The live 2026-09-01 fill, reproduced: 4,875,437 units at deposit 4499's
    /// rate is $4.84, which is what was actually sent.
    #[test]
    fn reproduces_the_four_eighty_four() {
        let cents = payment_cents_for(
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
        )
        .unwrap();
        assert_eq!(cents, 484);
    }

    /// And the fix: sized the other way, the same rate pays exactly $5.00.
    #[test]
    fn a_five_dollar_request_sizes_to_a_five_dollar_payment() {
        let rate = U256::from(990_881_148_896_019_200u128);
        let units = intent_units_for_cents(500, rate).unwrap();
        assert_eq!(units, U256::from(5_046_013u64));
        assert_eq!(payment_cents_for(units, rate).unwrap(), 500);
        // The gross-up is added on top of the request, not taken out of it.
        assert!(units > U256::from(5_000_000u64));
    }

    /// The 2026-09-02 run is sized at $1.00. Same property, smaller order: the
    /// spread is added on top, so the payment is the requested dollar exactly.
    #[test]
    fn a_one_dollar_request_sizes_to_a_one_dollar_payment() {
        for rate in [
            ONE,
            990_881_148_896_019_200,
            988_652_000_000_000_000,
        ] {
            let rate = U256::from(rate);
            let units = intent_units_for_cents(100, rate).unwrap();
            assert_eq!(
                payment_cents_for(units, rate).unwrap(),
                100,
                "a $1.00 request must pay exactly $1.00"
            );
            assert!(units >= U256::from(1_000_000u64));
        }
    }

    #[test]
    fn the_sized_intent_is_the_top_of_its_range() {
        let rate = U256::from(990_881_148_896_019_200u128);
        let units = intent_units_for_cents(500, rate).unwrap();
        assert_eq!(payment_cents_for(units, rate).unwrap(), 500);
        assert_eq!(
            payment_cents_for(units + U256::from(1u64), rate).unwrap(),
            501
        );
    }

    /// The round trip is the guarantee, over the rates and sizes this will see.
    #[test]
    fn every_size_prices_back_to_its_request() {
        let rates = [
            ONE,
            990_881_148_896_019_200,
            988_652_000_000_000_000,
            998_000_000_000_000_000,
            950_000_000_000_000_000,
        ];
        for rate in rates {
            for target in [1u64, 5, 99, 100, 484, 500, 501, 1_000, 2_500, 100_000] {
                let units = intent_units_for_cents(target, U256::from(rate))
                    .unwrap_or_else(|e| panic!("rate {rate} target {target}: {e}"));
                assert_eq!(
                    payment_cents_for(units, U256::from(rate)).unwrap(),
                    u128::from(target),
                    "rate {rate} target {target}"
                );
            }
        }
    }

    #[test]
    fn a_rate_of_one_needs_no_gross_up() {
        assert_eq!(
            intent_units_for_cents(500, U256::from(ONE)).unwrap(),
            U256::from(5_000_000u64)
        );
    }

    #[test]
    fn refuses_degenerate_inputs() {
        assert_eq!(
            payment_cents_for(U256::ZERO, U256::from(ONE)),
            Err(PricingError::ZeroAmount)
        );
        assert_eq!(
            payment_cents_for(U256::from(1u64), U256::ZERO),
            Err(PricingError::ZeroRate)
        );
        assert_eq!(
            intent_units_for_cents(0, U256::from(ONE)),
            Err(PricingError::ZeroTarget)
        );
        assert_eq!(
            intent_units_for_cents(500, U256::ZERO),
            Err(PricingError::ZeroRate)
        );
    }
}
