//! Backend A: the route that runs today.
//!
//! The sender's ZEC goes to a 1Click deposit address; 1Click delivers USDC to
//! `OfframpGlue` on Base; the glue deposits into zk-p2p's EscrowV2; a taker
//! pays the rail; the enclave attests the payment and the USDC releases.
//!
//! The one structural change from the `/offramp` route it replaces is when the
//! on-chain session is created. `/offramp` calls `createSession` while opening,
//! which spends keeper gas on an order nobody has funded. Here an order is a
//! database row and a 1Click quote until the ZEC is seen, and the keeper sends
//! `createSession` and `creditSession` in the tick that sees the settlement.
//! `OfframpGlue.creditSession` gates only on the session existing, with no
//! block or ordering rule against `createSession`, so the two go in one tick.
//!
//! That matters because the main route's session keys are free. The EIP-191
//! signature still proves the caller holds the key it names, but it no longer
//! costs an attacker anything to make one, so it can no longer be what stops
//! an unfunded order from burning the keeper's ETH. Deferring the gas is what
//! stops it.

use alloy::primitives::U256;
use chrono::{Duration, Utc};
use zecp2p_types::settlement::{
    Amount, BackendId, Capabilities, FeeLine, Quote, Rail,
};

use crate::error::AppError;

/// How long a main-route quote stays good.
pub const QUOTE_TTL_SECONDS: u64 = 300;

/// What the sender is told to expect, end to end. The 1Click leg's own
/// estimate is a couple of minutes; the rest is a taker noticing the deposit
/// and paying a rail by hand.
pub const EXPECTED_SECONDS: u64 = 1200;

/// The largest order this route takes, in zatoshi.
///
/// Not a protocol limit. It is a liquidity limit: the deposit has to be filled
/// by one taker paying one rail transfer, and Venmo's own per-transaction
/// ceiling is what a taker can actually send.
pub const MAX_ZATOSHI: u64 = 50_000_000_000;

pub fn capabilities() -> Capabilities {
    Capabilities {
        backend: BackendId::OneclickZkp2p,
        rails: Rail::all().iter().copied().filter(|r| r.is_live()).collect(),
        min_zatoshi: crate::near::MIN_ZEC_ZATOSHI,
        max_zatoshi: MAX_ZATOSHI,
        quote_ttl_seconds: QUOTE_TTL_SECONDS,
        expected_seconds: EXPECTED_SECONDS,
    }
}

/// The inputs the quote arithmetic needs, separated from the network calls so
/// the arithmetic can be tested without one.
#[derive(Debug, Clone, Copy)]
pub struct QuoteInputs {
    /// What the sender sends.
    pub zec_zatoshi: u64,
    /// USDC units 1Click expects to deliver, 6 decimals.
    pub expected_usdc_units: u64,
    /// The zk-p2p spread floor, 18 decimals: USD per USDC the taker must pay.
    pub min_rate: U256,
    /// Basis points of the zpay fee.
    pub fee_bps: u32,
}

/// Turn a 1Click quote and a spread into the net price the sender reads.
///
/// Three numbers come out and the sender sees two of them: the headline net,
/// and the zpay fee as one labelled line. The spread between what the swap
/// delivers and what the taker pays is the other line, because it is money the
/// sender does not get and hiding it would make the fee line a lie about where
/// the difference went.
pub fn build_quote(
    quote_id: String,
    inputs: QuoteInputs,
    fee_label: String,
    expires_at: chrono::DateTime<Utc>,
) -> Result<Quote, AppError> {
    // What the taker actually sends on the rail, at the spread floor. This is
    // the same function that computes it at fill time, so the quote and the
    // fill cannot drift apart.
    let payable_cents = zecp2p_types::pricing::payment_cents_for(
        U256::from(inputs.expected_usdc_units),
        inputs.min_rate,
    )
    .map_err(|e| AppError::InvalidState(e.to_string()))?;

    let payable_cents = u64::try_from(payable_cents)
        .map_err(|_| AppError::InvalidState("payout does not fit in cents".to_string()))?;

    // The gross is what the ZEC is worth before anything is taken: the swap's
    // own output, in cents.
    let gross_cents = inputs.expected_usdc_units / 10_000;

    // The spread is the part of the gross the taker keeps. It can be zero when
    // min_rate is 1.0, which is what the advanced route's default does.
    let spread_cents = gross_cents.saturating_sub(payable_cents);

    let fee_cents = payable_cents
        .saturating_mul(inputs.fee_bps as u64)
        .div_ceil(10_000);

    let net_cents = payable_cents.checked_sub(fee_cents).ok_or_else(|| {
        AppError::InvalidRequest(
            "this amount is too small to cover the fee; send more ZEC".to_string(),
        )
    })?;

    if net_cents == 0 {
        return Err(AppError::InvalidRequest(
            "this amount rounds to nothing after fees; send more ZEC".to_string(),
        ));
    }

    let mut lines = Vec::new();
    if spread_cents > 0 {
        lines.push(FeeLine {
            label: "network and market spread".to_string(),
            cents: spread_cents,
            is_zpay_fee: false,
        });
    }
    lines.push(FeeLine {
        label: fee_label,
        cents: fee_cents,
        is_zpay_fee: true,
    });

    let zec_decimal = inputs.zec_zatoshi as f64 / 100_000_000.0;
    let rate = if zec_decimal > 0.0 {
        format!("{:.2}", (gross_cents as f64 / 100.0) / zec_decimal)
    } else {
        "0.00".to_string()
    };

    Ok(Quote {
        quote_id,
        backend: BackendId::OneclickZkp2p,
        gross_cents,
        lines,
        net_cents,
        zec_zatoshi: inputs.zec_zatoshi,
        rate,
        expires_at,
        expected_seconds: EXPECTED_SECONDS,
        route_label: BackendId::OneclickZkp2p.route_label().to_string(),
    })
}

/// The default quote lifetime, as a timestamp.
pub fn default_expiry() -> chrono::DateTime<Utc> {
    Utc::now() + Duration::seconds(QUOTE_TTL_SECONDS as i64)
}

/// Check an amount against this backend's bounds before spending a round trip.
pub fn check_amount(amount: Amount) -> Result<(), AppError> {
    if let Amount::Zec { zatoshi } = amount {
        if zatoshi < crate::near::MIN_ZEC_ZATOSHI {
            return Err(AppError::InvalidRequest(format!(
                "{} zatoshi is below the {} zatoshi minimum this route can swap",
                zatoshi,
                crate::near::MIN_ZEC_ZATOSHI
            )));
        }
        if zatoshi > MAX_ZATOSHI {
            return Err(AppError::InvalidRequest(format!(
                "{zatoshi} zatoshi is more than one taker can fill in a single payment"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: u128 = 1_000_000_000_000_000_000;

    fn rate(x: f64) -> U256 {
        U256::from((x * ONE as f64) as u128)
    }

    fn inputs(usdc_units: u64, min_rate: U256) -> QuoteInputs {
        QuoteInputs {
            zec_zatoshi: 50_000_000,
            expected_usdc_units: usdc_units,
            min_rate,
            fee_bps: 15,
        }
    }

    /// Every quote reconciles: the lines subtract from the gross to exactly the
    /// net the sender is shown. This is the property the contract and the page
    /// have to agree on.
    #[test]
    fn a_quote_reconciles_across_the_whole_range() {
        for units in [1_100_000u64, 5_000_000, 25_000_000, 100_000_000, 900_000_000] {
            for r in [1.0f64, 0.99, 0.98, 0.95] {
                let q = build_quote(
                    "q".into(),
                    inputs(units, rate(r)),
                    "zpay fee (0.15%)".into(),
                    default_expiry(),
                )
                .unwrap();
                assert!(q.reconciles(), "units={units} rate={r} did not reconcile: {q:?}");
                assert!(q.net_cents <= q.gross_cents);
            }
        }
    }

    /// Exactly one line is the zpay fee, always, whatever the spread is.
    #[test]
    fn there_is_always_exactly_one_zpay_fee_line() {
        for r in [1.0f64, 0.98] {
            let q = build_quote(
                "q".into(),
                inputs(25_000_000, rate(r)),
                "zpay fee (0.15%)".into(),
                default_expiry(),
            )
            .unwrap();
            assert_eq!(q.lines.iter().filter(|l| l.is_zpay_fee).count(), 1);
            assert!(q.zpay_fee().is_some());
        }
    }

    /// At a 1.0 floor there is no spread, so the only line is the fee. The
    /// quote must not invent a zero-valued line the sender has to read past.
    #[test]
    fn a_zero_spread_shows_no_spread_line() {
        let q = build_quote(
            "q".into(),
            inputs(25_000_000, rate(1.0)),
            "zpay fee (0.15%)".into(),
            default_expiry(),
        )
        .unwrap();
        assert_eq!(q.lines.len(), 1, "{:?}", q.lines);
        assert!(q.lines[0].is_zpay_fee);
    }

    /// A spread shows as its own line, because it is money the sender does not
    /// get and folding it into the fee line would misstate where it went.
    #[test]
    fn a_spread_gets_its_own_line_and_is_not_called_a_zpay_fee() {
        let q = build_quote(
            "q".into(),
            inputs(25_000_000, rate(0.98)),
            "zpay fee (0.15%)".into(),
            default_expiry(),
        )
        .unwrap();
        assert_eq!(q.lines.len(), 2);
        let spread = q.lines.iter().find(|l| !l.is_zpay_fee).unwrap();
        assert!(spread.cents > 0);
        assert!(!spread.label.to_lowercase().contains("zpay"));
    }

    /// The headline is the net, and the net is strictly less than the payable
    /// once a fee exists.
    #[test]
    fn the_fee_actually_comes_out_of_the_payout() {
        let free = build_quote(
            "q".into(),
            QuoteInputs { fee_bps: 0, ..inputs(25_000_000, rate(1.0)) },
            "zpay fee (0%)".into(),
            default_expiry(),
        )
        .unwrap();
        let charged = build_quote(
            "q".into(),
            inputs(25_000_000, rate(1.0)),
            "zpay fee (0.15%)".into(),
            default_expiry(),
        )
        .unwrap();
        assert!(charged.net_cents < free.net_cents);
        assert_eq!(free.net_cents - charged.net_cents, charged.zpay_fee().unwrap().cents);
    }

    /// An order so small the fee eats it is refused with a sentence a sender
    /// can act on, rather than quoting a net of zero.
    ///
    /// 5,000 USDC units is half a cent, which prices to zero payable cents, so
    /// the net would be zero and there would be nothing to pay anyone.
    #[test]
    fn an_amount_that_rounds_to_nothing_is_refused() {
        let err = build_quote(
            "q".into(),
            QuoteInputs {
                zec_zatoshi: 52_000,
                expected_usdc_units: 5_000,
                min_rate: rate(1.0),
                fee_bps: 15,
            },
            "zpay fee (0.15%)".into(),
            default_expiry(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("send more ZEC"), "{err}");
    }

    /// The bounds are the ones 1Click and a single rail payment actually
    /// impose, checked before a round trip rather than after a 400.
    #[test]
    fn amounts_outside_the_backends_range_are_refused_locally() {
        assert!(check_amount(Amount::Zec { zatoshi: 51_999 }).is_err());
        assert!(check_amount(Amount::Zec { zatoshi: crate::near::MIN_ZEC_ZATOSHI }).is_ok());
        assert!(check_amount(Amount::Zec { zatoshi: MAX_ZATOSHI }).is_ok());
        assert!(check_amount(Amount::Zec { zatoshi: MAX_ZATOSHI + 1 }).is_err());
    }

    /// Only Venmo is offered, because it is the only rail the curator can
    /// register a payee for.
    #[test]
    fn the_backend_offers_only_the_live_rail() {
        assert_eq!(capabilities().rails, vec![Rail::Venmo]);
    }
}
