//! Pricing an escrow, and where the platform fee comes from.
//!
//! Two numbers here are not this module's to choose, and getting either wrong
//! is a trade that cannot settle:
//!
//! **The miner fee** must be exactly `fees::release_fee_zat(redeem_len,
//! n_outputs)`. The page recomputes it and refuses any other number, because a
//! miner fee it did not expect means the LP proposed a different transaction
//! from the one the quote described. So it is computed, not configured.
//!
//! **The platform fee** comes from `treasury::platform_fee_zat` and is paid to
//! the pinned treasury script. When no address is pinned for the network - which
//! is mainnet's state today - the fee is **zero** and the release is
//! two-output. It is never paid to an address that came from configuration:
//! that is the one substitution the user's pre-signature cannot detect, because
//! the user has no independent copy of what the treasury is supposed to be.

use anyhow::{bail, Result};

use zecp2p_escrow::address::AddrNetwork;
use zecp2p_escrow::fees::release_fee_zat;
use zecp2p_escrow::script::CompressedPubkey;
use zecp2p_escrow::treasury;

use crate::config::QuoteConfig;
use crate::order::{Quote, QuoteLine};

/// The fee, and where it is paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFee {
    pub zat: u64,
    /// Empty exactly when `zat` is zero. `ReleaseSplit::outputs` refuses any
    /// other combination.
    pub treasury_script: Vec<u8>,
}

impl PlatformFee {
    pub fn none() -> Self {
        Self {
            zat: 0,
            treasury_script: Vec::new(),
        }
    }
}

/// The platform fee for an escrow on this network.
///
/// Returns no fee when the network has no pinned treasury, rather than
/// failing. The fee is the platform's revenue and the trade is the user's
/// money; forgoing the first to keep the second working is the right trade, and
/// it is the same call `treasury`'s dust gate makes.
pub fn platform_fee_for(amount_zat: u64, fee_bps: u64, network: AddrNetwork) -> PlatformFee {
    if fee_bps == 0 {
        return PlatformFee::none();
    }
    let zat = treasury::platform_fee_zat(amount_zat, fee_bps);
    if zat == 0 {
        return PlatformFee::none();
    }
    match treasury::treasury_script(network) {
        Ok(script) => PlatformFee {
            zat,
            treasury_script: script,
        },
        Err(e) => {
            // Mainnet today. Worth a log line every time, because revenue
            // quietly not being collected is the failure this cannot detect
            // from its own output.
            tracing::warn!(
                error = %e,
                "no treasury is pinned for this network, so this escrow pays no platform fee"
            );
            PlatformFee::none()
        }
    }
}

/// The escrow amount whose payout, after both fees, is `payout_zat`.
///
/// The user types what the payee receives; the fees are added on top. That
/// inverts the arithmetic: the platform fee is a share of the escrow, which is
/// the number being solved for, so it cannot be written in closed form. It is
/// also not continuous - `platform_fee_zat` floors, and drops to zero below the
/// dust threshold - so this iterates to the fixed point instead of dividing.
///
/// Each round recomputes the fee on the current candidate and re-adds it. The
/// sequence is non-decreasing and bounded by the max-escrow gate above it, so
/// it settles within a few rounds; the loop is capped anyway rather than
/// trusting that argument with a user's money.
fn escrow_for_payout(
    payout_zat: u64,
    miner_fee_zat: u64,
    fee_bps: u64,
    network: AddrNetwork,
) -> Result<u64> {
    let base = payout_zat
        .checked_add(miner_fee_zat)
        .ok_or_else(|| anyhow::anyhow!("the fees overflow"))?;

    let mut amount = base;
    for _ in 0..64 {
        let fee = platform_fee_for(amount, fee_bps, network).zat;
        let need = base
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("the fees overflow"))?;
        if need == amount {
            // The fee this escrow charges is exactly the fee it was sized for.
            return Ok(amount);
        }
        amount = need;
    }
    // Unreachable for any amount that passes the ceiling above, and a refusal
    // rather than a guess if it ever is reached: a quote whose fee does not
    // settle would fund an escrow that cannot pay out what it promised.
    bail!("Could not price that amount. Try a different one.")
}

/// The redeem script length a quote must assume.
///
/// The miner fee depends on it, and the quote is made before the user's key
/// exists. Every redeem script is the same length for a given `refund_height`
/// encoding, so this builds one with placeholder keys at the height the order
/// will actually use.
pub fn redeem_script_len(refund_height: u64) -> Result<usize> {
    // Any valid points will do: only the length matters, and both keys are
    // always 33 bytes.
    let placeholder: CompressedPubkey = {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).expect("a valid scalar");
        zecp2p_escrow::keystore::public_key(&key)
    };
    let script = zecp2p_escrow::script::redeem_script(&placeholder, &placeholder, refund_height)
        .map_err(|e| anyhow::anyhow!("could not size the redeem script: {e}"))?;
    Ok(script.len())
}

/// What the user typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Zec,
    Usd,
}

impl std::str::FromStr for Unit {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "zec" | "" => Ok(Unit::Zec),
            "usd" => Ok(Unit::Usd),
            other => bail!("unknown unit {other:?}"),
        }
    }
}

/// Prices one escrow at a rate the caller has already established.
///
/// `refund_height` is the height this order would use, which fixes the redeem
/// script length and therefore the miner fee.
///
/// `rate_usd_per_zec` is passed in rather than read from `config` so that
/// there is no path to a quote without a price: a caller must have obtained
/// one, and `web::rate_for_quote` is the only thing that produces it. It is
/// the *effective* rate, spread already applied.
pub fn quote_for(
    amount: &str,
    unit: Unit,
    config: &QuoteConfig,
    rate_usd_per_zec: f64,
    network: AddrNetwork,
    refund_height: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Quote> {
    // The rate reaches here from a feed or a pinned config value, and both are
    // checked before this. Re-checking is cheap and this is the last point
    // before it multiplies into every number in the quote.
    if !(rate_usd_per_zec.is_finite() && rate_usd_per_zec > 0.0) {
        bail!("No price is available right now. Try again in a moment.");
    }
    let n: f64 = amount
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Enter a number."))?;
    // Written as a positive test so NaN falls through to the refusal: `n > 0.0`
    // is false for NaN, which is the answer we want.
    if !(n.is_finite() && n > 0.0) {
        bail!("Enter a number.");
    }

    // What the number the user typed means. In dollars it is what the payee
    // receives and the fees are added on top, because that is the promise the
    // page makes: type $2 and $2.00 lands in their Venmo. In ZEC it is what
    // leaves the sender's wallet, because a ZEC figure is chosen against a
    // balance and grossing it up would ask for more than the sender has.
    let typed_zat = match unit {
        Unit::Zec => (n * 1e8).round(),
        Unit::Usd => ((n / rate_usd_per_zec) * 1e8).round(),
    };
    if !(typed_zat >= 1.0 && typed_zat <= u64::MAX as f64) {
        bail!("Enter a number.");
    }
    let typed_zat = typed_zat as u64;

    // The miner fee is sized before the escrow is, and it depends on the
    // output count, which depends on whether the platform fee survives its
    // dust gate. Sizing the fee against the typed amount decides that: the
    // gross-up only ever moves the escrow up, and by well under the margin
    // between a dust-sized fee and a real one.
    let probe_fee = platform_fee_for(typed_zat, config.fee_bps, network);
    let n_outputs = if probe_fee.zat > 0 { 2 } else { 1 };
    let miner_fee_zat = release_fee_zat(redeem_script_len(refund_height)?, n_outputs);

    let amount_zat = match unit {
        Unit::Zec => typed_zat,
        Unit::Usd => escrow_for_payout(typed_zat, miner_fee_zat, config.fee_bps, network)?,
    };

    if amount_zat < config.min_zat {
        bail!(
            "The smallest escrow is {} ZEC.",
            zec_string(config.min_zat)
        );
    }
    if amount_zat > config.max_zat {
        bail!(
            "The largest escrow right now is {} ZEC.",
            zec_string(config.max_zat)
        );
    }

    let fee = platform_fee_for(amount_zat, config.fee_bps, network);
    // The escrow was sized for a fee of exactly this much. If the gross-up
    // crossed the dust gate or the output count, the two disagree and the
    // payout would not be what the page promised.
    if unit == Unit::Usd {
        let settled_outputs = if fee.zat > 0 { 2 } else { 1 };
        if settled_outputs != n_outputs {
            bail!("Could not price that amount. Try a different one.");
        }
    }

    // The escrow must cover both fees and still leave a payout above dust, or
    // the release cannot be built at all. Refusing here beats refusing at the
    // sighash, after the user has funded.
    let committed = miner_fee_zat
        .checked_add(fee.zat)
        .ok_or_else(|| anyhow::anyhow!("the fees overflow"))?;
    if amount_zat <= committed {
        bail!("That is too small to cover the network fee.");
    }

    let gross_cents = cents_of(amount_zat, rate_usd_per_zec);
    let fee_cents = cents_of(fee.zat, rate_usd_per_zec);
    let miner_cents = cents_of(miner_fee_zat, rate_usd_per_zec);

    // The payee's dollars. When the user typed dollars, this is that number
    // exactly and not a re-derivation of it: `escrow_for_payout` sized the
    // escrow in zatoshi, and converting each of the three zatoshi figures back
    // to cents independently rounds three times, which lands a cent either side
    // of what the page promised. `net_cents` is what the rail is actually told
    // to send, so it is the typed amount itself.
    let net_cents = match unit {
        Unit::Usd => (n * 100.0).round() as u64,
        Unit::Zec => gross_cents
            .saturating_sub(fee_cents)
            .saturating_sub(miner_cents),
    };

    if net_cents < 100 {
        bail!("That is under a dollar after fees.");
    }
    if net_cents > config.max_payment_cents {
        bail!(
            "That is more than this coordinator will send in one payment (${}.{:02}).",
            config.max_payment_cents / 100,
            config.max_payment_cents % 100
        );
    }

    Ok(Quote {
        quote_id: crate::new_id("q"),
        amount_zat,
        gross_cents,
        net_cents,
        // The enclave's units. `payment_cents` reads this back and must agree
        // with `net_cents`, which it does because the rate is the identity.
        usd_amount_6dec: net_cents * 10_000,
        platform_fee_zat: fee.zat,
        miner_fee_zat,
        rate_usd_per_zec,
        lines: vec![
            QuoteLine {
                label: format!("zpay fee ({:.2}%)", config.fee_bps as f64 / 100.0),
                cents: fee_cents as i64,
                is_zpay_fee: true,
            },
            QuoteLine {
                label: "zcash network fee".into(),
                cents: miner_cents as i64,
                is_zpay_fee: false,
            },
        ],
        expires_at: now + chrono::Duration::seconds(config.quote_seconds as i64),
    })
}

fn cents_of(zat: u64, rate_usd_per_zec: f64) -> u64 {
    ((zat as f64 / 1e8) * rate_usd_per_zec * 100.0).round().max(0.0) as u64
}

/// ZEC with trailing zeros trimmed, the way the page prints it.
pub fn zec_string(zat: u64) -> String {
    let s = format!("{:.8}", zat as f64 / 1e8);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".into()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> QuoteConfig {
        QuoteConfig {
            rate_usd_per_zec: Some(40.25),
                spread_bps: 50,
                price_timeout_seconds: 10,
            fee_bps: 20,
            min_zat: 120_000,
            max_zat: 5_000_000_000,
            quote_seconds: 300,
            max_payment_cents: 2500,
            max_open_orders: 200,
            max_open_per_handle: 5,
        }
    }

    #[test]
    fn dollars_typed_are_dollars_received_and_the_fees_ride_on_top() {
        // Casper's rule: type $2 and $2.00 lands in their Venmo. The fees are
        // added to what the sender pays in ZEC, never subtracted from what the
        // payee gets. This is the whole contract of the USD unit.
        let cfg = config();
        let rate = 1014.268175;
        let q = quote_for("2", Unit::Usd, &cfg, rate, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();

        assert_eq!(q.net_cents, 200, "the payee receives exactly what was typed");
        assert_eq!(q.usd_amount_6dec, 2_000_000, "the enclave is told the same number");
        assert!(
            q.gross_cents > q.net_cents,
            "the sender pays more than the payee receives: {} vs {}",
            q.gross_cents,
            q.net_cents
        );

        // And the escrow really does cover both fees with the payout intact.
        let payout = q.amount_zat - q.platform_fee_zat - q.miner_fee_zat;
        let payout_cents = cents_of(payout, rate);
        assert_eq!(payout_cents, 200, "the zatoshi left over are worth what was typed");
    }

    #[test]
    fn the_escrow_covers_both_fees_exactly_across_a_range_of_amounts() {
        // The gross-up solves a fixed point, because the platform fee is a
        // share of the number being solved for. Every amount must land on it:
        // an escrow one zatoshi short pays the payee less than promised, and
        // the release is built from these numbers.
        let cfg = config();
        let rate = 1014.268175;
        for dollars in ["1.37", "2", "3", "4.50", "7.77", "10", "24.99"] {
            let q = quote_for(dollars, Unit::Usd, &cfg, rate, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
                .unwrap_or_else(|e| panic!("{dollars} did not quote: {e}"));

            let expected_cents = (dollars.parse::<f64>().unwrap() * 100.0).round() as u64;
            assert_eq!(q.net_cents, expected_cents, "{dollars} landed short");

            // The identity the release depends on.
            assert_eq!(
                q.amount_zat,
                q.platform_fee_zat + q.miner_fee_zat + (q.amount_zat - q.platform_fee_zat - q.miner_fee_zat),
                "{dollars} does not decompose"
            );
            // The fee charged is the fee the escrow was sized for.
            assert_eq!(
                q.platform_fee_zat,
                platform_fee_for(q.amount_zat, cfg.fee_bps, AddrNetwork::Test).zat,
                "{dollars} was sized for a different fee than it charges"
            );
            assert!(
                q.amount_zat > q.platform_fee_zat + q.miner_fee_zat,
                "{dollars} leaves nothing for the payee"
            );
        }
    }

    #[test]
    fn a_zec_amount_is_still_what_leaves_the_wallet() {
        // The other unit is unchanged: a sender who types ZEC is choosing
        // against a balance, and grossing that up would ask for ZEC they may
        // not have. The fees come out of it, as they always did.
        let cfg = config();
        let q = quote_for("0.05", Unit::Zec, &cfg, 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        assert_eq!(q.amount_zat, 5_000_000, "the escrow is what was typed");
        assert!(q.net_cents < q.gross_cents, "the fees come out of it");
    }

    #[test]
    fn the_payment_cap_is_checked_against_what_the_payee_receives() {
        // The cap is a ceiling on the payment that actually leaves the rail,
        // which is `net_cents`. Under the inclusive model the gross was the
        // bigger number and the cap bit early; now the received amount is what
        // counts, so the boundary is exact.
        let cfg = config(); // max_payment_cents = 2500
        let rate = 1014.268175;

        let ok = quote_for("25", Unit::Usd, &cfg, rate, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect("exactly the cap is allowed");
        assert_eq!(ok.net_cents, 2500);

        let err = quote_for("25.01", Unit::Usd, &cfg, rate, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("a cent over the cap is refused");
        assert!(
            err.to_string().contains("more than this coordinator will send"),
            "got {err}"
        );
    }

    #[test]
    fn a_grossed_up_escrow_is_still_held_to_the_escrow_ceiling() {
        // The gross-up happens before `max_zat`, so an amount that only clears
        // the ceiling by ignoring its fees is still refused.
        let mut cfg = config();
        cfg.max_zat = 200_000;
        let err = quote_for("2", Unit::Usd, &cfg, 1014.268175, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("over the escrow ceiling");
        assert!(err.to_string().contains("largest escrow"), "got {err}");
    }

    #[test]
    fn the_gross_up_solves_the_fee_it_is_charged() {
        // The helper directly, including the dust cliff: below the threshold
        // the platform fee is zero and the escrow is just payout plus miner.
        for (payout, bps) in [(443_670u64, 15u64), (1_000_000, 15), (5_000_000, 20), (200_000, 15)] {
            let amount = escrow_for_payout(payout, 15_000, bps, AddrNetwork::Test).unwrap();
            let fee = platform_fee_for(amount, bps, AddrNetwork::Test).zat;
            assert_eq!(
                amount - fee - 15_000,
                payout,
                "payout {payout} at {bps} bps settled on {amount}, which does not pay it back"
            );
        }
    }

    #[test]
    fn the_six_dollar_cap_admits_six_dollars_received_and_refuses_more() {
        // Mainnet runs a $6 ceiling. Under the inclusive model the gross was
        // the number compared against it, so a $6 payment was refused for the
        // fees riding on it. The cap is a limit on what the rail sends, which
        // is the received amount, so $6.00 received must be allowed and
        // $6.01 refused - at the live rate, where the miner fee is real money.
        let mut cfg = config();
        cfg.max_payment_cents = 600;
        cfg.fee_bps = 15;
        let rate = 1019.7556;

        let ok = quote_for("6", Unit::Usd, &cfg, rate, AddrNetwork::Main, 3_472_000, chrono::Utc::now())
            .expect("six dollars received is exactly the cap");
        assert_eq!(ok.net_cents, 600);
        assert!(
            ok.gross_cents > 600,
            "the sender still pays the fees on top: {}",
            ok.gross_cents
        );

        let err = quote_for("6.01", Unit::Usd, &cfg, rate, AddrNetwork::Main, 3_472_000, chrono::Utc::now())
            .expect_err("a cent over the cap");
        assert!(err.to_string().contains("more than this coordinator will send"), "got {err}");
    }

    #[test]
    fn a_fraction_of_a_cent_cannot_promise_more_than_the_escrow_holds() {
        // `net_cents` is the typed amount rounded to cents, and the escrow was
        // sized from the same typed amount. A third of a cent must not round
        // the promise up past what the zatoshi in escrow actually pay out.
        let cfg = config();
        let rate = 1019.7556;
        for amount in ["2.004", "2.005", "2.006", "4.999", "1.371"] {
            let q = quote_for(amount, Unit::Usd, &cfg, rate, AddrNetwork::Main, 3_472_000, chrono::Utc::now())
                .unwrap_or_else(|e| panic!("{amount} did not quote: {e}"));
            let payout = q.amount_zat - q.platform_fee_zat - q.miner_fee_zat;
            let payout_cents = cents_of(payout, rate);
            assert!(
                payout_cents >= q.net_cents,
                "{amount}: the escrow pays out {payout_cents} cents but the rail is told to send {}",
                q.net_cents
            );
        }
    }

    #[test]
    fn the_miner_fee_is_the_conventional_one_the_page_recomputes() {
        // `prepareEscrow` refuses any other number, so a quote that invented
        // one would produce an order nobody can pre-sign.
        let q = quote_for("0.05", Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        let expected = release_fee_zat(redeem_script_len(3_472_000).unwrap(), 2);
        assert_eq!(q.miner_fee_zat, expected);
    }

    #[test]
    fn a_testnet_quote_charges_the_fee_and_names_a_treasury() {
        let q = quote_for("0.05", Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        assert!(q.platform_fee_zat > 0, "testnet has a pinned treasury");
        assert_eq!(q.platform_fee_zat, treasury::platform_fee_zat(q.amount_zat, 20));

        let fee = platform_fee_for(q.amount_zat, 20, AddrNetwork::Test);
        assert!(!fee.treasury_script.is_empty());
    }

    #[test]
    fn a_mainnet_quote_charges_the_fee_and_names_a_treasury() {
        // Mainnet was unpinned until 2026-09-04 and this test asserted the
        // forgo-the-fee path. An address is pinned now, so mainnet charges like
        // testnet does; the forgo path is still the behaviour for any network
        // without an address, which `no_treasury_means_no_fee_rather_than_no_trade`
        // covers directly.
        let fee = platform_fee_for(1_000_000, 20, AddrNetwork::Main);
        assert!(fee.zat > 0, "mainnet has a pinned treasury");
        assert_eq!(fee.zat, treasury::platform_fee_zat(1_000_000, 20));
        assert!(!fee.treasury_script.is_empty());
    }

    #[test]
    fn no_treasury_means_no_fee_rather_than_no_trade() {
        // The rule that mattered when mainnet was unpinned, kept because it is
        // what happens on any network that has no address: the fee is revenue,
        // the trade is the user's money, and forgoing the first to keep the
        // second working is the call the dust gate already makes.
        //
        // Driven through a sub-dust amount, which reaches the same
        // "no fee, no script" outcome by the other route the function has.
        let fee = platform_fee_for(1, 20, AddrNetwork::Main);
        assert_eq!(fee.zat, 0);
        assert!(fee.treasury_script.is_empty());
    }

    #[test]
    fn the_fee_and_its_destination_are_set_together_or_not_at_all() {
        // `ReleaseSplit::outputs` refuses a half-specified fee, because it
        // means the two sides build different transactions from the same terms.
        for (amount, network) in [
            (1_000_000u64, AddrNetwork::Test),
            (1_000_000, AddrNetwork::Main),
            (120_000, AddrNetwork::Test),
        ] {
            let fee = platform_fee_for(amount, 20, network);
            assert_eq!(
                fee.zat == 0,
                fee.treasury_script.is_empty(),
                "a fee of {} with a {}-byte script",
                fee.zat,
                fee.treasury_script.len()
            );
        }
    }

    #[test]
    fn a_zero_rate_config_disables_the_fee_entirely() {
        let fee = platform_fee_for(1_000_000, 0, AddrNetwork::Test);
        assert_eq!(fee, PlatformFee::none());
    }

    #[test]
    fn an_escrow_below_the_minimum_is_refused_with_the_minimum_named() {
        let err = quote_for("0.0001", Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("below the minimum");
        assert!(err.to_string().contains("smallest escrow"));
    }

    #[test]
    fn a_quote_refuses_when_no_price_is_available() {
        // The refuse-on-failure contract, at the last gate before the numbers
        // are computed. `rate_for_quote` returns an error when no feed can be
        // trusted and the handler never reaches here; this is the backstop for
        // anything that calls `quote_for` directly.
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let err = quote_for(
                "0.05",
                Unit::Zec,
                &config(),
                bad,
                AddrNetwork::Test,
                3_472_000,
                chrono::Utc::now(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains("No price is available"),
                "a rate of {bad} produced {err:?} rather than a refusal"
            );
        }
    }

    #[test]
    fn the_live_rate_reaches_the_quote_it_priced() {
        // A quote built at a realistic ZEC price reports that price back, and
        // the ZEC asked for is the dollars divided by it. At 40.25 this same
        // request asked for 0.124 ZEC - about $127 of ZEC for a $5 payout,
        // which is the bug the price feed exists to close.
        let rate = 1022.0;
        let q = quote_for(
            "5",
            Unit::Usd,
            &config(),
            rate,
            AddrNetwork::Test,
            3_472_000,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(q.rate_usd_per_zec, rate);
        // $5 at $1,022/ZEC is 0.00489 ZEC, near 489,236 zat - and that is what
        // the payee receives, so the escrow is that plus both fees. The bug
        // this test exists for is an order of magnitude, not a fee's width:
        // what matters is that the ZEC asked for tracks the rate.
        let payout = ((5.0 / rate) * 1e8).round() as u64;
        assert_eq!(
            q.amount_zat - q.platform_fee_zat - q.miner_fee_zat,
            payout,
            "the payout is the dollars divided by the rate"
        );
        assert!(q.amount_zat > payout, "the fees ride on top");
        assert_eq!(q.net_cents, 500);
        assert!(
            q.amount_zat < 1_000_000,
            "a $5 quote asked for {} zat, which is more than 0.01 ZEC",
            q.amount_zat
        );
    }

    #[test]
    fn a_quote_over_the_payment_cap_is_refused_before_an_order_exists() {
        // The cap is the operator's ceiling on one payment. Refusing at the
        // quote means the user never sees an address for a trade that would
        // stall at the browser.
        let err = quote_for("10", Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("over the cap");
        assert!(err.to_string().contains("one payment"), "got: {err}");
    }

    #[test]
    fn usd_and_zec_agree_at_the_configured_rate() {
        let c = config();
        let by_zec = quote_for("0.05", Unit::Zec, &c, 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now()).unwrap();
        // The two units mean different things now: ZEC is what leaves the
        // wallet, USD is what the payee receives. So they agree at the payout,
        // not at the escrow. Pricing the ZEC leg's *payout* in dollars and
        // asking for that many dollars must come back to the same escrow.
        let usd = format!("{:.6}", by_zec.net_cents as f64 / 100.0);
        let by_usd = quote_for(&usd, Unit::Usd, &c, 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now()).unwrap();
        // Rounding through the rate may move the last zatoshi; the point is
        // that the two paths land on the same escrow, not that they are bitwise
        // identical.
        // The round trip goes through whole cents, and a cent is about 1,250
        // zatoshi at this rate, so it is compared in cents.
        assert_eq!(
            by_usd.net_cents, by_zec.net_cents,
            "asking for the ZEC leg's payout in dollars pays the same dollars"
        );
    }

    #[test]
    fn a_non_number_is_refused_in_the_pages_own_words() {
        for bad in ["", "abc", "-1", "0", "NaN", "1e400"] {
            let err = quote_for(bad, Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
                .expect_err("not a quotable amount");
            assert!(
                err.to_string().contains("Enter a number")
                    || err.to_string().contains("smallest escrow"),
                "{bad:?} gave: {err}"
            );
        }
    }

    #[test]
    fn the_usd_leg_is_the_net_and_not_the_gross() {
        // The user is paid what the quote said lands, not what the escrow held.
        // Quoting the gross would have the LP send the fee back out as dollars.
        let q = quote_for("0.05", Unit::Zec, &config(), 40.25, AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        assert_eq!(q.usd_amount_6dec, q.net_cents * 10_000);
        assert!(q.net_cents < q.gross_cents);
    }
}
