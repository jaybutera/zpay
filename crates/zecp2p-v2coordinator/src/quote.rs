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

/// Prices one escrow.
///
/// `refund_height` is the height this order would use, which fixes the redeem
/// script length and therefore the miner fee.
pub fn quote_for(
    amount: &str,
    unit: Unit,
    config: &QuoteConfig,
    network: AddrNetwork,
    refund_height: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Quote> {
    let n: f64 = amount
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Enter a number."))?;
    // Written as a positive test so NaN falls through to the refusal: `n > 0.0`
    // is false for NaN, which is the answer we want.
    if !(n.is_finite() && n > 0.0) {
        bail!("Enter a number.");
    }

    let amount_zat = match unit {
        Unit::Zec => (n * 1e8).round(),
        Unit::Usd => ((n / config.rate_usd_per_zec) * 1e8).round(),
    };
    if !(amount_zat >= 1.0 && amount_zat <= u64::MAX as f64) {
        bail!("Enter a number.");
    }
    let amount_zat = amount_zat as u64;

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
    let n_outputs = if fee.zat > 0 { 2 } else { 1 };
    let miner_fee_zat = release_fee_zat(redeem_script_len(refund_height)?, n_outputs);

    // The escrow must cover both fees and still leave a payout above dust, or
    // the release cannot be built at all. Refusing here beats refusing at the
    // sighash, after the user has funded.
    let committed = miner_fee_zat
        .checked_add(fee.zat)
        .ok_or_else(|| anyhow::anyhow!("the fees overflow"))?;
    if amount_zat <= committed {
        bail!("That is too small to cover the network fee.");
    }

    let gross_cents = cents_of(amount_zat, config.rate_usd_per_zec);
    let fee_cents = cents_of(fee.zat, config.rate_usd_per_zec);
    let miner_cents = cents_of(miner_fee_zat, config.rate_usd_per_zec);
    let net_cents = gross_cents
        .saturating_sub(fee_cents)
        .saturating_sub(miner_cents);

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
        rate_usd_per_zec: config.rate_usd_per_zec,
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
            rate_usd_per_zec: 40.25,
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
    fn the_miner_fee_is_the_conventional_one_the_page_recomputes() {
        // `prepareEscrow` refuses any other number, so a quote that invented
        // one would produce an order nobody can pre-sign.
        let q = quote_for("0.05", Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        let expected = release_fee_zat(redeem_script_len(3_472_000).unwrap(), 2);
        assert_eq!(q.miner_fee_zat, expected);
    }

    #[test]
    fn a_testnet_quote_charges_the_fee_and_names_a_treasury() {
        let q = quote_for("0.05", Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
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
        let err = quote_for("0.0001", Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("below the minimum");
        assert!(err.to_string().contains("smallest escrow"));
    }

    #[test]
    fn a_quote_over_the_payment_cap_is_refused_before_an_order_exists() {
        // The cap is the operator's ceiling on one payment. Refusing at the
        // quote means the user never sees an address for a trade that would
        // stall at the browser.
        let err = quote_for("10", Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .expect_err("over the cap");
        assert!(err.to_string().contains("one payment"), "got: {err}");
    }

    #[test]
    fn usd_and_zec_agree_at_the_configured_rate() {
        let c = config();
        let by_zec = quote_for("0.05", Unit::Zec, &c, AddrNetwork::Test, 3_472_000, chrono::Utc::now()).unwrap();
        let usd = format!("{:.6}", 0.05 * c.rate_usd_per_zec);
        let by_usd = quote_for(&usd, Unit::Usd, &c, AddrNetwork::Test, 3_472_000, chrono::Utc::now()).unwrap();
        // Rounding through the rate may move the last zatoshi; the point is
        // that the two paths land on the same escrow, not that they are bitwise
        // identical.
        assert!(
            (by_zec.amount_zat as i64 - by_usd.amount_zat as i64).abs() <= 2,
            "{} vs {}",
            by_zec.amount_zat,
            by_usd.amount_zat
        );
    }

    #[test]
    fn a_non_number_is_refused_in_the_pages_own_words() {
        for bad in ["", "abc", "-1", "0", "NaN", "1e400"] {
            let err = quote_for(bad, Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
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
        let q = quote_for("0.05", Unit::Zec, &config(), AddrNetwork::Test, 3_472_000, chrono::Utc::now())
            .unwrap();
        assert_eq!(q.usd_amount_6dec, q.net_cents * 10_000);
        assert!(q.net_cents < q.gross_cents);
    }
}
