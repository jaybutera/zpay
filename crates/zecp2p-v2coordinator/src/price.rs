//! The ZEC/USD price a quote is built on, and the spread taken over it.
//!
//! Every quote converts between ZEC and dollars, so this number decides what a
//! user hands over and what they are paid. It used to be a constant in the
//! config file. A constant is wrong the moment the market moves, and it is
//! wrong silently: `rate_usd_per_zec = 40.25` against a market near $1,022
//! quoted 0.124 ZEC - about $127 - for a $5 payout, and nothing in the system
//! could tell. So the rate is read from a market, and a rate that cannot be
//! read is a refusal rather than a fallback.
//!
//! Three rules follow from that, and each is a test below:
//!
//! **No fallback to a default.** There is no default price. A feed that cannot
//! be reached means no quote, because a wrong price on a service that holds
//! funds costs a user more than an outage does.
//!
//! **No stale price.** A cached price is served only inside [`PRICE_TTL`].
//! Past that it is discarded, not stretched: the cache holds a value that was
//! true when read, in the same spirit as `AppState::chain_head_cache`.
//!
//! **A price must be plausible.** A feed can answer with a decimal point in the
//! wrong place, and that answer arrives as a valid HTTP 200. Two bounds catch
//! it: an absolute range, and a move-from-last-good limit. Either one failing
//! refuses the quote.
//!
//! And because a single feed is a single point of control, both exchanges are
//! read on every refresh and compared. When they disagree beyond
//! [`MAX_SOURCE_DISAGREEMENT`] the lower price wins, which bounds what one
//! wrong or hostile source can do to a trade: it can only make the coordinator
//! pay less, never more.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// How long a fetched price is served before it must be read again.
///
/// 45 s sits between the "refresh every 30-60 s" this was asked for and the
/// chain head's 30 s.
///
/// Note what this does *not* bound. A quote holds the rate it was built on for
/// `quote.quote_seconds` (300 s by default) and `open_order` honours a stored
/// quote without re-pricing, so the real worst case between reading a price and
/// an order being opened on it is this TTL plus that one - about 345 s, not 45.
/// That is deliberate: a quote shown to a user has to stay honourable while
/// they act on it. But it means the spread is covering five minutes of drift,
/// not forty-five seconds, and `quote_seconds` is the number to shorten if that
/// exposure is ever too wide.
pub const PRICE_TTL: Duration = Duration::from_secs(45);

/// The widest a price may be and still be believed, in USD.
///
/// This is a sanity bound on a parse, not a market forecast. It is deliberately
/// loose - ZEC has traded under $20 and, on 2026-09-04, near $1,022 - because
/// its job is to catch a feed that answers 0, 1e12, or a price in the wrong
/// currency, not to second-guess a real move. A genuine market outside this
/// range stops quotes until an operator widens it, which is the safe direction.
pub const MIN_PLAUSIBLE_USD: f64 = 1.0;
pub const MAX_PLAUSIBLE_USD: f64 = 100_000.0;

/// The furthest a new price may sit from the last good one, as a ratio.
///
/// A feed that starts answering a tenth or ten times the real price passes the
/// absolute range above but not this. 0.5 means a new price is refused if it is
/// less than half or more than double the last one this process trusted. Real
/// ZEC does not halve between two reads 45 s apart; a broken feed does.
pub const MAX_MOVE_RATIO: f64 = 0.5;

/// How far the two exchanges may disagree before neither is believed.
///
/// A single source is a single point of control: anything that can change what
/// the coordinator sees from one exchange - a poisoned resolver, a hostile
/// upstream - moves the quoted price freely inside the bounds above, and a
/// primary that answers successfully means the fallback is never consulted. So
/// both are read and compared, and the cheaper the check the less reason not to
/// run it: one extra HTTP call per [`PRICE_TTL`].
///
/// 2% is far wider than the two normally sit apart (measured 0.005% between
/// Coinbase and Kraken on 2026-09-04) and narrow enough that one of them being
/// wrong shows up. When they disagree by more, the *lower* price is taken
/// rather than refusing outright: the low price is the conservative one for an
/// LP buying ZEC, and a thin market is a bad reason to stop trading.
pub const MAX_SOURCE_DISAGREEMENT: f64 = 0.02;

/// A price that was read from a market, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpotPrice {
    /// USD per ZEC, before any spread.
    pub usd_per_zec: f64,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Coinbase,
    Kraken,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Coinbase => "coinbase",
            Source::Kraken => "kraken",
        }
    }
}

/// Parses Coinbase's spot answer: `{"data":{"amount":"1025.02",...}}`.
///
/// The amount is a JSON *string*, not a number, which is why this is a parse
/// and not a `f64` field.
pub fn parse_coinbase(body: &str) -> Result<f64> {
    let v: serde_json::Value =
        serde_json::from_str(body).context("coinbase answered something that is not JSON")?;
    let amount = v
        .get("data")
        .and_then(|d| d.get("amount"))
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow::anyhow!("coinbase answered no data.amount"))?;
    amount
        .trim()
        .parse::<f64>()
        .with_context(|| format!("coinbase amount {amount:?} is not a number"))
}

/// Parses Kraken's ticker: the last trade price is `result.<pair>.c[0]`.
///
/// Kraken names the pair `XZECZUSD` rather than the `ZECUSD` that was asked
/// for, so the pair is taken as whichever key `result` carries rather than
/// looked up by name.
pub fn parse_kraken(body: &str) -> Result<f64> {
    let v: serde_json::Value =
        serde_json::from_str(body).context("kraken answered something that is not JSON")?;
    if let Some(errors) = v.get("error").and_then(|e| e.as_array()) {
        if let Some(first) = errors.first().and_then(|e| e.as_str()) {
            bail!("kraken refused: {first}");
        }
    }
    let result = v
        .get("result")
        .and_then(|r| r.as_object())
        .ok_or_else(|| anyhow::anyhow!("kraken answered no result"))?;
    let pair = result
        .values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("kraken answered an empty result"))?;
    let last = pair
        .get("c")
        .and_then(|c| c.get(0))
        .and_then(|p| p.as_str())
        .ok_or_else(|| anyhow::anyhow!("kraken answered no last trade price"))?;
    last.trim()
        .parse::<f64>()
        .with_context(|| format!("kraken price {last:?} is not a number"))
}

/// Whether a price is inside the absolute plausible range.
///
/// Written as a positive test so NaN falls through to the refusal, the same
/// shape `quote::build` uses on user input.
pub fn is_plausible(usd: f64) -> bool {
    usd.is_finite() && usd >= MIN_PLAUSIBLE_USD && usd <= MAX_PLAUSIBLE_USD
}

/// Whether `next` is close enough to `last` to be believed.
///
/// The first price of a process has no `last` and is checked by the absolute
/// range alone; there is nothing to compare it against, and refusing every
/// cold start would mean never quoting at all.
pub fn is_near(last: Option<f64>, next: f64) -> bool {
    let Some(last) = last else {
        return true;
    };
    // Fails closed. Nothing non-finite can reach `last_good` today, because
    // `accept` runs `is_plausible` before `store`. If that invariant ever
    // breaks, a bounds check that returns `true` would silently stop bounding
    // anything, so the unreachable branch refuses instead.
    if !(last.is_finite() && last > 0.0) {
        return false;
    }
    let ratio = (next - last).abs() / last;
    ratio <= MAX_MOVE_RATIO
}

/// The price the user is quoted, after the platform's spread.
///
/// The spread is the LP's margin: it fronts real dollars against a coin whose
/// price moves while the escrow is open, and before this it captured nothing
/// but the 0.15% fee. `spread_bps` of 50 means the coordinator values a ZEC at
/// 0.5% under the market when buying it from a user, which is the direction
/// every trade here runs.
///
/// Kept as one function so the direction is stated once. A spread applied the
/// wrong way is a discount, not a margin, and it would not show up as an
/// error anywhere.
pub fn apply_spread(spot_usd_per_zec: f64, spread_bps: u64) -> f64 {
    spot_usd_per_zec * (1.0 - (spread_bps as f64 / 10_000.0))
}

/// The cached spot price and the last one trusted, shared across requests.
#[derive(Debug, Default)]
pub struct PriceCache {
    /// The price served while it is inside [`PRICE_TTL`], and when it was read.
    fresh: Mutex<Option<(SpotPrice, Instant)>>,
    /// The last price that passed both bounds, kept past the TTL solely as the
    /// reference for [`is_near`]. It is never served as a quote: a value here
    /// with an expired `fresh` still means refuse.
    last_good: Mutex<Option<f64>>,
    /// Held across a refresh so only one request fetches when the TTL lapses.
    ///
    /// A `tokio::Mutex` rather than a `std` one because it is held across
    /// `await`. It guards no data - the two caches above have their own locks -
    /// it exists only to make concurrent misses collapse into one fetch.
    refreshing: tokio::sync::Mutex<()>,
}

impl PriceCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The cached price if it was read within [`PRICE_TTL`].
    pub fn fresh(&self) -> Option<SpotPrice> {
        // `into_inner` on a poisoned lock rather than `.ok()?`: the critical
        // sections here assign an `Option` and read a clock, so a panic inside
        // one is close to unreachable - but if it happened, silently answering
        // "no price" forever would refuse every quote until restart with
        // nothing in the log saying why.
        let slot = self.fresh.lock().unwrap_or_else(|e| e.into_inner());
        let (price, read_at) = (*slot)?;
        (read_at.elapsed() < PRICE_TTL).then_some(price)
    }

    /// The last price that passed the bounds, however old.
    pub fn last_good(&self) -> Option<f64> {
        *self.last_good.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records a price that passed both bounds.
    pub fn store(&self, price: SpotPrice) {
        let mut fresh = self.fresh.lock().unwrap_or_else(|e| e.into_inner());
        let mut last_good = self.last_good.lock().unwrap_or_else(|e| e.into_inner());
        // Both under both guards, so `fresh` can never advance while
        // `last_good` stays behind - that would measure the next move against
        // a stale anchor.
        *fresh = Some((price, Instant::now()));
        *last_good = Some(price.usd_per_zec);
    }

    /// Checks a freshly fetched price against both bounds and stores it.
    ///
    /// The single place a price becomes trusted, so neither bound can be
    /// skipped by a caller that fetched its own.
    pub fn accept(&self, price: SpotPrice) -> Result<SpotPrice> {
        if !is_plausible(price.usd_per_zec) {
            bail!(
                "{} answered {} USD/ZEC, outside the plausible range {}-{}",
                price.source.label(),
                price.usd_per_zec,
                MIN_PLAUSIBLE_USD,
                MAX_PLAUSIBLE_USD
            );
        }
        let last = self.last_good();
        if !is_near(last, price.usd_per_zec) {
            bail!(
                "{} answered {} USD/ZEC, more than {:.0}% from the last good price {:?}",
                price.source.label(),
                price.usd_per_zec,
                MAX_MOVE_RATIO * 100.0,
                last
            );
        }
        self.store(price);
        Ok(price)
    }
}

/// Where the prices are read from.
///
/// Both are keyless public endpoints. Coinbase is primary because its answer is
/// one field and its public rate limit (10,000 requests per hour per IP, per
/// Coinbase's public API documentation) is far above the one call per
/// [`PRICE_TTL`] this makes. Kraken is the fallback and is a different company
/// on different infrastructure, which is the point of having one.
pub const COINBASE_URL: &str = "https://api.coinbase.com/v2/prices/ZEC-USD/spot";
pub const KRAKEN_URL: &str = "https://api.kraken.com/0/public/Ticker?pair=ZECUSD";

/// Reads the spot price: both sources, cross-checked, behind one refresh.
///
/// Returns the cached price without any request while it is fresh, so quote
/// latency is a lock rather than a round trip.
///
/// The refresh itself is single-flight. `refreshing` is held across the fetch,
/// so when the TTL lapses under concurrent traffic one request goes to the
/// exchanges and the rest wait for it - without it, N simultaneous quotes meant
/// N calls at the same instant, and this coordinator is a single IP behind
/// CloudFront. Every waiter re-checks the cache after taking the lock, so the
/// common case is one fetch and N-1 cache reads.
pub async fn spot(
    http: &reqwest::Client,
    cache: &PriceCache,
    timeout: Duration,
) -> Result<SpotPrice> {
    if let Some(price) = cache.fresh() {
        return Ok(price);
    }

    let _refreshing = cache.refreshing.lock().await;
    // The request that held the lock may have just filled the cache.
    if let Some(price) = cache.fresh() {
        return Ok(price);
    }

    // Both sources, concurrently: the second costs no wall-clock time and it is
    // what makes a single compromised or broken feed detectable.
    let (coinbase, kraken) = tokio::join!(
        fetch(http, Source::Coinbase, timeout),
        fetch(http, Source::Kraken, timeout)
    );

    let price = match (coinbase, kraken) {
        (Ok(cb), Ok(kr)) => {
            let disagreement = (cb.usd_per_zec - kr.usd_per_zec).abs() / cb.usd_per_zec.max(kr.usd_per_zec);
            if disagreement > MAX_SOURCE_DISAGREEMENT {
                // One of them is wrong and there is no third opinion to break
                // the tie, so take the lower price. It is the conservative one
                // for an LP buying ZEC, and it bounds what a single hostile
                // feed can do: it can only ever make the coordinator pay less.
                tracing::warn!(
                    coinbase = cb.usd_per_zec,
                    kraken = kr.usd_per_zec,
                    disagreement,
                    "the price sources disagree; taking the lower"
                );
                if cb.usd_per_zec <= kr.usd_per_zec {
                    cb
                } else {
                    kr
                }
            } else {
                cb
            }
        }
        // One source down is not a reason to stop trading; one source down
        // *and* the other implausible is, and `accept` below decides that.
        (Ok(cb), Err(e)) => {
            tracing::warn!(error = %e, "kraken failed; pricing on coinbase alone");
            cb
        }
        (Err(e), Ok(kr)) => {
            tracing::warn!(error = %e, "coinbase failed; pricing on kraken alone");
            kr
        }
        (Err(cb_err), Err(kr_err)) => {
            bail!("no price could be read: coinbase: {cb_err}; kraken: {kr_err}")
        }
    };

    cache.accept(price)
}

/// One HTTP read of one source. No bounds are applied here; that is
/// [`PriceCache::accept`], so every path through this module shares them.
async fn fetch(http: &reqwest::Client, source: Source, timeout: Duration) -> Result<SpotPrice> {
    let url = match source {
        Source::Coinbase => COINBASE_URL,
        Source::Kraken => KRAKEN_URL,
    };
    let resp = http
        .get(url)
        .timeout(timeout)
        .send()
        .await
        .with_context(|| format!("{} could not be reached", source.label()))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("{} answer unreadable", source.label()))?;
    if !status.is_success() {
        bail!("{} returned HTTP {status}", source.label());
    }
    let usd_per_zec = match source {
        Source::Coinbase => parse_coinbase(&body)?,
        Source::Kraken => parse_kraken(&body)?,
    };
    Ok(SpotPrice {
        usd_per_zec,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from the live endpoints on 2026-09-04, trimmed to the fields
    // parsed. Real shapes rather than invented ones, so a provider changing its
    // envelope shows up here.
    const COINBASE_BODY: &str = r#"{"data":{"amount":"1025.02","base":"ZEC","currency":"USD"}}"#;
    const KRAKEN_BODY: &str = r#"{"error":[],"result":{"XZECZUSD":{"a":["1025.11000","1","1.000"],"b":["1024.84000","2","2.000"],"c":["1025.74000","0.96727584"],"p":["1022.05837","1003.34382"]}}}"#;

    #[test]
    fn coinbase_parses_its_string_amount() {
        assert_eq!(parse_coinbase(COINBASE_BODY).unwrap(), 1025.02);
    }

    #[test]
    fn kraken_parses_the_last_trade_under_its_renamed_pair() {
        // Asked for ZECUSD, answered XZECZUSD: the key is not the pair name.
        assert_eq!(parse_kraken(KRAKEN_BODY).unwrap(), 1025.74);
    }

    #[test]
    fn a_parse_refuses_rather_than_guessing() {
        assert!(parse_coinbase("not json").is_err());
        assert!(parse_coinbase(r#"{"data":{}}"#).is_err());
        assert!(parse_coinbase(r#"{"data":{"amount":"free"}}"#).is_err());
        assert!(parse_kraken(r#"{"error":["EQuery:Unknown asset pair"]}"#).is_err());
        assert!(parse_kraken(r#"{"error":[],"result":{}}"#).is_err());
    }

    #[test]
    fn the_spread_is_taken_off_the_market_price() {
        // 50 bps under 1000 is 995: the LP buys a ZEC for less than it is worth,
        // which is where the margin is.
        assert_eq!(apply_spread(1000.0, 50), 995.0);
        assert_eq!(apply_spread(1000.0, 0), 1000.0);
        assert_eq!(apply_spread(1024.0, 100), 1013.76);
    }

    #[test]
    fn the_spread_never_pays_more_than_the_market() {
        for bps in [0u64, 1, 25, 50, 100, 500] {
            let quoted = apply_spread(1022.0, bps);
            assert!(
                quoted <= 1022.0,
                "a {bps} bps spread quoted {quoted}, above the market"
            );
        }
    }

    #[test]
    fn an_absurd_price_is_not_plausible() {
        assert!(is_plausible(1022.0));
        assert!(is_plausible(40.25));
        assert!(!is_plausible(0.0));
        assert!(!is_plausible(-5.0));
        assert!(!is_plausible(1e12));
        assert!(!is_plausible(f64::NAN));
        assert!(!is_plausible(f64::INFINITY));
    }

    #[test]
    fn a_price_that_jumped_is_refused_against_the_last_good_one() {
        assert!(is_near(Some(1022.0), 1030.0));
        assert!(is_near(Some(1022.0), 900.0));
        // A tenth of the price passes the absolute range and fails this.
        assert!(!is_near(Some(1022.0), 102.2));
        assert!(!is_near(Some(1022.0), 10_220.0));
        // The old hardcoded constant against a real market: exactly the
        // mistake this bound exists to catch.
        assert!(!is_near(Some(1022.0), 40.25));
    }

    #[test]
    fn a_corrupt_last_good_stops_bounding_nothing() {
        // Unreachable today - `accept` validates before `store` - but the
        // bounds check must fail closed if that ever stops being true.
        assert!(!is_near(Some(f64::NAN), 1022.0));
        assert!(!is_near(Some(0.0), 1022.0));
        assert!(!is_near(Some(-1.0), 1022.0));
    }

    #[test]
    fn the_disagreement_bound_is_wider_than_the_exchanges_normally_sit() {
        // Coinbase 1024.55 and Kraken 1024.60, measured 2026-09-04: 0.005%.
        let cb = 1024.55f64;
        let kr = 1024.60f64;
        let seen = (cb - kr).abs() / cb.max(kr);
        assert!(
            seen < MAX_SOURCE_DISAGREEMENT,
            "the real spread {seen} should not trip the bound"
        );
        // A source that is out by a factor of ten must trip it.
        let broken = (1022.0f64 - 102.2).abs() / 1022.0;
        assert!(broken > MAX_SOURCE_DISAGREEMENT);
    }

    #[test]
    fn the_lower_price_is_the_one_that_protects_the_lp() {
        // When the sources disagree the lower price is taken. Lower USD per ZEC
        // means a user hands over more ZEC for the same dollars, so a single
        // wrong feed can only ever cost the user's counterparty less - never
        // more. This states the direction the branch in `spot` relies on.
        let honest = 1022.0f64;
        let hostile_high = 5000.0f64;
        let taken = honest.min(hostile_high);
        assert_eq!(taken, honest);
        let zat_at = |rate: f64| ((5.0 / rate) * 1e8).round() as u64;
        assert!(
            zat_at(taken) > zat_at(hostile_high),
            "the lower rate must ask for more ZEC, not less"
        );
    }

    #[test]
    fn the_first_price_has_nothing_to_compare_against() {
        assert!(is_near(None, 1022.0));
        // ...but the absolute range still applies to it.
        assert!(!is_plausible(1e12));
    }

    #[test]
    fn accept_stores_a_good_price_and_refuses_a_bad_one() {
        let cache = PriceCache::default();
        let good = SpotPrice {
            usd_per_zec: 1022.0,
            source: Source::Coinbase,
        };
        assert!(cache.accept(good).is_ok());
        assert_eq!(cache.fresh().map(|p| p.usd_per_zec), Some(1022.0));
        assert_eq!(cache.last_good(), Some(1022.0));

        let absurd = SpotPrice {
            usd_per_zec: 5e9,
            source: Source::Kraken,
        };
        assert!(cache.accept(absurd).is_err());
        // The bad price did not displace the good one.
        assert_eq!(cache.last_good(), Some(1022.0));

        let jumped = SpotPrice {
            usd_per_zec: 40.25,
            source: Source::Kraken,
        };
        assert!(cache.accept(jumped).is_err());
        assert_eq!(cache.fresh().map(|p| p.usd_per_zec), Some(1022.0));
    }

    #[test]
    fn an_empty_cache_offers_nothing_to_serve() {
        // The refuse-on-failure path: no price cached means the caller has
        // nothing to fall back to, which is what makes a failed fetch a refusal
        // rather than a stale quote.
        let cache = PriceCache::default();
        assert_eq!(cache.fresh(), None);
        assert_eq!(cache.last_good(), None);
    }

    #[test]
    fn an_expired_price_is_not_served_even_though_it_is_remembered() {
        let cache = PriceCache::default();
        let price = SpotPrice {
            usd_per_zec: 1022.0,
            source: Source::Coinbase,
        };
        // Store it as though it were read a full TTL ago.
        if let Ok(mut slot) = cache.fresh.lock() {
            *slot = Some((price, Instant::now() - PRICE_TTL - Duration::from_secs(1)));
        }
        if let Ok(mut slot) = cache.last_good.lock() {
            *slot = Some(price.usd_per_zec);
        }
        assert_eq!(cache.fresh(), None, "an expired price must not be served");
        // It survives as the reference for the move check, which is the only
        // thing it is kept for.
        assert_eq!(cache.last_good(), Some(1022.0));
    }

    #[test]
    fn a_price_inside_the_ttl_is_served_without_a_fetch() {
        let cache = PriceCache::default();
        cache
            .accept(SpotPrice {
                usd_per_zec: 1022.0,
                source: Source::Coinbase,
            })
            .unwrap();
        assert!(cache.fresh().is_some());
    }
}

/// Tests that talk to the real exchanges.
///
/// `#[ignore]` because a network test that runs by default makes CI depend on
/// somebody else's uptime. Run them deliberately:
/// `cargo test -p zecp2p-v2coordinator --lib live_price -- --ignored --nocapture`
#[cfg(test)]
mod live_price {
    use super::*;

    /// The band a real ZEC price should fall in for this test to mean
    /// anything. ZEC traded near $1,022 on 2026-09-04 (Coinbase and Kraken
    /// agreed within 0.02%). This is wide enough to survive an ordinary market
    /// but narrow enough to catch a feed answering the old 40.25 constant, a
    /// price in the wrong currency, or a decimal point in the wrong place.
    const SANE_LOW: f64 = 100.0;
    const SANE_HIGH: f64 = 10_000.0;

    #[tokio::test]
    #[ignore]
    async fn both_sources_answer_a_sane_zec_price_and_agree() {
        let http = reqwest::Client::new();
        let timeout = Duration::from_secs(15);

        let cb = super::fetch(&http, Source::Coinbase, timeout)
            .await
            .expect("coinbase should answer");
        let kr = super::fetch(&http, Source::Kraken, timeout)
            .await
            .expect("kraken should answer");

        for p in [cb, kr] {
            assert!(
                p.usd_per_zec > SANE_LOW && p.usd_per_zec < SANE_HIGH,
                "{} answered {} USD/ZEC, outside the sane band",
                p.source.label(),
                p.usd_per_zec
            );
            assert!(is_plausible(p.usd_per_zec));
        }

        // Two independent exchanges on the same asset should not disagree by
        // much. 5% is loose enough for a genuinely thin moment and tight
        // enough that one of them being broken shows up.
        let spread = (cb.usd_per_zec - kr.usd_per_zec).abs() / cb.usd_per_zec;
        assert!(
            spread < 0.05,
            "coinbase {} and kraken {} disagree by {:.2}%",
            cb.usd_per_zec,
            kr.usd_per_zec,
            spread * 100.0
        );

        println!(
            "coinbase={:.2} kraken={:.2} spread={:.3}%",
            cb.usd_per_zec,
            kr.usd_per_zec,
            spread * 100.0
        );
    }

    #[tokio::test]
    #[ignore]
    async fn the_quoted_rate_sits_just_under_the_market() {
        let http = reqwest::Client::new();
        let cache = PriceCache::default();
        let spot = spot(&http, &cache, Duration::from_secs(15))
            .await
            .expect("a price should be readable");

        let quoted = apply_spread(spot.usd_per_zec, 50);
        assert!(
            quoted < spot.usd_per_zec,
            "the spread must leave the LP a margin"
        );
        // 50 bps off, and nothing more: a spread bug that dropped a factor of
        // ten would pass the line above and fail this one.
        let taken = (spot.usd_per_zec - quoted) / spot.usd_per_zec;
        assert!(
            (taken - 0.005).abs() < 1e-9,
            "a 50 bps spread took {:.4}%",
            taken * 100.0
        );
        assert!(quoted > SANE_LOW && quoted < SANE_HIGH);

        println!(
            "source={} spot={:.2} quoted={:.2} (50 bps)",
            spot.source.label(),
            spot.usd_per_zec,
            quoted
        );
    }

    /// The second read inside the TTL must not touch the network.
    #[tokio::test]
    #[ignore]
    async fn a_second_read_is_served_from_the_cache() {
        let http = reqwest::Client::new();
        let cache = PriceCache::default();
        let first = spot(&http, &cache, Duration::from_secs(15)).await.unwrap();
        let second = spot(&http, &cache, Duration::from_secs(15)).await.unwrap();
        assert_eq!(
            first, second,
            "a read inside the TTL should return the cached price"
        );
    }
}

#[cfg(test)]
mod refusal {
    use super::*;

    /// A feed that cannot be reached produces an error, not a price.
    ///
    /// The client is pointed at a port nothing listens on, so both sources
    /// fail, which is the outage this must refuse on. The assertion that
    /// matters is the absence of any fallback: no default, no last-good value,
    /// no 40.25.
    #[tokio::test]
    async fn an_unreachable_feed_refuses_rather_than_inventing_a_price() {
        let http = reqwest::Client::builder()
            // Resolve both exchanges to a closed port on localhost.
            .resolve(
                "api.coinbase.com",
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            )
            .resolve(
                "api.kraken.com",
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            )
            .build()
            .unwrap();
        let cache = PriceCache::default();

        let err = spot(&http, &cache, Duration::from_secs(2))
            .await
            .expect_err("an unreachable feed must not yield a price");
        let text = err.to_string();
        assert!(
            text.contains("no price could be read"),
            "unexpected error: {text}"
        );
        // Nothing was cached, so a later quote cannot be served a stale value.
        assert_eq!(cache.fresh(), None);
        assert_eq!(cache.last_good(), None);
    }

    /// A good price already held is not served once it has aged out, even
    /// though the feed is now unreachable and a stale value would be the
    /// convenient answer.
    #[tokio::test]
    async fn an_outage_after_a_good_price_still_refuses_once_it_is_stale() {
        let http = reqwest::Client::builder()
            .resolve(
                "api.coinbase.com",
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            )
            .resolve(
                "api.kraken.com",
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
            )
            .build()
            .unwrap();
        let cache = PriceCache::default();
        let good = SpotPrice {
            usd_per_zec: 1022.0,
            source: Source::Coinbase,
        };
        cache.accept(good).unwrap();

        // While fresh, it is served without touching the network.
        assert_eq!(
            spot(&http, &cache, Duration::from_secs(2)).await.unwrap(),
            good
        );

        // Age it past the TTL and the same call must now fail.
        if let Ok(mut slot) = cache.fresh.lock() {
            *slot = Some((good, Instant::now() - PRICE_TTL - Duration::from_secs(1)));
        }
        let err = spot(&http, &cache, Duration::from_secs(2))
            .await
            .expect_err("a stale price must not be served");
        assert!(err.to_string().contains("no price could be read"));
        // last_good survives as the move-check reference, and is still not a
        // price anyone may be quoted.
        assert_eq!(cache.last_good(), Some(1022.0));
    }
}
