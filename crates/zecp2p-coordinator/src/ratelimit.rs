//! A per-source token bucket for the endpoints anyone can reach.
//!
//! U1-2. `POST /v2/orders` and `GET /v2/quote` are the first browser-reachable
//! endpoints on this coordinator, and neither was limited. Each open made the
//! coordinator wait 1Click's full 5,000 ms relay window, which is the one
//! server-side cost an attacker imposes per request and which nothing bounded.
//!
//! The quote registry already ties an order to an issued price, so limiting
//! quotes limits orders. Both are limited anyway: they are separate costs and
//! an attacker choosing between them should find neither free.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

/// One bucket's state.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: DateTime<Utc>,
}

/// A token bucket keyed by source address.
pub struct RateLimiter {
    /// Bucket capacity: how many requests may arrive at once.
    burst: f64,
    /// How many tokens are restored per second.
    refill_per_second: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(burst: u32, refill_per_second: f64) -> Self {
        Self {
            burst: burst as f64,
            refill_per_second,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `source`, or refuse.
    ///
    /// Refusing is cheap and happens before any upstream call, which is the
    /// point: the cost an attacker imposes should stop at this function.
    pub async fn check(&self, source: IpAddr) -> Result<(), TooMany> {
        let now = Utc::now();
        let mut buckets = self.buckets.lock().await;

        // Buckets at full capacity carry no information, so a caller who has
        // gone quiet is forgotten and the map stays bounded by the number of
        // *active* sources rather than by every address ever seen.
        let full_after = self.burst / self.refill_per_second;
        buckets.retain(|_, b| {
            (now - b.last).num_seconds() as f64 <= full_after
        });

        let bucket = buckets.entry(source).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });

        let elapsed = (now - bucket.last).num_milliseconds().max(0) as f64 / 1000.0;
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.burst);
        bucket.last = now;

        if bucket.tokens < 1.0 {
            let wait = ((1.0 - bucket.tokens) / self.refill_per_second).ceil() as u64;
            return Err(TooMany {
                retry_after_seconds: wait.max(1),
            });
        }

        bucket.tokens -= 1.0;
        Ok(())
    }
}

/// The refusal, carrying how long to wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooMany {
    pub retry_after_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, n])
    }

    #[tokio::test]
    async fn a_burst_is_allowed_and_then_refused() {
        let limiter = RateLimiter::new(5, 0.5);

        for i in 0..5 {
            assert!(limiter.check(ip(1)).await.is_ok(), "request {i} is within the burst");
        }
        assert!(limiter.check(ip(1)).await.is_err(), "the sixth is not");
    }

    /// One noisy caller must not refuse everyone else, or the limiter is itself
    /// the denial of service.
    #[tokio::test]
    async fn one_source_running_out_does_not_affect_another() {
        let limiter = RateLimiter::new(3, 0.5);

        for _ in 0..3 {
            limiter.check(ip(1)).await.unwrap();
        }
        assert!(limiter.check(ip(1)).await.is_err());
        assert!(limiter.check(ip(2)).await.is_ok());
    }

    #[tokio::test]
    async fn a_refusal_says_how_long_to_wait() {
        let limiter = RateLimiter::new(1, 0.5);
        limiter.check(ip(1)).await.unwrap();

        let err = limiter.check(ip(1)).await.unwrap_err();
        assert!(err.retry_after_seconds >= 1);
    }

    /// Tokens come back over time, so a legitimate caller who paused is not
    /// permanently penalised.
    #[tokio::test]
    async fn tokens_refill() {
        let limiter = RateLimiter::new(2, 100.0);
        limiter.check(ip(1)).await.unwrap();
        limiter.check(ip(1)).await.unwrap();
        assert!(limiter.check(ip(1)).await.is_err());

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(limiter.check(ip(1)).await.is_ok());
    }
}

/// The address to attribute a request to.
///
/// The peer address, unless the operator has said a proxy they control sets
/// `X-Forwarded-For`. Trusting that header on a direct bind would let a caller
/// choose their own bucket, so it is opt-in and off by default.
///
/// U2-2. When it is on, the entry read is the **rightmost**, not the leftmost.
/// A proxy appends what it saw to whatever arrived, so the header a trusted
/// proxy hands on is `<whatever the client wrote>, <the address the proxy
/// actually saw>`. The leftmost entry is therefore the one entry in the header
/// that the client controls completely: reading it let a caller send
/// `X-Forwarded-For: 10.1.2.3`, get attributed to `10.1.2.3`, and mint a fresh
/// bucket per request by rotating the value. The rightmost entry is the one the
/// nearest hop wrote on its own authority, and the only one worth a limit.
pub fn source_of(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    behind_trusted_proxy: bool,
) -> IpAddr {
    if behind_trusted_proxy {
        // A header sent more than once is the same chain split across lines, so
        // the last entry of the last line is the nearest hop either way.
        if let Some(nearest) = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .last()
            .and_then(parse_forwarded_entry)
        {
            return nearest;
        }
    }

    // No peer address and no trusted header: attribute everything to one
    // bucket rather than to none. A shared limit is a limit; no limit is not.
    peer.map(|p| p.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// One `X-Forwarded-For` entry as an address.
///
/// Entries carry a port often enough to be worth handling: `1.2.3.4:5678` and
/// the bracketed IPv6 form `[::1]:5678` both appear. Dropping the port keeps
/// one caller in one bucket instead of a new bucket per connection, which is
/// the same spoofing the rightmost rule exists to stop.
fn parse_forwarded_entry(raw: &str) -> Option<IpAddr> {
    if let Ok(addr) = raw.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Ok(sock) = raw.parse::<std::net::SocketAddr>() {
        return Some(sock.ip());
    }
    // `[::1]` with no port.
    let unbracketed = raw.strip_prefix('[')?.strip_suffix(']')?;
    unbracketed.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod source_tests {
    use super::*;

    fn hdrs(xff: Option<&str>) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if let Some(v) = xff {
            h.insert("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    fn peer() -> Option<std::net::SocketAddr> {
        Some("10.0.0.7:5555".parse().unwrap())
    }

    /// The whole point of the flag: a caller must not be able to pick their own
    /// bucket by sending a header.
    #[test]
    fn the_forwarded_header_is_ignored_unless_it_is_trusted() {
        let source = source_of(&hdrs(Some("1.2.3.4")), peer(), false);
        assert_eq!(source, IpAddr::from([10, 0, 0, 7]));
    }

    /// A single-entry header behind a trusted proxy is what that proxy saw, so
    /// it is the address to attribute.
    #[test]
    fn a_trusted_proxy_supplies_the_address_it_saw() {
        let source = source_of(&hdrs(Some("1.2.3.4")), peer(), true);
        assert_eq!(source, IpAddr::from([1, 2, 3, 4]));
    }

    /// U2-2. A proxy appends, so the *last* entry is the one it wrote and every
    /// entry to the left of it is whatever the client chose to send. Reading
    /// the first entry let a caller pick their own bucket and rotate it.
    #[test]
    fn the_last_entry_of_a_chain_is_the_nearest_hop() {
        let source = source_of(&hdrs(Some("1.2.3.4, 10.0.0.1, 10.0.0.2")), peer(), true);
        assert_eq!(source, IpAddr::from([10, 0, 0, 2]));
    }

    /// The attack the finding priced: a spoofed prefix must not mint a bucket.
    /// Two requests whose only difference is the client-written prefix have to
    /// land in the same bucket, or the limit is not a limit.
    #[test]
    fn a_spoofed_prefix_does_not_change_the_bucket() {
        let a = source_of(&hdrs(Some("203.0.113.7, 10.0.0.9")), peer(), true);
        let b = source_of(&hdrs(Some("198.51.100.4, 10.0.0.9")), peer(), true);
        let c = source_of(&hdrs(Some("10.0.0.9")), peer(), true);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, IpAddr::from([10, 0, 0, 9]));
    }

    /// A client that writes the header without a comma still cannot choose its
    /// bucket: the proxy appends what it saw, and that is what is read.
    #[test]
    fn a_client_written_header_is_overtaken_by_the_proxys_entry() {
        let spoofed = source_of(&hdrs(Some("9.9.9.9, 10.0.0.7")), peer(), true);
        assert_ne!(spoofed, IpAddr::from([9, 9, 9, 9]));
        assert_eq!(spoofed, IpAddr::from([10, 0, 0, 7]));
    }

    /// Some proxies send the chain as repeated header lines rather than one
    /// comma-joined line. The nearest hop is the last entry either way.
    #[test]
    fn a_chain_split_across_header_lines_reads_the_same() {
        let mut h = axum::http::HeaderMap::new();
        h.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        h.append("x-forwarded-for", "10.0.0.3".parse().unwrap());
        assert_eq!(source_of(&h, peer(), true), IpAddr::from([10, 0, 0, 3]));
    }

    /// An entry carrying a port is one caller, not one caller per connection.
    #[test]
    fn a_port_on_an_entry_is_dropped_rather_than_making_a_new_bucket() {
        assert_eq!(
            source_of(&hdrs(Some("1.2.3.4, 10.0.0.5:41234")), peer(), true),
            IpAddr::from([10, 0, 0, 5])
        );
        assert_eq!(
            source_of(&hdrs(Some("[2001:db8::1]:443")), peer(), true),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            source_of(&hdrs(Some("[2001:db8::2]")), peer(), true),
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
    }

    /// Trusted but absent, or unparseable: fall back rather than fail open.
    ///
    /// A last entry that will not parse falls back to the peer rather than
    /// walking left, because walking left is exactly what the client controls:
    /// an unparseable trailing entry would otherwise be a way to reach the
    /// spoofable part of the header.
    #[test]
    fn a_missing_or_broken_header_falls_back_to_the_peer() {
        assert_eq!(source_of(&hdrs(None), peer(), true), IpAddr::from([10, 0, 0, 7]));
        assert_eq!(
            source_of(&hdrs(Some("not-an-address")), peer(), true),
            IpAddr::from([10, 0, 0, 7])
        );
        assert_eq!(
            source_of(&hdrs(Some("1.2.3.4, garbage")), peer(), true),
            IpAddr::from([10, 0, 0, 7])
        );
        assert_eq!(source_of(&hdrs(Some("")), peer(), true), IpAddr::from([10, 0, 0, 7]));
        assert_eq!(source_of(&hdrs(Some(",  ,")), peer(), true), IpAddr::from([10, 0, 0, 7]));
    }
}
