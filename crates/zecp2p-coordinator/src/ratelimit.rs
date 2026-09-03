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
pub fn source_of(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    behind_trusted_proxy: bool,
) -> IpAddr {
    if behind_trusted_proxy {
        if let Some(first) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .and_then(|v| v.parse::<IpAddr>().ok())
        {
            return first;
        }
    }

    // No peer address and no trusted header: attribute everything to one
    // bucket rather than to none. A shared limit is a limit; no limit is not.
    peer.map(|p| p.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
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

    #[test]
    fn a_trusted_proxy_supplies_the_client_address() {
        let source = source_of(&hdrs(Some("1.2.3.4")), peer(), true);
        assert_eq!(source, IpAddr::from([1, 2, 3, 4]));
    }

    /// A proxy appends, so the client is the first entry.
    #[test]
    fn the_first_entry_of_a_chain_is_the_client() {
        let source = source_of(&hdrs(Some("1.2.3.4, 10.0.0.1, 10.0.0.2")), peer(), true);
        assert_eq!(source, IpAddr::from([1, 2, 3, 4]));
    }

    /// Trusted but absent, or unparseable: fall back rather than fail open.
    #[test]
    fn a_missing_or_broken_header_falls_back_to_the_peer() {
        assert_eq!(source_of(&hdrs(None), peer(), true), IpAddr::from([10, 0, 0, 7]));
        assert_eq!(
            source_of(&hdrs(Some("not-an-address")), peer(), true),
            IpAddr::from([10, 0, 0, 7])
        );
    }
}
