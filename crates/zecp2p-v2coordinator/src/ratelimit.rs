//! What one caller may do at the door. Finding 4.
//!
//! No route had any bound on request rate, and opening an order is free: a
//! quote id, a curve point, a served handle. Nothing was ever sent to an
//! escrow, and the order still counted against the global open-order cap, the
//! per-handle cap, and the same-amount-per-handle guard, until its refund
//! height about a day later.
//!
//! # What this is and is not
//!
//! Two bounds, both on the order-opening route:
//!
//! - a **rate** on attempts, including refused ones, because a refused attempt
//!   still costs a quote lookup, a curator call and a scan of the store;
//! - a **standing count** of open orders one caller holds, which is the bound
//!   the existing per-handle cap cannot be: the handle is the *payee*, chosen
//!   by whoever opens the order, so it identifies who gets paid rather than who
//!   is calling.
//!
//! An IP is a weak identity, and this is a weak bound. It raises the cost of
//! closing intake from "one script" to "one address per five orders", which is
//! the improvement available at this layer without making users hold accounts.
//! A serious adversary with addresses to spend still gets through, and the
//! global rate is the backstop for that: it degrades everyone rather than
//! letting one caller close the service.
//!
//! Nothing here is specific to any deployment. Every number is configuration,
//! and an LP who fronts this with their own relay can set every limit to zero
//! and let the relay do it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitVerdict {
    Allowed,
    /// This caller has asked too often.
    TooManyRequests {
        retry_after_seconds: u64,
    },
    /// This caller already holds as many open orders as it may.
    TooManyOpenOrders {
        held: usize,
        limit: usize,
    },
    /// Everyone together has asked too often.
    ServiceBusy {
        retry_after_seconds: u64,
    },
}

impl LimitVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, LimitVerdict::Allowed)
    }
}

/// A fixed-window counter per key, plus one for everyone.
///
/// A fixed window rather than a sliding one or a token bucket, deliberately.
/// The bound being enforced is "not very many per minute" against a service
/// whose real work takes tens of seconds, so the classic fixed-window flaw -
/// twice the limit across a window boundary - is not a difference that matters
/// here, and the state it costs is one integer per key instead of a queue of
/// timestamps per key. The memory is the point: this map is keyed on something
/// a caller chooses.
#[derive(Debug, Default)]
pub struct RateLimiter {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    per_key: HashMap<String, Window>,
    global: Window,
    last_swept: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Option<Instant>,
    count: u32,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            started: None,
            count: 0,
        }
    }
}

impl Window {
    /// Counts one request, returning the count in the current window and how
    /// long until it resets.
    fn hit(&mut self, now: Instant, window: Duration) -> (u32, Duration) {
        match self.started {
            Some(started) if now.duration_since(started) < window => {
                self.count += 1;
                (self.count, window - now.duration_since(started))
            }
            _ => {
                self.started = Some(now);
                self.count = 1;
                (1, window)
            }
        }
    }

    fn is_stale(&self, now: Instant, window: Duration) -> bool {
        match self.started {
            Some(started) => now.duration_since(started) >= window * 2,
            None => true,
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts one order-opening attempt from `key`.
    ///
    /// Both counters are incremented whatever the verdict, so a caller cannot
    /// get free attempts by being refused. The global check comes first: when
    /// the service as a whole is over its limit, saying so is more useful than
    /// telling one caller they personally asked too often.
    pub fn check(
        &self,
        key: &str,
        per_key_limit: u32,
        global_limit: u32,
        window: Duration,
    ) -> LimitVerdict {
        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(i) => i,
            // A poisoned lock must not become an open door, but it also must
            // not close the service: this is a bound on abuse, not a safety
            // gate, and every guard that protects money is elsewhere.
            Err(poisoned) => poisoned.into_inner(),
        };

        // Evicting here rather than on a timer: this map is keyed on something
        // a caller chooses, so it must not be the unbounded one the audit found
        // in the order-lock map.
        Self::sweep(&mut inner, now, window);

        let (global_count, global_reset) = inner.global.hit(now, window);
        let (key_count, key_reset) = inner
            .per_key
            .entry(key.to_string())
            .or_default()
            .hit(now, window);

        if global_limit > 0 && global_count > global_limit {
            return LimitVerdict::ServiceBusy {
                retry_after_seconds: global_reset.as_secs().max(1),
            };
        }
        if per_key_limit > 0 && key_count > per_key_limit {
            return LimitVerdict::TooManyRequests {
                retry_after_seconds: key_reset.as_secs().max(1),
            };
        }
        LimitVerdict::Allowed
    }

    /// Drops keys whose windows are long over.
    ///
    /// Run at most once per window, because it walks the map: a sweep on every
    /// request would make the rate limiter's own cost scale with the number of
    /// distinct callers, which is the thing being defended against.
    fn sweep(inner: &mut Inner, now: Instant, window: Duration) {
        let due = match inner.last_swept {
            Some(at) => now.duration_since(at) >= window,
            None => true,
        };
        if !due {
            return;
        }
        inner.last_swept = Some(now);
        inner.per_key.retain(|_, w| !w.is_stale(now, window));
    }

    /// How many distinct keys are being tracked, for a test and for `/health`.
    pub fn tracked_keys(&self) -> usize {
        match self.inner.lock() {
            Ok(i) => i.per_key.len(),
            Err(p) => p.into_inner().per_key.len(),
        }
    }
}

/// The address to count a request against.
///
/// `header` names a header a *trusted* proxy sets. Reading one that nothing
/// upstream overwrites would hand the caller the key they are limited on, which
/// is worse than no limit at all - it would look like one. So this is only
/// consulted when an operator has named a header, which they should do only
/// when their own relay rewrites it.
///
/// Takes the **first** entry of a comma-separated list, which is the client
/// address in the `X-Forwarded-For` convention, and refuses anything that is
/// not an address.
pub fn client_key(
    socket_addr: Option<IpAddr>,
    header_value: Option<&str>,
    header_configured: bool,
) -> String {
    if header_configured {
        if let Some(raw) = header_value {
            if let Some(first) = raw.split(',').next() {
                let first = first.trim();
                // A bare address, or one with a port.
                let candidate = first
                    .parse::<IpAddr>()
                    .ok()
                    .or_else(|| first.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()));
                if let Some(ip) = candidate {
                    return ip.to_string();
                }
            }
        }
    }
    match socket_addr {
        Some(ip) => ip.to_string(),
        // No address at all. One bucket for everyone in that position, which
        // is stricter than letting them through unbounded.
        None => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    /// Under the limit, every request is allowed.
    #[test]
    fn requests_under_the_limit_pass() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert_eq!(limiter.check("1.2.3.4", 5, 100, WINDOW), LimitVerdict::Allowed);
        }
    }

    /// The request past the limit is refused, and it is refused with a wait
    /// the caller can act on.
    #[test]
    fn the_request_past_the_limit_is_refused() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check("1.2.3.4", 5, 100, WINDOW).is_allowed());
        }
        match limiter.check("1.2.3.4", 5, 100, WINDOW) {
            LimitVerdict::TooManyRequests { retry_after_seconds } => {
                assert!(retry_after_seconds > 0 && retry_after_seconds <= 60);
            }
            other => panic!("expected a per-caller refusal, got {other:?}"),
        }
    }

    /// One caller being refused must not refuse anybody else. This is the
    /// property that makes the limit a bound on abuse rather than an outage.
    #[test]
    fn one_caller_hitting_the_limit_does_not_stop_another() {
        let limiter = RateLimiter::new();
        for _ in 0..6 {
            let _ = limiter.check("1.2.3.4", 5, 1000, WINDOW);
        }
        assert!(!limiter.check("1.2.3.4", 5, 1000, WINDOW).is_allowed());
        assert!(
            limiter.check("5.6.7.8", 5, 1000, WINDOW).is_allowed(),
            "a second caller must be unaffected"
        );
    }

    /// The global limit is the backstop for many callers, or one caller behind
    /// many addresses.
    #[test]
    fn the_global_limit_catches_what_per_caller_cannot() {
        let limiter = RateLimiter::new();
        for i in 0..10 {
            // Every request from a different address, so the per-caller limit
            // never fires.
            assert!(limiter.check(&format!("10.0.0.{i}"), 5, 10, WINDOW).is_allowed());
        }
        match limiter.check("10.0.0.99", 5, 10, WINDOW) {
            LimitVerdict::ServiceBusy { retry_after_seconds } => {
                assert!(retry_after_seconds > 0);
            }
            other => panic!("expected the global limit to fire, got {other:?}"),
        }
    }

    /// A refused request still counts, so being over the limit is not a way to
    /// get free attempts.
    #[test]
    fn refused_requests_still_count() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            let _ = limiter.check("1.2.3.4", 5, 100, WINDOW);
        }
        for _ in 0..20 {
            assert!(!limiter.check("1.2.3.4", 5, 100, WINDOW).is_allowed());
        }
    }

    /// Zero means off, which is what an LP fronted by their own rate-limiting
    /// relay configures.
    #[test]
    fn zero_disables_a_limit() {
        let limiter = RateLimiter::new();
        for _ in 0..500 {
            assert!(limiter.check("1.2.3.4", 0, 0, WINDOW).is_allowed());
        }
    }

    /// A short window resets, so a limit is a rate and not a lifetime quota.
    #[test]
    fn the_window_resets() {
        let limiter = RateLimiter::new();
        let window = Duration::from_millis(60);
        for _ in 0..3 {
            assert!(limiter.check("1.2.3.4", 3, 100, window).is_allowed());
        }
        assert!(!limiter.check("1.2.3.4", 3, 100, window).is_allowed());
        std::thread::sleep(Duration::from_millis(90));
        assert!(
            limiter.check("1.2.3.4", 3, 100, window).is_allowed(),
            "the window should have reset"
        );
    }

    /// The key map is keyed on something a caller chooses, so it must not grow
    /// without bound - that is the flaw the audit found in the order-lock map.
    #[test]
    fn stale_keys_are_evicted() {
        let limiter = RateLimiter::new();
        let window = Duration::from_millis(20);
        for i in 0..50 {
            let _ = limiter.check(&format!("10.0.0.{i}"), 5, 0, window);
        }
        assert_eq!(limiter.tracked_keys(), 50);
        std::thread::sleep(Duration::from_millis(60));
        // One more request triggers the sweep.
        let _ = limiter.check("10.9.9.9", 5, 0, window);
        assert!(
            limiter.tracked_keys() < 50,
            "stale windows should have been dropped, {} remain",
            limiter.tracked_keys()
        );
    }

    /// Without a configured header, the socket address is the key, whatever a
    /// caller puts in a header. Trusting an unwritten header would hand the
    /// caller the key they are limited on.
    #[test]
    fn a_header_is_ignored_unless_the_operator_named_one() {
        let socket: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(
            client_key(Some(socket), Some("1.1.1.1"), false),
            "9.9.9.9",
            "an unconfigured header must not be trusted"
        );
        assert_eq!(client_key(Some(socket), Some("1.1.1.1"), true), "1.1.1.1");
    }

    /// The forwarding convention puts the client first in the list.
    #[test]
    fn the_first_forwarded_address_is_the_client() {
        let socket: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(
            client_key(Some(socket), Some("1.1.1.1, 10.0.0.1, 10.0.0.2"), true),
            "1.1.1.1"
        );
    }

    /// Garbage in a trusted header falls back to the socket rather than
    /// becoming its own bucket, which would be a bucket the caller chose.
    #[test]
    fn an_unparseable_header_falls_back_to_the_socket() {
        let socket: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(client_key(Some(socket), Some("not-an-address"), true), "9.9.9.9");
        assert_eq!(client_key(Some(socket), None, true), "9.9.9.9");
    }

    /// No address at all shares one bucket, which is stricter than unbounded.
    #[test]
    fn no_address_shares_one_bucket() {
        assert_eq!(client_key(None, None, false), "unknown");
    }
}
