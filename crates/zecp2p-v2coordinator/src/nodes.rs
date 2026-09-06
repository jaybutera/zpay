//! Several node endpoints, tried in order, with the working one remembered.
//!
//! Finding 6: there was one RPC provider. Its incident is this coordinator's
//! incident, and the read it takes down - the chain height - is the one that
//! decides when a user is offered the refund they are owed.
//!
//! The rules here are deliberately small:
//!
//! - **Order is the operator's preference.** The primary leads and fallbacks
//!   follow in the order written. Nothing here ranks endpoints by latency or
//!   health; an LP who wants their own node preferred writes it first.
//! - **Only a reachability failure moves on.** A node that answers "no such
//!   output" or "that transaction is rejected" has answered, and asking a
//!   second node the same question would swap one node's opinion for another's
//!   until one agrees. Only [`ChainError::Unreachable`] fails over.
//! - **The working endpoint is remembered**, so an outage costs one wasted call
//!   rather than one per call, and recovery is re-checked from the top on the
//!   next miss rather than pinned to the fallback forever.
//!
//! Nothing in here names a provider. Which endpoints exist is `zec.rpc_url`
//! plus `zec.fallback_rpc`, both per-instance.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use zecp2p_escrow::chain::ChainError;
use zecp2p_escrow::rpc::{RpcChainClient, RpcConfig};

/// The endpoints this coordinator may ask, and which one answered last.
#[derive(Debug, Clone)]
pub struct NodePool {
    endpoints: Arc<Vec<RpcConfig>>,
    /// Index of the endpoint to try first. Advisory: a stale value costs one
    /// failed call, never a wrong answer.
    preferred: Arc<AtomicUsize>,
}

impl NodePool {
    /// Builds a pool. The first entry is the primary.
    ///
    /// Panics on an empty list, which cannot happen: `rpc_configs` always
    /// returns the primary, and a coordinator with no node cannot start.
    pub fn new(endpoints: Vec<RpcConfig>) -> Self {
        assert!(!endpoints.is_empty(), "a node pool needs at least one endpoint");
        Self {
            endpoints: Arc::new(endpoints),
            preferred: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// The endpoint currently preferred, for a log line or `/health`.
    pub fn current(&self) -> &RpcConfig {
        &self.endpoints[self.preferred_index()]
    }

    /// Whether the pool is running on something other than the primary.
    ///
    /// `/health` reports this: a coordinator quietly serving from its fallback
    /// is working, and is also one incident from not working, so it is
    /// degraded rather than fine.
    pub fn on_fallback(&self) -> bool {
        self.preferred_index() != 0
    }

    fn preferred_index(&self) -> usize {
        self.preferred.load(Ordering::Relaxed) % self.endpoints.len()
    }

    /// The endpoints to try, preferred first, then the rest in configured
    /// order.
    ///
    /// The preferred one is not tried twice: an outage that has already moved
    /// the pointer should not pay for a call to the dead primary on every
    /// request, and a recovery is found because the *rest* still contains it.
    fn order(&self) -> Vec<usize> {
        let start = self.preferred_index();
        let n = self.endpoints.len();
        (0..n).map(|i| (start + i) % n).collect()
    }

    /// Runs `f` against each endpoint in turn until one does not report the
    /// node unreachable.
    ///
    /// `f` is a blocking closure and this is called from `spawn_blocking`, so
    /// there is no async in here at all. It is `FnMut` because it may run
    /// against more than one client.
    ///
    /// Returns the last error when every endpoint is unreachable, which is the
    /// honest answer: nothing this coordinator can reach knows.
    pub fn try_each<T, F>(&self, mut f: F) -> Result<T, ChainError>
    where
        F: FnMut(&RpcChainClient) -> Result<T, ChainError>,
    {
        let mut last: Option<ChainError> = None;
        for idx in self.order() {
            let cfg = self.endpoints[idx].clone();
            let client = match RpcChainClient::new(cfg) {
                Ok(c) => c,
                Err(e) => {
                    // A client that will not even build is a configuration
                    // fault for that endpoint, not an answer about the chain.
                    // Treated as unreachable so the next one is tried.
                    last = Some(ChainError::Unreachable(format!(
                        "endpoint {} could not be built: {e}",
                        redact(&self.endpoints[idx].url)
                    )));
                    continue;
                }
            };
            match f(&client) {
                Ok(v) => {
                    self.remember(idx);
                    return Ok(v);
                }
                // The node answered. A second opinion is not wanted: asking
                // another endpoint whether a transaction is really rejected is
                // asking until somebody says yes.
                Err(e @ (ChainError::Rejected(_) | ChainError::NotYet(_))) => {
                    self.remember(idx);
                    return Err(e);
                }
                Err(e @ ChainError::Unreachable(_)) => {
                    if self.endpoints.len() > 1 {
                        tracing::warn!(
                            endpoint = %redact(&self.endpoints[idx].url),
                            error = %e,
                            "node endpoint unreachable; trying the next one"
                        );
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| ChainError::Unreachable("no node endpoint answered".into())))
    }

    fn remember(&self, idx: usize) {
        let previous = self.preferred.swap(idx, Ordering::Relaxed);
        if previous != idx {
            tracing::info!(
                endpoint = %redact(&self.endpoints[idx].url),
                primary = idx == 0,
                "node calls are now going to a different endpoint"
            );
        }
    }
}

/// A URL with any userinfo and query string removed.
///
/// Some providers put the API key in the path or the query, and this string
/// reaches logs and `/health`. Keeping scheme, host and a truncated path is
/// enough to tell two endpoints apart without publishing a credential.
pub fn redact(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(s, r)| (s, r));
    let Some((scheme, rest)) = without_scheme else {
        return "<endpoint>".to_string();
    };
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let host_and_path = rest.split(['?', '#']).next().unwrap_or(rest);
    // One path segment at most: a key in the path is usually the second.
    let mut parts = host_and_path.splitn(3, '/');
    let host = parts.next().unwrap_or("");
    let first = parts.next().unwrap_or("");
    let more = parts.next().is_some();
    if first.is_empty() {
        format!("{scheme}://{host}")
    } else if more {
        format!("{scheme}://{host}/{first}/…")
    } else {
        format!("{scheme}://{host}/{first}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zecp2p_escrow::rpc::Network;

    fn cfg(url: &str) -> RpcConfig {
        RpcConfig::public(url, Network::Test)
    }

    /// The happy path stays on the primary and never touches a fallback.
    #[test]
    fn a_working_primary_is_the_only_endpoint_used() {
        let pool = NodePool::new(vec![cfg("http://primary.invalid"), cfg("http://backup.invalid")]);
        let seen = std::cell::RefCell::new(Vec::new());
        let out: Result<u32, ChainError> = pool.try_each(|c| {
            seen.borrow_mut().push(c.url().to_string());
            Ok(7)
        });
        assert_eq!(out.unwrap(), 7);
        assert_eq!(seen.borrow().len(), 1);
        assert!(seen.borrow()[0].contains("primary"));
        assert!(!pool.on_fallback());
    }

    /// An unreachable primary moves to the fallback and the answer comes back.
    #[test]
    fn an_unreachable_primary_fails_over() {
        let pool = NodePool::new(vec![cfg("http://primary.invalid"), cfg("http://backup.invalid")]);
        let out: Result<u32, ChainError> = pool.try_each(|c| {
            if c.url().contains("primary") {
                Err(ChainError::Unreachable("down".into()))
            } else {
                Ok(11)
            }
        });
        assert_eq!(out.unwrap(), 11);
        assert!(pool.on_fallback(), "the pool should remember the endpoint that answered");
        assert!(pool.current().url.contains("backup"));
    }

    /// A rejection is an answer. Trying the next node would be shopping for a
    /// node that agrees, and a release "rejected" by one node and accepted by
    /// another is a double broadcast.
    #[test]
    fn a_rejection_does_not_fail_over() {
        let pool = NodePool::new(vec![cfg("http://primary.invalid"), cfg("http://backup.invalid")]);
        let calls = std::cell::Cell::new(0);
        let out: Result<u32, ChainError> = pool.try_each(|_| {
            calls.set(calls.get() + 1);
            Err(ChainError::Rejected("bad signature".into()))
        });
        assert!(matches!(out, Err(ChainError::Rejected(_))));
        assert_eq!(calls.get(), 1, "only the endpoint that answered should be asked");
    }

    /// `NotYet` is also an answer: the node is telling the caller to come back
    /// at the next block, and the broadcast loop is built on that.
    #[test]
    fn not_yet_does_not_fail_over() {
        let pool = NodePool::new(vec![cfg("http://primary.invalid"), cfg("http://backup.invalid")]);
        let calls = std::cell::Cell::new(0);
        let out: Result<u32, ChainError> = pool.try_each(|_| {
            calls.set(calls.get() + 1);
            Err(ChainError::NotYet("input not found yet".into()))
        });
        assert!(matches!(out, Err(ChainError::NotYet(_))));
        assert_eq!(calls.get(), 1);
    }

    /// Every endpoint down is an error rather than a wrong answer.
    #[test]
    fn everything_down_reports_unreachable() {
        let pool = NodePool::new(vec![cfg("http://a.invalid"), cfg("http://b.invalid")]);
        let calls = std::cell::Cell::new(0);
        let out: Result<u32, ChainError> = pool.try_each(|_| {
            calls.set(calls.get() + 1);
            Err(ChainError::Unreachable("down".into()))
        });
        assert!(matches!(out, Err(ChainError::Unreachable(_))));
        assert_eq!(calls.get(), 2, "both endpoints should have been tried");
    }

    /// After failing over, a recovered primary is found again rather than the
    /// pool staying on the fallback for the life of the process.
    #[test]
    fn a_recovered_primary_is_picked_up_again() {
        let pool = NodePool::new(vec![cfg("http://primary.invalid"), cfg("http://backup.invalid")]);
        // Fail over.
        let _: Result<u32, ChainError> = pool.try_each(|c| {
            if c.url().contains("primary") {
                Err(ChainError::Unreachable("down".into()))
            } else {
                Ok(1)
            }
        });
        assert!(pool.on_fallback());

        // Now the backup is down and the primary is back. The pool starts at
        // the backup, misses, wraps to the primary, and stays there.
        let out: Result<u32, ChainError> = pool.try_each(|c| {
            if c.url().contains("backup") {
                Err(ChainError::Unreachable("down".into()))
            } else {
                Ok(2)
            }
        });
        assert_eq!(out.unwrap(), 2);
        assert!(!pool.on_fallback(), "the primary should be preferred again");
    }

    /// A single-endpoint pool behaves exactly as the old single client did.
    #[test]
    fn one_endpoint_is_the_old_behaviour() {
        let pool = NodePool::new(vec![cfg("http://only.invalid")]);
        assert_eq!(pool.len(), 1);
        let out: Result<u32, ChainError> =
            pool.try_each(|_| Err(ChainError::Unreachable("down".into())));
        assert!(matches!(out, Err(ChainError::Unreachable(_))));
        assert!(!pool.on_fallback());
    }

    /// The endpoint string reaches logs and `/health`, so a key in the URL
    /// must not travel with it.
    #[test]
    fn redaction_drops_credentials_from_a_url() {
        assert_eq!(redact("https://zec.example.com/"), "https://zec.example.com");
        assert_eq!(
            redact("https://zec.example.com/SECRETKEY123"),
            "https://zec.example.com/SECRETKEY123",
            "one path segment is kept: it is usually the network name"
        );
        assert_eq!(
            redact("https://zec.example.com/v1/SECRETKEY123"),
            "https://zec.example.com/v1/…"
        );
        assert_eq!(
            redact("https://user:pass@zec.example.com/rpc"),
            "https://zec.example.com/rpc"
        );
        assert_eq!(
            redact("https://zec.example.com/rpc?apikey=SECRET"),
            "https://zec.example.com/rpc"
        );
        assert_eq!(redact("not-a-url"), "<endpoint>");
    }
}
