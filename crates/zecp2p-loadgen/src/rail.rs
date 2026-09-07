//! The fiat leg, modelled.
//!
//! The real rail drives a browser against Venmo and takes a minute or two per
//! payment. Pointing a load harness at it would be both slow and wrong: the
//! payments are real dollars, they go to one account, and the audience question
//! is settled elsewhere. So the leg is modelled, and everything downstream of
//! it - the attestation shape, the outcome scalar, the release assembly and the
//! broadcast - stays the production path.
//!
//! What the model has to get right is **timing and failure**, because those are
//! what the coordinator's safety argument is built around. A rail that returns
//! instantly and never fails exercises none of it: the payment slot never
//! contends, the crash windows never open, and a soak run reports throughput
//! for a system that does not exist.
//!
//! So this rail takes a configurable delay, and it injects the failures the
//! live system actually produced:
//!
//! * **Prover config gaps.** `attest` fails after `pay` succeeded. The dollars
//!   are gone and no attestation can be produced, which is the worst case the
//!   journal exists for.
//! * **The false paid.** `pay` returns `fiat_left: true` when nothing left.
//!   This is the shape of the 2026-09-05 incident, where a confirmation
//!   challenge was read as a completed send. The harness cannot detect this
//!   from inside - that is the point - but it counts what it was asked to do,
//!   so a run can assert the ledger against the truth the rail kept.
//! * **Hard pay failures.** `pay` errors after the journal claim, which is the
//!   ambiguous case: the browser may or may not have sent.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use zecp2p_taker::auto::rail::FiatLeg;
use zecp2p_v2coordinator::state::{FiatRail, PaidFiat};

/// How the modelled rail should behave.
#[derive(Debug, Clone)]
pub struct RailProfile {
    /// How long a payment takes. The real browser drive is 60-120 s; a load run
    /// usually wants this small, but not zero - a zero-latency rail never
    /// contends for the payment slot, which is the thing under test.
    pub pay_latency_ms: u64,
    /// How long the preflight takes.
    pub preflight_latency_ms: u64,
    /// One payment in this many errors inside `pay`, after the journal claim.
    /// Zero disables it.
    ///
    /// Tested before [`Self::false_paid_in`], so on a call that is a multiple
    /// of both this one wins and the false paid does not fire. Two ratios that
    /// share a factor therefore inject fewer false paids than the ratio alone
    /// suggests; pick coprime ones, or set one at a time.
    pub pay_failure_in: u32,
    /// One payment in this many gets past `pay` and fails to attest, the way a
    /// missing prover configuration does. Zero disables it.
    pub attest_failure_in: u32,
    /// One payment in this many reports success without sending, the way the
    /// confirmation-challenge incident did. Zero disables it.
    ///
    /// The coordinator cannot tell; the run's ledger can, because
    /// [`ModelRail::truly_sent`] counts only the ones that really left.
    pub false_paid_in: u32,
}

impl Default for RailProfile {
    fn default() -> Self {
        Self {
            // Enough to make the slot a real constraint without making a run
            // take an afternoon.
            pay_latency_ms: 50,
            preflight_latency_ms: 5,
            pay_failure_in: 0,
            attest_failure_in: 0,
            false_paid_in: 0,
        }
    }
}

/// What the rail did, as against what it told the coordinator.
#[derive(Debug, Default)]
pub struct RailCounters {
    /// Calls into `pay` that returned `fiat_left: true`.
    pub reported_sent: AtomicUsize,
    /// Calls into `pay` where dollars really left the model's account.
    ///
    /// Below `reported_sent` exactly when a false paid was injected. A run in
    /// which these differ without `false_paid_in` set is a bug in the
    /// coordinator, not in the harness.
    pub truly_sent: AtomicUsize,
    pub pay_errors: AtomicUsize,
    pub attest_errors: AtomicUsize,
    pub attests: AtomicUsize,
    /// The most payments ever in flight at one moment.
    ///
    /// The invariant the coordinator's slot exists to hold: this must never
    /// exceed one, however many orders a run drives at once.
    pub max_overlap: AtomicUsize,
    in_flight: AtomicUsize,
}

impl RailCounters {
    pub fn reported_sent(&self) -> usize {
        self.reported_sent.load(Ordering::SeqCst)
    }
    pub fn truly_sent(&self) -> usize {
        self.truly_sent.load(Ordering::SeqCst)
    }
    pub fn pay_errors(&self) -> usize {
        self.pay_errors.load(Ordering::SeqCst)
    }
    pub fn attest_errors(&self) -> usize {
        self.attest_errors.load(Ordering::SeqCst)
    }
    pub fn attests(&self) -> usize {
        self.attests.load(Ordering::SeqCst)
    }
    pub fn max_overlap(&self) -> usize {
        self.max_overlap.load(Ordering::SeqCst)
    }
}

/// A fiat rail that models Venmo: it takes time, it sometimes fails, and it
/// keeps its own honest ledger of what really left.
pub struct ModelRail {
    profile: RailProfile,
    counters: Arc<RailCounters>,
    /// Every call into `pay`, so the injection ratios are deterministic in
    /// sequence rather than random. A soak run that fails one time in seven
    /// should fail on the seventh, not on a coin flip: a reproduction needs the
    /// same failures in the same places.
    calls: AtomicUsize,
}

impl ModelRail {
    pub fn new(profile: RailProfile) -> Self {
        Self {
            profile,
            counters: Arc::new(RailCounters::default()),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn counters(&self) -> Arc<RailCounters> {
        self.counters.clone()
    }
}

/// The note the real rail types: the configured note, then the leg's tag.
///
/// Kept identical to `VenmoRail`'s, because the coordinator records this string
/// and the feed search later looks for the tag inside it. A harness that typed
/// something else would drive every order down the "paid with a note nobody
/// recorded" path instead of the ordinary one.
pub fn note_a_rail_would_type(leg: &FiatLeg) -> String {
    match &leg.tag {
        Some(tag) => format!("thanks {tag}"),
        None => "thanks".to_string(),
    }
}

/// Whether this call is the one that should be failed, given a ratio.
///
/// `n` counts from one. A ratio of zero never fires.
fn every(n: usize, ratio: u32) -> bool {
    ratio > 0 && n.is_multiple_of(ratio as usize)
}

#[async_trait::async_trait]
impl FiatRail for ModelRail {
    async fn preflight(&self) -> Result<()> {
        if self.profile.preflight_latency_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                self.profile.preflight_latency_ms,
            ))
            .await;
        }
        Ok(())
    }

    async fn pay(&self, leg: &FiatLeg) -> Result<PaidFiat> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;

        // Before the in-flight window opens, not inside it. A `?` between the
        // increment and the decrement would leave `in_flight` raised for the
        // rest of the run and every later payment would read as an overlap,
        // failing the one invariant the slot exists to hold. Unreachable in
        // practice - the cents come from a `u128` of a real amount - which is
        // exactly why it would be missed.
        let cents = u64::try_from(leg.payment.cents()).map_err(|_| {
            anyhow::anyhow!(
                "a payment of {} cents does not fit a u64",
                leg.payment.cents()
            )
        })?;

        // The overlap measurement brackets the whole drive, so it sees the
        // window the slot has to close rather than an instant.
        let now = self.counters.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.counters.max_overlap.fetch_max(now, Ordering::SeqCst);

        if self.profile.pay_latency_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.profile.pay_latency_ms)).await;
        }

        let result = if every(n, self.profile.pay_failure_in) {
            self.counters.pay_errors.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!(
                "the browser died halfway through the payment"
            ))
        } else if every(n, self.profile.false_paid_in) {
            // The 2026-09-05 shape: the rail is certain the money went and it
            // did not. `truly_sent` is deliberately not incremented.
            self.counters.reported_sent.fetch_add(1, Ordering::SeqCst);
            tracing::warn!(
                recipient = %leg.recipient,
                "INJECTED false paid: reporting fiat_left with nothing sent"
            );
            Ok(PaidFiat {
                cents,
                fiat_left: true,
                note: Some(note_a_rail_would_type(leg)),
            })
        } else {
            self.counters.reported_sent.fetch_add(1, Ordering::SeqCst);
            self.counters.truly_sent.fetch_add(1, Ordering::SeqCst);
            Ok(PaidFiat {
                cents,
                fiat_left: true,
                note: Some(note_a_rail_would_type(leg)),
            })
        };

        self.counters.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }

    async fn attest(&self, leg: &FiatLeg) -> Result<zecp2p_escrow::lp_client::WireAttestation> {
        let n = self.counters.attests.fetch_add(1, Ordering::SeqCst) + 1;
        if every(n, self.profile.attest_failure_in) {
            self.counters.attest_errors.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("no prover configured for this deployment");
        }
        // The shape a real enclave export has. The harness attestor checks the
        // terms rather than the signature, which is the one part of the system
        // this rail does not exercise.
        Ok(zecp2p_escrow::lp_client::WireAttestation {
            intent_hash: hex::encode(leg.intent_hash.0),
            release_amount: leg.intent_amount_6dec.to_string(),
            data_hash: hex::encode([0u8; 32]),
            signature: hex::encode([0u8; 65]),
            encoded_payment_details: hex::encode(vec![0u8; 448]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ratio_of_zero_never_fires() {
        for n in 1..100 {
            assert!(!every(n, 0));
        }
    }

    #[test]
    fn a_ratio_fires_on_the_nth_call_and_not_before() {
        assert!(!every(1, 3));
        assert!(!every(2, 3));
        assert!(every(3, 3));
        assert!(every(6, 3));
    }
}
