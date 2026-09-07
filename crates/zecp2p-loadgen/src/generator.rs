//! The traffic generator: many orders, concurrently or in sequence, for a
//! count or for a duration.
//!
//! # What the concurrency knob actually stresses
//!
//! Not the payment rate. The coordinator holds **one global payment slot** on
//! purpose: two payments in flight mean two feed entries of the same amount to
//! the same handle, and the feed search refuses to guess between them - after
//! both payments have left. So raising concurrency does not raise the number of
//! payments in flight, and a run that reported it did would be reporting a bug.
//!
//! What concurrency stresses is everything around that slot: the order store's
//! locks, the funding scan, the announcement path, the queue of orders waiting
//! for the slot, and the refusals themselves. `max_overlap` in the rail's
//! counters is the invariant, and it must read 1 at the end of every run.
//!
//! # Why amounts and handles vary
//!
//! Two open orders for the same handle at the same cents are refused by
//! `put_unless_in_flight`, for the same feed-ambiguity reason. A generator that
//! sent identical orders would measure that refusal and nothing else. So each
//! iteration draws its own amount from a spread, and the handle pool rotates.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::scenario::{self, Env, Outcome, Path};

/// How much traffic to make, and of what shape.
#[derive(Debug, Clone)]
pub struct Plan {
    /// How many orders to run in total. Ignored when `duration` is set.
    pub count: usize,
    /// Run for this long instead of for a count.
    pub duration: Option<Duration>,
    /// How many orders may be in flight at once.
    pub concurrency: usize,
    /// The mix of paths, as weights. An empty mix is all releases.
    pub mix: Vec<(Path, u32)>,
    /// The smallest and largest escrow to open, in ZEC.
    pub amount_min_zec: f64,
    pub amount_max_zec: f64,
    /// The handles orders are opened against. Must all be served by the
    /// coordinator's configuration.
    pub handles: Vec<String>,
    /// How long one order may spend waiting for the slot before the iteration
    /// gives up on it.
    pub sweep_timeout: Duration,
    /// Pause between starting iterations, which shapes arrival rate.
    pub arrival_gap: Duration,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            count: 10,
            duration: None,
            concurrency: 1,
            mix: vec![(Path::Release, 1)],
            // Above the escrow crate's own minimum, and small enough that a
            // long run does not need a large fake balance.
            amount_min_zec: 0.05,
            amount_max_zec: 0.25,
            handles: vec!["alice".into()],
            sweep_timeout: Duration::from_secs(30),
            arrival_gap: Duration::ZERO,
        }
    }
}

impl Plan {
    /// Picks a path from the mix.
    fn path_for(&self, n: usize) -> Path {
        if self.mix.is_empty() {
            return Path::Release;
        }
        let total: u32 = self.mix.iter().map(|(_, w)| *w).sum();
        if total == 0 {
            return Path::Release;
        }
        // Deterministic in sequence rather than random, so a failing run
        // reproduces with the same paths in the same order.
        let mut pick = (n as u32) % total;
        for (path, weight) in &self.mix {
            if pick < *weight {
                return *path;
            }
            pick -= *weight;
        }
        Path::Release
    }

    /// An amount for iteration `n`, spread across the configured range.
    ///
    /// Rounded to a ten-thousandth of a ZEC so two iterations that land on the
    /// same value are rare but the number stays one a person can read in a log.
    ///
    /// The period used to be a flat 1,000, which the four-handle rotation
    /// divides: iteration n+1,000 asked for the same handle and the same
    /// amount as iteration n, and `put_unless_in_flight` refuses the second
    /// while the first is still open. Orders stay open for the refund window
    /// on the `never_fund` path and indefinitely on a `NeedsOperator` line, so
    /// a long soak reported refusals that were the harness's own. The period is
    /// now every value the range can express, forced odd so the handle count
    /// cannot divide it.
    ///
    /// That raises the ceiling; it does not remove it. Two orders collide on
    /// the *cents* the coordinator quotes, not on the ZEC, and a span of `s`
    /// ZEC at rate `r` can only express `s * r * 100` distinct cents - 805 for
    /// the default 0.05-0.25 range at $40.25. A soak that intends to hold more
    /// open orders than the handles times that should widen `--amount-min` and
    /// `--amount-max` or name more `--handles`.
    fn amount_for(&self, n: usize) -> f64 {
        if self.amount_max_zec <= self.amount_min_zec {
            return self.amount_min_zec;
        }
        let span = self.amount_max_zec - self.amount_min_zec;
        // Counted in whole ten-thousandths of a ZEC rather than as a fraction
        // of the span, so every step is a distinct amount. Spacing them any
        // finer than the rounding does not make more amounts, it makes two
        // steps round to one - which is how a period longer than the range can
        // express still repeats.
        //
        // Forced odd, because a period the handle count divides repeats the
        // whole (handle, amount) pair on its own cycle rather than on the
        // product of the two.
        let units = ((span * 10_000.0).round().max(1.0) as usize) | 1;
        // A prime stride, so it is coprime with the period and every amount is
        // visited before any repeats, and large enough that consecutive
        // iterations land far apart in the range rather than adjacent.
        let stride = if units.is_multiple_of(7919) { 7907 } else { 7919 };
        let base = (self.amount_min_zec * 10_000.0).round();
        let raw = (base + (n.wrapping_mul(stride) % units) as f64) / 10_000.0;
        (raw * 10_000.0).round() / 10_000.0
    }

    fn handle_for(&self, n: usize) -> String {
        if self.handles.is_empty() {
            return "alice".into();
        }
        self.handles[n % self.handles.len()].clone()
    }
}

/// What a whole run did.
#[derive(Debug, Default)]
pub struct Stats {
    pub outcomes: Vec<Outcome>,
    pub wall: Duration,
}

impl Stats {
    pub fn total(&self) -> usize {
        self.outcomes.len()
    }

    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.ok).count()
    }

    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| !o.ok).count()
    }

    /// Completed orders per second across the whole run.
    pub fn throughput(&self) -> f64 {
        let secs = self.wall.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.total() as f64 / secs
    }

    pub fn released(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.final_stage.as_deref() == Some("released"))
            .count()
    }

    pub fn refunded(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.final_stage.as_deref() == Some("refunded"))
            .count()
    }

    /// How many orders got as far as being given an escrow address.
    ///
    /// The denominator for [`Self::distinct_addresses`]. An order refused at
    /// the quote - which is what every order does while the node is down - has
    /// no address and never had one, so counting it as a missing address says
    /// the coordinator reused one when it did nothing of the kind.
    pub fn orders_with_an_address(&self) -> usize {
        self.outcomes.iter().filter(|o| o.address.is_some()).count()
    }

    /// The escrow addresses a run used, deduplicated.
    ///
    /// Distinct addresses are not a nice-to-have: two orders sharing one would
    /// have the funding scan find the wrong escrow's output. The count coming
    /// back below the order count is a failure of key derivation.
    pub fn distinct_addresses(&self) -> usize {
        let mut seen: Vec<&str> = self
            .outcomes
            .iter()
            .filter_map(|o| o.address.as_deref())
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len()
    }

    /// Latency percentile over the successful iterations, in milliseconds.
    pub fn percentile_ms(&self, p: f64) -> u128 {
        let mut times: Vec<u128> = self
            .outcomes
            .iter()
            .filter(|o| o.ok)
            .map(|o| o.timings.total.as_millis())
            .collect();
        if times.is_empty() {
            return 0;
        }
        times.sort_unstable();
        let idx = (((times.len() - 1) as f64) * p).round() as usize;
        times[idx]
    }

    /// The distinct errors a run produced, most frequent first.
    pub fn error_histogram(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for outcome in self.outcomes.iter().filter(|o| !o.ok) {
            let key = outcome
                .error
                .as_deref()
                .unwrap_or("unknown")
                // The order id and the amounts make every message unique, and a
                // histogram of unique strings is a list. The first clause is
                // what names the failure.
                .split(':')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            *counts.entry(key).or_default() += 1;
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

/// Runs the plan.
pub async fn run(env: Arc<Env>, plan: Plan) -> Result<Stats> {
    let started = Instant::now();
    let issued = Arc::new(AtomicUsize::new(0));
    let deadline = plan.duration.map(|d| started + d);

    let outcomes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let permits = Arc::new(tokio::sync::Semaphore::new(plan.concurrency.max(1)));
    let plan = Arc::new(plan);
    let mut tasks = Vec::new();

    // A soak run that says nothing for half an hour is indistinguishable from a
    // hung one. This reports what has finished, once a minute, and stops when
    // the run does.
    let ticker = {
        let outcomes = outcomes.clone();
        let issued = issued.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(60));
            every.tick().await;
            loop {
                every.tick().await;
                let done = outcomes.lock().await;
                let finished = done.len();
                let failed = done.iter().filter(|o: &&Outcome| !o.ok).count();
                drop(done);
                let elapsed = started.elapsed().as_secs_f64();
                tracing::info!(
                    finished,
                    failed,
                    started = issued.load(Ordering::SeqCst),
                    per_sec = format!("{:.2}", finished as f64 / elapsed.max(1.0)),
                    elapsed_s = elapsed as u64,
                    "progress"
                );
            }
        })
    };

    loop {
        match deadline {
            Some(end) => {
                if Instant::now() >= end {
                    break;
                }
            }
            None => {
                if issued.load(Ordering::SeqCst) >= plan.count {
                    break;
                }
            }
        }

        // Waiting for a permit is waiting for an iteration to finish, and an
        // iteration may take the whole sweep timeout - so in duration mode the
        // clock has to be part of the wait. Checking it only above meant a run
        // parked behind a stuck payment slot sat here past its deadline, then
        // spent the permit that freed on one more iteration begun entirely
        // outside the run's window, which itself ran up to the sweep timeout:
        // a `--duration 60 --sweep-timeout 600` run kept going for twenty
        // minutes, and `orders/sec` was divided by the inflated wall.
        let permit = match deadline {
            Some(end) => {
                tokio::select! {
                    biased;
                    permit = permits.clone().acquire_owned() => {
                        permit.expect("the semaphore is not closed")
                    }
                    // The deadline passed while every permit was held. The
                    // iterations already in flight still get their full sweep
                    // timeout to finish below; what stops here is starting
                    // new ones.
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => break,
                }
            }
            None => permits
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is not closed"),
        };

        // The sequence number is drawn once the iteration is certain to start,
        // and only this loop draws one, so the numbers stay unique and no two
        // iterations collide on the store's in-flight rule. Drawing it above
        // the wait instead made the progress line count an iteration that had
        // not started - by one, for as long as the loop was parked here, which
        // is exactly when someone is reading that line.
        let n = issued.fetch_add(1, Ordering::SeqCst);

        let env = env.clone();
        let task_plan = plan.clone();
        let outcomes = outcomes.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let path = task_plan.path_for(n);
            let amount = task_plan.amount_for(n);
            let handle = task_plan.handle_for(n);

            tracing::info!(
                iteration = n,
                path = path.as_str(),
                amount_zec = amount,
                handle = %handle,
                "starting"
            );

            let outcome =
                scenario::run_one(&env, path, amount, &handle, task_plan.sweep_timeout).await;

            match (&outcome.ok, &outcome.error) {
                (true, _) => tracing::info!(
                    iteration = n,
                    path = path.as_str(),
                    order = outcome.order_id.as_deref().unwrap_or("-"),
                    stage = outcome.final_stage.as_deref().unwrap_or("-"),
                    ms = outcome.timings.total.as_millis(),
                    "done"
                ),
                (false, err) => tracing::warn!(
                    iteration = n,
                    path = path.as_str(),
                    order = outcome.order_id.as_deref().unwrap_or("-"),
                    stage = outcome.final_stage.as_deref().unwrap_or("-"),
                    error = err.as_deref().unwrap_or("unknown"),
                    "failed"
                ),
            }

            outcomes.lock().await.push(outcome);
        }));

        if !plan.arrival_gap.is_zero() {
            tokio::time::sleep(plan.arrival_gap).await;
        }
    }

    // `abort` only *schedules* the cancellation. The ticker's future - and with
    // it the clone of `outcomes` it holds - is not dropped until the runtime
    // polls the task again, and when the last iteration has already finished
    // nothing below yields long enough for that to happen. Awaiting the handle
    // is what makes the ordering certain: it resolves only once the task has
    // been dropped. Without it a soak whose arrival gap is longer than one
    // iteration threw away every result it had, every time.
    ticker.abort();
    let _ = ticker.await;

    for task in tasks {
        // A panicking iteration should not take the run's report with it.
        if let Err(e) = task.await {
            tracing::error!(error = %e, "an iteration panicked");
        }
    }

    // Taken out of the mutex rather than unwrapped out of the `Arc`. Every
    // iteration has been awaited and the ticker has been joined, so nothing
    // else holds a reference - but an hour of soak results is not a thing to
    // discard because some future edit kept one alive.
    let outcomes = std::mem::take(&mut *outcomes.lock().await);

    Ok(Stats {
        outcomes,
        wall: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_mix_is_all_releases() {
        let plan = Plan {
            mix: vec![],
            ..Plan::default()
        };
        assert_eq!(plan.path_for(0), Path::Release);
        assert_eq!(plan.path_for(7), Path::Release);
    }

    #[test]
    fn a_mix_hands_out_every_path_it_names() {
        let plan = Plan {
            mix: vec![(Path::Release, 2), (Path::Refund, 1), (Path::NeverFund, 1)],
            ..Plan::default()
        };
        let paths: Vec<Path> = (0..8).map(|n| plan.path_for(n)).collect();
        assert!(paths.contains(&Path::Release));
        assert!(paths.contains(&Path::Refund));
        assert!(paths.contains(&Path::NeverFund));
        // The weights are respected: two in four are releases.
        assert_eq!(paths.iter().filter(|p| **p == Path::Release).count(), 4);
    }

    /// Two open orders for one handle at one amount are refused by the store,
    /// so consecutive iterations must not ask for the same thing.
    #[test]
    fn consecutive_iterations_ask_for_different_amounts() {
        let plan = Plan {
            amount_min_zec: 0.05,
            amount_max_zec: 0.25,
            ..Plan::default()
        };
        let amounts: Vec<f64> = (0..20).map(|n| plan.amount_for(n)).collect();
        for pair in amounts.windows(2) {
            assert_ne!(
                pair[0], pair[1],
                "consecutive orders would collide on the in-flight rule"
            );
        }
        for a in &amounts {
            assert!(*a >= 0.05 && *a <= 0.25, "{a} is outside the range");
        }
    }

    #[test]
    fn a_degenerate_range_is_the_minimum() {
        let plan = Plan {
            amount_min_zec: 0.1,
            amount_max_zec: 0.1,
            ..Plan::default()
        };
        assert_eq!(plan.amount_for(3), 0.1);
    }

    /// The period is the range's own, not a flat thousand.
    ///
    /// A soak past the period asks a handle for an amount it may still have an
    /// order open at, and `put_unless_in_flight` refuses it. That refusal is
    /// the harness's, not the coordinator's, and it lands in the report as if
    /// it were a finding.
    #[test]
    fn the_amount_and_handle_pair_outlasts_a_long_soak() {
        let plan = Plan {
            amount_min_zec: 0.05,
            amount_max_zec: 0.25,
            handles: vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()],
            ..Plan::default()
        };

        // The old sequence repeated here, exactly.
        assert_ne!(
            (plan.handle_for(0), plan.amount_for(0)),
            (plan.handle_for(1000), plan.amount_for(1000)),
            "iteration 1,000 asks for what iteration 0 asked for"
        );

        // Nothing repeats across a run four times that long.
        let mut seen = std::collections::HashSet::new();
        for n in 0..4000 {
            let key = (plan.handle_for(n), plan.amount_for(n).to_bits());
            assert!(
                seen.insert(key),
                "iteration {n} repeats a (handle, amount) pair from earlier in the run"
            );
        }
    }

    #[test]
    fn the_handle_pool_rotates() {
        let plan = Plan {
            handles: vec!["alice".into(), "bob".into()],
            ..Plan::default()
        };
        assert_eq!(plan.handle_for(0), "alice");
        assert_eq!(plan.handle_for(1), "bob");
        assert_eq!(plan.handle_for(2), "alice");
    }
}
