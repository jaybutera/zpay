//! The harness's own tests.
//!
//! A load harness that is quietly broken reports a healthy system, which is
//! worse than no harness. These hold it to the four things it claims: that one
//! order completes, that every order gets its own escrow, that the payment slot
//! holds under concurrency, and that the injected failures are visible in the
//! numbers rather than swallowed.

use std::sync::Arc;
use std::time::Duration;

use zecp2p_loadgen::generator::{self, Plan};
use zecp2p_loadgen::rail::RailProfile;
use zecp2p_loadgen::scenario::Path;
use zecp2p_loadgen::{Harness, HarnessOptions};

/// A harness with a rail fast enough for a test.
async fn harness(rail: RailProfile) -> Harness {
    Harness::build(HarnessOptions {
        rail,
        ..HarnessOptions::default()
    })
    .await
    .expect("the harness builds")
}

fn plan(count: usize, concurrency: usize, mix: Vec<(Path, u32)>) -> Plan {
    Plan {
        count,
        concurrency,
        mix,
        sweep_timeout: Duration::from_secs(120),
        handles: vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()],
        ..Plan::default()
    }
}

/// The loop the whole harness exists to run: quote, order, fund, depth,
/// announce, pre-sign, pay, attest, release.
#[tokio::test]
async fn one_order_runs_from_a_quote_to_a_release() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(1, 1, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    assert_eq!(stats.total(), 1);
    assert_eq!(
        stats.succeeded(),
        1,
        "the happy path failed: {:?}",
        stats.outcomes[0].error
    );
    assert_eq!(stats.released(), 1);
    assert!(
        stats.outcomes[0].release_txid.is_some(),
        "a released order must carry the txid of the transaction that was broadcast"
    );
    // The release really went to the node, rather than only being recorded.
    assert_eq!(h.node.broadcast_count().await, 1);
}

/// Every path the generator can pick reaches its own end.
#[tokio::test]
async fn every_path_reaches_the_end_it_defines() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(
        h.env.clone(),
        plan(
            8,
            1,
            vec![
                (Path::Release, 1),
                (Path::Refund, 1),
                (Path::NeverSign, 1),
                (Path::NeverFund, 1),
            ],
        ),
    )
    .await
    .expect("the run completes");

    let failures: Vec<&str> = stats
        .outcomes
        .iter()
        .filter(|o| !o.ok)
        .filter_map(|o| o.error.as_deref())
        .collect();
    assert!(
        failures.is_empty(),
        "every path should reach its own end: {failures:?}"
    );
    assert_eq!(stats.released(), 2);
    assert_eq!(stats.refunded(), 2);
}

/// The address question, settled by running.
///
/// Escrow addresses derive from the user's key, so a fresh keypair per order is
/// the whole of it: no pool, no pre-generation, no bookkeeping. Two orders
/// sharing an address would have the funding scan find one escrow's output
/// while looking for the other's.
#[tokio::test]
async fn every_order_derives_its_own_escrow_address() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(12, 4, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    assert_eq!(
        stats.distinct_addresses(),
        stats.total(),
        "two orders shared an escrow address, so the funding scan can find the wrong output"
    );
}

/// The invariant the coordinator's slot exists to hold.
///
/// Two payments in flight mean two feed entries of the same amount to the same
/// handle, which `locate_payment` refuses to resolve - after both have left. No
/// amount of concurrency here may produce a second one.
#[tokio::test]
async fn concurrency_never_puts_two_payments_in_flight() {
    // Slow enough that any overlap is certain to be observed rather than
    // depending on the scheduler interleaving two instant calls.
    let h = harness(RailProfile {
        pay_latency_ms: 40,
        preflight_latency_ms: 5,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(12, 6, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    assert_eq!(
        h.rail_counters.max_overlap(),
        1,
        "two payments were in flight at once, which is the double-pay the slot prevents"
    );
    assert!(
        stats.succeeded() > 0,
        "the run proved nothing if no order completed"
    );
}

/// A rail that lies must show up in the ledger, because the coordinator cannot
/// see it.
///
/// This is the 2026-09-05 incident in miniature: the rail reports a send that
/// never happened, the coordinator believes it, and the escrow releases. The
/// harness's job is to make the gap countable.
#[tokio::test]
async fn a_lying_rail_releases_escrows_the_ledger_can_count() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        // Every other payment is a lie.
        false_paid_in: 2,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(6, 1, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    let released = stats.released();
    let truly = h.rail_counters.truly_sent();
    assert!(released > 0, "nothing released, so nothing is being measured");
    assert!(
        released > truly,
        "a rail that lied about half its payments should have released more escrows \
         ({released}) than it really paid for ({truly}); if these agree the injection \
         is not reaching the coordinator"
    );
    // Every payment was reported, and the lies are exactly the difference.
    assert_eq!(
        h.rail_counters.reported_sent(),
        stats.released(),
        "a released escrow is one the rail reported paying for"
    );
}

/// An attestation that fails must not strand the escrow.
///
/// The prover-config gap: `pay` succeeds, `attest` does not, and the dollars are
/// already gone. The coordinator retries on the next sweep, which is what keeps
/// the LP from having bought an escrow it cannot release.
#[tokio::test]
async fn an_attestation_failure_is_retried_rather_than_stranding_the_escrow() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        attest_failure_in: 2,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(4, 1, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    assert!(
        h.rail_counters.attest_errors() > 0,
        "the injection never fired, so this proves nothing"
    );
    assert_eq!(
        stats.released(),
        stats.total(),
        "an escrow whose attestation failed once was never released, leaving the LP \
         having paid for a coin it cannot claim"
    );
    // The retry is what did it: more attest calls than orders.
    assert!(
        h.rail_counters.attests() > stats.total(),
        "the releases did not come from a retry"
    );
}

/// The harness cannot be pointed at anything real.
#[tokio::test]
async fn the_harness_is_testnet_and_loopback_only() {
    let h = harness(RailProfile::default()).await;
    assert!(
        h.node.url.starts_with("http://127.0.0.1:"),
        "the node must be loopback, and it is {}",
        h.node.url
    );
    assert!(
        h.attestor.url.starts_with("http://127.0.0.1:"),
        "the attestor must be loopback, and it is {}",
        h.attestor.url
    );
    assert_eq!(
        h.env.state.network_name(),
        "test",
        "the harness must never run against any network but test"
    );
}

/// A run's own bookkeeping.
#[tokio::test]
async fn the_report_counts_what_the_run_actually_did() {
    let h = harness(RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        ..RailProfile::default()
    })
    .await;

    let stats = generator::run(h.env.clone(), plan(5, 2, vec![(Path::Release, 1)]))
        .await
        .expect("the run completes");

    assert_eq!(stats.total(), 5);
    assert_eq!(stats.succeeded() + stats.failed(), stats.total());
    assert!(stats.throughput() > 0.0);
    assert!(
        stats.percentile_ms(0.5) > 0,
        "a completed order takes measurable time"
    );
    // The node saw the run.
    assert!(Arc::strong_count(&h.env) >= 1);
    assert!(h.node.counters().total() > 0);
}
