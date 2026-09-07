//! The fault knobs, exercised.
//!
//! The README's findings about a node outage, an ambiguous pay failure and a
//! release that cannot be broadcast came from runs a person did by hand. Those
//! are exactly the runs a harness exists to make repeatable: each one is a
//! shape the coordinator's safety argument depends on, and none of them happens
//! on the happy path. What these hold is the *shape* - what did and did not
//! move, and which invariants survived - rather than exact counts, which depend
//! on scheduling.

use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use zecp2p_escrow::chain::ChainClient;

use zecp2p_loadgen::generator::{self, Plan};
use zecp2p_loadgen::rail::RailProfile;
use zecp2p_loadgen::scenario::Path;
use zecp2p_loadgen::stack::{FakeNode, BRANCH_ID};
use zecp2p_loadgen::{Harness, HarnessOptions};

async fn harness(rail: RailProfile) -> Harness {
    Harness::build(HarnessOptions {
        rail,
        ..HarnessOptions::default()
    })
    .await
    .expect("the harness builds")
}

/// A rail fast enough that a test is not mostly sleep.
fn quick() -> RailProfile {
    RailProfile {
        pay_latency_ms: 1,
        preflight_latency_ms: 0,
        ..RailProfile::default()
    }
}

fn plan(count: usize, concurrency: usize, mix: Vec<(Path, u32)>, sweep: Duration) -> Plan {
    Plan {
        count,
        concurrency,
        mix,
        sweep_timeout: sweep,
        handles: vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()],
        ..Plan::default()
    }
}

/// The escrow crate's own RPC client, pointed at the fake node.
///
/// The client the coordinator uses, so what a fault does to it here is what it
/// does in a run. It is blocking, hence `spawn_blocking`.
async fn on_the_node<T, F>(node: &FakeNode, f: F) -> T
where
    F: FnOnce(&dyn ChainClient) -> T + Send + 'static,
    T: Send + 'static,
{
    let url = node.url.clone();
    tokio::task::spawn_blocking(move || {
        let client = zecp2p_escrow::rpc::RpcChainClient::new(zecp2p_escrow::rpc::RpcConfig::public(
            url,
            zecp2p_escrow::rpc::Network::Test,
        ))
        .expect("the client builds");
        f(&client)
    })
    .await
    .expect("the blocking call finishes")
}

/// A provider that rate-limits, which this project has hit twice for real.
///
/// The README's soak said nothing unsafe happened: orders that could not be
/// quoted were refused before any key was drawn, so no escrow existed to
/// strand, and both money invariants held. This is that, made repeatable: the
/// outage is switched on for one batch of orders and off for the next.
#[tokio::test]
async fn a_node_outage_refuses_orders_before_an_escrow_exists() {
    let h = harness(quick()).await;

    h.node.faults().fail_rpc.store(true, Relaxed);
    let down = generator::run(
        h.env.clone(),
        plan(3, 1, vec![(Path::Release, 1)], Duration::from_secs(5)),
    )
    .await
    .expect("the run completes even though every order in it fails");

    assert!(
        h.node.counters().failed.load(Relaxed) > 0,
        "the outage never reached the node, so this proves nothing"
    );
    assert_eq!(down.succeeded(), 0, "an order cannot complete with no chain");
    assert_eq!(
        down.orders_with_an_address(),
        0,
        "an order refused at the quote never had an escrow address, and counting \
         it as one would report a reuse that did not happen"
    );
    assert_eq!(down.released(), 0);
    assert_eq!(
        h.node.broadcast_count().await,
        0,
        "nothing may be settled on an answer nobody got"
    );
    assert_eq!(h.rail_counters.truly_sent(), 0, "no dollars left either");

    // And the provider comes back.
    h.node.faults().fail_rpc.store(false, Relaxed);
    let up = generator::run(
        h.env.clone(),
        plan(3, 1, vec![(Path::Release, 1)], Duration::from_secs(60)),
    )
    .await
    .expect("the run completes");

    assert_eq!(
        up.released(),
        3,
        "the coordinator did not recover from the outage: {:?}",
        up.outcomes.iter().filter_map(|o| o.error.as_deref()).collect::<Vec<_>>()
    );
    // The money invariants, across both batches.
    assert!(up.released() <= h.rail_counters.truly_sent());
    assert_eq!(h.node.broadcast_count().await, up.released() + up.refunded());
}

/// A node that answers, slowly. Every call pays the delay, and the run must
/// still finish and still be correct.
#[tokio::test]
async fn a_stalling_node_slows_a_run_without_breaking_it() {
    let h = harness(quick()).await;
    h.node.faults().stall_ms.store(40, Relaxed);

    let stats = generator::run(
        h.env.clone(),
        plan(2, 1, vec![(Path::Release, 1)], Duration::from_secs(120)),
    )
    .await
    .expect("the run completes");

    assert_eq!(
        stats.released(),
        2,
        "a slow node is not a broken one: {:?}",
        stats.outcomes.iter().filter_map(|o| o.error.as_deref()).collect::<Vec<_>>()
    );
    assert!(
        stats.percentile_ms(0.5) >= 40,
        "the stall never reached the client, so this proves nothing: p50 was {}ms",
        stats.percentile_ms(0.5)
    );
    assert_eq!(h.node.broadcast_count().await, 2);
}

/// The one the README calls the worst case: the dollars go and the release
/// cannot be relayed.
///
/// Reads keep working, so the coordinator gets all the way to a valid release
/// and then has nowhere to put it. Nothing may be recorded as released, and the
/// chain must show no spend.
#[tokio::test]
async fn a_release_that_cannot_be_broadcast_is_not_recorded_as_released() {
    let h = harness(quick()).await;
    h.node.faults().reject_broadcast.store(true, Relaxed);

    let stats = generator::run(
        h.env.clone(),
        plan(1, 1, vec![(Path::Release, 1)], Duration::from_secs(10)),
    )
    .await
    .expect("the run completes");

    assert_eq!(stats.released(), 0, "the node refused every broadcast");
    assert_eq!(
        h.node.broadcast_count().await,
        0,
        "a refused broadcast is not a spend"
    );
    assert!(
        h.node.counters().failed.load(Relaxed) > 0,
        "the refusal never fired, so this proves nothing"
    );
    // The dollars did leave. That is the whole reason this state needs a human:
    // the LP has paid for a coin whose release nobody has relayed.
    assert_eq!(h.rail_counters.truly_sent(), 1);
    assert!(
        stats.released() <= h.rail_counters.truly_sent(),
        "no escrow was released without dollars behind it"
    );
}

/// One ambiguous pay failure stops all trading, and the harness can show it.
///
/// On a `pay` error after the journal claim the line is written `NeedsOperator`
/// - the money may or may not have gone - and `slot.rs` counts that as holding
/// the global payment slot. Nothing else pays until a human clears it. Correct,
/// and expensive: this is the finding the README records, and it is the one a
/// regression would most easily undo by quietly releasing the slot.
#[tokio::test]
async fn an_ambiguous_pay_failure_holds_the_slot_against_every_later_order() {
    let h = harness(RailProfile {
        // The second payment of the run dies after the journal claim.
        pay_failure_in: 2,
        ..quick()
    })
    .await;

    let stats = generator::run(
        h.env.clone(),
        // A short lease: the orders behind the stuck one will never move, and
        // the point of the test is that they do not.
        plan(5, 1, vec![(Path::Release, 1)], Duration::from_secs(2)),
    )
    .await
    .expect("the run completes");

    assert_eq!(
        h.rail_counters.pay_errors(),
        1,
        "exactly one payment should have failed; the rest never got the slot"
    );
    assert_eq!(
        stats.released(),
        1,
        "the order before the failure should have released, and nothing after it"
    );
    assert_eq!(
        h.rail_counters.reported_sent(),
        1,
        "a slot that was released would have let a later order pay"
    );
    assert_eq!(
        h.node.broadcast_count().await,
        1,
        "one release reached the chain, and the stuck slot stopped the rest"
    );
    // The later orders did not fail silently: each one says what it was doing.
    assert_eq!(stats.failed(), 4);
}

/// The chain-tip lease, under concurrency.
///
/// The `refund` and `never_sign` paths reach `T` by moving the one chain's tip,
/// which every other open order also sees. Without the lease a mixed run
/// reports failures against a coordinator that is behaving correctly, which is
/// what the first mixed run here did. The existing mixed test runs at
/// concurrency 1, where the lease cannot be wrong.
#[tokio::test]
async fn a_mixed_run_under_concurrency_does_not_trip_over_the_tip() {
    let h = harness(quick()).await;

    let stats = generator::run(
        h.env.clone(),
        plan(
            12,
            4,
            vec![
                (Path::Release, 1),
                (Path::Refund, 1),
                (Path::NeverSign, 1),
                (Path::NeverFund, 1),
            ],
            Duration::from_secs(120),
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
        "a time-travelling order was visible to one that assumed the present: {failures:?}"
    );
    assert_eq!(stats.released(), 3);
    assert_eq!(stats.refunded(), 3);
    // The tip is where it started: a refund path that left it in the future
    // would have every later order compute its refund height from there.
    assert_eq!(h.node.height().await, zecp2p_loadgen::stack::START_HEIGHT);
    assert_eq!(
        h.node.broadcast_count().await,
        stats.released() + stats.refunded()
    );
}

/// An enclave with no prover configured, at the outcome-scalar seam.
///
/// `--attest-failure-in` fails the rail's payment attestation. This is the
/// other one: the attestor will not sign the outcome, so the pre-signature
/// cannot be decrypted and there is no release to assemble at all.
#[tokio::test]
async fn an_attestor_that_will_not_sign_the_outcome_releases_nothing() {
    let h = harness(quick()).await;
    h.attestor.set_refuse_attest(true);

    let stats = generator::run(
        h.env.clone(),
        plan(1, 1, vec![(Path::Release, 1)], Duration::from_secs(5)),
    )
    .await
    .expect("the run completes");

    assert!(h.attestor.attests() > 0, "the attestor was never asked");
    assert_eq!(stats.released(), 0);
    assert_eq!(
        h.node.broadcast_count().await,
        0,
        "no outcome scalar means no release to broadcast"
    );
}

/// A network upgrade moves the sighash, and the branch id is read from the node
/// rather than pinned. Spec 4.3, in the one place a harness can move it.
#[tokio::test]
async fn an_order_commits_to_the_branch_id_the_node_reports() {
    let h = harness(quick()).await;
    const AFTER_UPGRADE: u32 = 0xc2d6_d0b4;
    h.node.set_branch_id(AFTER_UPGRADE).await;

    assert_eq!(
        on_the_node(&h.node, |c| c.consensus_branch_id()).await.unwrap(),
        AFTER_UPGRADE,
        "the node did not report the new branch"
    );

    let stats = generator::run(
        h.env.clone(),
        plan(1, 1, vec![(Path::Release, 1)], Duration::from_secs(60)),
    )
    .await
    .expect("the run completes");

    let order = h
        .env
        .state
        .store
        .get(stats.outcomes[0].order_id.as_deref().expect("an order id"))
        .expect("the order is in the store");
    assert_eq!(
        order.consensus_branch_id, AFTER_UPGRADE,
        "the order was built against the pinned branch instead of the node's"
    );
    assert_ne!(AFTER_UPGRADE, BRANCH_ID, "the test would prove nothing");
    // And the whole flow still works against it, which is the point of reading
    // it rather than pinning it.
    assert_eq!(
        stats.released(),
        1,
        "{:?}",
        stats.outcomes[0].error.as_deref()
    );
}

/// An output that goes away: a reorg, or a spend the coordinator did not make.
///
/// `gettxout` returns null for an output that does not exist or has been spent,
/// and the escrow's whole depth argument rests on that answer. A fake node that
/// could not take an output back could not model the case.
#[tokio::test]
async fn an_output_that_is_unwound_stops_being_reported() {
    let h = harness(quick()).await;

    let txid = [0x11u8; 32];
    h.node.add_utxo(txid, 0, vec![0x51], 500_000, 12).await;

    let found = on_the_node(&h.node, move |c| c.utxo(&txid, 0)).await.unwrap();
    let found = found.expect("the output the node was just told about");
    assert_eq!(found.amount_zat, 500_000);
    assert_eq!(found.confirmations, 12);

    h.node.remove_utxo(txid, 0).await;

    let gone = on_the_node(&h.node, move |c| c.utxo(&txid, 0)).await.unwrap();
    assert!(
        gone.is_none(),
        "an unwound output is still being reported, so no reorg can be modelled"
    );
}

/// A duration run ends when its duration ends, even with the slot stuck.
///
/// The run loop waits for a permit, and waiting for a permit means waiting for
/// an iteration - which, behind the ambiguous pay failure above, waits the
/// whole sweep timeout. The deadline used to be checked only before that wait,
/// so the loop sat there past its own end, then spent the permit that freed on
/// one more iteration begun entirely outside the window, which ran up to the
/// sweep timeout of its own: a run ended at roughly `duration + 2 x
/// sweep_timeout`. At the soak settings this harness exists for
/// (`--duration 60 --sweep-timeout 600`) a one-minute run kept going for
/// twenty, and every rate the report quotes was divided by that wall.
///
/// The bound held here is the contract: once the deadline passes, the
/// iterations already in flight get their full sweep timeout to finish and no
/// new one starts. So a run cannot outlast `duration + sweep_timeout`, and the
/// pre-fix run - which needed twice the sweep timeout - is outside it.
#[tokio::test]
async fn a_duration_run_stops_at_its_deadline_behind_a_stuck_slot() {
    let h = harness(RailProfile {
        // Every payment dies after the journal claim, so the first iteration
        // takes the slot and never gives it back.
        pay_failure_in: 1,
        ..quick()
    })
    .await;

    let duration = Duration::from_millis(300);
    let sweep = Duration::from_secs(2);

    let stats = generator::run(
        h.env.clone(),
        Plan {
            duration: Some(duration),
            ..plan(0, 1, vec![(Path::Release, 1)], sweep)
        },
    )
    .await
    .expect("the run completes");

    assert_eq!(
        h.rail_counters.pay_errors(),
        1,
        "the slot was never stuck, so the loop never had to wait for it"
    );
    assert!(
        stats.total() >= 2,
        "the loop never got as far as queueing behind the stuck slot, so this \
         proves nothing"
    );
    assert!(
        stats.wall < duration + sweep + Duration::from_secs(1),
        "the run overran its deadline: {:?} for a {duration:?} run with a \
         {sweep:?} sweep timeout, which is the shape of starting an iteration \
         after the deadline had passed",
        stats.wall
    );
}
