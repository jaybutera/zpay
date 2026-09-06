//! The load harness's command line.
//!
//!     cargo run -p zecp2p-loadgen -- --count 1
//!     cargo run -p zecp2p-loadgen -- --count 200 --concurrency 8
//!     cargo run -p zecp2p-loadgen -- --duration 600 --concurrency 16 --mix release=8,refund=1,never_sign=1
//!
//! Everything it talks to is a loopback listener this process owns, and the
//! only network it will configure is `test`. There is no flag that points it at
//! a real node, a real attestor or a real Venmo session, and adding one would
//! have to get past the guard in `Harness::build`.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use zecp2p_loadgen::generator::{self, Plan};
use zecp2p_loadgen::rail::RailProfile;
use zecp2p_loadgen::scenario::Path;
use zecp2p_loadgen::{Harness, HarnessOptions};

#[derive(Parser, Debug)]
#[command(
    name = "zecp2p-loadgen",
    about = "Testnet traffic and soak harness for the v2 escrow coordinator"
)]
struct Args {
    /// How many orders to run. Ignored when --duration is given.
    #[arg(long, default_value_t = 10)]
    count: usize,

    /// Run for this many seconds instead of for a count.
    #[arg(long)]
    duration: Option<u64>,

    /// How many orders may be in flight at once.
    ///
    /// This does not raise the payment rate: the coordinator holds one global
    /// payment slot by design. What it raises is the pressure on everything
    /// around that slot.
    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    /// The path mix, as `name=weight` pairs.
    ///
    /// Names: release, refund, never_sign, never_fund.
    #[arg(long, default_value = "release=1")]
    mix: String,

    /// The smallest escrow to open, in ZEC.
    #[arg(long, default_value_t = 0.05)]
    amount_min: f64,

    /// The largest escrow to open, in ZEC.
    #[arg(long, default_value_t = 0.25)]
    amount_max: f64,

    /// Venmo handles to open orders against, comma separated.
    #[arg(long, default_value = "alice,bob,carol,dave")]
    handles: String,

    /// How long one order may wait for the payment slot, in seconds.
    #[arg(long, default_value_t = 60)]
    sweep_timeout: u64,

    /// Milliseconds between starting iterations, which shapes arrival rate.
    #[arg(long, default_value_t = 0)]
    arrival_gap_ms: u64,

    /// How long the modelled fiat leg takes, in milliseconds.
    ///
    /// The real browser drive is 60-120 seconds. Keep this above zero: a rail
    /// that returns instantly never makes the payment slot contend, which is
    /// the thing a concurrent run is measuring.
    #[arg(long, default_value_t = 50)]
    pay_latency_ms: u64,

    /// Fail one payment in this many inside `pay`, after the journal claim.
    #[arg(long, default_value_t = 0)]
    pay_failure_in: u32,

    /// Fail one attestation in this many, the way a missing prover config does.
    #[arg(long, default_value_t = 0)]
    attest_failure_in: u32,

    /// Report success without sending, one payment in this many.
    ///
    /// The 2026-09-05 incident's shape. The coordinator cannot tell; the run's
    /// ledger can, and the report prints both numbers.
    #[arg(long, default_value_t = 0)]
    false_paid_in: u32,

    /// Write every iteration's outcome to this file as JSON lines.
    #[arg(long)]
    jsonl: Option<String>,

    /// Make the node fail every RPC for this many seconds, starting this far
    /// into the run: `--node-outage-at 60 --node-outage-for 30`.
    ///
    /// A rate-limited provider, in the shape the client sees it. This project
    /// has hit that twice for real, so it is worth a soak: what must not happen
    /// is an escrow settled or released on a node answer nobody got.
    #[arg(long)]
    node_outage_at: Option<u64>,

    /// How long the injected node outage lasts, in seconds.
    #[arg(long, default_value_t = 30)]
    node_outage_for: u64,

    /// Delay every node answer by this many milliseconds, for the whole run.
    #[arg(long, default_value_t = 0)]
    node_stall_ms: u64,
}

fn parse_mix(text: &str) -> Result<Vec<(Path, u32)>> {
    let mut out = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, weight) = part
            .split_once('=')
            .with_context(|| format!("a mix entry looks like release=3, and this is {part:?}"))?;
        let path = match name.trim() {
            "release" => Path::Release,
            "refund" => Path::Refund,
            "never_sign" => Path::NeverSign,
            "never_fund" => Path::NeverFund,
            other => anyhow::bail!(
                "unknown path {other:?}: use release, refund, never_sign or never_fund"
            ),
        };
        let weight: u32 = weight
            .trim()
            .parse()
            .with_context(|| format!("{weight:?} is not a weight"))?;
        out.push((path, weight));
    }
    if out.is_empty() {
        anyhow::bail!("the mix names no paths");
    }
    if out.iter().all(|(_, w)| *w == 0) {
        anyhow::bail!("every weight in the mix is zero, so no order would ever run");
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,zecp2p_v2coordinator=warn".into()),
        )
        .init();

    let args = Args::parse();
    let mix = parse_mix(&args.mix)?;
    let handles: Vec<String> = args
        .handles
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .collect();
    if handles.is_empty() {
        anyhow::bail!("--handles named nobody");
    }

    let harness = Harness::build(HarnessOptions {
        rail: RailProfile {
            pay_latency_ms: args.pay_latency_ms,
            preflight_latency_ms: 5,
            pay_failure_in: args.pay_failure_in,
            attest_failure_in: args.attest_failure_in,
            false_paid_in: args.false_paid_in,
        },
        handles: handles.clone(),
        ..HarnessOptions::default()
    })
    .await?;

    let plan = Plan {
        count: args.count,
        duration: args.duration.map(Duration::from_secs),
        concurrency: args.concurrency,
        mix,
        amount_min_zec: args.amount_min,
        amount_max_zec: args.amount_max,
        handles,
        sweep_timeout: Duration::from_secs(args.sweep_timeout),
        arrival_gap: Duration::from_millis(args.arrival_gap_ms),
    };

    println!("zecp2p-loadgen: testnet only, everything on loopback, no real money.");
    println!(
        "  node {}  attestor {}",
        harness.node.url, harness.attestor.url
    );
    match plan.duration {
        Some(d) => println!(
            "  running for {}s at concurrency {}",
            d.as_secs(),
            plan.concurrency
        ),
        None => println!(
            "  running {} orders at concurrency {}",
            plan.count, plan.concurrency
        ),
    }
    println!();

    // A node that stalls for the whole run, if asked.
    if args.node_stall_ms > 0 {
        harness
            .node
            .faults()
            .stall_ms
            .store(args.node_stall_ms, std::sync::atomic::Ordering::Relaxed);
        println!("  node answers delayed by {}ms", args.node_stall_ms);
    }

    // And a provider that goes away in the middle of the run and comes back.
    if let Some(at) = args.node_outage_at {
        let node = harness.node.clone();
        let for_secs = args.node_outage_for;
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            tokio::time::sleep(Duration::from_secs(at)).await;
            tracing::warn!(seconds = for_secs, "INJECTED node outage: every RPC now fails");
            node.faults().fail_rpc.store(true, Relaxed);
            tokio::time::sleep(Duration::from_secs(for_secs)).await;
            node.faults().fail_rpc.store(false, Relaxed);
            tracing::warn!("the node is answering again");
        });
        println!(
            "  node fails every RPC from {}s for {}s",
            at, args.node_outage_for
        );
    }

    let env = harness.env.clone();
    let stats = generator::run(env, plan).await?;

    if let Some(path) = &args.jsonl {
        write_jsonl(path, &stats).with_context(|| format!("writing {path}"))?;
        println!("wrote {} iterations to {path}", stats.total());
    }

    report(&harness, &stats);
    Ok(())
}

fn write_jsonl(path: &str, stats: &generator::Stats) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    for o in &stats.outcomes {
        let line = serde_json::json!({
            "order_id": o.order_id,
            "path": o.path.as_str(),
            "address": o.address,
            "final_stage": o.final_stage,
            "ok": o.ok,
            "error": o.error,
            "release_txid": o.release_txid,
            "refund_txid": o.refund_txid,
            "ms": {
                "quote": o.timings.quote.as_millis(),
                "open": o.timings.open.as_millis(),
                "fund_to_depth": o.timings.fund_to_depth.as_millis(),
                "presign": o.timings.presign.as_millis(),
                "settle": o.timings.settle.as_millis(),
                "total": o.timings.total.as_millis(),
            },
        });
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn report(harness: &Harness, stats: &generator::Stats) {
    let counters = &harness.rail_counters;
    let node = harness.node.counters();
    use std::sync::atomic::Ordering::Relaxed;

    println!();
    println!("== throughput ==");
    println!("  orders          {}", stats.total());
    println!(
        "  succeeded       {}  failed {}",
        stats.succeeded(),
        stats.failed()
    );
    println!("  wall            {:.2}s", stats.wall.as_secs_f64());
    println!("  orders/sec      {:.2}", stats.throughput());
    println!(
        "  latency p50/p95/p99 ms   {} / {} / {}",
        stats.percentile_ms(0.50),
        stats.percentile_ms(0.95),
        stats.percentile_ms(0.99)
    );

    println!();
    println!("== outcomes ==");
    println!("  released        {}", stats.released());
    println!("  refunded        {}", stats.refunded());
    println!(
        "  distinct escrow addresses  {} of {} orders that opened",
        stats.distinct_addresses(),
        stats.orders_with_an_address()
    );

    println!();
    println!("== fiat leg ==");
    println!("  reported sent   {}", counters.reported_sent());
    println!("  truly sent      {}", counters.truly_sent());
    println!("  pay errors      {}", counters.pay_errors());
    println!(
        "  attests         {}  errors {}",
        counters.attests(),
        counters.attest_errors()
    );
    println!("  max overlap     {}", counters.max_overlap());

    println!();
    println!("== node ==");
    println!(
        "  calls           {} (chaininfo {}, gettxout {}, broadcast {})",
        node.total(),
        node.getblockchaininfo.load(Relaxed),
        node.gettxout.load(Relaxed),
        node.sendrawtransaction.load(Relaxed)
    );
    if stats.total() > 0 {
        println!(
            "  calls per order {:.1}",
            node.total() as f64 / stats.total() as f64
        );
    }
    let refused = node.failed.load(Relaxed);
    if refused > 0 {
        println!("  refused         {refused} (injected outage)");
    }
    println!(
        "  attestor        {} announces, {} attests",
        harness.attestor.announces(),
        harness.attestor.attests()
    );

    let errors = stats.error_histogram();
    if !errors.is_empty() {
        println!();
        println!("== failures ==");
        for (what, n) in errors {
            println!("  {n:>5}  {what}");
        }
    }

    // The invariants a soak run exists to check. These are printed last and
    // loudly, because a run whose numbers look healthy can still have broken
    // one of them.
    println!();
    println!("== invariants ==");
    check(
        "at most one payment in flight",
        counters.max_overlap() <= 1,
        format!("max overlap was {}", counters.max_overlap()),
    );
    // Against the orders that were *given* an address, not against every order
    // attempted. A node outage refuses orders at the quote, and those never had
    // an address to reuse; comparing against the total reported a reuse that
    // had not happened, which is exactly the false alarm a soak must not raise.
    check(
        "every order that opened got its own escrow address",
        stats.distinct_addresses() == stats.orders_with_an_address(),
        format!(
            "{} distinct addresses for {} orders that opened",
            stats.distinct_addresses(),
            stats.orders_with_an_address()
        ),
    );
    // The one an operator most wants to be told about.
    //
    // A release hands the user's ZEC to the LP, and the only thing that
    // justifies it is dollars having actually reached the payee. The
    // coordinator cannot check that: it believes what the rail tells it, and on
    // 2026-09-05 the rail told it a confirmation challenge was a completed
    // send. So the harness keeps the honest ledger the coordinator has no
    // access to, and compares it against what was released.
    //
    // With `--false-paid-in` unset this must hold outright. With it set, it is
    // expected to fail, and the size of the gap is the number of escrows a
    // lying rail could drain.
    let released = stats.released();
    let truly = counters.truly_sent();
    check(
        "every release was backed by dollars that really left",
        released <= truly,
        format!(
            "{released} escrows released against {truly} payments that really left, so \
             {} released with no money behind them",
            released.saturating_sub(truly)
        ),
    );
    check(
        "no escrow released more than once",
        harness_broadcasts_le(stats),
        "more releases than released orders".to_string(),
    );
}

/// Releases are one per released order. More than that would mean an escrow was
/// spent twice, which the chain would refuse and the harness must not miss.
fn harness_broadcasts_le(stats: &generator::Stats) -> bool {
    let release_txids: Vec<&str> = stats
        .outcomes
        .iter()
        .filter_map(|o| o.release_txid.as_deref())
        .collect();
    let mut unique = release_txids.clone();
    unique.sort_unstable();
    unique.dedup();
    unique.len() == release_txids.len()
}

fn check(what: &str, ok: bool, detail: String) {
    if ok {
        println!("  PASS  {what}");
    } else {
        println!("  FAIL  {what} ({detail})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mix_parses_into_weights() {
        let mix = parse_mix("release=8,refund=1,never_sign=1").unwrap();
        assert_eq!(mix.len(), 3);
        assert_eq!(mix[0], (Path::Release, 8));
        assert_eq!(mix[2], (Path::NeverSign, 1));
    }

    #[test]
    fn an_unknown_path_is_refused_rather_than_ignored() {
        // Silently dropping it would run a mix the operator did not ask for.
        assert!(parse_mix("release=1,teleport=1").is_err());
    }

    #[test]
    fn a_mix_that_would_run_nothing_is_refused() {
        assert!(parse_mix("release=0,refund=0").is_err());
        assert!(parse_mix("").is_err());
    }
}
