//! The v2 coordinator binary: the LP's side of the native Zcash escrow.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zecp2p_v2coordinator::config::CoordinatorConfig;
use zecp2p_v2coordinator::state::{AppStateBuilder, FiatRail, PaidFiat};

mod venmo_rail;

#[derive(Parser, Debug)]
#[command(name = "zecp2p-v2coordinator", about = "The native Zcash escrow coordinator")]
struct Args {
    /// The configuration file.
    #[arg(long, env = "ZECP2P_V2_CONFIG", default_value = "config.v2coordinator.toml")]
    config: String,

    /// Check the configuration, the node, the attestor and the key, then exit.
    #[arg(long)]
    check: bool,

    /// How often to sweep open orders, in seconds.
    ///
    /// 60 rather than the 20 this shipped with. Every deadline the sweep acts
    /// on is measured in tens of minutes - 75 minutes of paying room, 50 of
    /// broadcast room, 24 hours to `T` - so noticing a block up to 60 s late
    /// costs nothing any of them can see. What it saves is node calls: the
    /// sweep is the only periodic caller, so the tick rate multiplies
    /// everything it does.
    ///
    /// 60 s is deliberately still under the 75 s block time, so a sweep cannot
    /// step over a block; 120 would, which is why this is not simply as long as
    /// it could be.
    #[arg(long, default_value_t = 60)]
    poll_seconds: u64,

    /// Print what build this is and exit.
    ///
    /// Finding 10: identifying a deployed binary meant `strings` for a symbol.
    /// This is the same answer `/health` publishes and the same hash the deploy
    /// script verifies, so all three agree by construction.
    #[arg(long)]
    version: bool,

    /// Settle with a simulated fiat leg instead of a browser and an enclave.
    ///
    /// Only exists in a build with `--features test-rails`. It reports a
    /// payment that never happened, so the release it produces is real and the
    /// dollars are not. Never point it at mainnet.
    #[arg(long)]
    simulate_fiat: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zecp2p_v2coordinator=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    if args.version {
        println!("{}", zecp2p_v2coordinator::version::describe());
        println!("built_at_unix {}", zecp2p_v2coordinator::version::BUILD_TIME);
        println!("{}", zecp2p_v2coordinator::version::STAMP);
        return Ok(());
    }
    let config = CoordinatorConfig::load(&args.config)
        .with_context(|| format!("could not load {}", args.config))?;

    let fiat: Arc<dyn FiatRail> = if args.simulate_fiat {
        #[cfg(feature = "test-rails")]
        {
            if config.network()? == zecp2p_escrow::rpc::Network::Main {
                anyhow::bail!(
                    "--simulate-fiat on a mainnet coordinator would release real ZEC \
                     against a payment nobody made. Refusing."
                );
            }
            tracing::warn!(
                "--simulate-fiat: the fiat leg is simulated. No dollars will be sent, and \
                 escrows will release anyway. This is a test posture."
            );
            Arc::new(zecp2p_v2coordinator::simulated_rail::SimulatedRail)
        }
        #[cfg(not(feature = "test-rails"))]
        {
            anyhow::bail!(
                "--simulate-fiat needs a build with `--features test-rails`. This binary \
                 has no path that settles an escrow without a real payment."
            );
        }
    } else {
        Arc::new(venmo_rail::VenmoRail::new(&config)?)
    };
    let state = AppStateBuilder::new(config).with_fiat(fiat).build()?;

    tracing::info!(
        build = %zecp2p_v2coordinator::version::describe(),
        network = state.network_name(),
        l_pub = %hex::encode(state.l_pub),
        payout = %state.config.lp.payout_address,
        live_payments = state.config.serve.live_payments,
        "coordinator starting"
    );

    // Fail at startup, not at the first order. A node that cannot be reached
    // or an attestor that will not answer is something the operator should
    // hear about now.
    // Uncached on purpose: this is the startup check that the node is actually
    // reachable, and a cache hit here would report a node nobody had asked.
    let (height, branch) = wait_for_node(&state, args.check).await?;
    tracing::info!(
        height,
        branch = format!("{branch:#x}"),
        endpoints = state.nodes.len(),
        "node reachable"
    );

    let identity = state
        .with_attestor(|client| {
            client
                .identity()
                .map_err(|e| anyhow::anyhow!("the attestor would not identify itself: {e}"))
        })
        .await;
    match identity {
        Ok((p, build_id)) => {
            tracing::info!(attestor_key = %p, build = %build_id, "attestor reachable");
            if let Some(pinned) = &state.attestor_pubkey {
                let pinned_hex = hex::encode(pinned.serialize());
                if p.trim().to_ascii_lowercase() != pinned_hex {
                    anyhow::bail!(
                        "the attestor at {} identifies as {p}, and this coordinator pins \
                         {pinned_hex}. Refusing to start: the page is shown whatever this \
                         process relays, so serving with the wrong attestor means every \
                         pre-signature is encrypted under a key somebody else chose.",
                        state.config.attestor.url
                    );
                }
            }
        }
        Err(e) => {
            // Not fatal: the attestor may come back, and an order that cannot
            // be announced simply stays refundable. But it is a warning the
            // operator sees at startup rather than discovering from a stall.
            tracing::warn!(error = %format!("{e:#}"), "the attestor is not reachable right now");
        }
    }

    // The address-index scanner needs zcashd with `addressindex=1`; zebrad
    // does not implement `getaddressutxos` at all. Asking now means an
    // operator hears about it at startup rather than from an order that never
    // leaves `awaiting_zec`.
    if state.config.zec.scanner == zecp2p_v2coordinator::config::ScannerKind::AddressIndex {
        let rpc = state.rpc.clone();
        let supported = tokio::task::spawn_blocking(move || {
            zecp2p_v2coordinator::funding::NodeRpc::new(&rpc)
                .map(|node| node.supports_address_index())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if supported {
            tracing::info!("the node answers getaddressutxos");
        } else {
            tracing::warn!(
                "zec.scanner is address_index but this node does not answer \
                 getaddressutxos. zcashd needs addressindex=1 and zebrad does not \
                 implement it at all, so no funding output will ever be found. Switch \
                 zec.scanner to block_scan."
            );
        }
    }

    // A pinned rate is the one configuration mistake that cannot announce
    // itself later: every quote it prices looks perfectly well formed. So it is
    // said once, loudly, at the only moment an operator is reading the log.
    match state.config.quote.rate_usd_per_zec {
        Some(rate) => tracing::warn!(
            rate,
            "quote.rate_usd_per_zec is pinned: the live price feed is OFF and every trade \
             is priced at this constant. Correct only for a regtest or a rehearsal - remove \
             it before quoting real trades."
        ),
        None => {
            // Read the price once at startup for the same reason the node and
            // the attestor are checked here: an operator should learn the feed
            // is unreachable now, not from a user whose quote was refused.
            match zecp2p_v2coordinator::price::spot(
                &state.http,
                &state.prices,
                std::time::Duration::from_secs(state.config.quote.price_timeout_seconds),
            )
            .await
            {
                Ok(spot) => {
                    let quoted = zecp2p_v2coordinator::price::apply_spread(
                        spot.usd_per_zec,
                        state.config.quote.spread_bps,
                    );
                    tracing::info!(
                        source = spot.source.label(),
                        spot = spot.usd_per_zec,
                        quoted,
                        spread_bps = state.config.quote.spread_bps,
                        "ZEC price feed reachable"
                    );
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "the ZEC price feed could not be read: quotes will be refused until it can"
                ),
            }
        }
    }

    if !state.config.serve.live_payments {
        tracing::warn!(
            "serve.live_payments is false: this coordinator drives the browser and stops \
             at the irreversible step. No dollars will be sent and no escrow will release."
        );
    }
    if state.config.serve.allow_any_handle {
        tracing::warn!(
            "serve.allow_any_handle is set: this coordinator will front fiat for any Venmo \
             handle a caller names. That is the liquidity business, deliberately entered."
        );
    }

    if args.check {
        println!("configuration, node and key all check out");
        return Ok(());
    }

    let driver_state = state.clone();
    tokio::spawn(zecp2p_v2coordinator::driver::run(
        driver_state,
        std::time::Duration::from_secs(args.poll_seconds),
    ));

    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    tracing::info!(%addr, "listening");

    // `into_make_service_with_connect_info` rather than the plain service, so
    // the order-opening route can see who is calling. Without it the
    // `ConnectInfo` extractor is missing at runtime and every request falls
    // into one rate-limit bucket. Finding 4.
    axum::serve(
        listener,
        zecp2p_v2coordinator::web::router(state)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .context("the server stopped")?;
    Ok(())
}

/// Waits for a node rather than exiting on the first refusal. Finding 6.
///
/// The old behaviour exited, and the unit restarts, so a provider incident
/// during a restart became a restart loop: every 15 s a process started, made
/// its calls, waited out a rate limit and died. A coordinator that is not
/// running does not offer anybody the refund they are owed, and every deadline
/// it serves is tens of minutes wide, so waiting is strictly better than
/// exiting for any wait shorter than those deadlines.
///
/// It still gives up eventually. `zec.startup_retry_seconds` at zero restores
/// the old fail-fast behaviour, and `--check` never waits: that mode exists to
/// answer a question now, and a check that blocks for ten minutes in a deploy
/// script is a check nobody runs.
async fn wait_for_node(
    state: &Arc<zecp2p_v2coordinator::state::AppState>,
    check_only: bool,
) -> Result<(u32, u32)> {
    let budget = std::time::Duration::from_secs(state.config.zec.startup_retry_seconds);
    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match state.chain_head_uncached().await {
            Ok(head) => {
                if attempt > 1 {
                    tracing::info!(
                        attempt,
                        waited_seconds = started.elapsed().as_secs(),
                        "the node answered; carrying on"
                    );
                }
                return Ok(head);
            }
            Err(e) => {
                if check_only || budget.is_zero() {
                    return Err(e).context("could not reach the Zcash node");
                }
                if started.elapsed() >= budget {
                    return Err(e).with_context(|| {
                        format!(
                            "no Zcash node answered in {} s across {} endpoint(s). Raise \
                             zec.startup_retry_seconds, add a zec.fallback_rpc entry, or \
                             fix the endpoint.",
                            budget.as_secs(),
                            state.nodes.len()
                        )
                    });
                }
                // Backs off to a minute rather than hammering an endpoint that
                // may be rate-limiting, which is one of the ways it fails.
                let wait = std::time::Duration::from_secs(u64::from(attempt.min(6)) * 10);
                tracing::warn!(
                    attempt,
                    error = %format!("{e:#}"),
                    retry_in_seconds = wait.as_secs(),
                    budget_seconds = budget.as_secs(),
                    "no Zcash node answered; waiting rather than exiting into a restart loop"
                );
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// A rail that refuses to do anything, for a coordinator run without Venmo.
#[allow(dead_code)]
struct NoFiat;

#[async_trait::async_trait]
impl FiatRail for NoFiat {
    async fn pay(&self, _leg: &zecp2p_taker::auto::rail::FiatLeg) -> Result<PaidFiat> {
        anyhow::bail!("no fiat rail is configured")
    }

    async fn attest(
        &self,
        _leg: &zecp2p_taker::auto::rail::FiatLeg,
    ) -> Result<zecp2p_escrow::lp_client::WireAttestation> {
        anyhow::bail!("no fiat rail is configured")
    }
}
