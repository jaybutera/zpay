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
    #[arg(long, default_value_t = 20)]
    poll_seconds: u64,

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
        network = state.network_name(),
        l_pub = %hex::encode(state.l_pub),
        payout = %state.config.lp.payout_address,
        live_payments = state.config.serve.live_payments,
        "coordinator starting"
    );

    // Fail at startup, not at the first order. A node that cannot be reached
    // or an attestor that will not answer is something the operator should
    // hear about now.
    let (height, branch) = state
        .chain_head()
        .await
        .context("could not reach the Zcash node")?;
    tracing::info!(height, branch = format!("{branch:#x}"), "node reachable");

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

    axum::serve(listener, zecp2p_v2coordinator::web::router(state))
        .await
        .context("the server stopped")?;
    Ok(())
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
