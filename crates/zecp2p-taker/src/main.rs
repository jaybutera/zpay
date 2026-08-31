//! zecp2p-taker: watch Base for claimable offramp deposits and serve them.
//!
//! ```text
//! zecp2p-taker run --dry-run          # watch and report, spend nothing
//! zecp2p-taker run                    # claim, pay, and hand off for proving
//! zecp2p-taker stake --amount 100     # fund the zk-p2p StakeVault
//! zecp2p-taker fulfill --intent 0x..  # submit an enclave attestation
//! zecp2p-taker cancel --intent 0x..   # give a claim back
//! ```

use alloy::{
    network::EthereumWallet,
    primitives::{B256, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use zecp2p_taker::{
    claim::Claimer,
    config::TakerConfig,
    proof::load_proof,
    venmo::{SendMode, VenmoBrowser},
    TakerAgent,
};

#[derive(Parser)]
#[command(name = "zecp2p-taker", about = "Taker agent for zecp2p offramps")]
struct Cli {
    /// Path to the taker config file
    #[arg(long, env = "ZECP2P_TAKER_CONFIG", default_value = "config.taker.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Watch for claimable deposits and serve them
    Run {
        /// Go through the motions without claiming or paying anything.
        ///
        /// The agent scans, prices deposits, checks stake, inspects the Venmo
        /// tab, and prints the steps it would take. No transaction is sent and
        /// no money moves.
        #[arg(long)]
        dry_run: bool,

        /// Pay this Venmo username instead of asking the coordinator.
        ///
        /// The chain does not carry the username, only the curator's opaque
        /// payee hash, so without a coordinator the agent needs to be told.
        #[arg(long)]
        recipient: Option<String>,
    },

    /// Deposit USDC into the zk-p2p StakeVault
    Stake {
        /// Whole USDC (e.g. 100 for 100 USDC)
        #[arg(long)]
        amount: u64,
    },

    /// Show stake and wallet balances
    Status,

    /// Submit an enclave attestation for a claimed intent
    Fulfill {
        #[arg(long)]
        intent: String,
        /// Path to the attestation, as written by scripts/proof/prove_payment.mjs
        #[arg(long)]
        proof: String,
    },

    /// Release a claimed intent you cannot pay
    Cancel {
        #[arg(long)]
        intent: String,
    },

    /// Check that the browser has a usable, logged-in Venmo tab
    CheckVenmo,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zecp2p_taker=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = TakerConfig::load(&cli.config)?;

    // CheckVenmo is the one command that needs no key: it is what an operator
    // runs before funding anything.
    if let Commands::CheckVenmo = cli.command {
        let browser = VenmoBrowser::new(config.venmo.cdp_url.clone(), config.venmo.timeout_seconds);
        let tab = browser.find_venmo_tab().await?;
        if VenmoBrowser::session_looks_live(&tab) {
            println!("Venmo tab ready: {}", tab.url);
        } else {
            println!("Found a Venmo tab at {} but it looks signed out.", tab.url);
            std::process::exit(1);
        }
        return Ok(());
    }

    let key = std::env::var("TAKER_PRIVATE_KEY")
        .context("TAKER_PRIVATE_KEY is not set; the agent needs a funded Base key")?;
    // Accept the key with or without the 0x prefix; both spellings are common
    // in .env files and the parser only takes one of them.
    let signer: PrivateKeySigner = key
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| key.trim())
        .parse()
        .context("TAKER_PRIVATE_KEY is not a valid 32-byte hex private key")?;
    let taker = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(config.network.base_rpc_url.parse()?);

    let claimer = Claimer::new(
        provider.clone(),
        config.contracts.zkp2p_orchestrator,
        config.contracts.zkp2p_escrow,
        config.contracts.stake_vault,
        config.contracts.usdc,
        taker,
    );

    match cli.command {
        Commands::CheckVenmo => unreachable!("handled above"),

        Commands::Run { dry_run, recipient } => {
            let mode = if dry_run {
                SendMode::DryRun
            } else {
                SendMode::Live
            };
            tracing::info!(taker = %taker, dry_run, "starting taker agent");
            let agent =
                TakerAgent::with_recipient(config, provider.clone(), taker, mode, recipient);
            agent.run(&provider).await?;
        }

        Commands::Stake { amount } => {
            let units = U256::from(amount) * U256::from(1_000_000u64);
            match claimer.ensure_stake(units).await? {
                Some(tx) => println!("staked, tx {tx}"),
                None => println!("already have {amount} USDC of free stake; nothing to do"),
            }
        }

        Commands::Status => {
            let free = claimer.free_stake().await?;
            println!("taker:      {taker}");
            println!("free stake: {} USDC", format_usdc(free));
        }

        Commands::Fulfill { intent, proof } => {
            let intent_hash: B256 = intent.parse().context("intent hash is not a 32-byte hex")?;
            let attested = load_proof(&proof)?;
            let tx = claimer
                .fulfill_intent(
                    intent_hash,
                    attested.payment_proof,
                    attested.verification_data,
                )
                .await?;
            println!("fulfilled, tx {tx}");
        }

        Commands::Cancel { intent } => {
            let intent_hash: B256 = intent.parse().context("intent hash is not a 32-byte hex")?;
            let tx = claimer.cancel_intent(intent_hash).await?;
            println!("cancelled, tx {tx}");
            println!("the maker's USDC is released and your stake is unlocked");
        }
    }

    Ok(())
}

fn format_usdc(amount: U256) -> String {
    let units: u128 = amount.to::<u128>();
    format!("{}.{:06}", units / 1_000_000, units % 1_000_000)
}
