//! zecp2p CLI - Command line interface for ZEC → Venmo offramps
//!
//! Usage:
//!   zecp2p offramp <amount> ZEC to venmo @<username> --taker <address>
//!   zecp2p status <session-id>
//!   zecp2p quote <amount>

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Client;
use zecp2p_types::{OfframpResponse, OfframpStatus, QuoteResponse};

#[derive(Parser)]
#[command(name = "zecp2p")]
#[command(about = "Trustless ZEC → Venmo offramp")]
#[command(version)]
struct Cli {
    /// Coordinator URL
    #[arg(long, env = "ZECP2P_COORDINATOR_URL", default_value = "http://localhost:3000")]
    coordinator: String,

    /// Config file path
    #[arg(long, env = "ZECP2P_CONFIG", default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get a quote for ZEC → Venmo conversion
    Quote {
        /// Amount in ZEC (e.g., 0.5)
        amount: String,
    },

    /// Initiate an offramp
    Offramp {
        /// Amount in ZEC (e.g., 0.5)
        amount: String,

        /// Venmo username (without @)
        #[arg(long)]
        venmo: String,

        /// Your Base wallet address
        #[arg(long)]
        user_address: String,

        /// Pre-arranged taker address (required for V0)
        #[arg(long)]
        taker: String,

        /// Minimum USDC/ZEC rate to accept
        #[arg(long)]
        min_rate: Option<String>,

        /// Timeout for NEAR settlement in seconds
        #[arg(long, default_value = "600")]
        timeout: u64,
    },

    /// Check offramp status
    Status {
        /// Session ID (UUID)
        session_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load env
    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    let client = Client::new();

    match cli.command {
        Commands::Quote { amount } => {
            let resp: QuoteResponse = client
                .get(format!("{}/quote", cli.coordinator))
                .query(&[("zec_amount", &amount)])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Quote for {} ZEC:", amount);
            println!("  USDC: {}", resp.usdc_amount);
            println!("  Venmo (est): ${}", resp.venmo_amount);
            println!("  Rate: {} USDC/ZEC", resp.rate);
            println!("  Expires: {}", resp.expires_at);
        }

        Commands::Offramp {
            amount,
            venmo,
            user_address,
            taker,
            min_rate,
            timeout,
        } => {
            let body = serde_json::json!({
                "zec_amount": amount,
                "venmo_username": venmo,
                "user_address": user_address,
                "taker_address": taker,
                "min_rate": min_rate,
                "timeout_seconds": timeout,
            });

            let resp: OfframpResponse = client
                .post(format!("{}/offramp", cli.coordinator))
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Offramp initiated!");
            println!("  Session ID: {}", resp.session_id);
            println!("  Status: {:?}", resp.status);

            if let Some(addr) = resp.near_deposit_address {
                println!();
                println!("Send {} ZEC to: {}", amount, addr);
                println!();
                println!("Monitor status with:");
                println!("  zecp2p status {}", resp.session_id);
            }

            if let Some(err) = resp.error {
                println!("  Error: {}", err);
            }
        }

        Commands::Status { session_id } => {
            let resp: OfframpResponse = client
                .get(format!("{}/offramp/{}", cli.coordinator, session_id))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Session: {}", resp.session_id);
            println!("Status: {:?}", resp.status);

            if let Some(ref addr) = resp.near_deposit_address {
                println!("NEAR Deposit Address: {}", addr);
            }

            if let Some(ref usdc) = resp.expected_usdc {
                println!("Expected USDC: {}", usdc);
            }

            if let Some(ref err) = resp.error {
                println!("Error: {}", err);
            }

            // Print status-specific messages
            match resp.status {
                OfframpStatus::Created => {
                    println!("\nWaiting for NEAR Intent to be initiated...");
                }
                OfframpStatus::NearIntentPending => {
                    if let Some(ref addr) = resp.near_deposit_address {
                        println!("\nSend ZEC to: {}", addr);
                    }
                }
                OfframpStatus::UsdcReceived => {
                    println!("\nUSDC received! Processing deposit to zk-p2p...");
                }
                OfframpStatus::Zkp2pDeposited => {
                    println!("\nDeposit created on zk-p2p. Waiting for taker...");
                }
                OfframpStatus::IntentSignaled => {
                    println!("\nTaker signaled intent! Waiting for Venmo payment...");
                }
                OfframpStatus::Fulfilled => {
                    println!("\nOfframp complete! Check your Venmo for payment.");
                }
                OfframpStatus::Failed => {
                    println!("\nOfframp failed.");
                }
                OfframpStatus::Rescued => {
                    println!("\nFunds rescued to your wallet.");
                }
                OfframpStatus::Withdrawn => {
                    println!("\nFunds withdrawn from zk-p2p.");
                }
            }
        }
    }

    Ok(())
}
