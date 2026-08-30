//! zecp2p CLI - Command line interface for ZEC → Venmo offramps
//!
//! Usage:
//!   zecp2p quote <amount>
//!   zecp2p offramp <amount> --venmo <username> [--taker <address>] ...
//!   zecp2p status <session-id>
//!   zecp2p watch <session-id>
//!   zecp2p rescue <session-id>
//!   zecp2p withdraw <session-id>

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Client;
use std::time::Duration;
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

        /// Address you expect to take this offramp. Optional; without it the
        /// deposit is open to any zk-p2p taker, which is the normal case.
        #[arg(long)]
        taker: Option<String>,

        /// Your Zcash address for refunds (t1/t3/zs prefix)
        #[arg(long)]
        zec_address: String,

        /// Minimum USD per USDC the taker must pay on zk-p2p (default 1.0)
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

    /// Watch offramp status until completion
    Watch {
        /// Session ID (UUID)
        session_id: String,

        /// Poll interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Rescue USDC from GlueContract (if processOfframp failed)
    Rescue {
        /// Session ID (UUID)
        session_id: String,
    },

    /// Withdraw USDC from zk-p2p deposit (if no taker)
    Withdraw {
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
            zec_address,
            min_rate,
            timeout,
        } => {
            let body = serde_json::json!({
                "zec_amount": amount,
                "venmo_username": venmo,
                "user_address": user_address,
                "taker_address": taker,
                "zec_refund_address": zec_address,
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
            let resp = fetch_status(&client, &cli.coordinator, &session_id).await?;
            print_status(&resp);
        }

        Commands::Watch {
            session_id,
            interval,
        } => {
            println!("Watching session {}...", session_id);
            println!("Press Ctrl+C to stop\n");

            let mut last_status: Option<OfframpStatus> = None;
            let poll_interval = Duration::from_secs(interval);

            loop {
                let resp = fetch_status(&client, &cli.coordinator, &session_id).await?;

                // Only print if status changed
                if last_status.as_ref() != Some(&resp.status) {
                    print_status(&resp);
                    println!();
                    last_status = Some(resp.status);
                } else {
                    // Print a dot to show we're still polling
                    print!(".");
                    use std::io::Write;
                    std::io::stdout().flush().ok();
                }

                // Check if terminal state
                if is_terminal(&resp.status) {
                    println!("\nSession complete.");
                    break;
                }

                tokio::time::sleep(poll_interval).await;
            }
        }

        Commands::Rescue { session_id } => {
            println!("Rescuing funds for session {}...", session_id);

            let resp: OfframpResponse = client
                .post(format!("{}/offramp/{}/rescue", cli.coordinator, session_id))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Rescue successful!");
            print_status(&resp);
        }

        Commands::Withdraw { session_id } => {
            println!("Withdrawing funds for session {}...", session_id);

            let resp: OfframpResponse = client
                .post(format!("{}/offramp/{}/withdraw", cli.coordinator, session_id))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Withdrawal successful!");
            print_status(&resp);
        }
    }

    Ok(())
}

async fn fetch_status(
    client: &Client,
    coordinator: &str,
    session_id: &str,
) -> Result<OfframpResponse> {
    let resp: OfframpResponse = client
        .get(format!("{}/offramp/{}", coordinator, session_id))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp)
}

fn is_terminal(status: &OfframpStatus) -> bool {
    matches!(
        status,
        OfframpStatus::Fulfilled
            | OfframpStatus::Failed
            | OfframpStatus::Rescued
            | OfframpStatus::Withdrawn
    )
}

fn print_status(resp: &OfframpResponse) {
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
