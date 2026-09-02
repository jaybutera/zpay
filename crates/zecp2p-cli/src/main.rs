//! zecp2p CLI - Command line interface for ZEC → Venmo offramps
//!
//! Usage:
//!   zecp2p quote <amount>
//!   zecp2p offramp <amount> --venmo <username> [--taker <address>] ...
//!   zecp2p status <session-id>
//!   zecp2p watch <session-id>
//!   zecp2p rescue <session-id>
//!   zecp2p withdraw <session-id>

use alloy::primitives::{Address, B256, U256};
use alloy::providers::ProviderBuilder;
use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use std::time::Duration;
use zecp2p_types::{abi::OfframpGlue, OfframpResponse, OfframpStatus, QuoteResponse};

/// Header the coordinator reads the ownership signature from.
///
/// Kept in step with `zecp2p_coordinator::auth::SIGNATURE_HEADER`; the CLI does
/// not depend on the coordinator crate.
const SIGNATURE_HEADER: &str = "x-zecp2p-signature";

/// The message the coordinator expects to be signed. Must match
/// `zecp2p_coordinator::auth::ownership_message`.
fn ownership_message(action: &str, user_address: Address, scope: &str) -> String {
    format!("zecp2p:{action}:{user_address:?}:{scope}")
}

/// Load the user's key.
///
/// This is the key that owns the session, not the coordinator's. It never
/// leaves the machine: it signs a message locally, or a transaction sent
/// straight to Base with `--self-signed`.
fn user_signer(key: Option<&str>) -> Result<PrivateKeySigner> {
    let key = match key {
        Some(k) => k.to_string(),
        None => std::env::var("ZECP2P_USER_PRIVATE_KEY").context(
            "no user key. Pass --private-key, or set ZECP2P_USER_PRIVATE_KEY. \
             This is your own wallet key; it signs locally and is never sent.",
        )?,
    };
    key.trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("ZECP2P_USER_PRIVATE_KEY is not a valid private key"))
}

/// Sign `action`/`scope` for the coordinator, returning the header value.
fn sign_for(signer: &PrivateKeySigner, action: &str, scope: &str) -> Result<String> {
    let message = ownership_message(action, signer.address(), scope);
    Ok(signer.sign_message_sync(message.as_bytes())?.to_string())
}

/// The on-chain session id the contract knows a session by.
///
/// The coordinator derives it the same way, in `OfframpSession::compute_session_id`.
fn on_chain_session_id(session_uuid: &str) -> Result<B256> {
    let uuid: uuid::Uuid = session_uuid
        .parse()
        .context("session id is not a UUID")?;
    Ok(alloy::primitives::keccak256(uuid.as_bytes()))
}

/// Call the glue directly, with the user's own key, bypassing the coordinator.
///
/// This is the escape hatch. The contract accepts `rescue` and
/// `withdrawFromZkp2p` from the session's user and pays that user, so this
/// works with the coordinator offline, uncooperative, or gone. It needs the
/// user to hold a little ETH on Base for gas, and the glue address, which
/// `zecp2p status` prints and which is in the deploy record.
async fn self_signed_recovery(
    action: &str,
    session_uuid: &str,
    rpc_url: &str,
    glue: Address,
    signer: PrivateKeySigner,
) -> Result<()> {
    let session_id = on_chain_session_id(session_uuid)?;
    let user = signer.address();

    println!("Sending {action} directly to the glue at {glue:?}");
    println!("  session : {session_uuid}");
    println!("  on-chain: {session_id:?}");
    println!("  from    : {user:?}");

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc_url.parse().context("invalid --rpc-url")?);

    let contract = OfframpGlue::new(glue, &provider);

    // Read the session first, so a mistake costs a call rather than a revert.
    let session = contract
        .getSession(session_id)
        .call()
        .await
        .context("could not read the session from the glue")?;

    if session.user == Address::ZERO {
        anyhow::bail!("the glue has no session with that id");
    }
    if session.user != user {
        anyhow::bail!(
            "that session belongs to {:?}, not to your key {:?}",
            session.user,
            user
        );
    }

    let tx_hash = match action {
        "rescue" => {
            if session.credited == U256::ZERO {
                anyhow::bail!(
                    "the session has no credited USDC to rescue; \
                     if the deposit is already open, use `withdraw` instead"
                );
            }
            println!("  amount  : {} USDC units", session.credited);
            contract.rescue(session_id).send().await?.watch().await?
        }
        "withdraw" => {
            if !session.processed {
                anyhow::bail!("the session has no zk-p2p deposit yet; use `rescue` instead");
            }
            if session.withdrawn {
                anyhow::bail!("this session's deposit was already withdrawn");
            }
            contract
                .withdrawFromZkp2p(session_id)
                .send()
                .await?
                .watch()
                .await?
        }
        other => anyhow::bail!("unknown recovery action {other}"),
    };

    println!("\nSent. tx {tx_hash:?}");
    println!("The USDC goes to {user:?}, which the contract reads from the session.");
    Ok(())
}

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

        /// Your Base wallet address. Defaults to the address of --private-key,
        /// which is the address the coordinator will require a signature from.
        #[arg(long)]
        user_address: Option<String>,

        /// Your wallet key. Signs the request locally; never sent anywhere.
        ///
        /// The coordinator requires proof that you hold the key for the address
        /// the session names, so this address is also the one rescue and
        /// withdraw pay.
        #[arg(long, env = "ZECP2P_USER_PRIVATE_KEY", hide_env_values = true)]
        private_key: Option<String>,

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

        /// The exact dollars the taker must send on Venmo ("1.00").
        ///
        /// Sizes the deposit's intent so the payment is this number exactly,
        /// with the spread and the curator's fee added on top of it. Left out,
        /// the intent is the whole swap output and the payment is whatever that
        /// prices to: the 2026-09-01 fill went out that way and paid $4.84
        /// against a $5.00 request.
        #[arg(long)]
        target_payment: Option<String>,

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

        /// Your wallet key. Signs locally; never sent anywhere.
        #[arg(long, env = "ZECP2P_USER_PRIVATE_KEY", hide_env_values = true)]
        private_key: Option<String>,

        /// Skip the coordinator and send the transaction yourself.
        ///
        /// The contract pays the session's user whoever sends this, so this
        /// works with the coordinator down or unwilling. Needs --glue and a
        /// little ETH on Base for gas.
        #[arg(long)]
        self_signed: bool,

        /// OfframpGlue address, for --self-signed.
        #[arg(long, env = "GLUE_CONTRACT_ADDRESS")]
        glue: Option<String>,

        /// Base RPC, for --self-signed.
        #[arg(long, env = "BASE_RPC_URL", default_value = "https://mainnet.base.org")]
        rpc_url: String,
    },

    /// Withdraw USDC from zk-p2p deposit (if no taker)
    Withdraw {
        /// Session ID (UUID)
        session_id: String,

        /// Your wallet key. Signs locally; never sent anywhere.
        #[arg(long, env = "ZECP2P_USER_PRIVATE_KEY", hide_env_values = true)]
        private_key: Option<String>,

        /// Skip the coordinator and send the transaction yourself.
        #[arg(long)]
        self_signed: bool,

        /// OfframpGlue address, for --self-signed.
        #[arg(long, env = "GLUE_CONTRACT_ADDRESS")]
        glue: Option<String>,

        /// Base RPC, for --self-signed.
        #[arg(long, env = "BASE_RPC_URL", default_value = "https://mainnet.base.org")]
        rpc_url: String,
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
            private_key,
            taker,
            zec_address,
            min_rate,
            target_payment,
            timeout,
        } => {
            let signer = user_signer(private_key.as_deref())?;
            let signer_address = signer.address();

            // If both were given they have to agree, or the coordinator would
            // reject the signature and the reason would be unclear.
            let user_address = match user_address {
                Some(given) => {
                    let given: Address = given
                        .parse()
                        .context("--user-address is not a valid address")?;
                    if given != signer_address {
                        anyhow::bail!(
                            "--user-address {given:?} is not the address of --private-key \
                             ({signer_address:?}). The session's owner and the signer must match; \
                             rescue and withdraw pay the address in the session."
                        );
                    }
                    given
                }
                None => signer_address,
            };

            let body = serde_json::json!({
                "zec_amount": amount,
                "venmo_username": venmo,
                "user_address": format!("{user_address:?}"),
                "taker_address": taker,
                "zec_refund_address": zec_address,
                "min_rate": min_rate,
                "target_payment": target_payment,
                "timeout_seconds": timeout,
            });

            // Scope must match the coordinator's: amount and payee.
            let scope = format!("{}:{}", amount.trim(), venmo.trim());

            let resp: OfframpResponse = client
                .post(format!("{}/offramp", cli.coordinator))
                .header(SIGNATURE_HEADER, sign_for(&signer, "create", &scope)?)
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

        Commands::Rescue {
            session_id,
            private_key,
            self_signed,
            glue,
            rpc_url,
        } => {
            let signer = user_signer(private_key.as_deref())?;

            if self_signed {
                let glue: Address = glue
                    .ok_or_else(|| {
                        anyhow::anyhow!("--self-signed needs --glue (or GLUE_CONTRACT_ADDRESS)")
                    })?
                    .parse()
                    .context("--glue is not a valid address")?;
                self_signed_recovery("rescue", &session_id, &rpc_url, glue, signer).await?;
                return Ok(());
            }

            println!("Rescuing funds for session {}...", session_id);

            let resp: OfframpResponse = client
                .post(format!("{}/offramp/{}/rescue", cli.coordinator, session_id))
                .header(SIGNATURE_HEADER, sign_for(&signer, "rescue", &session_id)?)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            println!("Rescue successful!");
            print_status(&resp);
        }

        Commands::Withdraw {
            session_id,
            private_key,
            self_signed,
            glue,
            rpc_url,
        } => {
            let signer = user_signer(private_key.as_deref())?;

            if self_signed {
                let glue: Address = glue
                    .ok_or_else(|| {
                        anyhow::anyhow!("--self-signed needs --glue (or GLUE_CONTRACT_ADDRESS)")
                    })?
                    .parse()
                    .context("--glue is not a valid address")?;
                self_signed_recovery("withdraw", &session_id, &rpc_url, glue, signer).await?;
                return Ok(());
            }

            println!("Withdrawing funds for session {}...", session_id);

            let resp: OfframpResponse = client
                .post(format!("{}/offramp/{}/withdraw", cli.coordinator, session_id))
                .header(SIGNATURE_HEADER, sign_for(&signer, "withdraw", &session_id)?)
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
