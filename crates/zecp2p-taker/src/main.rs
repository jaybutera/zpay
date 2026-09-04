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
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zecp2p_types::abi::{usd_currency_code, venmo_payment_method};
use zecp2p_taker::{
    auto::{
        attest::{AttestRequest, AttestationFile, Attester},
        cookie::CookieStore,
        daemon::{require_usable_session, Confirm, FillPlan, FixedConfirm, Outcome, TerminalConfirm},
        intent::{IntentReader, IntentTerms},
        journal::{FillRecord, FillState, Journal},
        money::payment_cents,
        pipeline::Gate,
        rail::WorkId,
        watch::{GlueDeposit, WatchConfig, Watcher},
    },
    abi::IEscrowTaker,
    claim::Claimer,
    config::TakerConfig,
    proof::load_proof,
    venmo::{PaymentRequest, SendMode, VenmoBrowser},
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

    /// Report the Venmo session's health and what the daemon could do about it.
    ///
    /// Runs one health check and prints the answer, plus whether an expiry
    /// could be repaired without a human. Use it after filling in
    /// `config/venmo.local.toml` to find out whether the daemon will actually
    /// survive an expiry before trusting it to run overnight.
    ///
    /// With `--relogin` it drives the login form for real, which types the
    /// configured password into Venmo's sign-in page. Without it, nothing is
    /// typed and nothing is clicked.
    VenmoHealth {
        /// Actually attempt a sign-in if the session is dead.
        #[arg(long)]
        relogin: bool,
    },

    /// Re-derive an attestation for an intent whose payment is already sent.
    ///
    /// The daemon's own attestation path, run against an intent that already
    /// exists. It reads the intent's terms from chain (from the IntentSignaled
    /// log when the intent has been fulfilled and pruned), builds the prover
    /// environment from those terms, and asks the enclave.
    ///
    /// This spends the Venmo cookie and nothing else: no transaction is sent,
    /// no fiat moves, and `fulfillIntent` is never called. It exists to prove
    /// the pipeline reproduces an attestation a human obtained by hand, which
    /// is the only way to validate the fill path without paying for a new one.
    Attest {
        /// The intent to bind the attestation to.
        #[arg(long)]
        intent: String,
        /// Where to write it.
        #[arg(long, default_value = "attestation.json")]
        out: String,
        /// Which entry of the Venmo feed. 0 is the most recent.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// How far back to look for the IntentSignaled log.
        #[arg(long, default_value_t = 50_000)]
        lookback: u64,
        /// Compare the result against an attestation obtained earlier.
        ///
        /// Reports field by field whether the two bind the same intent, the
        /// same release amount and the same enclave signer.
        #[arg(long)]
        compare: Option<String>,
        /// The deposit's payee hash, when the deposit itself no longer has one.
        ///
        /// A deposit that was fully drained and closed reads back as a zero
        /// struct, so a settled intent cannot recover its payee from chain.
        /// The enclave still needs it: it binds the attestation to the account
        /// that was actually paid.
        #[arg(long)]
        payee_hash: Option<String>,
    },

    /// Phase 1: watch our glue and drive a fill, stopping at each money step.
    ///
    /// The whole loop, with a human at the two irreversible steps. Everything
    /// that can fail for free runs before the first prompt.
    Auto {
        /// Report what would happen and stop before every gate.
        #[arg(long)]
        dry_run: bool,
        /// Fill only sessions opened by this address.
        ///
        /// Self-service. Without it the daemon serves every session our glue
        /// created, which means fronting fiat for strangers.
        #[arg(long)]
        only_user: Option<String>,
        /// Pay this Venmo username rather than asking the coordinator.
        #[arg(long)]
        recipient: Option<String>,
        /// Scan this many blocks back on the first pass.
        #[arg(long)]
        lookback: Option<u64>,
        /// Scan once and exit rather than looping.
        #[arg(long)]
        once: bool,
        /// Answer both money gates yes, with no terminal input.
        ///
        /// This is phase 2: the daemon signals, pays Venmo, attests and
        /// fulfils without stopping. The cap, the payee check, the amount
        /// readback in the browser and the journal are what stand between a
        /// bad value and a real payment; there is no human left to catch it.
        /// `--only-user` is strongly advised with this, or the daemon will
        /// front fiat for strangers unattended.
        #[arg(long)]
        yes: bool,
    },

    /// Drive the real Venmo payment page for an amount, stopping before the send.
    ///
    /// This is the test the unit tests cannot be: it navigates the live DOM,
    /// waits for the real selectors, fills the React-controlled amount field and
    /// reads the value back out of the page, then stops. Every step of a live
    /// payment runs except the click, so a stale selector or a silently
    /// discarded React input fails here rather than during a real fill.
    TestPay {
        /// Venmo username to open a payment to, without the leading @.
        #[arg(long)]
        recipient: String,
        /// The amount to type, as Venmo's field expects it ("1.00").
        #[arg(long)]
        amount: String,
        /// Actually click send. Real money leaves, bound to no intent.
        ///
        /// Without this the run stops at the button, which tests every step
        /// except the click. With it the payment is real and there is no escrow
        /// behind it to release anything back: this is the browser driver being
        /// exercised, not a fill.
        #[arg(long)]
        send_for_real: bool,
    },

    /// Ask the live feed which entry a payment is, without attesting anything.
    FindPayment {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: String,
        /// Only entries at or after this time, e.g. 2026-09-02T15:55:00.
        ///
        /// The same account pays the same handle the same dollar repeatedly, so
        /// amount and recipient alone are ambiguous. The daemon cuts at the
        /// intent's signal time; this is the manual equivalent.
        #[arg(long)]
        after: Option<String>,
    },

    /// Report both settlement rails' status side by side, and stop.
    ///
    /// Reads only. It says which rail holds the daemon's one in-flight slot,
    /// what each rail's journal has open, and whether the native escrow rail is
    /// configured at all. Nothing is signalled, staked, paid or broadcast.
    Rails {
        /// Also read the configured Zcash node for each watched escrow's state.
        ///
        /// Without this the report is journal-only and touches no network.
        #[arg(long)]
        check_chain: bool,
    },

    /// Watch one native-escrow trade and report what the rail would do.
    ///
    /// The Zcash counterpart of `terms`: it reads the escrow off the chain,
    /// asks `zecp2p-escrow`'s own state machine what state it is in, and prints
    /// the fiat leg that would be paid. It sends no money and broadcasts
    /// nothing, so it is the dry run for the second rail.
    ZecWatch {
        /// The funding transaction, in the order an explorer prints it.
        #[arg(long)]
        txid: String,
        #[arg(long, default_value_t = 0)]
        vout: u32,
        /// The refund height `T` burned into the redeem script.
        #[arg(long)]
        refund_height: u64,
        /// The escrow's value in zatoshi.
        #[arg(long)]
        amount_zat: u64,
        /// The user's public key from the redeem script, 33 bytes of hex.
        #[arg(long)]
        u_pub: String,
        /// The LP's public key from the redeem script, 33 bytes of hex.
        #[arg(long)]
        l_pub: String,
        /// What the LP owes, in 6-decimal USD.
        #[arg(long)]
        usd_6dec: u64,
        /// The quoted rate, scaled by 1e18.
        #[arg(long, default_value_t = 1_000_000_000_000_000_000)]
        rate_18dec: u128,
        /// The curator's hashedOnchainId for the payee.
        #[arg(long)]
        payee_hash: String,
        /// The Venmo handle behind that hash. Checked against the curator.
        #[arg(long)]
        recipient: String,
        /// When the escrow reached its confirmation depth, in ms.
        ///
        /// The enclave's snapshot and the cut for the feed search. `paid_path`
        /// prints it; passing a different value here produces a different
        /// intent hash and an attestation that releases nothing.
        #[arg(long)]
        lock_confirmed_ms: u64,
        /// The platform fee in zatoshis, to reproduce an escrow that was
        /// announced under a different treasury from this build's.
        ///
        /// Normally omitted. The fee and the treasury script are *derived* from
        /// the pinned constant in `zecp2p_escrow::treasury` and this rail's
        /// configured network, exactly as the user's client derives them, so a
        /// watch that supplies neither watches the escrow the client built.
        /// Supplying them is for reproducing a recorded run - an escrow
        /// announced before a treasury rotation, say - and both must be given
        /// together, since a fee with no destination cannot be paid.
        #[arg(long, requires = "treasury_script")]
        platform_fee_zat: Option<u64>,
        /// The treasury scriptPubKey, hex. Only with --platform-fee-zat.
        #[arg(long, requires = "platform_fee_zat")]
        treasury_script: Option<String>,
        /// Treat the user's pre-signature as verified.
        ///
        /// The escrow crate refuses to reach `ReadyToPay` without it. This flag
        /// exists so a watch can report the state a verified escrow would be
        /// in; it does not verify anything, and the real run gets this from the
        /// announce step's own record.
        #[arg(long)]
        assume_presigned: bool,
    },

    /// Report an intent's terms as the daemon reads them, and stop.
    ///
    /// Touches no cookie and sends nothing. Useful for checking what the
    /// attestation would be built from before spending a session on it.
    Terms {
        #[arg(long)]
        intent: String,
        #[arg(long, default_value_t = 50_000)]
        lookback: u64,
    },
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

    // The session report needs no key: it reads the browser and, with
    // --relogin, drives the login form. Neither sends a transaction.
    if let Commands::VenmoHealth { relogin } = &cli.command {
        return run_venmo_health(&config, *relogin).await;
    }

    // Driving the payment page needs no key either: it stops before the click
    // and sends nothing on-chain.
    if let Commands::TestPay {
        recipient,
        amount,
        send_for_real,
    } = &cli.command
    {
        return run_test_pay(&config, recipient, amount, *send_for_real).await;
    }
    // Both rail reports are read-only and need no key. `rails` reads the
    // journal and, with --check-chain, the Zcash node; `zec-watch` reads the
    // Zcash node and the curator. Neither sends a transaction on either chain
    // and neither touches the Venmo cookie.
    if let Commands::Rails { check_chain } = &cli.command {
        return run_rails(&config, *check_chain).await;
    }
    if let Commands::ZecWatch { .. } = &cli.command {
        return run_zec_watch(&config, &cli.command).await;
    }

    if let Commands::FindPayment {
        recipient,
        amount,
        after,
    } = &cli.command
    {
        let after = match after {
            Some(text) => Some(
                chrono::NaiveDateTime::parse_from_str(text.trim(), "%Y-%m-%dT%H:%M:%S")
                    .context("--after wants a naive time like 2026-09-02T15:55:00")?
                    .and_utc(),
            ),
            None => None,
        };
        return run_find_payment(&config, recipient, amount, after).await;
    }

    // Attest and Terms are read-only and need no key: they read the chain and,
    // for Attest, the enclave. Neither sends a transaction. Requiring a funded
    // key to reproduce an attestation would mean the safest command in this
    // binary had the same prerequisites as the one that moves money.
    match &cli.command {
        Commands::Terms { intent, lookback } => {
            let provider = ProviderBuilder::new().connect_http(config.network.base_rpc_url.parse()?);
            let terms = read_terms(&provider, &config, intent, *lookback).await?;
            print_terms(&terms);
            return Ok(());
        }
        Commands::Attest {
            intent,
            out,
            index,
            lookback,
            compare,
            payee_hash,
        } => {
            let provider = ProviderBuilder::new().connect_http(config.network.base_rpc_url.parse()?);
            return run_attest(
                &provider,
                &config,
                intent,
                out,
                *index,
                *lookback,
                compare.as_deref(),
                payee_hash.as_deref(),
            )
            .await;
        }
        _ => {}
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
        Commands::CheckVenmo
        | Commands::VenmoHealth { .. }
        | Commands::TestPay { .. }
        | Commands::FindPayment { .. }
        | Commands::Rails { .. }
        | Commands::ZecWatch { .. } => {
            unreachable!("handled above")
        }

        Commands::Run { dry_run, recipient } => {
            // R5-2: `TakerAgent` pays through the browser with no journal read
            // and no journal write, so it cannot see the coordinator's claim and
            // the coordinator cannot see its. `--dry-run` still works: it drives
            // the page and stops at the irreversible step.
            if !dry_run {
                return refuse_ungated_live_payment("run", "auto");
            }
            // Only reachable with `--dry-run`, by the refusal above.
            let mode = SendMode::DryRun;
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

        Commands::Auto {
            dry_run,
            only_user,
            recipient,
            lookback,
            once,
            yes,
        } => {
            let only_user = match only_user {
                Some(a) => Some(a.parse::<alloy::primitives::Address>().context(
                    "--only-user is not an address",
                )?),
                None => None,
            };
            if only_user.is_none() {
                tracing::warn!(
                    "no --only-user: this daemon will serve every session our glue \
                     created, not just its operator's. That is the serve-others \
                     posture and it fronts real fiat for strangers."
                );
            }
            let watcher = Watcher::new(
                provider.clone(),
                WatchConfig {
                    glue: config.contracts.glue_contract,
                    only_user,
                    lookback_blocks: lookback.unwrap_or(config.taker.lookback_blocks),
                },
            );
            run_auto(&provider, &config, &watcher, taker, dry_run, recipient, once, yes).await?;
        }

        Commands::Terms { .. } | Commands::Attest { .. } => unreachable!("handled above"),
    }

    Ok(())
}

fn format_usdc(amount: U256) -> String {
    let units: u128 = amount.to::<u128>();
    format!("{}.{:06}", units / 1_000_000, units % 1_000_000)
}


/// Read an intent's terms the way the daemon does.
async fn read_terms<P: alloy::providers::Provider>(
    provider: &P,
    config: &TakerConfig,
    intent: &str,
    lookback: u64,
) -> Result<IntentTerms> {
    let intent_hash: B256 = intent.parse().context("intent hash is not a 32-byte hex")?;
    let reader = IntentReader::new(
        provider,
        config.contracts.zkp2p_orchestrator,
        config.contracts.zkp2p_escrow,
    );
    reader.terms(intent_hash, lookback).await
}

fn print_terms(terms: &IntentTerms) {
    println!("intent      : {}", terms.intent_hash);
    println!("deposit     : {}", terms.deposit_id);
    println!("amount      : {} units", terms.amount);
    println!("rate        : {}", terms.conversion_rate);
    println!("timestamp   : {} ({} ms)", terms.timestamp, terms.timestamp_ms());
    println!("payee hash  : {}", terms.payee_hash);
    if terms.block_number > 0 {
        println!("signalled at: block {}", terms.block_number);
    }
}

/// Drive the real payment page and stop before the send button.
///
/// Exists because every other test of this path asserts over generated strings.
/// The selectors in `venmo.rs` are guesses at Venmo's markup until something
/// runs them against the page, and `PaymentStep::Fill` sets a React-controlled
/// input, which is the failure that silently does nothing. This runs the live
/// Refuses a live payment from a path that does not take the payment slot.
///
/// R5-2: two subcommands drove the browser with no journal read and no journal
/// write - `run`, whose whole purpose is to claim and pay, and `test-pay
/// --send-for-real`. The slot is what stops this taker and
/// `zecp2p-v2coordinator` paying the same Venmo account at the same time, and
/// the config comments told operators the two programs were bound. For these
/// paths that was false.
///
/// Rather than thread a journal through the agent - which would be a second
/// implementation of a gate that already exists in `handle_one` - these paths
/// refuse in `Live` mode and name the one that is gated. A payer that cannot
/// take the slot must not send money.
fn refuse_ungated_live_payment(command: &str, gated: &str) -> Result<()> {
    bail!(
        "`{command}` sends money without taking the payment slot, and this build \
         shares that slot with zecp2p-v2coordinator through the fill journal \
         (taker.journal_path). A payer that does not read the journal can pay the \
         same Venmo account while the other daemon is paying it, and two identical \
         entries in the feed cannot be told apart afterwards.\n\n\
         Use `{gated}`, which reads the slot, claims it before the click, and \
         records what happened. `{command} --dry-run` still drives the page \
         without sending."
    )
}

/// sequence with the irreversible step removed, so both failures surface here.
async fn run_test_pay(
    config: &TakerConfig,
    recipient: &str,
    amount: &str,
    send_for_real: bool,
) -> Result<()> {
    // Refuse a malformed amount before opening a payment page for it.
    let cents = zecp2p_taker::venmo::amount_matches(amount, amount);
    if !cents {
        bail!("{amount:?} is not an amount Venmo's field would accept");
    }
    let claimed = zecp2p_taker::payee::validate_username_shape(recipient)?.to_string();

    // R5-2. Refused before the browser opens, so the refusal costs nothing.
    if send_for_real {
        return refuse_ungated_live_payment("test-pay --send-for-real", "auto");
    }

    let browser = VenmoBrowser::new(config.venmo.cdp_url.clone(), config.venmo.timeout_seconds);
    let tab = browser
        .find_venmo_tab()
        .await
        .context("no Venmo tab; start Chrome with --remote-debugging-port=9222 and sign in")?;
    println!("tab        : {}", tab.url);
    if !VenmoBrowser::session_looks_live(&tab) {
        bail!("the Venmo tab at {} looks signed out", tab.url);
    }

    let request = PaymentRequest {
        recipient: claimed.clone(),
        amount: amount.to_string(),
        note: config.venmo.note.clone(),
    };

    println!("\nsteps this would run for ${amount} to @{claimed}:");
    for step in browser.payment_steps(&request) {
        println!("  {}", step.describe());
    }

    let mode = if send_for_real {
        // The cap still applies: it is the one guard that does not depend on the
        // page behaving, and it refuses rather than clamps.
        let cents = zecp2p_taker::auto::money::payment_cents(
            alloy::primitives::U256::from(
                amount.replace('.', "").parse::<u64>().unwrap_or(u64::MAX),
            ) * alloy::primitives::U256::from(10_000u64),
            alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
            config.taker.max_payment_cents,
        )?;
        println!("\nSENDING FOR REAL: ${cents} to @{claimed}\n");
        SendMode::Live
    } else {
        println!("\ndriving the page (DryRun: the send button is never clicked)\n");
        SendMode::DryRun
    };

    match browser.pay(&tab, &request, mode).await? {
        zecp2p_taker::venmo::PaymentOutcome::WouldHaveSent { recipient, amount } => {
            println!(
                "PASS: the page accepted ${amount} to @{recipient}, the recipient \
                 matched, and the amount read back out of the field."
            );
            println!("Nothing was sent.");
        }
        zecp2p_taker::venmo::PaymentOutcome::Sent { recipient, amount } => {
            if !send_for_real {
                bail!("a dry run reported a send; this is a bug and money may have moved");
            }
            println!("SENT: ${amount} to @{recipient}");
        }
    }
    Ok(())
}

/// Reproduce an attestation for an intent whose payment is already sent.
///
/// Sends the cookie and nothing else. No transaction, no fiat, no fulfilment.
async fn run_attest<P: alloy::providers::Provider>(
    provider: &P,
    config: &TakerConfig,
    intent: &str,
    out: &str,
    index: u32,
    lookback: u64,
    compare: Option<&str>,
    payee_override: Option<&str>,
) -> Result<()> {
    let mut terms = read_terms(provider, config, intent, lookback).await?;

    // A settled order's deposit is closed and carries no payee, so the operator
    // supplies it. Checked against the deposit when the deposit still has one:
    // an override that disagrees with the chain is the case where a wrong
    // handle gets attested, and it is refused rather than preferred.
    if let Some(supplied) = payee_override {
        let supplied: B256 = supplied
            .parse()
            .context("--payee-hash is not a 32-byte hex value")?;
        if !terms.payee_hash.is_zero() && terms.payee_hash != supplied {
            anyhow::bail!(
                "--payee-hash is {supplied} but deposit {} carries {}. \
                 Refusing to attest against a payee the deposit disagrees with.",
                terms.deposit_id,
                terms.payee_hash
            );
        }
        terms.payee_hash = supplied;
    }
    if terms.payee_hash.is_zero() {
        anyhow::bail!(
            "the deposit carries no payee hash, so it has been withdrawn or closed. \
             Pass --payee-hash with the curator's hashedOnchainId for the account \
             that was paid; the enclave binds the attestation to it."
        );
    }

    print_terms(&terms);

    // The health check runs here for the same reason the pipeline runs it
    // before signalling: failing on a dead cookie should cost nothing.
    let store = CookieStore::new(&config.session.path, config.session.max_age_hours)
        .with_identity(
            config.session.sender_id.clone(),
            config.session.user_agent.clone(),
        );
    let health = store.health()?;
    if !health.is_usable() {
        anyhow::bail!("{}", health.explain());
    }
    let material = store
        .load()?
        .ok_or_else(|| anyhow::anyhow!("no session material at {}", config.session.path))?;
    println!("session     : {material}");

    let request = AttestRequest {
        intent_hash: terms.intent_hash,
        amount: terms.amount,
        conversion_rate: terms.conversion_rate,
        timestamp_ms: terms.timestamp_ms(),
        payee_hash: terms.payee_hash,
        payment_index: index,
    };

    let root = repo_root()?;
    let attester = Attester::new(
        &root,
        config.attestation.service_url.clone(),
        config.attestation.verifier.to_string(),
        config.network.chain_id,
    );

    println!("\nasking the enclave; this sends the cookie and nothing else\n");
    let file = attester
        .attest(&request, &material, std::path::Path::new(out))
        .await?;

    println!("\n=== ATTESTATION ===");
    println!("signer        : {}", file.attestation.signer);
    println!("intentHash    : {}", file.attestation.typed_data_value.intent_hash);
    println!("releaseAmount : {}", file.attestation.typed_data_value.release_amount);
    println!("dataHash      : {}", file.attestation.typed_data_value.data_hash);
    println!("signature     : {}", file.attestation.signature);
    println!("wrote {out}");

    if let Some(reference) = compare {
        compare_attestations(&file, reference)?;
    }

    println!("\nNo transaction was sent. fulfillIntent was not called.");
    Ok(())
}

/// Compare a fresh attestation against one obtained earlier.
///
/// The signature itself is not expected to match byte for byte: the enclave
/// signs over a `dataHash` that commits to the snapshot it just took, and two
/// reads of a live Venmo feed are not the same bytes. What must match is what
/// the verifier checks: the intent it is bound to, the amount it releases, and
/// the enclave that signed it.
fn compare_attestations(fresh: &AttestationFile, reference_path: &str) -> Result<()> {
    let contents = std::fs::read_to_string(reference_path)
        .with_context(|| format!("could not read the reference at {reference_path}"))?;
    let reference: AttestationFile =
        serde_json::from_str(&contents).context("the reference is not an attestation file")?;

    let rows: [(&str, String, String); 6] = [
        (
            "intentHash",
            fresh.attestation.typed_data_value.intent_hash.clone(),
            reference.attestation.typed_data_value.intent_hash.clone(),
        ),
        (
            "releaseAmount",
            fresh.attestation.typed_data_value.release_amount.clone(),
            reference.attestation.typed_data_value.release_amount.clone(),
        ),
        (
            "dataHash",
            fresh.attestation.typed_data_value.data_hash.clone(),
            reference.attestation.typed_data_value.data_hash.clone(),
        ),
        (
            "signer",
            fresh.attestation.signer.to_lowercase(),
            reference.attestation.signer.to_lowercase(),
        ),
        (
            "domainSeparator",
            fresh.attestation.domain_separator.clone(),
            reference.attestation.domain_separator.clone(),
        ),
        (
            "chainId",
            fresh.chain_id.to_string(),
            reference.chain_id.to_string(),
        ),
    ];

    println!("\n=== COMPARISON against {reference_path} ===");
    let mut mismatched = Vec::new();
    for (field, a, b) in &rows {
        let same = a == b;
        println!(
            "{:<16} {}  {}",
            field,
            if same { "MATCH" } else { "DIFFER" },
            if same { a.clone() } else { format!("{a} vs {b}") }
        );
        if !same {
            mismatched.push(*field);
        }
    }

    // Bytewise equality of the signature is not required and not expected: the
    // dataHash commits to a fresh snapshot of a live feed.
    let signature_identical = fresh.attestation.signature == reference.attestation.signature;
    println!(
        "{:<16} {}",
        "signature",
        if signature_identical {
            "IDENTICAL"
        } else {
            "differs (expected: a fresh snapshot has its own dataHash)"
        }
    );

    // These three are what UnifiedPaymentVerifierV3 actually checks.
    let semantic = ["intentHash", "releaseAmount", "signer"];
    let broken: Vec<_> = mismatched
        .iter()
        .filter(|f| semantic.contains(f))
        .collect();
    if broken.is_empty() {
        println!(
            "\nVERDICT: semantically identical. Same intent, same release amount, \n\
             same enclave signer. The pipeline reproduced the manual attestation."
        );
    } else {
        anyhow::bail!(
            "VERDICT: the reproduction differs on {:?}, which is what the verifier \
             checks. The pipeline did not reproduce the manual attestation.",
            broken
        );
    }
    Ok(())
}

/// The repository root, so the prover path resolves from anywhere.
/// Report both settlement rails side by side.
///
/// The command an operator runs to answer "what is this daemon doing". Both
/// systems are live at once, so a per-rail report is not enough on its own: the
/// in-flight slot is global, because two open payments draw on one Venmo
/// balance whichever chain settles them.
async fn run_rails(config: &TakerConfig, check_chain: bool) -> Result<()> {
    use zecp2p_taker::auto::rail::Rail;

    let journal = Journal::open(config.taker.journal_path())?;
    let records = journal.latest()?;

    println!("journal : {}", config.taker.journal_path());
    println!();

    for rail in Rail::all() {
        let configured = match rail {
            Rail::Base => true,
            Rail::Zec => config.zec.is_some(),
        };
        println!("== {rail} ==");
        if !configured {
            // Silence in the config means off, and saying so is the point:
            // a second settlement system that switched itself on because a
            // section was missing would be watching a chain nobody set up.
            println!("  not configured. Add a [zec] section to run this rail.");
            println!();
            continue;
        }
        println!("  locks   {}", rail.collateral());

        let mine: Vec<_> = records.iter().filter(|r| r.rail == rail).collect();
        if mine.is_empty() {
            println!("  no fills recorded");
        }
        for record in &mine {
            println!(
                "  {:<34} {:?}{}",
                record.describe(),
                record.state,
                match &record.paid {
                    Some(amount) => format!("  paid ${amount} to @{}", record.recipient),
                    None => String::new(),
                }
            );
            if let Some(note) = &record.note {
                println!("      note: {note}");
            }
        }
        println!();
    }

    // The slot is global on purpose. A report that showed it per rail would
    // suggest the two can run concurrently, and they cannot: one Venmo balance.
    match journal.in_flight()? {
        Some(record) => println!(
            "the one in-flight slot is held by {} ({:?})",
            record.describe(),
            record.state
        ),
        None => println!("the in-flight slot is free; either rail may start work"),
    }

    let stuck = journal.needs_operator()?;
    if !stuck.is_empty() {
        println!();
        println!("{} fill(s) need an operator before anything else moves:", stuck.len());
        for record in &stuck {
            println!(
                "  {} is {:?}: ${} to @{}",
                record.describe(),
                record.state,
                record.paid.clone().unwrap_or_else(|| "?".into()),
                record.recipient
            );
        }
        println!();
        println!(
            "the journal is written before the send button, so a Paying record may or \n\
             may not have gone out. Check the Venmo feed."
        );
    }

    if check_chain {
        match &config.zec {
            Some(zec) => {
                println!();
                // The escrow crate's chain client is blocking, by design: it is
                // shared with `paid_path`, which is a synchronous tool. Calling
                // it directly from this runtime panics the moment it blocks, so
                // every use of it here goes through `spawn_blocking`.
                let rpc = zec.rpc_config()?;
                let (height, branch) = tokio::task::spawn_blocking(move || {
                    let chain = zecp2p_escrow::rpc::RpcChainClient::new(rpc)?;
                    let height = zecp2p_escrow::chain::ChainClient::height(&chain)?;
                    let branch = zecp2p_escrow::chain::ChainClient::consensus_branch_id(&chain)?;
                    Ok::<_, zecp2p_escrow::chain::ChainError>((height, branch))
                })
                .await
                .context("the Zcash node read did not complete")?
                .map_err(|e| anyhow::anyhow!("could not read the Zcash node: {e}"))?;
                println!("zcash node: height {height}, consensus branch {branch:#x}");
                let policy = zec.policy()?;
                println!(
                    "policy    : refund after {} blocks, no paying inside the last {}, \
                     broadcast by {} before T",
                    policy.refund_delay_blocks,
                    policy.pay_deadline_blocks,
                    policy.broadcast_deadline_blocks
                );
            }
            None => println!("\n--check-chain: the zec rail is not configured, nothing to read"),
        }
    }

    Ok(())
}

/// Read one native escrow off the chain and report what the rail would do.
///
/// The dry run for the second settlement system. It calls the escrow crate's
/// own `evaluate` through `auto::zec`, so what it reports is what a live run
/// would act on rather than a second opinion about it.
async fn run_zec_watch(config: &TakerConfig, command: &Commands) -> Result<()> {
    let Commands::ZecWatch {
        txid,
        vout,
        refund_height,
        amount_zat,
        u_pub,
        l_pub,
        usd_6dec,
        rate_18dec,
        payee_hash,
        recipient,
        lock_confirmed_ms,
        platform_fee_zat,
        treasury_script,
        assume_presigned,
    } = command
    else {
        unreachable!("run_zec_watch is only called for ZecWatch")
    };

    let zec = config.zec.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "the native escrow rail is not configured. Add a [zec] section with \
             rpc_url, network and attestor_url before watching an escrow."
        )
    })?;

    let policy = zec.policy()?;

    // The wire format keeps txids in internal order; an explorer prints the
    // reverse. The operator pastes the explorer's, so it is converted here
    // rather than expecting them to reverse it by hand.
    let funding_txid = zecp2p_escrow::rpc::rpc_hex_to_txid(txid.trim())
        .map_err(|e| anyhow::anyhow!("--txid is not a transaction id: {e}"))?;

    let parse_key = |name: &str, text: &str| -> Result<[u8; 33]> {
        let bytes = hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
            .with_context(|| format!("{name} is not hex"))?;
        <[u8; 33]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("{name} must be a 33-byte compressed public key"))
    };
    let u_pub = parse_key("--u-pub", u_pub)?;
    let l_pub = parse_key("--l-pub", l_pub)?;

    let payee_bytes = hex::decode(
        payee_hash
            .trim()
            .strip_prefix("0x")
            .unwrap_or(payee_hash.trim()),
    )
    .context("--payee-hash is not hex")?;
    let payee_bytes = <[u8; 32]>::try_from(payee_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("--payee-hash must be 32 bytes"))?;

    // The branch id is read from the node rather than assumed. A stale value
    // produces a sighash nobody will accept, and the pre-signature was made
    // against the branch in force when it was drawn.
    //
    // Blocking, like every other call into the escrow crate's chain client, so
    // it runs off this runtime's reactor rather than panicking on it.
    let rpc = zec.rpc_config()?;
    let consensus_branch_id = tokio::task::spawn_blocking({
        let rpc = rpc.clone();
        move || {
            let chain = zecp2p_escrow::rpc::RpcChainClient::new(rpc)?;
            zecp2p_escrow::chain::ChainClient::consensus_branch_id(&chain)
        }
    })
    .await
    .context("the branch id read did not complete")?
    .map_err(|e| anyhow::anyhow!("could not read the consensus branch id: {e}"))?;

    let terms = zecp2p_escrow::tx::EscrowTerms {
        funding_txid,
        vout: *vout,
        amount_zat: *amount_zat,
        u_pub,
        l_pub,
        refund_height: *refund_height,
        consensus_branch_id,
    };

    // The payee hash is checked against the curator before anything else, on
    // the same principle the Base rail applies: the handle a human typed and
    // the hash the terms committed to must be the same account, or the payment
    // goes somewhere the attestation will not release for.
    let claimed = zecp2p_taker::payee::validate_username_shape(recipient)?.to_string();
    let resolved = zecp2p_taker::payee::curator_hash_for(
        &reqwest::Client::new(),
        &config.zkp2p.api_url,
        &claimed,
    )
    .await
    .context("could not check the username against the zk-p2p curator")?;
    zecp2p_taker::payee::require_match(
        &claimed,
        resolved,
        alloy::primitives::B256::from(payee_bytes),
    )?;
    println!("payee   : @{claimed} matches the terms' payee hash");

    // Derived, not defaulted. `clap`'s `requires` makes the pair all-or-nothing,
    // so the only two shapes that reach here are "both given" and "neither".
    let (platform_fee_zat, treasury_script) = match (platform_fee_zat, treasury_script) {
        (Some(fee), Some(script)) => {
            println!(
                "fee     : {fee} zat to a treasury supplied on the command line, \
                 reproducing a recorded run"
            );
            (
                *fee,
                hex::decode(script.trim_start_matches("0x"))
                    .context("--treasury-script is not hex")?,
            )
        }
        _ => {
            // The same policy site the user's client uses: the rate from
            // `treasury::PLATFORM_FEE_BPS`, the address from the constant
            // pinned for this network. If the two disagree the terms hash
            // differs and the escrow this watch reports on is not the one the
            // user funded, which is why nothing here guesses.
            let quote = zecp2p_escrow::client::AcceptedQuote::at_identity_rate(
                *usd_6dec,
                payee_bytes,
                terms.refund_height,
                terms.l_pub,
                terms.amount_zat,
                match zec.network()? {
                    zecp2p_escrow::rpc::Network::Main => {
                        zecp2p_escrow::address::AddrNetwork::Main
                    }
                    zecp2p_escrow::rpc::Network::Test => {
                        zecp2p_escrow::address::AddrNetwork::Test
                    }
                },
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "this escrow cannot be quoted, so its terms cannot be rebuilt: {e}. \
                     If it was announced under a different treasury, pass \
                     --platform-fee-zat and --treasury-script to reproduce it."
                )
            })?;
            if quote.platform_fee_zat() > 0 {
                println!(
                    "fee     : {} zat to the pinned treasury",
                    quote.platform_fee_zat()
                );
            }
            (quote.platform_fee_zat(), quote.treasury_script().to_vec())
        }
    };

    let canonical = zecp2p_taker::auto::zec::canonical_terms(
        &terms,
        *usd_6dec,
        *rate_18dec,
        payee_bytes,
        *lock_confirmed_ms,
        platform_fee_zat,
        treasury_script,
    )?;

    let escrow = zecp2p_taker::auto::zec::WatchedEscrow {
        terms,
        canonical,
        recipient: claimed,
        pre_signature_verified: *assume_presigned,
        venmo_paid: false,
        outcome_secret_held: false,
    };

    println!("escrow  : {}", escrow.work_id());
    println!("value   : {} zat", escrow.terms.amount_zat);
    println!("T       : {}", escrow.terms.refund_height);
    println!("branch  : {consensus_branch_id:#x}");
    println!(
        "intent  : 0x{}",
        hex::encode(escrow.canonical.intent_hash())
    );
    if !assume_presigned {
        println!(
            "note    : --assume-presigned was not passed, so this reports the state of \n\
             \x20         an escrow whose pre-signature has not verified. The escrow crate \n\
             \x20         refuses to reach ReadyToPay without it."
        );
    }
    println!();

    let state = {
        let escrow = escrow.clone();
        let cap = config.taker.max_payment_cents;
        tokio::task::spawn_blocking(move || {
            let chain = zecp2p_escrow::rpc::RpcChainClient::new(rpc)
                .map_err(|e| anyhow::anyhow!("could not reach the Zcash node: {e}"))?;
            zecp2p_taker::auto::zec::state_of(&chain, &escrow, &policy, cap)
        })
        .await
        .context("the escrow state read did not complete")??
    };

    use zecp2p_taker::auto::rail::RailState;
    match &state {
        RailState::Waiting { why } => println!("state   : waiting\n          {why}"),
        RailState::ReadyToPay(leg) => {
            println!("state   : READY TO PAY");
            println!("          ${} to @{}", leg.payment, leg.recipient);
            println!("          feed entries before {} are not this payment", leg.not_before);
            println!();
            println!("the prover environment this escrow needs:");
            for (key, value) in zecp2p_taker::auto::fiat::prover_environment(leg) {
                println!("  {key:<20} {value}");
            }
            println!();
            println!("nothing was paid: this command is read-only.");
        }
        RailState::AwaitingSettlement(leg) => {
            println!("state   : paid, awaiting settlement");
            println!("          ${} to @{}", leg.payment, leg.recipient);
        }
        RailState::Settled { reference } => println!("state   : settled, {reference}"),
        RailState::NeedsOperator { why } => println!("state   : NEEDS AN OPERATOR\n          {why}"),
    }

    Ok(())
}

fn repo_root() -> Result<std::path::PathBuf> {
    // The binary runs from wherever the operator invoked it, and the prover is
    // addressed relative to the repo. CARGO_MANIFEST_DIR is compiled in and
    // points at the crate, which is two levels down.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("could not locate the repository root"))?;
    Ok(root.to_path_buf())
}


/// Phase 1's loop: watch, plan, and stop at each money-moving step.
///
/// The ordering is the design's, and it is the point: everything that can fail
/// for free runs before the first prompt. A cap breach, a payee mismatch, a
/// dead cookie or a curator refusal all stop the fill having spent nothing.
#[allow(clippy::too_many_arguments)]
async fn run_auto<P: alloy::providers::Provider + Clone>(
    provider: &P,
    config: &TakerConfig,
    watcher: &Watcher<P>,
    taker: alloy::primitives::Address,
    dry_run: bool,
    recipient_override: Option<String>,
    once: bool,
    auto_yes: bool,
) -> Result<()> {
    let journal = Journal::open(config.taker.journal_path())?;

    // A fill whose fiat may have left is not something to reason around. It is
    // read by a human before anything else moves.
    let stuck = journal.needs_operator()?;
    if !stuck.is_empty() {
        println!("\n{} fill(s) need an operator before the daemon can continue:\n", stuck.len());
        for record in &stuck {
            println!(
                "  deposit {} is {:?}: ${} to @{}",
                record.deposit_id,
                record.state,
                record.paid.clone().unwrap_or_else(|| "?".into()),
                record.recipient
            );
        }
        anyhow::bail!(
            "check the Venmo feed for these before restarting. The journal is \
             written before the send button, so a Paying record may or may not \
             have gone out."
        );
    }

    let store = CookieStore::new(&config.session.path, config.session.max_age_hours)
        .with_identity(
            config.session.sender_id.clone(),
            config.session.user_agent.clone(),
        );

    // The Venmo session supervisor, running on its own timer beside the fill
    // loop rather than inside it.
    //
    // `once` gets no supervisor: a single scan that exits has no long-lived
    // session to keep alive, and spawning a background task that outlives the
    // work is how a `--once` run stops being once.
    let session_health = if once {
        None
    } else {
        Some(spawn_session_supervisor(config).await?)
    };

    let mut from_block = watcher.start_block().await?;
    println!("watching glue {} from block {from_block}", config.contracts.glue_contract);
    if dry_run {
        println!("dry run: nothing will be signalled, staked or paid.");
    } else if auto_yes {
        println!(
            "--yes: both money gates are answered automatically. This run can \
             signal, stake, send a real Venmo payment and fulfil with no further \
             input."
        );
    }

    loop {
        let head = watcher.head().await?;
        if head >= from_block {
            let deposits = watcher.scan(from_block, head).await?;
            if deposits.is_empty() {
                tracing::debug!(from_block, head, "no zpay deposits in range");
            }
            // R4-a: a deposit that was refused for a reason that will pass
            // later - the payment slot is held, the session is not usable -
            // used to be dropped for the life of the process, because the
            // cursor moved past it whatever happened. Now the cursor rewinds to
            // the earliest such deposit, so the next poll sees it again.
            //
            // The slot being held is no longer a rare case: it covers the whole
            // of a coordinator trade, attestation included, which is minutes.
            let mut retry_from: Option<u64> = None;
            let mut remember = |block: u64| {
                retry_from = Some(retry_from.map_or(block, |b: u64| b.min(block)));
            };

            for deposit in deposits {
                match handle_one(
                    provider,
                    config,
                    &journal,
                    &store,
                    &deposit,
                    taker,
                    dry_run,
                    recipient_override.as_deref(),
                    auto_yes,
                    session_health.as_ref(),
                )
                .await
                {
                    Ok(outcome) => {
                        // `Skipped` and `Blocked` both mean "not now", and both
                        // can become "yes" without anything about the deposit
                        // changing. `Declined` is a human saying no, and
                        // `Paid`/`Fulfilled` are done.
                        if matches!(outcome, Outcome::Skipped { .. } | Outcome::Blocked { .. }) {
                            remember(deposit.block_number);
                        }
                        println!("deposit {}: {outcome:?}", deposit.deposit_id);
                    }
                    Err(e) => {
                        // An error before anything was spent is also worth
                        // another look: an RPC that failed once may not fail
                        // twice. A fill that got as far as paying has a journal
                        // record, and `handle_one` refuses to re-enter it.
                        remember(deposit.block_number);
                        println!("deposit {}: stopped: {e:#}", deposit.deposit_id);
                    }
                }
            }

            from_block = match retry_from {
                Some(block) => {
                    tracing::info!(
                        block,
                        "rewinding the scan cursor: a deposit was refused for a reason that \
                         may pass"
                    );
                    block
                }
                None => head + 1,
            };
        }

        if once {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            config.taker.poll_interval_seconds,
        ))
        .await;
    }
}

/// Report the session's health, and optionally repair it.
///
/// The one command an operator runs after filling in the credentials file, and
/// the answer it gives is the one that matters: whether this daemon can survive
/// an expiry on its own, or whether it will stop and wait for a person.
async fn run_venmo_health(config: &TakerConfig, relogin: bool) -> Result<()> {
    use zecp2p_taker::auto::health::{SessionDriver, Supervisor, Tick};

    let credentials = config
        .venmo_credentials()
        .context("the Venmo credentials file is present but not usable")?;

    match &config.venmo.credentials_path {
        Some(path) if credentials.is_some() => println!("credentials : {path}"),
        Some(path) => println!("credentials : {path} (not present)"),
        None => println!("credentials : none configured"),
    }

    let browser = std::sync::Arc::new(VenmoBrowser::new(
        config.venmo.cdp_url.clone(),
        config.venmo.timeout_seconds,
    ));

    let state = browser.probe().await;
    println!("session     : {}", state.summary());

    // Readiness is reported from the credentials as configured, so the line
    // says what the *daemon* would do rather than what this invocation will.
    // Building it from the withheld set would tell an operator who has
    // configured everything correctly that they have configured nothing.
    println!(
        "readiness   : {}",
        Supervisor::new(
            std::sync::Arc::new(VenmoBrowser::new(
                config.venmo.cdp_url.clone(),
                config.venmo.timeout_seconds,
            )),
            credentials.clone(),
        )
        .readiness()
    );

    // `--relogin` is what separates a report from an action, so the supervisor
    // that actually runs only gets credentials when the operator asked for one.
    // Without the flag this cannot type a password even if auto_relogin is set.
    let mut supervisor = Supervisor::new(browser, if relogin { credentials } else { None });

    if !relogin {
        if !state.is_live() {
            println!(
                "\nThe session is not usable. Re-run with --relogin to have the \n\
                 taker try to sign back in, or sign in by hand."
            );
        }
        return Ok(());
    }

    let tick = supervisor.check_once().await;
    println!("\nresult      : {tick:?}");
    match tick {
        Tick::Healthy => println!("The session was already fine; nothing was driven."),
        Tick::Recovered => println!("Signed back in. The session is live."),
        Tick::AwaitingHumanCode { what_to_do, .. } => {
            println!("{what_to_do}");
            std::process::exit(2);
        }
        other if other.needs_operator() => std::process::exit(1),
        _ => std::process::exit(1),
    }
    Ok(())
}

/// The last thing the session supervisor reported, shared with the fill loop.
///
/// The fill loop reads this rather than probing the browser itself. That is the
/// whole ordering the health check exists to establish: by the time a deposit
/// arrives, whether the session is usable is already known, instead of being
/// discovered with a trade in hand.
type SessionHealth = std::sync::Arc<std::sync::Mutex<zecp2p_taker::auto::health::Tick>>;

/// Start the session supervisor on its own task.
///
/// Returns the shared cell it publishes into. The task is detached and runs for
/// the life of the process, which is the point: a check that only ran when a
/// deposit arrived would be the thing this replaces.
async fn spawn_session_supervisor(config: &TakerConfig) -> Result<SessionHealth> {
    use zecp2p_taker::auto::health::{Supervisor, Tick};

    // Loaded at startup, so a credentials file that exists but is unusable
    // stops the daemon here rather than at the first expiry. A file that is
    // simply absent is not an error: that is the daemon this repository had
    // before, health-checking and reporting without repairing.
    let credentials = config
        .venmo_credentials()
        .context("the Venmo credentials file is present but not usable")?;

    let browser = std::sync::Arc::new(VenmoBrowser::new(
        config.venmo.cdp_url.clone(),
        config.venmo.timeout_seconds,
    ));
    let supervisor = Supervisor::new(browser, credentials);
    println!("venmo session: {}", supervisor.readiness());

    let shared: SessionHealth = std::sync::Arc::new(std::sync::Mutex::new(Tick::Healthy));
    let publish = shared.clone();
    tokio::spawn(async move {
        supervisor
            .run(move |tick| {
                if let Ok(mut slot) = publish.lock() {
                    *slot = tick.clone();
                }
            })
            .await
    });

    Ok(shared)
}

/// Refuse to start a fill while the session is known to be dead.
///
/// Checked alongside the cookie check rather than instead of it: they are
/// different credentials with different failure modes. The cookie is what the
/// enclave replays after the payment; the browser session is what sends it.
/// Either one dead means the fill cannot finish, and both are cheaper to find
/// here than after the money has left.
fn require_healthy_session(health: Option<&SessionHealth>) -> Result<()> {
    use zecp2p_taker::auto::health::Tick;

    let Some(health) = health else {
        return Ok(());
    };
    let tick = health.lock().map(|t| t.clone()).unwrap_or(Tick::Healthy);
    match &tick {
        Tick::Healthy | Tick::Recovered => Ok(()),
        // A first failed attempt is not a reason to refuse: the supervisor is
        // still retrying and the session may well be back before this fill
        // needs it. The states below are the ones that will not fix themselves.
        Tick::ReloginFailed { .. } => Ok(()),
        Tick::NeedsOperator { why, .. } => bail!(
            "the Venmo session is not usable and will not repair itself: {why}\n\n\
             Checked before signalling on purpose: failing here costs nothing."
        ),
        Tick::AwaitingHumanCode { what_to_do, .. } => bail!(
            "the Venmo re-login is waiting for a human: {what_to_do}\n\n\
             Nothing was signalled or paid."
        ),
        Tick::GaveUp { attempts } => bail!(
            "the Venmo session is dead after {attempts} failed sign-in attempts, and \
             the daemon has stopped trying to avoid locking the account. Sign in by \
             hand and restart."
        ),
    }
}

/// Plan one deposit and take it as far as the gates allow.
#[allow(clippy::too_many_arguments)]
async fn handle_one<P: alloy::providers::Provider + Clone>(
    provider: &P,
    config: &TakerConfig,
    journal: &Journal,
    store: &CookieStore,
    deposit: &GlueDeposit,
    taker: alloy::primitives::Address,
    dry_run: bool,
    recipient_override: Option<&str>,
    auto_yes: bool,
    session_health: Option<&SessionHealth>,
) -> Result<Outcome> {
    // The one payment slot, read per fill and not just at startup.
    //
    // The startup check in `run_auto` is a check on the state the daemon
    // inherited. It says nothing about what happens later, and "later" now
    // includes another process: `zecp2p-v2coordinator` pays from the same Venmo
    // account and writes the same journal. Without this, a running taker starts
    // a fill while the coordinator is mid-payment, and the feed ends up with two
    // entries of the same amount to the same handle - which is precisely what
    // `locate_payment` refuses to resolve, once both have left.
    //
    // The read is before the `Seen` write below, so a fill that cannot have the
    // slot leaves no trace and is retried on the next poll.
    let mine = WorkId::base(deposit.deposit_id);
    if let Some(holder) = journal.holder_against(&mine)? {
        return Ok(Outcome::Skipped {
            why: format!(
                "{} holds the one payment slot ({:?}). One payment at a time: there is \
                 one Venmo balance, and two entries of the same amount to the same \
                 handle cannot be told apart in the feed.",
                holder.describe(),
                holder.state
            ),
        });
    }

    // Everything free comes first. The cookie check is here rather than before
    // the attestation because a dead cookie found after the payment means the
    // fiat is gone and only cancelIntent recovers the stake.
    //
    // The browser session is checked in the same breath and for the same
    // reason. The supervisor already knows the answer, so this reads its last
    // report rather than asking the browser again.
    require_healthy_session(session_health)?;
    require_usable_session(store)?;

    let escrow = IEscrowTaker::new(config.contracts.zkp2p_escrow, provider);
    let onchain = escrow.getDeposit(deposit.deposit_id).call().await?;
    if onchain.remainingDeposits.is_zero() || !onchain.acceptingIntents {
        return Ok(Outcome::Skipped {
            why: format!(
                "deposit {} has nothing claimable left",
                deposit.deposit_id
            ),
        });
    }

    let rate = escrow
        .getDepositCurrencyMinRate(
            deposit.deposit_id,
            venmo_payment_method(),
            usd_currency_code(),
        )
        .call()
        .await
        .context("could not read the deposit's rate")?;

    let amount = onchain
        .intentAmountRange
        .max
        .min(onchain.remainingDeposits)
        .min(config.taker.max_intent_amount);

    // Priced and capped before the gas, the stake, and the prompt.
    let payment = payment_cents(amount, rate, config.taker.max_payment_cents)?;

    let recipient = match recipient_override {
        Some(r) => r.to_string(),
        None => bail!(
            "deposit {} needs a Venmo username. The chain carries only the \
             curator's opaque payee hash, so pass --recipient or configure a \
             coordinator.",
            deposit.deposit_id
        ),
    };

    // The payee check that makes a hostile coordinator harmless: the name is
    // hashed by the curator and compared against the deposit's own hash.
    let claimed = zecp2p_taker::payee::validate_username_shape(&recipient)?.to_string();
    let payee_data = escrow
        .getDepositPaymentMethodData(deposit.deposit_id, venmo_payment_method())
        .call()
        .await?;
    let resolved = zecp2p_taker::payee::curator_hash_for(
        &reqwest::Client::new(),
        &config.zkp2p.api_url,
        &claimed,
    )
    .await
    .context("could not check the username against the zk-p2p curator")?;
    zecp2p_taker::payee::require_match(&claimed, resolved, payee_data.payeeDetails)?;

    let terms = IntentTerms {
        intent_hash: alloy::primitives::B256::ZERO,
        deposit_id: deposit.deposit_id,
        amount,
        conversion_rate: rate,
        timestamp: 0,
        payee_hash: payee_data.payeeDetails,
        block_number: deposit.block_number,
    };

    let plan = FillPlan {
        deposit: deposit.clone(),
        terms,
        recipient: claimed,
        payment,
        stake_needed: amount,
        taker,
    };

    // R5-1: this `Seen` line used to be an unconditional append, three chain
    // calls and a curator round-trip after the gate read at the top of this
    // function. If the coordinator took the slot inside that window, both ended
    // up holding a reservation - and then neither could proceed: the
    // coordinator saw this line and waited, while this fill signalled an
    // intent, lost at its own claim, and left a `Signalled` line open forever.
    // A stall that only an operator could clear.
    //
    // The reservation now goes through `claim_if`, which holds the journal's
    // lock across the read and the write, so exactly one side gets it.
    let mut lost_the_slot = None;
    let claimed_slot = journal.claim_if(|existing| {
        if let Some(holder) = zecp2p_taker::auto::journal::holder_among(existing, &mine) {
            lost_the_slot = Some(format!(
                "{} took the one payment slot ({:?}) while this fill was being priced",
                holder.describe(),
                holder.state
            ));
            return None;
        }
        Some(FillRecord::new(
            deposit.deposit_id,
            deposit.session_id,
            amount,
            rate,
            plan.recipient.clone(),
        ))
    })?;
    if let Some(why) = lost_the_slot {
        // Nothing has been signalled or spent yet, so there is nothing to undo.
        return Ok(Outcome::Skipped { why });
    }
    let mut record = claimed_slot
        .ok_or_else(|| anyhow::anyhow!("the payment slot could not be reserved"))?;

    if dry_run {
        println!("\n{}", plan.signal_prompt());
        println!("\n(dry run: stopping here, nothing signalled)");
        return Ok(Outcome::Blocked {
            why: "dry run".into(),
        });
    }

    // How the two money gates are answered. `--yes` is phase 2: no terminal
    // input at all. The guards that remain are the payment cap, the payee
    // check already done above, the browser's own amount readback, and the
    // journal.
    let confirm: Box<dyn Confirm> = if auto_yes {
        Box::new(FixedConfirm(true))
    } else {
        Box::new(TerminalConfirm)
    };

    // Gate one. Gas and a 14-day stake lock.
    if !confirm.confirm(Gate::Signal, &plan.signal_prompt())? {
        record.state = FillState::Cancelled;
        record.note = Some("operator declined at the signal gate".into());
        journal.record(&record)?;
        return Ok(Outcome::Declined { gate: Gate::Signal });
    }

    run_fill(
        provider,
        config,
        journal,
        &mut record,
        &plan,
        taker,
        confirm.as_ref(),
    )
    .await
}

/// Everything after the signal gate: stake, signal, pay, attest, fulfil.
///
/// Split out of `handle_one` because this is the part where money moves and the
/// ordering matters. Each step writes the journal *before* it acts, never after,
/// so a crash leaves a record that says what may have happened rather than one
/// that says nothing did.
#[allow(clippy::too_many_arguments)]
async fn run_fill<P: alloy::providers::Provider + Clone>(
    provider: &P,
    config: &TakerConfig,
    journal: &Journal,
    record: &mut FillRecord,
    plan: &FillPlan,
    taker: alloy::primitives::Address,
    confirm: &dyn Confirm,
) -> Result<Outcome> {
    let claimer = Claimer::new(
        provider.clone(),
        config.contracts.zkp2p_orchestrator,
        config.contracts.zkp2p_escrow,
        config.contracts.stake_vault,
        config.contracts.usdc,
        taker,
    );

    // The curator's signature, the referral fee it mandates, and the rate. Asked
    // for before the stake because a refusal here costs nothing and a 14-day
    // lock costs a fortnight of working capital. An ungated deposit needs none,
    // and 99 of 100 recently scanned deposits are gated.
    let escrow = IEscrowTaker::new(config.contracts.zkp2p_escrow, provider);
    let gating_service = escrow
        .getDepositGatingService(plan.deposit.deposit_id, venmo_payment_method())
        .call()
        .await
        .context("could not read the deposit's gating service")?;

    let gating = if gating_service == alloy::primitives::Address::ZERO {
        zecp2p_taker::auto::gating::GatingSignature::none()
    } else {
        let request = zecp2p_taker::auto::gating::GatingRequest {
            deposit_id: plan.deposit.deposit_id.to_string(),
            processor_name: "venmo".to_string(),
            amount: plan.terms.amount.to_string(),
            to_address: taker,
            payment_method: venmo_payment_method(),
            fiat_currency: usd_currency_code(),
            conversion_rate: plan.terms.conversion_rate.to_string(),
            chain_id: config.network.chain_id.to_string(),
            payee_details: plan.terms.payee_hash.to_string(),
            caller_address: taker,
            escrow_address: config.contracts.zkp2p_escrow,
            orchestrator_address: config.contracts.zkp2p_orchestrator,
            extra: config.zkp2p.gating_extra.clone(),
        };
        zecp2p_taker::auto::gating::GatingClient::new(
            reqwest::Client::new(),
            config.zkp2p.api_url.clone(),
        )
        .sign(&request)
        .await
        .context("the curator refused to sign this intent")?
    };

    claimer
        .ensure_stake(plan.stake_needed)
        .await
        .context("could not stake for this intent")?;

    record.state = FillState::Signalling;
    journal.record(record)?;

    let intent = claimer
        .signal_intent(
            plan.deposit.deposit_id,
            plan.terms.amount,
            venmo_payment_method(),
            usd_currency_code(),
            plan.terms.conversion_rate,
            &gating,
        )
        .await
        .context("signalIntent failed")?;

    record.state = FillState::Signalled;
    record.intent_hash = Some(intent.intent_hash);
    journal.record(record)?;
    println!("signalled intent {}", intent.intent_hash);

    // The attestation is bound to the intent's on-chain signal time, and a
    // guess reverts with "UPV: Snapshot timestamp mismatch" after the fiat has
    // left. Read it back from the chain rather than using the wall clock.
    let terms = IntentReader::new(
        provider,
        config.contracts.zkp2p_orchestrator,
        config.contracts.zkp2p_escrow,
    )
    .terms(intent.intent_hash, 50_000)
    .await
    .context("could not read back the intent we just signalled")?;
    record.signalled_at_ms = Some(terms.timestamp_ms());
    // The cut for finding this payment in the feed later. The payment cannot
    // predate the intent it pays for, so the signal time is a sound lower bound;
    // a minute of slack absorbs clock skew between the chain and Venmo.
    let signalled_at = chrono::DateTime::from_timestamp_millis(terms.timestamp_ms() as i64)
        .unwrap_or_else(chrono::Utc::now)
        - chrono::Duration::minutes(1);
    journal.record(record)?;

    // Gate two. Real dollars, and nothing recalls them.
    if !confirm.confirm(Gate::Pay, &plan.pay_prompt(intent.intent_hash))? {
        record.state = FillState::Cancelled;
        record.note = Some("operator declined at the payment gate".into());
        journal.record(record)?;
        // Give the claim back so the maker's USDC is not stranded and the stake
        // unlocks, rather than leaving it to expire.
        if let Err(e) = claimer.cancel_intent(intent.intent_hash).await {
            tracing::error!(error = %e, "declined at the pay gate but cancelIntent also failed; the intent will expire");
        }
        return Ok(Outcome::Declined { gate: Gate::Pay });
    }

    // Written before the click, never after. A record in this state means the
    // money may or may not have left, and only a human reading the Venmo feed
    // can tell which.
    //
    // R4-3: the slot is read again here, under the journal's own file lock, and
    // the `Paying` line is written in the same critical section. The check in
    // `handle_one` happened before four network calls, and `zecp2p-v2coordinator`
    // pays from this same Venmo account - so between that check and this write
    // the coordinator could have taken the slot. `claim_if` makes the last
    // decision before money moves and the record of it one indivisible step.
    let mine = record.work_id();
    let mut lost_the_slot = None;
    let claimed = journal.claim_if(|existing| {
        for other in existing {
            if !other.state.is_open() || other.work_id() == mine {
                continue;
            }
            lost_the_slot = Some(format!(
                "{} took the one payment slot ({:?}) while this fill was being prepared",
                other.describe(),
                other.state
            ));
            return None;
        }
        let mut claim = record.clone();
        claim.state = FillState::Paying;
        claim.paid = Some(plan.payment.to_venmo_string());
        Some(claim)
    })?;
    if let Some(why) = lost_the_slot {
        // R5-1: an intent is already signalled by this point, and it holds the
        // maker's USDC and this taker's stake. Walking away without cancelling
        // leaves both locked until the intent expires, and leaves an open
        // `Signalled` line that holds the slot against every later fill - a
        // stall only an operator could clear.
        //
        // Nothing has been paid, so cancelling is free and correct.
        tracing::warn!(%why, "lost the payment slot after signalling; cancelling the intent");
        match record.intent_hash {
            Some(intent_hash) => match claimer.cancel_intent(intent_hash).await {
                Ok(tx) => {
                    record.state = FillState::Cancelled;
                    record.note = Some(format!("{why}; intent cancelled in {tx}"));
                    journal.record(record)?;
                }
                Err(e) => {
                    // The cancel failed, so the intent stands. That needs a
                    // human, and the record must not be left saying the slot is
                    // free while an intent is outstanding.
                    tracing::error!(error = %e, "cancel failed; the intent will expire on its own");
                    record.state = FillState::NeedsOperator;
                    record.note = Some(format!(
                        "{why}; the intent could not be cancelled ({e:#}) and will expire. \
                         Nothing was paid."
                    ));
                    journal.record(record)?;
                }
            },
            None => {
                // Never signalled: give the reservation back so the next fill
                // is not blocked by a line that means nothing.
                record.state = FillState::Cancelled;
                record.note = Some(why.clone());
                journal.record(record)?;
            }
        }
        return Ok(Outcome::Skipped { why });
    }
    *record = claimed
        .ok_or_else(|| anyhow::anyhow!("the payment slot could not be claimed"))?;

    let browser = VenmoBrowser::new(config.venmo.cdp_url.clone(), config.venmo.timeout_seconds);
    let tab = browser
        .find_venmo_tab()
        .await
        .context("no logged-in Venmo tab to pay from")?;
    let request = PaymentRequest {
        recipient: plan.recipient.clone(),
        amount: plan.payment.to_venmo_string(),
        note: config.venmo.note.clone(),
    };

    if let Err(e) = browser.pay(&tab, &request, SendMode::Live).await {
        // The page refused somewhere. The recipient check and the amount
        // readback are built to fail closed before the click, but a failure
        // after it looks identical from here, so this does not guess.
        record.state = FillState::NeedsOperator;
        record.note = Some(format!(
            "the browser step failed: {e:#}. The journal was written before the \
             send button, so check the Venmo feed for a ${} payment to @{} \
             before retrying. If it went out, resume at the attestation with \
             intent {}; if not, cancel that intent.",
            request.amount, request.recipient, intent.intent_hash
        ));
        journal.record(record)?;
        return Err(e.context(
            "the Venmo payment step failed; this fill now needs an operator to \
             read the feed before anything else moves",
        ));
    }

    record.state = FillState::Paid;
    journal.record(record)?;
    println!("paid ${} to @{}", request.amount, request.recipient);

    // From here the fiat is gone and the only thing that recovers it is the
    // attestation and the fulfil. Neither is gated: asking a human for
    // permission to finish is asking permission to lose the payment.
    let store = CookieStore::new(&config.session.path, config.session.max_age_hours)
        .with_identity(
            config.session.sender_id.clone(),
            config.session.user_agent.clone(),
        );
    let material = store
        .load()?
        .ok_or_else(|| anyhow::anyhow!("no session material at {}", config.session.path))?;

    let root = repo_root()?;
    let attester = Attester::new(
        &root,
        config.attestation.service_url.clone(),
        config.attestation.verifier.to_string(),
        config.network.chain_id,
    );
    let out = std::path::PathBuf::from(format!("attestation.{}.json", plan.deposit.deposit_id));
    // Which feed entry the enclave should attest. Not 0: the enclave selects by
    // raw position with no filter of its own, and index 0 is whatever happened
    // most recently on the account, which an incoming transfer can make someone
    // else's money. Located by direction, amount and recipient instead.
    let payment_index = zecp2p_taker::auto::attest::feed::locate_payment(
        &reqwest::Client::new(),
        &material,
        &request.recipient,
        &request.amount,
        // Only entries newer than the intent we just signalled. The same account
        // pays the same handle the same dollar repeatedly, and without this cut
        // a $1.00 run is ambiguous against every earlier $1.00 payment.
        Some(signalled_at),
    )
    .await
    .context("could not tell which Venmo feed entry this payment is")?;
    println!("the payment is at feed index {payment_index}");

    let attest_request = AttestRequest {
        intent_hash: intent.intent_hash,
        amount: terms.amount,
        conversion_rate: terms.conversion_rate,
        timestamp_ms: terms.timestamp_ms(),
        payee_hash: terms.payee_hash,
        payment_index,
    };
    let attested = attester
        .attest(&attest_request, &material, &out)
        .await
        .context("the enclave would not attest the payment; the fiat has already left")?;

    // The enclave re-signs whatever intent hash it is handed, so this is our own
    // check that the attestation in hand belongs to the intent in hand.
    attested
        .check_binds(&attest_request)
        .context("the attestation does not bind to the intent we signalled")?;

    let proof = load_proof(
        out.to_str()
            .ok_or_else(|| anyhow::anyhow!("attestation path is not valid UTF-8"))?,
    )?;

    let tx = claimer
        .fulfill_intent(
            intent.intent_hash,
            proof.payment_proof.clone(),
            proof.verification_data.clone(),
        )
        .await
        .context("fulfillIntent failed after the payment was made")?;

    record.state = FillState::Fulfilled;
    journal.record(record)?;
    println!("fulfilled, tx {tx}");

    Ok(Outcome::Fulfilled)
}

/// Ask the live Venmo feed which entry a payment is, and print it.
///
/// Read-only: sends the cookie to Venmo's own API and nothing else. Exists so
/// the index the attestation will use can be checked before a payment is made,
/// rather than discovered afterwards.
async fn run_find_payment(
    config: &TakerConfig,
    recipient: &str,
    amount: &str,
    after: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    let store = CookieStore::new(&config.session.path, config.session.max_age_hours)
        .with_identity(
            config.session.sender_id.clone(),
            config.session.user_agent.clone(),
        );
    let health = store.health()?;
    if !health.is_usable() {
        bail!("{}", health.explain());
    }
    let material = store
        .load()?
        .ok_or_else(|| anyhow::anyhow!("no session material at {}", config.session.path))?;
    println!("session : {material}");

    let index = zecp2p_taker::auto::attest::feed::locate_payment(
        &reqwest::Client::new(),
        &material,
        recipient,
        amount,
        after,
    )
    .await?;
    println!("an outgoing ${amount} to @{recipient} is at feed index {index}");
    println!("(the enclave would be given PAYMENT_INDEX={index})");
    Ok(())
}
