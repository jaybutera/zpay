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

    // Driving the payment page needs no key either: it stops before the click
    // and sends nothing on-chain.
    if let Commands::TestPay { recipient, amount } = &cli.command {
        return run_test_pay(&config, recipient, amount).await;
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
        Commands::CheckVenmo | Commands::TestPay { .. } | Commands::FindPayment { .. } => {
            unreachable!("handled above")
        }

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
/// sequence with the irreversible step removed, so both failures surface here.
async fn run_test_pay(config: &TakerConfig, recipient: &str, amount: &str) -> Result<()> {
    // Refuse a malformed amount before opening a payment page for it.
    let cents = zecp2p_taker::venmo::amount_matches(amount, amount);
    if !cents {
        bail!("{amount:?} is not an amount Venmo's field would accept");
    }
    let claimed = zecp2p_taker::payee::validate_username_shape(recipient)?.to_string();

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

    println!("\ndriving the page (DryRun: the send button is never clicked)\n");
    match browser.pay(&tab, &request, SendMode::DryRun).await? {
        zecp2p_taker::venmo::PaymentOutcome::WouldHaveSent { recipient, amount } => {
            println!(
                "PASS: the page accepted ${amount} to @{recipient}, the recipient \
                 matched, and the amount read back out of the field."
            );
            println!("Nothing was sent.");
        }
        zecp2p_taker::venmo::PaymentOutcome::Sent { .. } => {
            bail!("a dry run reported a send; this is a bug and money may have moved")
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
    let journal = Journal::open(&config.taker.journal_path)?;

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
                )
                .await
                {
                    Ok(outcome) => println!("deposit {}: {outcome:?}", deposit.deposit_id),
                    Err(e) => println!("deposit {}: stopped: {e:#}", deposit.deposit_id),
                }
            }
            from_block = head + 1;
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
) -> Result<Outcome> {
    // Everything free comes first. The cookie check is here rather than before
    // the attestation because a dead cookie found after the payment means the
    // fiat is gone and only cancelIntent recovers the stake.
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

    let mut record = FillRecord::new(
        deposit.deposit_id,
        deposit.session_id,
        amount,
        rate,
        plan.recipient.clone(),
    );
    journal.record(&record)?;

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
    record.state = FillState::Paying;
    record.paid = Some(plan.payment.to_venmo_string());
    journal.record(record)?;

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
