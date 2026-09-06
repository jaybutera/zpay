//! The daemon loop: watch, claim, pay, prove.

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};
use serde::Deserialize;
use zecp2p_types::abi::{usd_currency_code, venmo_payment_method};

use crate::{
    abi::IEscrowTaker,
    auto::{
        gating::{GatingClient, GatingRequest, GatingSignature},
        money::payment_cents,
    },
    claim::{Claimer, SignaledIntent},
    config::TakerConfig,
    discovery::{ClaimableDeposit, Discovery},
    payee,
    proof::{ProofRequest, ProofStatus},
    venmo::{PaymentOutcome, PaymentRequest, SendMode, Unconfirmed, VenmoBrowser},
};

/// How one deposit ended.
#[derive(Debug)]
pub enum Handled {
    /// Dry run: we stopped before spending anything.
    DryRun {
        deposit_id: U256,
        amount: U256,
        recipient: String,
    },
    /// Paid and proven; the USDC is ours.
    Fulfilled {
        intent_hash: alloy::primitives::B256,
    },
    /// Paid, but the proof needs the operator.
    AwaitingProof(Box<ProofStatus>),
    /// Someone else got there first, or the deposit stopped being viable.
    Skipped { deposit_id: U256, why: String },
}

pub struct TakerAgent<P> {
    config: TakerConfig,
    discovery: Discovery<P>,
    claimer: Claimer<P>,
    browser: VenmoBrowser,
    mode: SendMode,
    http: reqwest::Client,
    /// Read side, for checking a deposit's payee against what the coordinator
    /// says before any money moves.
    provider: P,
    /// Username to pay, when the operator supplied one directly.
    recipient_override: Option<String>,
    /// This agent's own address. Inside the gating digest, so a signature
    /// issued for it cannot be relayed by anyone else.
    taker: Address,
}

/// One entry of the coordinator's `/deposits/open` listing.
#[derive(Debug, Deserialize)]
struct OpenDeposit {
    deposit_id: String,
    venmo_username: String,
}

impl<P: alloy::providers::Provider + Clone> TakerAgent<P> {
    pub fn new(config: TakerConfig, provider: P, taker: Address, mode: SendMode) -> Self {
        Self::with_recipient(config, provider, taker, mode, None)
    }

    /// Build an agent that pays a fixed username, skipping the coordinator.
    pub fn with_recipient(
        config: TakerConfig,
        provider: P,
        taker: Address,
        mode: SendMode,
        recipient_override: Option<String>,
    ) -> Self {
        let discovery = Discovery::new(
            provider.clone(),
            config.contracts.glue_contract,
            config.contracts.zkp2p_escrow,
        );
        let claimer = Claimer::new(
            provider.clone(),
            config.contracts.zkp2p_orchestrator,
            config.contracts.zkp2p_escrow,
            config.contracts.stake_vault,
            config.contracts.usdc,
            taker,
        );
        let browser = VenmoBrowser::new(config.venmo.cdp_url.clone(), config.venmo.timeout_seconds);
        Self {
            config,
            discovery,
            claimer,
            browser,
            mode,
            http: reqwest::Client::new(),
            provider,
            recipient_override,
            taker,
        }
    }

    /// Run until interrupted.
    pub async fn run(&self, provider: &P) -> Result<()> {
        let interval = std::time::Duration::from_secs(self.config.taker.poll_interval_seconds);
        let mut last_scanned = provider
            .get_block_number()
            .await?
            .saturating_sub(self.config.taker.lookback_blocks);

        if self.mode.is_dry_run() {
            tracing::warn!("dry-run mode: no Venmo payment and no on-chain claim will be made");
        }

        loop {
            match self.tick(provider, last_scanned).await {
                Ok(scanned_to) => last_scanned = scanned_to,
                Err(e) => tracing::error!(error = %e, "tick failed"),
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// One pass: scan, then handle the first deposit worth taking.
    async fn tick(&self, provider: &P, from_block: u64) -> Result<u64> {
        let head = provider.get_block_number().await?;
        if head < from_block {
            return Ok(head);
        }

        let deposits = self.discovery.scan(from_block, head).await?;
        if deposits.is_empty() {
            tracing::debug!(from_block, head, "no claimable deposits");
            return Ok(head + 1);
        }
        tracing::info!(count = deposits.len(), "found claimable deposits");

        for deposit in deposits {
            match self.handle(&deposit).await {
                Ok(Handled::Skipped { deposit_id, why }) => {
                    tracing::info!(deposit_id = %deposit_id, why, "skipped");
                }
                Ok(outcome) => {
                    tracing::info!(?outcome, "handled deposit");
                    // One at a time: a taker's stake and Venmo balance are
                    // finite, and a half-finished payment needs attention
                    // before the next claim.
                    return Ok(head + 1);
                }
                Err(e) => tracing::error!(deposit_id = %deposit.deposit_id, error = %e, "failed"),
            }
        }

        Ok(head + 1)
    }

    /// Take one deposit through the whole flow.
    async fn handle(&self, deposit: &ClaimableDeposit) -> Result<Handled> {
        let Some(amount) = deposit.takeable_amount(self.config.taker.max_intent_amount) else {
            return Ok(Handled::Skipped {
                deposit_id: deposit.deposit_id,
                why: format!(
                    "wants {}-{} USDC units, past this agent's limit of {}",
                    deposit.min_intent, deposit.max_intent, self.config.taker.max_intent_amount
                ),
            });
        };
        if amount < self.config.taker.min_intent_amount {
            return Ok(Handled::Skipped {
                deposit_id: deposit.deposit_id,
                why: format!("{amount} units is below the agent's floor"),
            });
        }

        // Who gets paid. The deposit stores only the curator's opaque payee
        // hash, so the Venmo username has to come from the session behind it.
        let recipient = self.recipient_for(deposit).await?;

        // The rate the deposit actually prices at, read rather than assumed. A
        // hardcoded 1e18 clears the on-chain floor and then fails the enclave's
        // snapshot check with the fiat already sent. See
        // `docs/status/auto-taker-daemon-design.md`.
        let conversion_rate = self.deposit_rate(deposit.deposit_id).await?;

        // Price the payment before anything is spent. A cap breach or a zero
        // rate costs nothing to discover here and costs gas plus a 14-day stake
        // lock to discover after signalling. The dry run reports this number
        // too: an operator deciding on a rate-blind figure is deciding on the
        // wrong one, by four cents on deposit 4499's $5.
        let payment = payment_cents(amount, conversion_rate, self.config.taker.max_payment_cents)?;
        let dollars = payment.to_venmo_string();

        if self.mode.is_dry_run() {
            let free = self.claimer.free_stake().await.unwrap_or(U256::ZERO);
            tracing::info!(
                deposit_id = %deposit.deposit_id,
                amount = %amount,
                free_stake = %free,
                "dry run: would signal, then pay ${dollars} to @{recipient}"
            );
            // Resolved for real, not stubbed. A dry run exists to show the
            // operator what the live run would do, and the live run's first act
            // is this lookup: it is a read, it moves no money, and if it
            // refuses then the dry run has found the thing worth finding
            // before an intent is ever signalled.
            match self.browser.find_venmo_tab().await {
                Ok(tab) => match self.browser.resolve_payee(&tab, &recipient).await {
                    Ok(payee) => {
                        tracing::info!(
                            "  Venmo resolves @{recipient} to @{} ({}), id {}",
                            payee.handle,
                            payee.display_name,
                            payee.id
                        );
                        for step in self.browser.payment_steps(
                            &PaymentRequest {
                                recipient: recipient.clone(),
                                amount: dollars.clone(),
                                note: self.config.venmo.note.clone(),
                            },
                            &payee,
                        ) {
                            tracing::info!("  would: {}", step.describe());
                        }
                    }
                    // Reported, not returned. The dry run's job is to say what
                    // it found, and a payee that will not resolve is the most
                    // useful thing it can say.
                    Err(e) => {
                        tracing::warn!("  would REFUSE: @{recipient} does not resolve ({e:#})")
                    }
                },
                Err(e) => tracing::warn!(
                    "  cannot show the payment steps: no Venmo tab to resolve @{recipient} \
                     against ({e:#})"
                ),
            }
            return Ok(Handled::DryRun {
                deposit_id: deposit.deposit_id,
                amount,
                recipient,
            });
        }

        // An empty gating signature reverts against the 99-in-100 of deposits
        // that are gated, so ask the curator before spending anything.
        let gating = self
            .gating_for(deposit.deposit_id, amount, conversion_rate)
            .await?;

        // Stake second: signalIntent reverts without free stake equal to the
        // intent, and finding that out mid-claim wastes gas.
        self.claimer.ensure_stake(amount).await?;

        let intent = match self
            .claimer
            .signal_intent(
                deposit.deposit_id,
                amount,
                venmo_payment_method(),
                usd_currency_code(),
                conversion_rate,
                &gating,
            )
            .await
        {
            Ok(intent) => intent,
            Err(e) => {
                // Losing a race is normal in an open market, not an error.
                return Ok(Handled::Skipped {
                    deposit_id: deposit.deposit_id,
                    why: format!("could not claim: {e}"),
                });
            }
        };
        tracing::info!(intent_hash = %intent.intent_hash, "claimed the deposit");

        self.pay_and_prove(&intent, &recipient, &dollars).await
    }

    /// Money leaves here.
    async fn pay_and_prove(
        &self,
        intent: &SignaledIntent,
        recipient: &str,
        dollars: &str,
    ) -> Result<Handled> {
        let tab = self.browser.find_venmo_tab().await?;
        let request = PaymentRequest {
            recipient: recipient.to_string(),
            amount: dollars.to_string(),
            note: self.config.venmo.note.clone(),
        };

        let outcome = match self.browser.pay(&tab, &request, self.mode).await {
            Ok(outcome) => outcome,

            // The click landed and the page never showed the payment posting.
            // Neither verdict is safe here, so neither is taken: cancelling
            // the intent is a claim that no money left, and if it did leave --
            // a post slower than the timeout, or a navigation that stopped us
            // asking -- the cancel hands the deposit back while our dollars
            // are gone, with no intent left to prove them against. That is the
            // double-payment side of the same coin the coordinator's rail
            // guards against by writing `NeedsOperator` instead of `paid`.
            //
            // So the intent is left standing and a human is told to read the
            // feed. An intent nobody cancels expires on its own; dollars sent
            // against a cancelled intent do not come back.
            //
            // This path only runs under `--dry-run` today (`main.rs` refuses a
            // live ungated payment), and `Unconfirmed` cannot arise in a dry
            // run because the run stops before the first click. It is written
            // out anyway: the gate is one edit away from being lifted, and the
            // wrong behaviour here is silent and expensive.
            Err(e) if cancelling_would_be_a_guess(&e) => {
                tracing::error!(
                    error = %format!("{e:#}"),
                    intent = %intent.intent_hash,
                    "the Venmo page never confirmed the send. NOT cancelling the intent: \
                     the money may have left. Read the Venmo feed for this amount and \
                     recipient before anything else runs."
                );
                return Err(e);
            }

            Err(e) => {
                // We hold a claim we cannot honour. Give it back so the maker's
                // USDC is not stranded and our stake unlocks.
                tracing::error!(error = %e, "payment failed; cancelling the intent");
                if let Err(cancel_err) = self.claimer.cancel_intent(intent.intent_hash).await {
                    tracing::error!(error = %cancel_err, "cancel also failed; intent will expire");
                }
                return Err(e);
            }
        };

        match outcome {
            PaymentOutcome::WouldHaveSent { .. } => Ok(Handled::DryRun {
                deposit_id: intent.deposit_id,
                amount: intent.amount,
                recipient: recipient.to_string(),
            }),
            PaymentOutcome::Sent { .. } => {
                // Everything from here needs an enclave signature we cannot make.
                let status = ProofStatus::NeedsAttestation(ProofRequest {
                    intent_hash: intent.intent_hash,
                    recipient: recipient.to_string(),
                    amount: dollars.to_string(),
                    sent_at: chrono::Utc::now(),
                });
                if let Some(report) =
                    status.manual_step_report_for(&self.config.attestation.service_url)
                {
                    tracing::warn!("\n{report}");
                }
                Ok(Handled::AwaitingProof(Box::new(status)))
            }
        }
    }

    /// The Venmo username for a deposit, checked against what the deposit will
    /// actually pay.
    ///
    /// On-chain there is only the curator's opaque `payeeDetails` hash, which by
    /// design does not reveal the username, so the name itself has to come from
    /// the coordinator. What does not have to be taken on trust is whether that
    /// name is the right one: the curator will hash a username on request, and
    /// the deposit carries the hash it will settle against. If they differ, the
    /// coordinator named someone else.
    ///
    /// Without this check a hostile or compromised coordinator, or anyone on the
    /// wire in front of a plain-http one, redirects the taker's real dollars to
    /// their own handle. The proof then fails, because the enclave binds
    /// `payeeDetails` from the deposit, so the taker eats the loss and can only
    /// cancel to recover stake.
    ///
    /// An operator can pin a username with `recipient_override` for a deposit
    /// they were told about out of band. That is checked too: the operator can
    /// be wrong about which deposit it belongs to.
    async fn recipient_for(&self, deposit: &ClaimableDeposit) -> Result<String> {
        let claimed = match &self.recipient_override {
            Some(recipient) => recipient.clone(),
            None => self.ask_coordinator(deposit).await?,
        };

        // Shape first: this string ends up in a URL.
        let claimed = payee::validate_username_shape(&claimed)?.to_string();

        // What the deposit will actually pay.
        let on_chain = self.deposit_payee(deposit.deposit_id).await?;

        // What the coordinator's answer hashes to, according to the curator that
        // issued the hash in the first place.
        let resolved = payee::curator_hash_for(
            &self.http,
            &self.config.zkp2p.api_url,
            &claimed,
        )
        .await
        .context("could not check the coordinator's username against the zk-p2p curator")?;

        payee::require_match(&claimed, resolved, on_chain)?;

        tracing::info!(
            deposit_id = %deposit.deposit_id,
            recipient = %claimed,
            payee = ?on_chain,
            "payee verified against the deposit"
        );

        Ok(claimed)
    }

    /// The rate this deposit prices at, in fiat per USDC scaled by 1e18.
    ///
    /// `agent.rs` used to pass `1e18` here unconditionally. That clears the
    /// on-chain floor at `OrchestratorV3.sol:553` on any deposit, so nothing
    /// reverts; the failure surfaces later, inside the enclave, which computes
    /// `releaseAmount` from the rate in the intent. On the 2026-09-01 fill the
    /// difference was 4,840,000 units against the intent's 4,875,437, and the
    /// fulfilment would have reverted with `UPV: Snapshot rate mismatch` after
    /// the Venmo payment had already gone out.
    async fn deposit_rate(&self, deposit_id: U256) -> Result<U256> {
        let escrow = IEscrowTaker::new(self.config.contracts.zkp2p_escrow, &self.provider);
        let rate = escrow
            .getDepositCurrencyMinRate(deposit_id, venmo_payment_method(), usd_currency_code())
            .call()
            .await
            .with_context(|| format!("could not read the rate for deposit {deposit_id}"))?;

        if rate.is_zero() {
            anyhow::bail!(
                "deposit {deposit_id} carries a zero minimum rate for Venmo/USD; \
                 refusing to price a payment against it"
            );
        }
        Ok(rate)
    }

    /// The gating signature this deposit needs, or none if it is open.
    ///
    /// The curator's `/v3/sign` returns the signature, its expiry and a
    /// mandatory 95 bps referral fee together, and all three go into
    /// `signalIntent` untouched. Rebuilding the fee locally reverts with
    /// `InvalidSignature()` even when the signature itself is genuine.
    async fn gating_for(
        &self,
        deposit_id: U256,
        amount: U256,
        conversion_rate: U256,
    ) -> Result<GatingSignature> {
        let escrow = IEscrowTaker::new(self.config.contracts.zkp2p_escrow, &self.provider);
        let gating_service = escrow
            .getDepositGatingService(deposit_id, venmo_payment_method())
            .call()
            .await
            .with_context(|| {
                format!("could not read the gating service for deposit {deposit_id}")
            })?;

        if gating_service == Address::ZERO {
            tracing::debug!(deposit_id = %deposit_id, "deposit is open; no gating signature needed");
            return Ok(GatingSignature::none());
        }

        let payee = self.deposit_payee(deposit_id).await?;
        let client = GatingClient::new(self.http.clone(), self.config.zkp2p.api_url.clone());
        let request = GatingRequest {
            deposit_id: deposit_id.to_string(),
            processor_name: "venmo".to_string(),
            amount: amount.to_string(),
            to_address: self.taker,
            payment_method: venmo_payment_method(),
            fiat_currency: usd_currency_code(),
            conversion_rate: conversion_rate.to_string(),
            chain_id: self.config.network.chain_id.to_string(),
            payee_details: payee.to_string(),
            caller_address: self.taker,
            escrow_address: self.config.contracts.zkp2p_escrow,
            orchestrator_address: self.config.contracts.zkp2p_orchestrator,
            extra: self.config.zkp2p.gating_extra.clone(),
        };

        tracing::info!(
            deposit_id = %deposit_id,
            gating_service = %gating_service,
            "deposit is gated; asking the curator to sign"
        );
        client.sign(&request).await
    }

    /// Read the deposit's own `payeeDetails` from the escrow.
    async fn deposit_payee(&self, deposit_id: U256) -> Result<alloy::primitives::B256> {
        let escrow = IEscrowTaker::new(self.config.contracts.zkp2p_escrow, &self.provider);
        let data = escrow
            .getDepositPaymentMethodData(deposit_id, venmo_payment_method())
            .call()
            .await
            .with_context(|| format!("could not read the payee for deposit {deposit_id}"))?;

        if data.payeeDetails == alloy::primitives::B256::ZERO {
            anyhow::bail!(
                "deposit {deposit_id} carries no Venmo payee on chain; refusing to pay against it"
            );
        }

        Ok(data.payeeDetails)
    }

    /// Ask the coordinator which username is behind a deposit.
    async fn ask_coordinator(&self, deposit: &ClaimableDeposit) -> Result<String> {
        let base = self
            .config
            .taker
            .coordinator_url
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "deposit {} needs a Venmo username, but no coordinator_url is set \
                 and no --recipient was given. payeeDetails on-chain is an opaque \
                 curator hash and cannot be reversed.",
                    deposit.deposit_id
                )
            })?;

        // The username is the one thing here worth intercepting, and a plain-http
        // coordinator hands it to anyone on the path to rewrite. Loopback is
        // exempt: nothing is on the wire.
        require_secure_url(base).context("taker.coordinator_url")?;

        let url = format!("{}/deposits/open", base.trim_end_matches('/'));
        let mut request = self.http.get(&url);
        if let Some(token) = &self.config.taker.coordinator_token {
            request = request.bearer_auth(token);
        }

        let open: Vec<OpenDeposit> = request
            .send()
            .await
            .with_context(|| format!("could not reach the coordinator at {url}"))?
            .error_for_status()
            .context(
                "the coordinator refused the deposit listing; it needs taker.coordinator_token",
            )?
            .json()
            .await
            .context("coordinator returned an unreadable deposit list")?;

        let wanted = deposit.deposit_id.to_string();
        open.into_iter()
            .find(|d| d.deposit_id == wanted)
            .map(|d| d.venmo_username)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the coordinator does not list deposit {} as open; it may have \
                     been claimed already, or belong to a different coordinator",
                    deposit.deposit_id
                )
            })
    }
}

/// Require https, unless the host is loopback.
///
/// The default in `config.taker.example.toml` was plain `http`, so the Venmo
/// username a taker is about to pay travelled in clear text and could be
/// rewritten in flight by anyone on the path.
pub fn require_secure_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("{url} is not a valid URL"))?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // host_str keeps the brackets on an IPv6 literal.
            let host = parsed
                .host_str()
                .unwrap_or("")
                .trim_start_matches('[')
                .trim_end_matches(']');
            let is_loopback = host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if is_loopback {
                Ok(())
            } else {
                anyhow::bail!(
                    "{url} is plain http. The Venmo username you are about to pay travels over \
                     this connection, and anyone on the path can rewrite it. Use https."
                )
            }
        }
        other => anyhow::bail!("{url} uses {other}, which is not supported; use https"),
    }
}

/// Whether cancelling the intent on this error would be asserting something we
/// do not know.
///
/// `cancel_intent` is a claim that no money left. It is right for a failure
/// before the click -- no tab, a wrong recipient, an amount that did not take
/// -- and wrong for [`Unconfirmed`], which is by definition the case where the
/// click landed and the page never said what came of it. Cancelling there
/// hands the deposit back while our dollars may already be gone, with no intent
/// left to prove them against.
fn cancelling_would_be_a_guess(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Unconfirmed>().is_some()
}

#[cfg(test)]
mod tests {
    use super::{cancelling_would_be_a_guess, require_secure_url};
    use crate::venmo::Unconfirmed;

    /// An unconfirmed send must not cancel the intent.
    ///
    /// `cancel_intent` asserts that no money left. `Unconfirmed` is defined as
    /// the case where nobody knows, and it is now the common post-click
    /// failure. Cancelling there gives the deposit back while our dollars may
    /// be gone and leaves no intent to prove them against -- the
    /// double-payment side of the same coin the coordinator's rail avoids by
    /// writing `NeedsOperator` rather than `paid`.
    #[test]
    fn an_unconfirmed_send_does_not_cancel_the_intent() {
        let unconfirmed = anyhow::Error::from(Unconfirmed {
            recipient: "jay-butera".into(),
            amount: "2.01".into(),
            why: "the confirmation is still on the page".into(),
        });
        assert!(cancelling_would_be_a_guess(&unconfirmed));
    }

    /// Every other failure still cancels, and must.
    ///
    /// These happen before the click -- no tab, a wrong recipient, an amount
    /// the field discarded -- so no money left and holding the claim strands
    /// the maker's USDC and our stake.
    #[test]
    fn a_failure_before_the_click_still_cancels() {
        let before = anyhow::anyhow!("no logged-in Venmo tab to pay from");
        assert!(!cancelling_would_be_a_guess(&before));

        // Including one that has been given context on the way up, which is
        // how these actually arrive.
        let wrapped = anyhow::anyhow!("the amount field reads \"\"")
            .context("could not drive the Venmo page");
        assert!(!cancelling_would_be_a_guess(&wrapped));
    }

    /// And the distinction survives being wrapped in context.
    ///
    /// `pay` adds the recipient on the way out and callers add their own
    /// context; if a wrap hid the type, the agent would silently go back to
    /// cancelling on an unconfirmed send.
    #[test]
    fn an_unconfirmed_send_is_still_recognised_under_context() {
        let wrapped = anyhow::Error::from(Unconfirmed {
            recipient: "jay-butera".into(),
            amount: "2.01".into(),
            why: "the page could not be asked".into(),
        })
        .context("the fiat leg failed");
        assert!(
            cancelling_would_be_a_guess(&wrapped),
            "a wrapped Unconfirmed must still be recognised"
        );
    }

    #[test]
    fn https_is_accepted() {
        assert!(require_secure_url("https://coordinator.example").is_ok());
        assert!(require_secure_url("https://coordinator.example:8443/").is_ok());
    }

    /// HIGH-2: the shipped example config used plain http, so the username the
    /// taker is about to pay was rewritable in flight.
    #[test]
    fn plain_http_to_a_remote_host_is_refused() {
        let err = require_secure_url("http://coordinator.example")
            .expect_err("plain http must be refused");
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn loopback_http_is_still_fine() {
        assert!(require_secure_url("http://127.0.0.1:3000").is_ok());
        assert!(require_secure_url("http://localhost:3000").is_ok());
        assert!(require_secure_url("http://[::1]:3000").is_ok());
    }

    #[test]
    fn other_schemes_are_refused() {
        assert!(require_secure_url("file:///etc/passwd").is_err());
        assert!(require_secure_url("not a url").is_err());
    }
}
