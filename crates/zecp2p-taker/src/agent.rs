//! The daemon loop: watch, claim, pay, prove.

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};
use serde::Deserialize;
use zecp2p_types::abi::{usd_currency_code, venmo_payment_method};

use crate::{
    claim::{Claimer, SignaledIntent},
    config::TakerConfig,
    discovery::{ClaimableDeposit, Discovery},
    proof::{ProofRequest, ProofStatus},
    venmo::{usdc_to_dollars, PaymentOutcome, PaymentRequest, SendMode, VenmoBrowser},
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
    /// Username to pay, when the operator supplied one directly.
    recipient_override: Option<String>,
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
            provider,
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
            recipient_override,
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
        let dollars = usdc_to_dollars(amount);

        if self.mode.is_dry_run() {
            let free = self.claimer.free_stake().await.unwrap_or(U256::ZERO);
            tracing::info!(
                deposit_id = %deposit.deposit_id,
                amount = %amount,
                free_stake = %free,
                "dry run: would signal, then pay ${dollars} to @{recipient}"
            );
            for step in self.browser.payment_steps(&PaymentRequest {
                recipient: recipient.clone(),
                amount: dollars.clone(),
                note: self.config.venmo.note.clone(),
            }) {
                tracing::info!("  would: {}", step.describe());
            }
            return Ok(Handled::DryRun {
                deposit_id: deposit.deposit_id,
                amount,
                recipient,
            });
        }

        // Stake first: signalIntent reverts without free stake equal to the
        // intent, and finding that out mid-claim wastes gas.
        self.claimer.ensure_stake(amount).await?;

        let intent = match self
            .claimer
            .signal_intent(
                deposit.deposit_id,
                amount,
                venmo_payment_method(),
                usd_currency_code(),
                U256::from(1_000_000_000_000_000_000u64),
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

    /// The Venmo username for a deposit.
    ///
    /// On-chain there is only the curator's opaque `payeeDetails` hash, which
    /// by design does not reveal the username, so this is the one thing a taker
    /// cannot read off Base. The coordinator that opened the session publishes
    /// it at `/deposits/open`.
    ///
    /// An operator can also pin a username with `recipient_override` for a
    /// single deposit they were told about out of band.
    async fn recipient_for(&self, deposit: &ClaimableDeposit) -> Result<String> {
        if let Some(recipient) = &self.recipient_override {
            return Ok(recipient.clone());
        }

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

        let url = format!("{}/deposits/open", base.trim_end_matches('/'));
        let open: Vec<OpenDeposit> = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("could not reach the coordinator at {url}"))?
            .error_for_status()?
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
