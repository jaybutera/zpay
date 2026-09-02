//! Staking and claiming: the on-chain half of taking a deposit.

use alloy::{
    primitives::{Address, Bytes, B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use zecp2p_types::abi::{IOrchestrator, IERC20};

use crate::{
    abi::{IOrchestratorWrite, IStakeVault},
    auto::gating::GatingSignature,
};

/// What a signalled intent left us holding.
#[derive(Debug, Clone)]
pub struct SignaledIntent {
    pub intent_hash: B256,
    pub deposit_id: U256,
    pub amount: U256,
    pub tx_hash: B256,
}

pub struct Claimer<P> {
    provider: P,
    orchestrator: Address,
    escrow: Address,
    stake_vault: Address,
    usdc: Address,
    taker: Address,
}

impl<P: Provider> Claimer<P> {
    pub fn new(
        provider: P,
        orchestrator: Address,
        escrow: Address,
        stake_vault: Address,
        usdc: Address,
        taker: Address,
    ) -> Self {
        Self {
            provider,
            orchestrator,
            escrow,
            stake_vault,
            usdc,
            taker,
        }
    }

    /// Free stake this taker can still lock against a new intent.
    pub async fn free_stake(&self) -> Result<U256> {
        let vault = IStakeVault::new(self.stake_vault, &self.provider);
        Ok(vault.freeStake(self.taker).call().await?)
    }

    /// Top the vault up so `amount` can be locked.
    ///
    /// OrchestratorV3's lifecycle hook locks stake equal to the intent amount,
    /// so a taker needs USDC staked on top of the USDC they are about to send
    /// over Venmo. Locked stake stays locked until the intent settles.
    pub async fn ensure_stake(&self, amount: U256) -> Result<Option<B256>> {
        let free = self.free_stake().await?;
        if free >= amount {
            return Ok(None);
        }
        let shortfall = amount - free;

        let balance = IERC20::new(self.usdc, &self.provider)
            .balanceOf(self.taker)
            .call()
            .await?;
        if balance < shortfall {
            anyhow::bail!(
                "need {shortfall} more USDC units of stake to signal for {amount}, wallet holds {balance}"
            );
        }

        tracing::info!(shortfall = %shortfall, "topping up stake");

        let usdc = IERC20::new(self.usdc, &self.provider);
        let approve = usdc
            .approve(self.stake_vault, shortfall)
            .send()
            .await
            .context("failed to approve the StakeVault to pull USDC")?;
        approve.get_receipt().await?;

        let vault = IStakeVault::new(self.stake_vault, &self.provider);
        let tx = vault
            .depositStake(shortfall)
            .send()
            .await
            .context("failed to deposit stake")?;
        let receipt = tx.get_receipt().await?;
        Ok(Some(receipt.transaction_hash))
    }

    /// Claim a deposit by signalling an intent for `amount`.
    ///
    /// The gating material comes from the caller, not from here. An earlier
    /// version of this function hardcoded an empty `gatingSignature` and an
    /// empty `referrers` array, on the reasoning that OfframpGlue creates every
    /// deposit with `intentGatingService = address(0)`. Two things make that
    /// wrong now.
    ///
    /// A scan of `DepositPaymentMethodAdded` over ~108,000 recent Base blocks
    /// found 100 events with 99 of them gated, every one to
    /// `0x396d31055db28c0c6f36e8b36f18fe7227248a97`. Ours are the outliers, and
    /// `fast-fill-network-design.md` establishes that pointing our own deposits
    /// at a gating key is a one-line coordinator change with no redeploy. A
    /// taker that cannot claim a gated deposit is limited to the deposits
    /// nobody else wants.
    ///
    /// The referral fee is the subtler half. The curator injects a **mandatory
    /// 95 bps fee** to `0x0bc26ff515411396dd588abd6ef6846e04470227` and signs a
    /// digest that includes it, so supplying the signature while rebuilding the
    /// fee array locally reverts with `InvalidSignature()` even though the
    /// signature itself is genuine. Both values arrive together from
    /// [`crate::auto::gating`] and are passed through untouched.
    ///
    /// `conversion_rate` is the deposit's real rate. Passing `1e18` clears the
    /// on-chain floor at `OrchestratorV3.sol:553` but makes the enclave compute
    /// a `releaseAmount` against the wrong rate, which reverts later at
    /// `UPV: Snapshot rate mismatch` with the fiat already sent.
    pub async fn signal_intent(
        &self,
        deposit_id: U256,
        amount: U256,
        payment_method: B256,
        fiat_currency: B256,
        conversion_rate: U256,
        gating: &GatingSignature,
    ) -> Result<SignaledIntent> {
        let orchestrator = IOrchestratorWrite::new(self.orchestrator, &self.provider);

        let params = IOrchestratorWrite::SignalIntentParams {
            escrow: self.escrow,
            depositId: deposit_id,
            amount,
            to: self.taker,
            paymentMethod: payment_method,
            fiatCurrency: fiat_currency,
            conversionRate: conversion_rate,
            referrers: gating
                .referrers
                .iter()
                .map(|r| IOrchestratorWrite::Referrer {
                    referrer: r.referrer,
                    fee: r.fee,
                })
                .collect(),
            gatingSignature: gating.signature.clone(),
            signatureExpiration: gating.expiration,
            postIntentHook: Address::ZERO,
            data: Bytes::new(),
            postIntentHookData: Bytes::new(),
        };

        let tx = orchestrator
            .signalIntent(params)
            .send()
            .await
            .context("signalIntent reverted or was rejected")?;
        let receipt = tx.get_receipt().await?;

        // The intent hash is the first indexed topic of IntentSignaled.
        let intent_hash = receipt
            .inner
            .logs()
            .iter()
            .find(|log| {
                log.topics().first() == Some(&IOrchestrator::IntentSignaled::SIGNATURE_HASH)
            })
            .and_then(|log| log.topics().get(1).copied())
            .ok_or_else(|| anyhow::anyhow!("signalIntent produced no IntentSignaled event"))?;

        Ok(SignaledIntent {
            intent_hash,
            deposit_id,
            amount,
            tx_hash: receipt.transaction_hash,
        })
    }

    /// Submit the witness-attested proof and collect the escrowed USDC.
    ///
    /// `payment_proof` has to come from the enclave; see `proof::ProofRequest`
    /// and `scripts/proof/prove_payment.mjs`.
    ///
    /// No gating signature is involved, even on a gated deposit. `fulfillIntent`
    /// takes only `(paymentProof, intentHash, verificationData,
    /// postIntentHookData)`; gating is a `signalIntent`-time check. Confirmed by
    /// reading `OrchestratorV3.sol:237-277` rather than by assuming, and then by
    /// the 2026-09-01 fill against gated deposit 4499.
    pub async fn fulfill_intent(
        &self,
        intent_hash: B256,
        payment_proof: Bytes,
        verification_data: Bytes,
    ) -> Result<B256> {
        let orchestrator = IOrchestratorWrite::new(self.orchestrator, &self.provider);

        let params = IOrchestratorWrite::FulfillIntentParams {
            paymentProof: payment_proof,
            intentHash: intent_hash,
            verificationData: verification_data,
            postIntentHookData: Bytes::new(),
        };

        let tx = orchestrator
            .fulfillIntent(params)
            .send()
            .await
            .context("fulfillIntent reverted; the proof was not accepted")?;
        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Give a claimed intent back if we cannot pay after all.
    ///
    /// Better than letting it expire: cancelling releases the maker's USDC and
    /// unlocks our stake immediately.
    pub async fn cancel_intent(&self, intent_hash: B256) -> Result<B256> {
        let orchestrator = IOrchestratorWrite::new(self.orchestrator, &self.provider);
        let tx = orchestrator
            .cancelIntent(intent_hash)
            .send()
            .await
            .context("cancelIntent reverted")?;
        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Has this intent already been fulfilled, by us or anyone?
    pub async fn is_fulfilled(
        &self,
        intent_hash: B256,
        from_block: u64,
        to_block: u64,
    ) -> Result<bool> {
        let filter = Filter::new()
            .address(self.orchestrator)
            .event_signature(IOrchestrator::IntentFulfilled::SIGNATURE_HASH)
            .topic1(intent_hash)
            .from_block(from_block)
            .to_block(to_block);
        Ok(!self.provider.get_logs(&filter).await?.is_empty())
    }
}
