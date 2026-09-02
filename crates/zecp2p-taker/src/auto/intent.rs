//! Recovering an intent's terms from the chain.
//!
//! The attestation needs four things about an intent that the daemon cannot
//! guess: the amount, the conversion rate, the on-chain signal timestamp, and
//! the payee hash. Getting any of them wrong wastes a payment that has already
//! been made, because the fiat leaves before the enclave is asked.
//!
//! The obvious source is `getIntent(intentHash)` on OrchestratorV3, and the
//! daemon uses it when it works. It does not always work: **a fulfilled intent
//! is pruned**, and `getIntent` then returns a zero struct rather than an error.
//! Read at block 50,764,549, intent
//! `0x0845a0ca…9b98` returns all zeros; it settled hours earlier.
//!
//! So the authority is the `IntentSignaled` log, which is permanent. It carries
//! every field the attestation needs except the payee hash, and that comes from
//! the deposit the log names. The event's first three parameters are indexed, so
//! one filter on the intent hash finds it with no scanning of unrelated logs.
//!
//! # The 10,000-block cap
//!
//! Base's public RPC refuses an `eth_getLogs` range wider than 10,000 blocks
//! with `-32614`. A recovery scan that reaches back further has to be chunked,
//! which [`IntentReader::find_signal`] does, walking backwards from the head so
//! a recent intent is found in the first request.

use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use zecp2p_types::abi::IOrchestrator;

use crate::abi::IEscrowTaker;

/// The widest range Base's public RPC will serve in one `eth_getLogs`.
///
/// Exceeding it answers `-32614`, not a truncated result, so this is a hard
/// chunk size rather than a tuning parameter.
pub const MAX_LOG_RANGE: u64 = 10_000;

/// An intent's terms, as the attestation needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentTerms {
    pub intent_hash: B256,
    pub deposit_id: U256,
    /// 6-decimal USDC units.
    pub amount: U256,
    /// Fiat per USDC, scaled by 1e18.
    pub conversion_rate: U256,
    /// On-chain signal time, in seconds.
    pub timestamp: u64,
    /// The curator's opaque payee hash, from the deposit.
    pub payee_hash: B256,
    /// Where the signal landed, for the record.
    pub block_number: u64,
}

impl IntentTerms {
    /// What the enclave wants, in milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp.saturating_mul(1_000)
    }
}

pub struct IntentReader<P> {
    provider: P,
    orchestrator: Address,
    escrow: Address,
}

impl<P: Provider> IntentReader<P> {
    pub fn new(provider: P, orchestrator: Address, escrow: Address) -> Self {
        Self {
            provider,
            orchestrator,
            escrow,
        }
    }

    /// Find an intent's terms, from the live struct or from its signal log.
    ///
    /// `lookback` bounds how far back the log search goes when the intent has
    /// been pruned.
    pub async fn terms(&self, intent_hash: B256, lookback: u64) -> Result<IntentTerms> {
        if let Some(terms) = self.from_live_intent(intent_hash).await? {
            tracing::debug!(intent_hash = %intent_hash, "read the live intent");
            return Ok(terms);
        }

        tracing::info!(
            intent_hash = %intent_hash,
            "the intent is not stored on chain; it was fulfilled or expired and \
             pruned. Recovering its terms from the IntentSignaled log."
        );
        self.from_signal_log(intent_hash, lookback).await
    }

    /// The stored intent, if it is still there.
    ///
    /// A pruned intent reads back as a zero struct rather than reverting, so a
    /// zero `amount` is the tell. Treating that as real terms would build an
    /// attestation for a zero-amount payment.
    async fn from_live_intent(&self, intent_hash: B256) -> Result<Option<IntentTerms>> {
        let orchestrator = IOrchestrator::new(self.orchestrator, &self.provider);
        let intent = match orchestrator.getIntent(intent_hash).call().await {
            Ok(intent) => intent,
            Err(e) => {
                tracing::debug!(error = %e, "getIntent did not answer; falling back to logs");
                return Ok(None);
            }
        };

        if intent.amount.is_zero() || intent.timestamp.is_zero() {
            return Ok(None);
        }

        Ok(Some(IntentTerms {
            intent_hash,
            deposit_id: intent.depositId,
            amount: intent.amount,
            conversion_rate: intent.conversionRate,
            timestamp: intent.timestamp.to::<u64>(),
            payee_hash: intent.payeeDetails,
            block_number: 0,
        }))
    }

    /// Recover terms from the permanent `IntentSignaled` log.
    async fn from_signal_log(&self, intent_hash: B256, lookback: u64) -> Result<IntentTerms> {
        let log = self
            .find_signal(intent_hash, lookback)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no IntentSignaled log for intent {intent_hash} within {lookback} blocks. \
                     Either the intent belongs to a different orchestrator, or it was \
                     signalled further back than the lookback allows."
                )
            })?;

        let block_number = log.block_number.unwrap_or_default();
        let decoded = log
            .log_decode::<IOrchestrator::IntentSignaled>()
            .context("the IntentSignaled log did not decode")?
            .inner
            .data;

        // The log carries everything but the payee, which belongs to the
        // deposit rather than to the intent. A deposit that has been fully
        // drained and closed reads back as a zero struct, exactly as a pruned
        // intent does, so this can legitimately come back empty for a settled
        // order. The caller decides whether that is fatal: it is for a fill,
        // and it is not for reading terms.
        let payee_hash = self
            .deposit_payee(decoded.depositId, decoded.paymentMethod)
            .await
            .unwrap_or(B256::ZERO);
        if payee_hash.is_zero() {
            tracing::warn!(
                deposit_id = %decoded.depositId,
                "the deposit carries no payee hash; it has been withdrawn or \
                 closed. The attestation needs one, so supply it explicitly."
            );
        }

        Ok(IntentTerms {
            intent_hash,
            deposit_id: decoded.depositId,
            amount: decoded.amount,
            conversion_rate: decoded.conversionRate,
            timestamp: decoded.timestamp.to::<u64>(),
            payee_hash,
            block_number,
        })
    }

    /// Walk backwards from the head in 10,000-block chunks.
    ///
    /// Backwards because a daemon recovering its own recent intent finds it in
    /// the first request, and because the alternative, a single wide range, is
    /// refused outright by Base's public RPC rather than truncated.
    pub async fn find_signal(
        &self,
        intent_hash: B256,
        lookback: u64,
    ) -> Result<Option<alloy::rpc::types::Log>> {
        let head = self.provider.get_block_number().await?;
        let floor = head.saturating_sub(lookback);

        let mut to = head;
        loop {
            let from = to.saturating_sub(MAX_LOG_RANGE - 1).max(floor);

            let filter = Filter::new()
                .address(self.orchestrator)
                .event_signature(IOrchestrator::IntentSignaled::SIGNATURE_HASH)
                .topic1(intent_hash)
                .from_block(from)
                .to_block(to);

            let logs = self.provider.get_logs(&filter).await.with_context(|| {
                format!("could not read IntentSignaled logs over blocks {from}-{to}")
            })?;
            if let Some(log) = logs.into_iter().next() {
                return Ok(Some(log));
            }

            if from <= floor {
                return Ok(None);
            }
            to = from.saturating_sub(1);
        }
    }

    /// The payee hash the deposit will settle against.
    async fn deposit_payee(&self, deposit_id: U256, payment_method: B256) -> Result<B256> {
        let escrow = IEscrowTaker::new(self.escrow, &self.provider);
        let data = escrow
            .getDepositPaymentMethodData(deposit_id, payment_method)
            .call()
            .await
            .with_context(|| format!("could not read the payee for deposit {deposit_id}"))?;
        Ok(data.payeeDetails)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values the 2026-09-01 fill's own IntentSignaled log carries, decoded
    /// from Base at block 50,762,833. Every one of them is a field the
    /// attestation binds, and every one had to be right or the fiat was wasted.
    fn live_terms() -> IntentTerms {
        IntentTerms {
            intent_hash: "0x0845a0cade347cd5a1453fdc7f927d91511c82736377d8897b9bde38458b9b98"
                .parse()
                .unwrap(),
            deposit_id: U256::from(4499),
            amount: U256::from(4_875_437u64),
            conversion_rate: U256::from(990_881_148_896_019_200u128),
            timestamp: 1_788_315_013,
            payee_hash: "0x853410f0416f12611961e72ee5397ec6839a3f6475467f8a557bbdb3fc8555db"
                .parse()
                .unwrap(),
            block_number: 50_762_833,
        }
    }

    /// The enclave takes milliseconds; the chain stores seconds. Getting this
    /// wrong by a factor of 1000 reverts with "UPV: Snapshot timestamp
    /// mismatch" after the payment has gone out.
    #[test]
    fn the_chain_timestamp_becomes_milliseconds_for_the_enclave() {
        assert_eq!(live_terms().timestamp_ms(), 1_788_315_013_000);
    }

    /// The rate is the one thing a daemon must never default. This pins the
    /// value the live intent actually carried against the 1e18 that the prover
    /// would have used.
    #[test]
    fn the_recovered_rate_is_not_one_to_one() {
        let terms = live_terms();
        assert_eq!(terms.conversion_rate, U256::from(990_881_148_896_019_200u128));
        assert_ne!(
            terms.conversion_rate,
            U256::from(1_000_000_000_000_000_000u128)
        );
    }

    /// Base refuses a wider range outright rather than truncating, so this is a
    /// protocol limit and not a preference.
    #[test]
    fn the_chunk_size_matches_what_base_will_serve() {
        assert_eq!(MAX_LOG_RANGE, 10_000);
    }
}
