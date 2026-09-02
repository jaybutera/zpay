//! Finding deposits worth taking.
//!
//! Discovery is the chain itself. `OfframpGlue.processOfframp` emits
//! `OfframpProcessed(sessionId, depositId, amount)` and EscrowV2 emits
//! `DepositReceived` in the same transaction, so scanning the glue's own logs
//! is enough to find every deposit zecp2p has opened. No registry, no
//! coordinator round trip: a taker who has never spoken to our server sees the
//! same deposits we do.

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::Result;
use zecp2p_types::abi::OfframpGlue;

use crate::abi::IEscrowTaker;

/// A glue-created deposit that still has liquidity to claim.
#[derive(Debug, Clone)]
pub struct ClaimableDeposit {
    pub deposit_id: U256,
    pub session_id: alloy::primitives::B256,
    /// USDC still unspoken for, in 6-decimal units.
    pub remaining: U256,
    /// The intent size the escrow will accept.
    pub min_intent: U256,
    pub max_intent: U256,
    /// USDC already locked by a live intent on this deposit, from any taker.
    pub outstanding: U256,
    pub block_number: u64,
}

impl ClaimableDeposit {
    /// Largest intent this deposit will accept right now.
    ///
    /// EscrowV2 rejects an intent outside `intentAmountRange`, and cannot serve
    /// more than `remainingDeposits`. The glue currently pins the range to the
    /// full deposit, so this is normally the whole amount.
    pub fn takeable_amount(&self, taker_max: U256) -> Option<U256> {
        // A deposit with a live intent on it is mid-fill, and the remainder is
        // not a fresh opportunity. On 2026-09-02 deposit 4526 was pinned to a
        // single $5.00 intent; once that intent was signalled, `remaining` fell
        // to the 120,606-unit dust the range could never serve, and the daemon
        // read that dust as a new deposit to claim and tried to signal a second
        // intent for $0.12 rather than paying the $5.00 intent it already held.
        // Whoever owns the outstanding intent, the right move is to leave this
        // deposit alone until it settles or expires.
        if !self.outstanding.is_zero() {
            return None;
        }

        let amount = self.max_intent.min(self.remaining).min(taker_max);
        if amount < self.min_intent || amount.is_zero() {
            return None;
        }
        Some(amount)
    }
}

pub struct Discovery<P> {
    provider: P,
    glue: Address,
    escrow: Address,
}

impl<P: Provider> Discovery<P> {
    pub fn new(provider: P, glue: Address, escrow: Address) -> Self {
        Self {
            provider,
            glue,
            escrow,
        }
    }

    /// Scan a block range for deposits the glue opened, keeping the ones that
    /// still hold liquidity.
    ///
    /// A deposit that has been fully claimed, withdrawn, or locked by another
    /// taker's intent shows up here with nothing left, and is dropped.
    pub async fn scan(&self, from_block: u64, to_block: u64) -> Result<Vec<ClaimableDeposit>> {
        let filter = Filter::new()
            .address(self.glue)
            .event_signature(OfframpGlue::OfframpProcessed::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let logs = self.provider.get_logs(&filter).await?;
        let mut out = Vec::new();

        for log in logs {
            let Ok(decoded) = log.log_decode::<OfframpGlue::OfframpProcessed>() else {
                continue;
            };
            let deposit_id = decoded.inner.depositId;
            let session_id = decoded.inner.sessionId;

            // The event says a deposit was created; the escrow says whether
            // anything is left. Another taker may have already claimed it.
            let escrow = IEscrowTaker::new(self.escrow, &self.provider);
            let deposit = match escrow.getDeposit(deposit_id).call().await {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(deposit_id = %deposit_id, error = %e, "skipping unreadable deposit");
                    continue;
                }
            };

            if !deposit.acceptingIntents || deposit.remainingDeposits.is_zero() {
                continue;
            }

            out.push(ClaimableDeposit {
                deposit_id,
                session_id,
                remaining: deposit.remainingDeposits,
                min_intent: deposit.intentAmountRange.min,
                max_intent: deposit.intentAmountRange.max,
                outstanding: deposit.outstandingIntentAmount,
                block_number: log.block_number.unwrap_or(0),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, U256};

    fn deposit(remaining: u64, min: u64, max: u64) -> ClaimableDeposit {
        ClaimableDeposit {
            deposit_id: U256::from(1),
            session_id: B256::ZERO,
            remaining: U256::from(remaining),
            min_intent: U256::from(min),
            max_intent: U256::from(max),
            outstanding: U256::ZERO,
            block_number: 1,
        }
    }

    #[test]
    fn takes_the_whole_deposit_when_it_fits() {
        let d = deposit(25_000_000, 25_000_000, 25_000_000);
        assert_eq!(
            d.takeable_amount(U256::from(100_000_000u64)),
            Some(U256::from(25_000_000u64))
        );
    }

    #[test]
    fn declines_a_deposit_larger_than_the_taker_allows() {
        // The glue pins min == max, so a taker who cannot cover the whole
        // deposit cannot take part of it either.
        let d = deposit(500_000_000, 500_000_000, 500_000_000);
        assert_eq!(d.takeable_amount(U256::from(100_000_000u64)), None);
    }

    #[test]
    fn declines_when_liquidity_is_already_gone() {
        let d = deposit(0, 1, 25_000_000);
        assert_eq!(d.takeable_amount(U256::from(100_000_000u64)), None);
    }

    #[test]
    fn clamps_to_the_taker_limit_on_a_ranged_deposit() {
        let d = deposit(90_000_000, 1_000_000, 90_000_000);
        assert_eq!(
            d.takeable_amount(U256::from(40_000_000u64)),
            Some(U256::from(40_000_000u64))
        );
    }

    #[test]
    fn leaves_a_deposit_alone_while_an_intent_is_live_on_it() {
        // Deposit 4526 after its $5.00 intent was signalled: the range still
        // reads [5057401, 5057401], but only 120,606 units are unspoken for.
        // Taking that as a claimable deposit is what made the daemon try to
        // signal a second intent for $0.12 instead of paying the one it held.
        let mut d = deposit(120_606, 5_057_401, 5_057_401);
        d.outstanding = U256::from(5_057_401u64);
        assert_eq!(d.takeable_amount(U256::from(6_000_000u64)), None);
    }

    #[test]
    fn takes_it_once_the_intent_has_settled() {
        let mut d = deposit(5_057_401, 5_057_401, 5_057_401);
        d.outstanding = U256::ZERO;
        assert_eq!(
            d.takeable_amount(U256::from(6_000_000u64)),
            Some(U256::from(5_057_401u64))
        );
    }
}
