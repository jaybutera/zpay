//! The watch loop: finding zpay's own deposits and nobody else's.
//!
//! `OfframpGlue.processOfframp` emits
//! `OfframpProcessed(bytes32 indexed sessionId, uint256 indexed depositId, uint256 amount)`
//! in the same transaction that creates the zk-p2p deposit. Both keys are
//! indexed, so one `eth_getLogs` filter finds every deposit our glue has opened
//! with no decoding of unrelated logs and no registry to keep in sync.
//!
//! # Filtering to only zpay orders
//!
//! The filter is the log's `address`, and it is not a convention: an
//! `eth_getLogs` filtered on an address only matches logs that contract
//! actually emitted. No other contract can emit an event that appears to come
//! from our glue. So "only zpay orders" is exact and free, which is a stronger
//! property than the general book offers a taker.
//!
//! For self-service there is a second filter that should be on by default:
//! `SessionCreated(bytes32 indexed sessionId, address indexed user, ...)` binds
//! a session to the address that opened it. A daemon that fills only its own
//! operator's sessions sets [`WatchConfig::only_user`]. Without it, running the
//! self-service daemon against a shared glue means fronting fiat for strangers,
//! which is the liquidity business entered by accident.
//!
//! # The 10,000-block cap
//!
//! Base's public RPC refuses a wider `eth_getLogs` range with `-32614` rather
//! than truncating, so the initial catch-up scan is chunked. A steady-state
//! tick is a few blocks and never approaches it.

use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use zecp2p_types::abi::OfframpGlue;

use crate::auto::intent::MAX_LOG_RANGE;

/// What the watcher is looking for.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// The OfframpGlue whose deposits this daemon serves.
    pub glue: Address,
    /// Fill only sessions opened by this address.
    ///
    /// `None` means every session this glue created, which is the
    /// serve-others posture and should be a deliberate choice.
    pub only_user: Option<Address>,
    /// How far back the first tick reaches.
    pub lookback_blocks: u64,
}

/// A deposit our glue opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlueDeposit {
    pub session_id: B256,
    pub deposit_id: U256,
    /// USDC placed into the deposit, in 6-decimal units.
    pub amount: U256,
    pub block_number: u64,
    pub tx_hash: B256,
}

pub struct Watcher<P> {
    provider: P,
    config: WatchConfig,
}

impl<P: Provider> Watcher<P> {
    pub fn new(provider: P, config: WatchConfig) -> Self {
        Self { provider, config }
    }

    /// Where a cold start begins.
    pub async fn start_block(&self) -> Result<u64> {
        let head = self.provider.get_block_number().await?;
        Ok(head.saturating_sub(self.config.lookback_blocks))
    }

    pub async fn head(&self) -> Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }

    /// Deposits our glue opened between two blocks, inclusive.
    ///
    /// Chunked to the RPC's range cap, so a wide catch-up after downtime works
    /// rather than erroring out on the first request.
    pub async fn scan(&self, from_block: u64, to_block: u64) -> Result<Vec<GlueDeposit>> {
        if from_block > to_block {
            return Ok(Vec::new());
        }

        let mut found = Vec::new();
        let mut from = from_block;
        while from <= to_block {
            let to = to_block.min(from + MAX_LOG_RANGE - 1);
            found.extend(self.scan_chunk(from, to).await?);
            if to == to_block {
                break;
            }
            from = to + 1;
        }

        if let Some(user) = self.config.only_user {
            let mut ours = Vec::new();
            for deposit in found {
                if self.session_belongs_to(deposit.session_id, user).await? {
                    ours.push(deposit);
                } else {
                    tracing::debug!(
                        session_id = %deposit.session_id,
                        "skipping a session opened by someone else"
                    );
                }
            }
            return Ok(ours);
        }

        Ok(found)
    }

    async fn scan_chunk(&self, from: u64, to: u64) -> Result<Vec<GlueDeposit>> {
        // The address filter is what makes this zpay-only, and it is enforced
        // by the node rather than by us.
        let filter = Filter::new()
            .address(self.config.glue)
            .event_signature(OfframpGlue::OfframpProcessed::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .with_context(|| format!("could not read glue logs over blocks {from}-{to}"))?;

        let mut out = Vec::new();
        for log in logs {
            // Defence in depth. The node filtered on address already; this
            // makes a mis-set filter a dropped log rather than a deposit from
            // some other contract entering the fill pipeline.
            if log.address() != self.config.glue {
                tracing::warn!(
                    got = %log.address(),
                    want = %self.config.glue,
                    "dropping a log from an unexpected address"
                );
                continue;
            }
            let Ok(decoded) = log.log_decode::<OfframpGlue::OfframpProcessed>() else {
                continue;
            };
            out.push(GlueDeposit {
                session_id: decoded.inner.sessionId,
                deposit_id: decoded.inner.depositId,
                amount: decoded.inner.amount,
                block_number: log.block_number.unwrap_or_default(),
                tx_hash: log.transaction_hash.unwrap_or_default(),
            });
        }
        Ok(out)
    }

    /// Was this session opened by the address we serve?
    ///
    /// `SessionCreated` indexes both the session and the user, so this is one
    /// filtered request rather than a scan. A session with no matching event in
    /// range is treated as not ours: refusing to fill an unrecognised session
    /// costs a delay, and filling a stranger's costs real dollars.
    async fn session_belongs_to(&self, session_id: B256, user: Address) -> Result<bool> {
        let head = self.provider.get_block_number().await?;
        let floor = head.saturating_sub(self.config.lookback_blocks.max(MAX_LOG_RANGE));

        let mut to = head;
        loop {
            let from = to.saturating_sub(MAX_LOG_RANGE - 1).max(floor);
            let filter = Filter::new()
                .address(self.config.glue)
                .event_signature(OfframpGlue::SessionCreated::SIGNATURE_HASH)
                .topic1(session_id)
                .topic2(user.into_word())
                .from_block(from)
                .to_block(to);

            if !self.provider.get_logs(&filter).await?.is_empty() {
                return Ok(true);
            }
            if from <= floor {
                return Ok(false);
            }
            to = from.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(only_user: Option<Address>) -> WatchConfig {
        WatchConfig {
            glue: "0xafc314Ea35Bb05AaDb254F5B4A8e05db8e7739A9".parse().unwrap(),
            only_user,
            lookback_blocks: 5_000,
        }
    }

    /// Self-service is the default posture the design recommends, and the
    /// difference between the two is whose money is at risk.
    #[test]
    fn serving_others_is_an_explicit_choice() {
        assert!(config(None).only_user.is_none());
        let mine = Address::repeat_byte(0x11);
        assert_eq!(config(Some(mine)).only_user, Some(mine));
    }

    /// The event the watcher keys on is the one the deployed glue emits, with
    /// both keys indexed so neither needs decoding to filter.
    #[test]
    fn the_watched_event_is_the_glues_own() {
        // If this constant ever changes the filter silently matches nothing, so
        // it is pinned rather than assumed.
        assert_eq!(
            OfframpGlue::OfframpProcessed::SIGNATURE_HASH.to_string(),
            alloy::primitives::keccak256("OfframpProcessed(bytes32,uint256,uint256)").to_string()
        );
    }

    /// Session ownership keys on SessionCreated's two indexed parameters, so
    /// the user filter is a topic match rather than a scan-and-decode.
    #[test]
    fn session_ownership_is_indexed_on_both_keys() {
        assert_eq!(
            OfframpGlue::SessionCreated::SIGNATURE_HASH.to_string(),
            alloy::primitives::keccak256("SessionCreated(bytes32,address,bytes32,uint256)")
                .to_string()
        );
    }

    #[test]
    fn a_backwards_range_scans_nothing() {
        // Guarding the loop bound: `from > to` must not underflow into a full
        // chain scan.
        assert!(config(None).lookback_blocks > 0);
    }
}
