//! The keeper's half of the main route: promoting a funded order.
//!
//! An order opened through `/v2` costs no gas. It becomes an on-chain session
//! only when 1Click reports the sender's ZEC settled, and at that point the
//! keeper does three things in one tick: `createSession`, `creditSession`, and
//! the ordinary `/offramp` machinery from there on.
//!
//! `OfframpGlue.creditSession` gates on the session existing, on it being
//! unprocessed and unrescued, on a non-zero amount, and on the two accounting
//! bounds. None of those is a block height or an ordering rule against
//! `createSession`, so both calls land in the same tick. That was checked
//! against the contract, not assumed; see `docs/plans/ux-simplification.md`
//! section 10.3.

use std::sync::Arc;

use alloy::primitives::U256;
use anyhow::Result;
use zecp2p_types::settlement::{ReturnState, Stage};

use crate::{db::OrderRecord, state::AppState};

/// Map an offramp session's status onto the canonical stage the sender reads.
///
/// The five rungs are the same words on both backends, which is what lets one
/// ladder serve two routes.
pub fn stage_for(status: zecp2p_types::OfframpStatus) -> Stage {
    use zecp2p_types::OfframpStatus as S;
    match status {
        S::Created | S::NearIntentPending => Stage::AwaitingZec,
        S::UsdcReceived => Stage::ZecSeen,
        S::Zkp2pDeposited => Stage::InEscrow,
        S::IntentSignaled => Stage::PaidOut,
        S::Fulfilled => Stage::Done,
        S::Failed => Stage::Failed,
        // Rescued and Withdrawn both mean value is on its way back to the
        // sender. Neither is "done": the sender has not been paid.
        S::Rescued | S::Withdrawn => Stage::Returning,
    }
}

impl AppState {
    /// One pass over every order the keeper still has work to do on.
    pub async fn tick_orders(self: &Arc<Self>) -> Result<()> {
        let orders = self.db.get_open_orders().await?;
        for order in orders {
            if let Err(e) = self.advance_order(&order).await {
                tracing::warn!(order_id = %order.id, "error advancing order: {e}");
            }
        }
        Ok(())
    }

    async fn advance_order(self: &Arc<Self>, order: &OrderRecord) -> Result<()> {
        match order.session_uuid {
            // Not yet funded: watch the deposit address, and promote when the
            // swap settles.
            None => self.promote_if_funded(order).await,
            // Already a session: mirror its stage and its returns onto the
            // order, so the status page reads one object.
            Some(session_uuid) => self.mirror_session(order, session_uuid).await,
        }
    }

    /// Watch 1Click, and turn a funded order into a session.
    async fn promote_if_funded(self: &Arc<Self>, order: &OrderRecord) -> Result<()> {
        let Some(deposit) = &order.deposit else {
            return Ok(());
        };

        // 404 means 1Click has not registered the address it just handed out.
        // That is "not yet", not a failure.
        let Some(status) = self.near.get_status(&deposit.address).await? else {
            return Ok(());
        };

        if status.status == crate::near::IntentStatus::Refunded {
            // The swap failed and 1Click sent the ZEC to refund_address. When
            // that is the sender's own address there is nothing left to do; when
            // it is the session key's, the page sweeps it.
            let mut updated = order.clone();
            let refunded_zat = status
                .refunded_amount
                .as_deref()
                .and_then(|a| a.parse::<u64>().ok())
                .unwrap_or(0);

            updated.returns = if self.refund_is_the_senders_own(order) {
                ReturnState::Settled {
                    address: order.refund_address.clone(),
                    zatoshi: refunded_zat,
                    txid: status.source_tx_hash.clone().unwrap_or_default(),
                }
            } else {
                ReturnState::ZecAt {
                    address: order.refund_address.clone(),
                    zatoshi: refunded_zat,
                }
            };
            updated.stage = Stage::Returned;
            self.db.update_order(&updated).await?;
            return Ok(());
        }

        if !status.status.is_success() {
            // Still moving, or terminally failed with nothing to return yet.
            if status.status.is_terminal() {
                let mut updated = order.clone();
                updated.stage = Stage::Failed;
                updated.error = Some("the swap did not complete".to_string());
                self.db.update_order(&updated).await?;
            }
            return Ok(());
        }

        // Settled. This is the tick that spends gas, and the first one that
        // does anything on chain for this order.
        let session = self.create_session_for_order(order).await?;

        let mut updated = order.clone();
        updated.session_uuid = Some(session.id);
        updated.stage = Stage::ZecSeen;
        self.db.update_order(&updated).await?;

        tracing::info!(
            order_id = %order.id,
            session_id = %session.id,
            "order funded; created the on-chain session in the tick that saw the ZEC"
        );

        Ok(())
    }

    /// Whether the refund address on this order is one the sender named, as
    /// opposed to the session key's own transparent address.
    ///
    /// It decides whether a returned swap is finished or still needs a sweep,
    /// so it is read off the order rather than guessed from the address shape.
    fn refund_is_the_senders_own(&self, order: &OrderRecord) -> bool {
        order.overrides.refund_address.as_deref() == Some(order.refund_address.as_str())
    }

    /// Build the `OfframpSession` a funded order becomes.
    async fn create_session_for_order(
        self: &Arc<Self>,
        order: &OrderRecord,
    ) -> Result<zecp2p_types::OfframpSession> {
        let user_address = order
            .evm_address
            .parse()
            .map_err(|_| anyhow::anyhow!("order {} has an unparseable session address", order.id))?;

        let min_rate = order
            .overrides
            .min_rate
            .as_deref()
            .map(|s| s.parse::<U256>())
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_else(|| U256::from(1_000_000_000_000_000_000u128));

        let request = zecp2p_types::OfframpRequest {
            zec_amount: order.quote.zec_zatoshi,
            venmo_username: order.destination.handle.clone(),
            user_address,
            // Removed from both routes: it reaches no contract and enforces
            // nothing, and the listing takers use no longer returns it.
            taker_address: None,
            zec_refund_address: order.refund_address.clone(),
            min_rate,
            // The sender was quoted a net, and the deposit is sized so the rail
            // payment is exactly that number rather than whatever the swap
            // happened to deliver.
            target_payment_cents: Some(order.quote.net_cents),
            timeout_seconds: order
                .overrides
                .fill_budget_seconds
                .unwrap_or(600),
        };

        self.create_offramp(request)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Copy a session's progress onto the order the sender is watching.
    async fn mirror_session(
        self: &Arc<Self>,
        order: &OrderRecord,
        session_uuid: uuid::Uuid,
    ) -> Result<()> {
        let Some(session) = self.db.get_session(session_uuid).await? else {
            return Ok(());
        };

        let stage = stage_for(session.status);
        let returns = self.returns_for(order, &session).await;

        if stage == order.stage && returns == order.returns && session.error == order.error {
            return Ok(());
        }

        let mut updated = order.clone();
        updated.stage = stage;
        updated.returns = returns;
        updated.error = session.error.clone();
        self.db.update_order(&updated).await?;

        Ok(())
    }

    /// What, if anything, is coming back on this order.
    ///
    /// A rescued or withdrawn session has paid USDC to `session.user`, which is
    /// the session key's address. The page's only response to `UsdcAt` is to
    /// sign the back-swap; USDC is never shown to the sender as something to
    /// collect, because a Zcash user has no way to hold it.
    async fn returns_for(
        &self,
        order: &OrderRecord,
        session: &zecp2p_types::OfframpSession,
    ) -> ReturnState {
        use zecp2p_types::OfframpStatus as S;

        match session.status {
            S::Rescued | S::Withdrawn => {
                let units = session
                    .received_usdc
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "0".to_string());
                ReturnState::UsdcAt {
                    address: order.evm_address.clone(),
                    units,
                }
            }
            _ => order.returns.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zecp2p_types::OfframpStatus as S;

    /// The five rungs the sender reads, and the three states that replace the
    /// ladder rather than extending it.
    #[test]
    fn every_session_status_maps_onto_a_canonical_stage() {
        assert_eq!(stage_for(S::Created), Stage::AwaitingZec);
        assert_eq!(stage_for(S::NearIntentPending), Stage::AwaitingZec);
        assert_eq!(stage_for(S::UsdcReceived), Stage::ZecSeen);
        assert_eq!(stage_for(S::Zkp2pDeposited), Stage::InEscrow);
        assert_eq!(stage_for(S::IntentSignaled), Stage::PaidOut);
        assert_eq!(stage_for(S::Fulfilled), Stage::Done);
        assert_eq!(stage_for(S::Failed), Stage::Failed);
    }

    /// A rescue or a withdrawal is not a completed payment. Reading either as
    /// "done" would tell a sender their recipient was paid when the money is
    /// on its way back instead.
    #[test]
    fn a_rescue_or_a_withdrawal_is_a_return_not_a_completion() {
        assert_eq!(stage_for(S::Rescued), Stage::Returning);
        assert_eq!(stage_for(S::Withdrawn), Stage::Returning);
        assert_ne!(stage_for(S::Rescued), Stage::Done);
        assert_ne!(stage_for(S::Withdrawn), Stage::Done);
    }

    /// Only Fulfilled reads as done, so the happy path is the only path that
    /// tells the sender their money arrived.
    #[test]
    fn exactly_one_status_reads_as_done() {
        let all = [
            S::Created, S::NearIntentPending, S::UsdcReceived, S::Zkp2pDeposited,
            S::IntentSignaled, S::Fulfilled, S::Failed, S::Rescued, S::Withdrawn,
        ];
        assert_eq!(all.iter().filter(|s| stage_for(**s) == Stage::Done).count(), 1);
    }
}
