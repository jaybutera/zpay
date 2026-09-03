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

use crate::{db::OrderRecord, state::{AppState, FundedSwap}};

/// How long past a deposit's stated deadline the keeper keeps asking 1Click
/// about it.
///
/// A sender who broadcasts in the last minute of the window has a transaction
/// 1Click will still settle, and retiring the order the instant the clock
/// passes would strand exactly that payment. An hour is far longer than a Zcash
/// confirmation takes and still bounds the polling set.
const EXPIRY_GRACE: chrono::Duration = chrono::Duration::hours(1);

/// The longest the keeper will watch one deposit address, measured from when
/// the order was opened.
///
/// U2-1 and U2-7. The coordinator asks 1Click for a ten-minute deadline and
/// 1Click answers with its own, which on 2026-09-03 was three days. Storing
/// that unexamined made the polling set as large as 1Click cares to make it,
/// and an unfunded order held a place in the sweep for seventy-three hours at
/// no cost to whoever opened it.
///
/// Six hours is the compromise the audit asked for. It is far longer than the
/// twenty minutes the page promises and far longer than any Zcash confirmation,
/// so a real sender is never cut off; it is short enough that a backlog of
/// unfunded orders drains the same day rather than the same week. It only ever
/// shortens: a 1Click deadline sooner than this still wins, because polling an
/// address 1Click has already closed is polling nothing.
const MAX_POLLING_WINDOW: chrono::Duration = chrono::Duration::hours(6);

/// How long one tick may spend polling orders before it gives up and lets the
/// next tick continue.
///
/// The default poll interval is 15 seconds and live sessions are swept first,
/// so five seconds leaves the loop responsive even if the open set is large or
/// 1Click is slow.
const ORDER_SWEEP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// A hard cap on how many orders one tick polls, on top of the wall-clock
/// budget.
///
/// The budget alone makes what a tick covers a function of how fast 1Click and
/// this machine happen to be, which is fine in production and useless in a
/// test: a sweep that covers the whole set in one pass cannot demonstrate a
/// rotation, and whether it does depends on load. This bounds a tick by a
/// number instead, so the property is testable without pinning wall-clock
/// timings, and in production it binds only when 1Click is answering faster
/// than about six milliseconds a call, which it never has.
const ORDER_SWEEP_MAX_PER_TICK: usize = 800;

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
    /// One pass over the orders the keeper still has work to do on.
    ///
    /// Bounded by a wall-clock budget, and fair. The budget exists because the
    /// open set is fed by an endpoint anyone can call and the sweep must not be
    /// able to consume a whole tick however many rows it finds.
    ///
    /// U2-1. The budget alone was the defect. `get_open_orders` returned
    /// oldest-first and this walked it from the front on every tick, recording
    /// nothing, so the same twenty-five orders were polled forever and every
    /// order behind them was polled never. Marking each order as it is reached
    /// and ordering the query by that mark turns the walk into a rotation: an
    /// order the budget did not reach sorts ahead of every order that was
    /// reached, so with `N` open orders and a budget covering `B`, every order
    /// is polled within `ceil(N / B)` ticks.
    ///
    /// The mark is written before the poll rather than after. A poll that fails
    /// or hangs must still cost its subject a turn, or one order that always
    /// errors holds the front of the queue and the starvation comes straight
    /// back by another route.
    pub async fn tick_orders(self: &Arc<Self>) -> Result<()> {
        let orders = self.db.get_open_orders().await?;
        let total = orders.len();
        let started = std::time::Instant::now();
        let mut swept = 0usize;

        for order in orders {
            if swept >= self.order_sweep_max_per_tick() {
                tracing::debug!(swept, total, "order sweep hit its per-tick cap");
                break;
            }
            if started.elapsed() > ORDER_SWEEP_BUDGET {
                tracing::warn!(
                    swept,
                    total,
                    "order sweep hit its time budget; the rest lead the next tick"
                );
                break;
            }
            if let Err(e) = self.db.mark_order_polled(order.id).await {
                tracing::warn!(order_id = %order.id, "could not record the poll: {e}");
            }
            if let Err(e) = self.advance_order(&order).await {
                tracing::warn!(order_id = %order.id, "error advancing order: {e}");
            }
            swept += 1;
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

        // U1-2. 1Click answers PENDING_DEPOSIT for an address long past its
        // deadline, so status alone never retires an order and the keeper polls
        // every order it has ever opened, on every tick, ahead of the live
        // sessions. The deadline is the bound, and it was written to the row
        // and read by nothing.
        let past_the_window = chrono::Utc::now() > self.polling_deadline(order);

        // 404 means 1Click has not registered the address it just handed out.
        // That is "not yet", not a failure.
        let Some(status) = self.near.get_status(&deposit.address).await? else {
            if past_the_window {
                self.retire_unfunded(order, "1Click has no record of the deposit address")
                    .await?;
            }
            return Ok(());
        };

        // U2-1. Retirement now happens *after* the status call, not instead of
        // it. The old code read the clock, wrote "nothing was sent, so nothing
        // is owed", and never asked. For an order the sweep had been starving,
        // that sentence was false as often as it was true: the sender's ZEC had
        // been swapped, the USDC was sitting on the glue attributed to nothing,
        // and the page told them nothing was owed.
        //
        // Asking first costs one status call per order per lifetime, which is
        // what a single ordinary tick already costs, and it turns the sentence
        // into a fact. A settled or refunded order past its window falls
        // through to the branches below and is handled as what it is.
        if past_the_window && !status.status.is_success()
            && status.status != crate::near::IntentStatus::Refunded
        {
            self.retire_unfunded(
                order,
                &format!("1Click reports {:?} past the deposit window", status.status),
            )
            .await?;
            return Ok(());
        }

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
        //
        // U2-5. A settled order that can *never* be promoted must say so on the
        // row. The pre-column case bails rather than re-quoting, which is
        // right, but the bail went only to the log: the order kept its place in
        // the open set, was polled every tick with `error: None`, and the
        // sender's page read "Waiting for your ZEC" for an order whose ZEC had
        // arrived, until the window closed and retired it.
        //
        // Only that case writes the note. A chain call that failed, an RPC that
        // dropped, a curator that answered 500: all of those succeed on a later
        // tick, and putting "this needs a hand" on the page for one of them
        // would alarm a sender whose payment is about to go through by itself.
        let session = match self.create_session_for_order(order).await {
            Ok(session) => session,
            Err(e) => {
                if self.cannot_ever_be_promoted(order) {
                    let note = format!(
                        "your ZEC arrived and the swap settled, but this order cannot be \
                         finished automatically: {e}. Keep this link; nothing is lost."
                    );
                    if order.error.as_deref() != Some(note.as_str()) {
                        let mut updated = order.clone();
                        updated.error = Some(note);
                        self.db.update_order(&updated).await?;
                    }
                }
                return Err(e);
            }
        };

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

    /// How many orders one tick may poll.
    ///
    /// `ORDER_SWEEP_MAX_PER_TICK` unless `ZECP2P_ORDER_SWEEP_MAX_PER_TICK` says
    /// otherwise. The override exists so the sweep tests can make a tick cover
    /// a known fraction of the open set and assert the rotation directly,
    /// rather than inferring it from how fast a mock replied on the day.
    fn order_sweep_max_per_tick(&self) -> usize {
        std::env::var("ZECP2P_ORDER_SWEEP_MAX_PER_TICK")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(ORDER_SWEEP_MAX_PER_TICK)
    }

    /// Whether this order is missing something promotion can never recover.
    ///
    /// Today that is only the pre-column case from U1-1: an order opened before
    /// `swap_expected_usdc` and `swap_min_usdc` existed has no record of the
    /// quote its deposit address came from, and the one thing promotion must
    /// not do is take a second quote to fill them in. Every other promotion
    /// failure is worth retrying on the next tick.
    fn cannot_ever_be_promoted(&self, order: &OrderRecord) -> bool {
        order.deposit.is_none()
            || order.swap_expected_usdc.is_none()
            || order.swap_min_usdc.is_none()
    }

    /// The last moment this order's deposit address is worth polling.
    ///
    /// The sooner of 1Click's own deadline plus a grace window, and the
    /// coordinator's own cap measured from when the order was opened. See
    /// `MAX_POLLING_WINDOW` for why the cap exists.
    fn polling_deadline(&self, order: &OrderRecord) -> chrono::DateTime<chrono::Utc> {
        let oneclick = order
            .deposit
            .as_ref()
            .map(|d| d.expires_at + EXPIRY_GRACE)
            .unwrap_or(order.created_at);
        oneclick.min(order.created_at + MAX_POLLING_WINDOW)
    }

    /// Retire an order that 1Click has been asked about and does not report as
    /// funded.
    ///
    /// The sentence the sender reads says nothing arrived, and by the time this
    /// runs that has been checked against 1Click rather than inferred from the
    /// clock (U2-1, U2-5). `why` is for the log, not for the sender: it records
    /// which answer 1Click gave, so an order retired wrongly can be traced to
    /// the reply that retired it.
    async fn retire_unfunded(self: &Arc<Self>, order: &OrderRecord, why: &str) -> Result<()> {
        let mut updated = order.clone();
        updated.stage = Stage::Failed;
        updated.error = Some(
            "the deposit window closed and the bridge never saw any ZEC at this address. \
             Nothing was sent, so nothing is owed. If you did send ZEC, keep this link \
             and get in touch; the payment is traceable from the address above."
                .to_string(),
        );
        self.db.update_order(&updated).await?;
        tracing::info!(
            order_id = %order.id,
            why,
            "order retired unfunded after asking 1Click; no longer polled"
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

        // U1-1. The session must watch the address the sender actually paid, and
        // record the outputs of the quote that minted it. Handing the request to
        // `create_offramp` would take a *second* 1Click quote and store that new
        // address, so the keeper would poll an address nobody funded, the USDC
        // on the glue would be credited to no session, and the dead session
        // would hold the one-session gate shut for the NEAR timeout.
        let deposit = order
            .deposit
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("order {} has no deposit to promote", order.id))?;

        let (Some(expected), Some(min)) =
            (&order.swap_expected_usdc, &order.swap_min_usdc)
        else {
            // Orders opened before the columns existed. Re-quoting is the one
            // thing that must not happen, so this stops rather than guesses.
            anyhow::bail!(
                "order {} predates the funded-swap fix and has no recorded quote outputs; \
                 it cannot be promoted safely and needs manual settlement",
                order.id
            )
        };

        self.create_offramp_for_funded_swap(
            request,
            FundedSwap {
                deposit_address: deposit.address.clone(),
                expected_output: expected.clone(),
                min_output: min.clone(),
            },
        )
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

        // A session spends one pass in NearIntentPending after promotion, which
        // maps to AwaitingZec. The order already reads ZecSeen by then, so
        // mirroring it raw would tell the sender their ZEC was un-received.
        let stage = stage_for(session.status).no_lower_than(order.stage);
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
