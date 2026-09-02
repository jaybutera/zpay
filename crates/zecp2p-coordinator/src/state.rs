//! Application state and keeper loop
//!
//! Contains the shared application state and offramp processing logic.

#![allow(dead_code)]

use std::sync::Arc;

use alloy::primitives::{Bytes, U256};
use anyhow::Result;
use tokio::sync::RwLock;
use zecp2p_types::{
    abi::{fixed_rate_currency, usd_currency_code, venmo_payment_method, OfframpGlue},
    Config, OfframpRequest, OfframpSession, OfframpStatus,
};

use crate::{
    chain::ChainClient,
    db::Database,
    error::AppError,
    near::{IntentStatus, NearIntentsClient},
    zkp2p::Zkp2pClient,
};

/// Key for storing last processed block in the database
const LAST_PROCESSED_BLOCK_KEY: &str = "last_processed_block";

// Loop timing lives in [`zecp2p_types::KeeperConfig`] (the `[keeper]` section of
// the config file), so an operator can slow the poll down on a metered RPC
// without a rebuild. The defaults there are the values this loop used to hard
// code: 15s poll, 3600s session budget, 302400s for a session still waiting on
// the NEAR leg, 1000 blocks of lookback.

/// Parse the settled output amount 1Click reports for a swap.
///
/// `swapDetails.amountOut` is a decimal string in the destination asset's own
/// units, so USDC's six decimals here. Returns `Ok(None)` when the field is
/// absent or empty, which is what a status carrying no settlement looks like.
/// A present-but-unparseable value is an error rather than a `None`: silently
/// treating garbage as "not settled yet" would leave a session stuck forever
/// with no record of why.
fn settled_output(amount_out: Option<&str>) -> Result<Option<U256>> {
    let Some(raw) = amount_out.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let parsed = U256::from_str_radix(raw, 10)
        .map_err(|e| anyhow::anyhow!("1Click reported an unparseable amountOut {raw:?}: {e}"))?;
    if parsed.is_zero() {
        return Ok(None);
    }
    Ok(Some(parsed))
}

/// What the keeper should do with a session whose swap 1Click reports settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditDecision {
    /// Credit this many USDC units to the session.
    Credit(U256),
    /// Not yet; the reason is for the log.
    Wait(&'static str),
    /// 1Click settled below the floor it guaranteed for this swap.
    Short { settled: U256, floor: U256 },
}

/// Decide how much of the glue's USDC belongs to one session.
///
/// The rule is: credit what 1Click reported *this session's own deposit address*
/// settled for, clamped to the quote. The unassigned balance is a sanity bound
/// only, saying the money has landed, not whose it is.
///
/// NEW-1 in the 2026-08-31 re-audit was the previous rule, `min(unassigned,
/// expected)`. That credited a session out of the shared pool, so with 50 bps of
/// quote slippage making an under-fill ordinary, the first session the tick
/// reached was topped up to its full quote out of a concurrent session's USDC.
/// The victim was then left below its own floor, never promoted, and, never
/// having been credited, had no working `rescue` either.
pub fn credit_decision(
    settled: Option<U256>,
    unassigned: U256,
    expected: U256,
    floor: U256,
) -> CreditDecision {
    let Some(settled) = settled else {
        return CreditDecision::Wait("1Click reports SUCCESS but no settled amountOut yet");
    };

    if settled < floor {
        return CreditDecision::Short { settled, floor };
    }

    // Never take more than the session was quoted. The contract enforces this
    // too (`CreditExceedsExpected`), but clamping here keeps the keeper from
    // sending a transaction that can only revert. The surplus stays unassigned.
    let credit = settled.min(expected);

    if unassigned < credit {
        return CreditDecision::Wait("the settled USDC has not landed on the glue yet");
    }

    CreditDecision::Credit(credit)
}

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub chain: ChainClient,
    pub near: NearIntentsClient,
    pub zkp2p: Zkp2pClient,
    /// In-memory cache of active sessions
    sessions: RwLock<std::collections::HashMap<uuid::Uuid, OfframpSession>>,
}

impl AppState {
    pub fn new(
        config: Config,
        db: Database,
        chain: ChainClient,
        near: NearIntentsClient,
        zkp2p: Zkp2pClient,
    ) -> Self {
        Self {
            config,
            db,
            chain,
            near,
            zkp2p,
            sessions: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Create a new offramp session
    pub async fn create_offramp(
        self: &Arc<Self>,
        request: OfframpRequest,
    ) -> Result<OfframpSession, AppError> {
        // Defence in depth for NEW-1. The glue holds one pot for every session and
        // an ERC-20 transfer names no session, so attribution rests entirely on
        // what 1Click reports settled. Crediting the settled amount is the real
        // fix; refusing a second concurrent session means a bug in that path has
        // no second user's money to reach, because there is none on the contract.
        // This is code rather than operator discipline because the keeper's own
        // tick is what would do the damage.
        //
        // First, before the curator and 1Click round trips, so a refused request
        // costs nothing and registers nothing.
        self.refuse_if_a_session_is_in_flight().await?;

        // Register the Venmo username with the zk-p2p curator. The hash it
        // returns is the only payeeDetails value the payment verifier accepts;
        // do this before touching the chain so a bad username costs no gas.
        let valid = self
            .zkp2p
            .validate_venmo_payee(&request.venmo_username)
            .await
            .map_err(|e| AppError::Zkp2p(e.to_string()))?;
        if !valid {
            return Err(AppError::InvalidState(format!(
                "Venmo username '{}' was rejected by zk-p2p (must match the account's exact casing, without '@')",
                request.venmo_username
            )));
        }
        let payee_details_hash = self
            .zkp2p
            .register_venmo_payee(&request.venmo_username)
            .await
            .map_err(|e| AppError::Zkp2p(e.to_string()))?;

        // Create session
        let mut session = OfframpSession::new(request.clone(), payee_details_hash);

        // Reject what 1Click would reject, before a round trip turns it into a 502.
        if request.zec_amount < crate::near::MIN_ZEC_ZATOSHI {
            return Err(AppError::InvalidRequest(format!(
                "ZEC amount {} zatoshi is below the 1Click minimum of {} zatoshi",
                request.zec_amount,
                crate::near::MIN_ZEC_ZATOSHI
            )));
        }
        crate::near::validate_zec_refund_address(&request.zec_refund_address)
            .map_err(|e| AppError::InvalidRequest(e.to_string()))?;

        // Get quote from NEAR Intents
        let glue_address = self
            .chain
            .glue_contract()
            .map_err(|e| AppError::Config(e.to_string()))?;

        // Use the helper to create ZEC → USDC on Base request
        let quote_request = crate::near::NearIntentsClient::zec_to_usdc_base_request(
            request.zec_amount,
            &glue_address.to_string(),
            &request.zec_refund_address,
            Some(50), // 0.5% slippage
        );

        let quote = self
            .near
            .get_quote(quote_request)
            .await
            .map_err(|e| AppError::NearIntents(e.to_string()))?;

        session.near_deposit_address = Some(quote.deposit_address);
        session.expected_usdc = Some(
            U256::from_str_radix(&quote.expected_output, 10)
                .map_err(|e| AppError::NearIntents(e.to_string()))?,
        );
        // The guaranteed floor, not the estimate. The keeper waits for this much
        // before crediting the session, so a short delivery cannot promote it.
        session.min_output_usdc = Some(
            U256::from_str_radix(&quote.min_output, 10)
                .map_err(|e| AppError::NearIntents(e.to_string()))?,
        );

        // Register session on-chain
        let tx_hash = self
            .chain
            .create_session(
                session.session_id,
                request.user_address,
                session.payee_details_hash,
                request.min_rate,
                session.expected_usdc.unwrap_or(U256::ZERO),
            )
            .await
            .map_err(|e| AppError::Chain(e.to_string()))?;

        session.create_session_tx = Some(tx_hash);
        session.set_status(OfframpStatus::NearIntentPending);

        // Persist to database
        self.db
            .insert_session(&session)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Add to in-memory cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session.clone());
        }

        Ok(session)
    }

    /// Refuse a new session while another one still has funds in flight.
    ///
    /// "In flight" means any session that is not terminal: it may still be owed
    /// USDC on the glue, or already own a slice of it. Sessions that have
    /// fulfilled, failed, been rescued or been withdrawn are done and do not
    /// block anything.
    ///
    /// Operators who have satisfied themselves that the settled-amount
    /// attribution is enough can turn this off with
    /// `keeper.allow_concurrent_sessions = true`; the default is off.
    pub async fn refuse_if_a_session_is_in_flight(&self) -> Result<(), AppError> {
        if self.config.keeper.allow_concurrent_sessions {
            return Ok(());
        }

        let active = self
            .db
            .get_active_sessions()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if let Some(existing) = active.first() {
            return Err(AppError::InvalidState(format!(
                "session {} is still in flight ({}); this coordinator runs one offramp at a \
                 time so a short settlement can never be covered out of another user's USDC. \
                 Wait for it to finish, or rescue it, before opening another.",
                existing.id, existing.status
            )));
        }

        Ok(())
    }

    /// Get session by ID
    pub async fn get_session(&self, id: uuid::Uuid) -> Result<Option<OfframpSession>, AppError> {
        // Try cache first
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&id) {
                return Ok(Some(session.clone()));
            }
        }

        // Fall back to database
        self.db.get_session(id).await.map_err(|e| AppError::Internal(e.to_string()))
    }

    /// Update session in both cache and database
    /// Used for testing and keeper loop operations
    pub async fn update_session(&self, session: &OfframpSession) -> Result<(), AppError> {
        // Update database
        self.db
            .update_session(session)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Update cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session.clone());
        }

        Ok(())
    }

    /// Process offramp - route USDC to zk-p2p
    pub async fn process_offramp(
        self: &Arc<Self>,
        id: uuid::Uuid,
    ) -> Result<OfframpSession, AppError> {
        let mut session = self
            .get_session(id)
            .await?
            .ok_or(AppError::SessionNotFound)?;

        if session.status != OfframpStatus::UsdcReceived {
            return Err(AppError::InvalidState(format!(
                "Cannot process offramp in state: {:?}",
                session.status
            )));
        }

        // Build zk-p2p deposit parameters
        let payment_methods = vec![venmo_payment_method()];

        let payment_method_data = vec![OfframpGlue::DepositPaymentMethodData {
            intentGatingService: alloy::primitives::Address::ZERO, // No gating service for V0
            payeeDetails: session.payee_details_hash,
            data: Bytes::new(),
        }];

        // min_rate is the USD-per-USDC floor the taker must pay (18 decimals)
        let currencies = vec![vec![fixed_rate_currency(
            usd_currency_code(),
            session.request.min_rate,
        )]];

        // Size the intent, if the user asked for an exact payment.
        //
        // Left unset, the deposit's intent range is the whole credited amount and
        // the taker's Venmo payment is `credited * min_rate`: a number nobody
        // chose, because `credited` is whatever the swap happened to deliver. The
        // 2026-09-01 fill went out that way and paid $4.84 against a $5.00
        // request. Pinning the range to the size that prices to the requested
        // payment puts the spread and the curator's fee on top of the request
        // instead of inside it, and leaves the swap's overshoot in the deposit.
        let intent_range = match session.request.target_payment_cents {
            None => None,
            Some(target_cents) => {
                // The money that will actually back the deposit, read from the
                // contract rather than from our own record of it. This is the
                // number `_processOfframp` will spend, so it is the number the
                // sized intent has to fit inside.
                let credited = self
                    .chain
                    .get_session(session.session_id)
                    .await
                    .map_err(|e| AppError::Chain(e.to_string()))?
                    .credited;

                let units = zecp2p_types::pricing::intent_units_for_cents(
                    target_cents,
                    session.request.min_rate,
                )
                .map_err(|e| AppError::InvalidState(e.to_string()))?;

                // The deposit is funded from this session's credit and nothing
                // else, so an intent larger than the credit cannot be created.
                // Refusing here names the shortfall; the contract would only say
                // InvalidIntentRange.
                if units > credited {
                    return Err(AppError::InvalidState(format!(
                        "a Venmo payment of ${}.{:02} at rate {} needs an intent of {} USDC \
                         units, but this session only credited {}. The swap delivered less \
                         than the requested payment needs. Send more ZEC, or lower the \
                         requested payment.",
                        target_cents / 100,
                        target_cents % 100,
                        session.request.min_rate,
                        units,
                        credited
                    )));
                }

                tracing::info!(
                    target_cents,
                    intent_units = %units,
                    credited = %credited,
                    rate = %session.request.min_rate,
                    "sizing the intent so the Venmo payment is exactly what was requested"
                );
                Some(units)
            }
        };

        // Execute on-chain
        let (tx_hash, deposit_id) = match intent_range {
            // A single intent pinned to the sized amount: min == max, so a taker
            // can claim that size and nothing else.
            Some(units) => self
                .chain
                .process_offramp_with_range(
                    session.session_id,
                    payment_methods,
                    payment_method_data,
                    currencies,
                    units,
                    units,
                )
                .await
                .map_err(|e| AppError::Chain(e.to_string()))?,
            None => self
                .chain
                .process_offramp(
                    session.session_id,
                    payment_methods,
                    payment_method_data,
                    currencies,
                )
                .await
                .map_err(|e| AppError::Chain(e.to_string()))?,
        };

        session.process_offramp_tx = Some(tx_hash);
        session.zkp2p_deposit_id = Some(deposit_id);
        session.set_status(OfframpStatus::Zkp2pDeposited);

        // Persist
        self.db
            .update_session(&session)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Update cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session.clone());
        }

        Ok(session)
    }

    /// Run the keeper loop to monitor and process sessions
    pub async fn run_keeper_loop(self: &Arc<Self>) -> Result<()> {
        let poll_interval =
            std::time::Duration::from_secs(self.config.keeper.poll_interval_seconds);

        loop {
            if let Err(e) = self.keeper_tick().await {
                tracing::error!("Keeper tick error: {}", e);
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Run the keeper loop with graceful shutdown support
    pub async fn run_keeper_loop_with_shutdown(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let poll_interval =
            std::time::Duration::from_secs(self.config.keeper.poll_interval_seconds);

        loop {
            // Check for shutdown signal
            if *shutdown_rx.borrow() {
                tracing::info!("Keeper loop received shutdown signal");
                break;
            }

            // Run keeper tick
            if let Err(e) = self.keeper_tick().await {
                tracing::error!("Keeper tick error: {}", e);
            }

            // Wait for next tick or shutdown
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Keeper loop received shutdown signal during sleep");
                        break;
                    }
                }
            }
        }

        tracing::info!("Keeper loop shutdown complete");
        Ok(())
    }

    async fn keeper_tick(self: &Arc<Self>) -> Result<()> {
        // Load active sessions
        let sessions = self.db.get_active_sessions().await?;

        for session in sessions {
            if let Err(e) = self.process_session(&session).await {
                tracing::warn!("Error processing session {}: {}", session.id, e);
            }
        }

        // Update last processed block
        if let Ok(block) = self.chain.current_block().await {
            let _ = self.db.set_kv(LAST_PROCESSED_BLOCK_KEY, &block.to_string()).await;
        }

        Ok(())
    }

    /// Get the block to start event scanning from
    async fn get_event_start_block(&self) -> Result<u64> {
        let current_block = self.chain.current_block().await?;

        // Try to get last processed block from DB
        if let Some(stored) = self.db.get_kv(LAST_PROCESSED_BLOCK_KEY).await? {
            if let Ok(block) = stored.parse::<u64>() {
                // Start from last processed block (with small overlap for safety)
                return Ok(block.saturating_sub(10));
            }
        }

        // Fallback to lookback
        Ok(current_block.saturating_sub(self.config.keeper.event_lookback_blocks))
    }

    async fn process_session(self: &Arc<Self>, session: &OfframpSession) -> Result<()> {
        // A session whose USDC is already committed on chain has an outcome the
        // clock cannot overrule. Read that outcome before considering the
        // timeout, or a fill that lands after the budget expires is recorded as
        // a failure while the escrow says it settled: on 2026-09-02 session
        // 866dda19 filled for the full 5,057,401 and still read "Session timed
        // out", because the timeout arm returned before the fulfilment check
        // ever ran. The intent is the last word, so ask it first.
        if session.status == OfframpStatus::IntentSignaled {
            self.check_zkp2p_fulfillment(session).await?;
            // Re-read: the check above may have just settled it, and a settled
            // session is terminal and must not then be failed.
            if let Some(latest) = self.db.get_session(session.id).await? {
                if latest.status == OfframpStatus::Fulfilled {
                    return Ok(());
                }
            }
        }

        // Check for timeout
        if self.is_session_timed_out(session) {
            tracing::warn!(
                "Session {} timed out after {} seconds",
                session.id,
                self.session_timeout_secs(session)
            );
            let mut updated = session.clone();
            updated.fail("Session timed out");
            self.db.update_session(&updated).await?;
            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);
            return Ok(());
        }

        match session.status {
            OfframpStatus::NearIntentPending => {
                self.check_near_intent(session).await?;
            }
            OfframpStatus::UsdcReceived => {
                // Auto-process if USDC arrived
                self.process_offramp(session.id).await?;
            }
            OfframpStatus::Zkp2pDeposited => {
                self.check_zkp2p_intent(session).await?;
            }
            OfframpStatus::IntentSignaled => {
                self.check_zkp2p_fulfillment(session).await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Check if a session has timed out
    ///
    /// A session waiting on the ZEC deposit gets the longer
    /// `keeper.near_intent_timeout_seconds` budget, since that leg is bounded by
    /// 1Click's deposit deadline rather than by anything the coordinator controls.
    fn is_session_timed_out(&self, session: &OfframpSession) -> bool {
        let now = chrono::Utc::now();
        let elapsed = now.signed_duration_since(session.created_at);
        elapsed.num_seconds() > self.session_timeout_secs(session)
    }

    /// The timeout budget that applies to a session at its current stage
    fn session_timeout_secs(&self, session: &OfframpSession) -> i64 {
        match session.status {
            OfframpStatus::NearIntentPending => self.config.keeper.near_intent_timeout_seconds,
            _ => self.config.keeper.session_timeout_seconds,
        }
    }

    async fn check_near_intent(&self, session: &OfframpSession) -> Result<()> {
        let deposit_addr = session
            .near_deposit_address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No deposit address"))?;

        // 1Click answers 404 until it has registered the deposit address it just
        // handed out. Treat that as "not yet", not as a failed session.
        let Some(status) = self.near.get_status(deposit_addr).await? else {
            tracing::debug!(
                "Session {} deposit address not yet known to 1Click",
                session.id
            );
            return Ok(());
        };

        if status.status.is_success() {
            // The glue is shared, so nothing about its balance says whose money
            // is there. The only per-session figure is what 1Click settled for
            // this session's own deposit address, and that is what gets credited.
            let expected = session
                .expected_usdc
                .ok_or_else(|| anyhow::anyhow!("session has no expected USDC amount"))?;

            // 1Click quotes an expected output and guarantees only min_amount_out;
            // accept anything at or above that floor and credit what actually arrived.
            let floor = session.min_output_usdc.unwrap_or(expected);

            // What this session's own swap settled for. 1Click reports it per
            // deposit address, so it is the only figure that says whose money
            // arrived; the glue's balance cannot, because an ERC-20 transfer
            // carries no session id.
            let settled = settled_output(status.output_amount.as_deref())?;
            let unassigned = self.chain.glue_unassigned_balance().await?;

            let credit = match credit_decision(settled, unassigned, expected, floor) {
                CreditDecision::Credit(amount) => amount,
                CreditDecision::Wait(why) => {
                    tracing::debug!("Session {} not credited yet: {}", session.id, why);
                    return Ok(());
                }
                CreditDecision::Short { settled, floor } => {
                    tracing::warn!(
                        "Session {} settled {} USDC, below its guaranteed floor of {}; not crediting",
                        session.id,
                        settled,
                        floor
                    );
                    return Ok(());
                }
            };

            // Claim it on-chain before recording it, so the session's slice of the
            // pot is fixed by the contract rather than by this loop's bookkeeping.
            self.chain
                .credit_session(session.session_id, credit)
                .await?;

            let mut updated = session.clone();
            updated.received_usdc = Some(credit);
            updated.near_tx_hash = status.destination_tx_hash;
            updated.set_status(OfframpStatus::UsdcReceived);

            self.db.update_session(&updated).await?;

            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);

            tracing::info!(
                "Session {} credited {} USDC, which is what 1Click settled \
                 (expected {}, floor {})",
                session.id,
                credit,
                expected,
                floor
            );
        } else if status.status == IntentStatus::Refunded {
            let mut updated = session.clone();
            updated.fail(match status.refunded_amount {
                Some(amount) => format!("NEAR Intent refunded {} zatoshi to the refund address", amount),
                None => "NEAR Intent refunded to the refund address".to_string(),
            });

            self.db.update_session(&updated).await?;

            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);
        } else if status.status.is_terminal() {
            let mut updated = session.clone();
            updated.fail("NEAR Intent failed");

            self.db.update_session(&updated).await?;

            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);
        } else if status.status == IntentStatus::IncompleteDeposit {
            // Under-deposit. 1Click refunds this by the quote deadline, which can be
            // days out, so keep polling rather than failing the session.
            tracing::warn!(
                "Session {} has an incomplete deposit; awaiting 1Click refund or top-up",
                session.id
            );
        }

        Ok(())
    }

    async fn check_zkp2p_intent(&self, session: &OfframpSession) -> Result<()> {
        let deposit_id = session
            .zkp2p_deposit_id
            .ok_or_else(|| anyhow::anyhow!("No deposit ID"))?;

        // Get block range for event scanning
        let current_block = self.chain.current_block().await?;
        let from_block = self.get_event_start_block().await?;

        // Check for IntentSignaled events for this deposit
        let events = self
            .chain
            .get_intent_signaled_events(deposit_id, from_block, current_block)
            .await?;

        if let Some(event) = events.first() {
            tracing::info!(
                "Session {} intent signaled: {:?} by {:?}",
                session.id,
                event.intent_hash,
                event.owner
            );

            let mut updated = session.clone();
            updated.zkp2p_intent_hash = Some(event.intent_hash);
            updated.set_status(OfframpStatus::IntentSignaled);

            self.db.update_session(&updated).await?;

            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);
        } else {
            tracing::debug!(
                "Session {} waiting for intent signal on deposit {:?}",
                session.id,
                deposit_id
            );
        }

        Ok(())
    }

    async fn check_zkp2p_fulfillment(&self, session: &OfframpSession) -> Result<()> {
        let intent_hash = session
            .zkp2p_intent_hash
            .ok_or_else(|| anyhow::anyhow!("No intent hash"))?;

        // Get block range for event scanning
        let current_block = self.chain.current_block().await?;
        let from_block = self.get_event_start_block().await?;

        // Check for IntentFulfilled events for this intent
        let events = self
            .chain
            .get_intent_fulfilled_events(intent_hash, from_block, current_block)
            .await?;

        if let Some(event) = events.first() {
            tracing::info!(
                "Session {} intent fulfilled: amount={}, to={:?}",
                session.id,
                event.amount,
                event.funds_transferred_to
            );

            let mut updated = session.clone();
            updated.set_status(OfframpStatus::Fulfilled);

            self.db.update_session(&updated).await?;

            let mut sessions = self.sessions.write().await;
            sessions.insert(updated.id, updated);
        } else {
            tracing::debug!(
                "Session {} waiting for fulfillment of intent {:?}",
                session.id,
                intent_hash
            );
        }

        Ok(())
    }

    /// Rescue funds from GlueContract
    pub async fn rescue(self: &Arc<Self>, id: uuid::Uuid) -> Result<OfframpSession, AppError> {
        let mut session = self
            .get_session(id)
            .await?
            .ok_or(AppError::SessionNotFound)?;

        // Can only rescue if USDC is in GlueContract (UsdcReceived state)
        // or if session failed after USDC arrived
        if !matches!(
            session.status,
            OfframpStatus::UsdcReceived | OfframpStatus::Failed
        ) {
            return Err(AppError::InvalidState(format!(
                "Cannot rescue in state: {:?}",
                session.status
            )));
        }

        // Execute rescue on-chain
        let _tx_hash = self
            .chain
            .rescue(session.session_id)
            .await
            .map_err(|e| AppError::Chain(e.to_string()))?;

        session.set_status(OfframpStatus::Rescued);

        // Persist
        self.db
            .update_session(&session)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Update cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session.clone());
        }

        Ok(session)
    }

    /// Withdraw from zk-p2p deposit
    pub async fn withdraw(self: &Arc<Self>, id: uuid::Uuid) -> Result<OfframpSession, AppError> {
        let mut session = self
            .get_session(id)
            .await?
            .ok_or(AppError::SessionNotFound)?;

        // Can only withdraw if USDC is in zk-p2p deposit (Zkp2pDeposited state)
        if session.status != OfframpStatus::Zkp2pDeposited {
            return Err(AppError::InvalidState(format!(
                "Cannot withdraw in state: {:?}",
                session.status
            )));
        }

        // Execute withdrawal on-chain; EscrowV2 returns all remaining liquidity
        let _tx_hash = self
            .chain
            .withdraw_from_zkp2p(session.session_id)
            .await
            .map_err(|e| AppError::Chain(e.to_string()))?;

        session.set_status(OfframpStatus::Withdrawn);

        // Persist
        self.db
            .update_session(&session)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Update cache
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session.clone());
        }

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band the fix has to be right across: 1Click quotes `amountOut` and
    /// guarantees only `minAmountOut`, 50 bps below it, so the fill lands
    /// anywhere in between.
    const ALICE_EXPECTED: u64 = 100_000_000; // 100.00 USDC
    const ALICE_FLOOR: u64 = 99_500_000; // 99.50
    const BOB_EXPECTED: u64 = 10_000_000; // 10.00
    const BOB_FLOOR: u64 = 9_950_000; // 9.95

    fn u(n: u64) -> U256 {
        U256::from(n)
    }

    #[test]
    fn an_empty_or_absent_amount_out_is_not_a_settlement() {
        assert_eq!(settled_output(None).unwrap(), None);
        assert_eq!(settled_output(Some("")).unwrap(), None);
        assert_eq!(settled_output(Some("   ")).unwrap(), None);
        assert_eq!(settled_output(Some("0")).unwrap(), None);
    }

    #[test]
    fn a_settled_amount_parses_as_usdc_units() {
        assert_eq!(settled_output(Some("443561")).unwrap(), Some(u(443_561)));
        assert_eq!(settled_output(Some(" 99500000 ")).unwrap(), Some(u(99_500_000)));
    }

    /// Garbage must be an error rather than a silent "not settled yet", which
    /// would strand the session with nothing in the log to say why.
    #[test]
    fn an_unparseable_amount_out_is_an_error() {
        assert!(settled_output(Some("1.5")).is_err());
        assert!(settled_output(Some("-1")).is_err());
        assert!(settled_output(Some("lots")).is_err());
    }

    /// NEW-1, at the level the bug actually lived. The old rule was
    /// `min(unassigned, expected)`; this asserts the new rule does not do that.
    ///
    /// Alice's swap under-fills to her floor. 109.50 is unassigned, because Bob's
    /// 10.00 is sitting in the same pot. The old rule credited Alice 100.00, half
    /// a dollar of which was Bob's.
    #[test]
    fn a_short_fill_is_credited_at_the_fill_not_out_of_the_pool() {
        let pool = u(ALICE_FLOOR + BOB_EXPECTED); // 109.50 unassigned

        // What the old rule would have done, kept here so the regression is legible.
        let old_rule = pool.min(u(ALICE_EXPECTED));
        assert_eq!(old_rule, u(ALICE_EXPECTED), "the old rule credited the quote");

        let decision = credit_decision(
            Some(u(ALICE_FLOOR)),
            pool,
            u(ALICE_EXPECTED),
            u(ALICE_FLOOR),
        );
        assert_eq!(
            decision,
            CreditDecision::Credit(u(ALICE_FLOOR)),
            "the fixed rule credits only what Alice's own swap settled for"
        );
    }

    /// And the concurrent session is left whole, which is the half the old rule
    /// broke: Bob used to be stuck below his floor forever.
    #[test]
    fn the_concurrent_session_still_clears_its_own_floor() {
        // Alice has been credited her 99.50; Bob's 10.00 is what remains.
        let remaining = u(BOB_EXPECTED);

        let decision = credit_decision(
            Some(u(BOB_EXPECTED)),
            remaining,
            u(BOB_EXPECTED),
            u(BOB_FLOOR),
        );
        assert_eq!(decision, CreditDecision::Credit(u(BOB_EXPECTED)));

        // Under the old rule Bob saw only 9.50 of pool against a 9.95 floor.
        let left_by_old_rule = u(ALICE_FLOOR + BOB_EXPECTED - ALICE_EXPECTED);
        assert!(
            left_by_old_rule < u(BOB_FLOOR),
            "the old rule left Bob below his floor: {left_by_old_rule} < {BOB_FLOOR}"
        );
    }

    #[test]
    fn a_fill_below_the_guaranteed_floor_is_not_credited() {
        let short = u(99_000_000);
        assert_eq!(
            credit_decision(Some(short), short, u(ALICE_EXPECTED), u(ALICE_FLOOR)),
            CreditDecision::Short {
                settled: short,
                floor: u(ALICE_FLOOR)
            }
        );
    }

    #[test]
    fn an_over_fill_is_clamped_to_the_quote() {
        let over = u(101_000_000);
        assert_eq!(
            credit_decision(Some(over), over, u(ALICE_EXPECTED), u(ALICE_FLOOR)),
            CreditDecision::Credit(u(ALICE_EXPECTED)),
            "the surplus stays unassigned rather than being credited"
        );
    }

    /// A SUCCESS whose `amountOut` has not been filled in yet must wait rather
    /// than fall back to the pool, which is what made the pool authoritative.
    #[test]
    fn success_without_a_settled_amount_waits() {
        assert!(matches!(
            credit_decision(None, u(1_000_000_000), u(ALICE_EXPECTED), u(ALICE_FLOOR)),
            CreditDecision::Wait(_)
        ));
    }

    /// 1Click can report a settlement before the ERC-20 transfer has landed.
    #[test]
    fn a_settlement_that_has_not_arrived_on_chain_waits() {
        assert!(matches!(
            credit_decision(
                Some(u(ALICE_EXPECTED)),
                U256::ZERO,
                u(ALICE_EXPECTED),
                u(ALICE_FLOOR)
            ),
            CreditDecision::Wait(_)
        ));
    }

    /// The property the fix buys: across every fill in the slippage band, and in
    /// either tick order, each session is credited exactly its own fill and the
    /// two credits together are exactly what arrived.
    #[test]
    fn neither_tick_order_moves_money_between_sessions() {
        for a_fill in [ALICE_FLOOR, ALICE_FLOOR + 1, 99_750_000, ALICE_EXPECTED] {
            for b_fill in [BOB_FLOOR, 9_975_000, BOB_EXPECTED] {
                let arrived = u(a_fill + b_fill);

                // Alice first.
                let a = credit_decision(Some(u(a_fill)), arrived, u(ALICE_EXPECTED), u(ALICE_FLOOR));
                assert_eq!(a, CreditDecision::Credit(u(a_fill)));
                let b = credit_decision(
                    Some(u(b_fill)),
                    arrived - u(a_fill),
                    u(BOB_EXPECTED),
                    u(BOB_FLOOR),
                );
                assert_eq!(b, CreditDecision::Credit(u(b_fill)), "Bob is not starved");

                // Bob first: same answers.
                let b2 = credit_decision(Some(u(b_fill)), arrived, u(BOB_EXPECTED), u(BOB_FLOOR));
                assert_eq!(b2, CreditDecision::Credit(u(b_fill)));
                let a2 = credit_decision(
                    Some(u(a_fill)),
                    arrived - u(b_fill),
                    u(ALICE_EXPECTED),
                    u(ALICE_FLOOR),
                );
                assert_eq!(a2, CreditDecision::Credit(u(a_fill)));
            }
        }
    }
}
