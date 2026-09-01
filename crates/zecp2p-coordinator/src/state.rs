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

        // Execute on-chain
        let (tx_hash, deposit_id) = self
            .chain
            .process_offramp(
                session.session_id,
                payment_methods,
                payment_method_data,
                currencies,
            )
            .await
            .map_err(|e| AppError::Chain(e.to_string()))?;

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
        // Check for timeout first
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
            // The glue is shared, so its balance is not this session's money. What
            // matters is whether enough USDC has arrived that nobody has claimed
            // yet to cover what this session is owed. Promoting on any nonzero
            // balance is how one session used to end up spending another's.
            let expected = session
                .expected_usdc
                .ok_or_else(|| anyhow::anyhow!("session has no expected USDC amount"))?;

            // 1Click quotes an expected output and guarantees only min_amount_out;
            // accept anything at or above that floor and credit what actually arrived.
            let floor = session.min_output_usdc.unwrap_or(expected);
            let unassigned = self.chain.glue_unassigned_balance().await?;

            if unassigned < floor {
                tracing::debug!(
                    "Session {} waiting on USDC: {} unassigned on the glue, needs {}",
                    session.id,
                    unassigned,
                    floor
                );
                return Ok(());
            }

            // Never take more than the session was quoted; the surplus belongs to
            // whichever other session it arrived for.
            let credit = unassigned.min(expected);

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
                "Session {} credited {} USDC (expected {}, floor {})",
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
