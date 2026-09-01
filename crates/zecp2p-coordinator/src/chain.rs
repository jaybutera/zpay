//! Ethereum/Base chain interaction
//!
//! Chain interaction functions for the coordinator. Many public API methods
//! are defined here for future use in the full offramp flow.

#![allow(dead_code)]

use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use zecp2p_types::{
    abi::{IEscrow, IOrchestrator, OfframpGlue, IERC20},
    Config,
};

pub struct ChainClient {
    base_rpc_url: String,
    wallet: Option<EthereumWallet>,
    usdc_address: Address,
    zkp2p_escrow: Address,
    zkp2p_orchestrator: Address,
    glue_contract: Option<Address>,
}

impl ChainClient {
    pub async fn new(config: &Config) -> Result<Self> {
        // Load wallet from env if available
        let wallet = if let Ok(key) = std::env::var("COORDINATOR_PRIVATE_KEY") {
            let signer: PrivateKeySigner = key.parse()?;
            Some(EthereumWallet::from(signer))
        } else {
            None
        };

        Ok(Self {
            base_rpc_url: config.network.base_rpc_url.clone(),
            wallet,
            usdc_address: config.contracts.usdc,
            zkp2p_escrow: config.contracts.zkp2p_escrow,
            zkp2p_orchestrator: config.contracts.zkp2p_orchestrator,
            glue_contract: config.contracts.glue_contract,
        })
    }

    /// Create a readonly client for testing (no wallet required)
    pub async fn new_readonly(config: &Config) -> Result<Self> {
        Ok(Self {
            base_rpc_url: config.network.base_rpc_url.clone(),
            wallet: None,
            usdc_address: config.contracts.usdc,
            zkp2p_escrow: config.contracts.zkp2p_escrow,
            zkp2p_orchestrator: config.contracts.zkp2p_orchestrator,
            glue_contract: config.contracts.glue_contract,
        })
    }

    fn provider(&self) -> impl Provider {
        ProviderBuilder::new()
            .connect_http(self.base_rpc_url.parse().expect("valid url"))
    }

    fn signing_provider(&self) -> Result<impl Provider> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No wallet configured for signing"))?
            .clone();

        Ok(ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.base_rpc_url.parse()?))
    }

    /// Get the GlueContract address, or return error if not configured
    pub fn glue_contract(&self) -> Result<Address> {
        self.glue_contract
            .ok_or_else(|| anyhow::anyhow!("GlueContract address not configured"))
    }

    /// Get current block number
    pub async fn block_number(&self) -> Result<u64> {
        Ok(self.provider().get_block_number().await?)
    }

    /// Get USDC balance of an address
    pub async fn usdc_balance(&self, address: Address) -> Result<U256> {
        let provider = self.provider();
        let usdc = IERC20::new(self.usdc_address, provider);
        let balance = usdc.balanceOf(address).call().await?;
        Ok(balance)
    }

    /// Get GlueContract's USDC balance
    pub async fn glue_usdc_balance(&self) -> Result<U256> {
        let glue_addr = self.glue_contract()?;
        self.usdc_balance(glue_addr).await
    }

    /// Get session from GlueContract
    pub async fn get_session(&self, session_id: B256) -> Result<OfframpGlue::Session> {
        let glue_addr = self.glue_contract()?;
        let provider = self.provider();
        let glue = OfframpGlue::new(glue_addr, provider);
        let session = glue.getSession(session_id).call().await?;
        Ok(session)
    }

    /// Create a session on GlueContract
    pub async fn create_session(
        &self,
        session_id: B256,
        user: Address,
        payee_details_hash: B256,
        min_conversion_rate: U256,
        expected_amount: U256,
    ) -> Result<B256> {
        let glue_addr = self.glue_contract()?;
        let provider = self.signing_provider()?;

        let glue = OfframpGlue::new(glue_addr, provider);

        let tx = glue
            .createSession(
                session_id,
                user,
                payee_details_hash,
                min_conversion_rate,
                expected_amount,
            )
            .send()
            .await
            .context("Failed to send createSession transaction")?;

        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Assign arrived USDC to a session on the glue.
    ///
    /// The token transfer that delivers a NEAR Intent carries no session id, so
    /// the keeper has to say which session the money is for. The contract only
    /// lets this draw on balance no other session owns, which is what keeps two
    /// concurrent offramps from spending each other's USDC.
    pub async fn credit_session(&self, session_id: B256, amount: U256) -> Result<B256> {
        let glue_addr = self.glue_contract()?;
        let provider = self.signing_provider()?;

        let glue = OfframpGlue::new(glue_addr, provider);

        let tx = glue
            .creditSession(session_id, amount)
            .send()
            .await
            .context("Failed to send creditSession transaction")?;

        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// USDC on the glue that no session owns yet.
    pub async fn glue_unassigned_balance(&self) -> Result<U256> {
        let glue_addr = self.glue_contract()?;
        let provider = self.provider();
        let glue = OfframpGlue::new(glue_addr, provider);
        Ok(glue.unassignedBalance().call().await?)
    }

    /// Process offramp - route USDC to zk-p2p
    pub async fn process_offramp(
        &self,
        session_id: B256,
        payment_methods: Vec<B256>,
        payment_method_data: Vec<OfframpGlue::DepositPaymentMethodData>,
        currencies: Vec<Vec<OfframpGlue::Currency>>,
    ) -> Result<(B256, U256)> {
        let glue_addr = self.glue_contract()?;
        let provider = self.signing_provider()?;

        let glue = OfframpGlue::new(glue_addr, provider);

        let tx = glue
            .processOfframp(session_id, payment_methods, payment_method_data, currencies)
            .send()
            .await
            .context("Failed to send processOfframp transaction")?;

        let receipt = tx.get_receipt().await?;

        // Parse OfframpProcessed event to get depositId
        let deposit_id = receipt
            .inner
            .logs()
            .iter()
            .filter_map(|log| {
                log.log_decode::<OfframpGlue::OfframpProcessed>()
                    .ok()
                    .map(|decoded| decoded.inner.depositId)
            })
            .next()
            .ok_or_else(|| anyhow::anyhow!("No OfframpProcessed event found"))?;

        Ok((receipt.transaction_hash, deposit_id))
    }

    /// Check if a zk-p2p deposit has any intents signaled
    pub async fn get_deposit(&self, deposit_id: U256) -> Result<IEscrow::Deposit> {
        let provider = self.provider();
        let escrow = IEscrow::new(self.zkp2p_escrow, provider);
        let deposit = escrow.getDeposit(deposit_id).call().await?;
        Ok(deposit)
    }

    /// Get the zk-p2p escrow address
    pub fn zkp2p_escrow(&self) -> Address {
        self.zkp2p_escrow
    }

    /// Get the zk-p2p orchestrator address
    pub fn zkp2p_orchestrator(&self) -> Address {
        self.zkp2p_orchestrator
    }

    /// Get the USDC address
    pub fn usdc_address(&self) -> Address {
        self.usdc_address
    }

    /// Watch for IntentSignaled events on zk-p2p Orchestrator
    /// Returns events matching the given deposit ID within a block range
    pub async fn get_intent_signaled_events(
        &self,
        deposit_id: U256,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<IntentSignaledEvent>> {
        let provider = self.provider();

        // Build filter for IntentSignaled events matching this deposit ID
        let filter = Filter::new()
            .address(self.zkp2p_orchestrator)
            .event_signature(IOrchestrator::IntentSignaled::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let logs = provider.get_logs(&filter).await?;

        let events: Vec<IntentSignaledEvent> = logs
            .into_iter()
            .filter_map(|log| {
                log.log_decode::<IOrchestrator::IntentSignaled>()
                    .ok()
                    .and_then(|decoded| {
                        let event = decoded.inner;
                        // Filter by deposit ID
                        if U256::from(event.depositId) == deposit_id {
                            Some(IntentSignaledEvent {
                                intent_hash: B256::from_slice(log.topics()[1].as_ref()),
                                escrow: event.escrow,
                                deposit_id: U256::from(event.depositId),
                                owner: event.owner,
                                to: event.to,
                                amount: event.amount,
                                timestamp: event.timestamp,
                                block_number: log.block_number.unwrap_or(0),
                            })
                        } else {
                            None
                        }
                    })
            })
            .collect();

        Ok(events)
    }

    /// Watch for IntentFulfilled events on zk-p2p Orchestrator
    /// Returns events matching the given intent hash within a block range
    pub async fn get_intent_fulfilled_events(
        &self,
        intent_hash: B256,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<IntentFulfilledEvent>> {
        let provider = self.provider();

        // Build filter for IntentFulfilled events matching this intent hash
        let filter = Filter::new()
            .address(self.zkp2p_orchestrator)
            .event_signature(IOrchestrator::IntentFulfilled::SIGNATURE_HASH)
            .topic1(intent_hash)
            .from_block(from_block)
            .to_block(to_block);

        let logs = provider.get_logs(&filter).await?;

        let events: Vec<IntentFulfilledEvent> = logs
            .into_iter()
            .filter_map(|log| {
                log.log_decode::<IOrchestrator::IntentFulfilled>()
                    .ok()
                    .map(|decoded| {
                        let event = decoded.inner;
                        IntentFulfilledEvent {
                            intent_hash,
                            funds_transferred_to: event.fundsTransferredTo,
                            amount: event.amount,
                            is_manual_release: event.isManualRelease,
                            block_number: log.block_number.unwrap_or(0),
                        }
                    })
            })
            .collect();

        Ok(events)
    }

    /// Get current block number
    pub async fn current_block(&self) -> Result<u64> {
        Ok(self.provider().get_block_number().await?)
    }

    /// Rescue a session's credited USDC back to its user.
    ///
    /// Sent with the keeper key. The contract accepts either the session's user
    /// or the keeper here and pays `session.user` either way, so this is a
    /// convenience path, not the guarantee: the user's own signed call is the
    /// escape hatch that survives this coordinator being gone. See
    /// `docs/ARCHITECTURE.md` and `zecp2p-cli rescue --self-signed`.
    pub async fn rescue(&self, session_id: B256) -> Result<B256> {
        let glue_addr = self.glue_contract()?;
        let provider = self.signing_provider()?;

        let glue = OfframpGlue::new(glue_addr, provider);

        let tx = glue
            .rescue(session_id)
            .send()
            .await
            .context("Failed to send rescue transaction")?;

        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }

    /// Withdraw a session's zk-p2p deposit back to its user.
    ///
    /// Same shape as [`ChainClient::rescue`]: keeper-sent, always paying
    /// `session.user`, with the user's own signed call as the real fallback.
    pub async fn withdraw_from_zkp2p(&self, session_id: B256) -> Result<B256> {
        let glue_addr = self.glue_contract()?;
        let provider = self.signing_provider()?;

        let glue = OfframpGlue::new(glue_addr, provider);

        let tx = glue
            .withdrawFromZkp2p(session_id)
            .send()
            .await
            .context("Failed to send withdrawFromZkp2p transaction")?;

        let receipt = tx.get_receipt().await?;
        Ok(receipt.transaction_hash)
    }
}

/// Parsed IntentSignaled event
#[derive(Debug, Clone)]
pub struct IntentSignaledEvent {
    pub intent_hash: B256,
    pub escrow: Address,
    pub deposit_id: U256,
    pub owner: Address,
    pub to: Address,
    pub amount: U256,
    pub timestamp: U256,
    pub block_number: u64,
}

/// Parsed IntentFulfilled event
#[derive(Debug, Clone)]
pub struct IntentFulfilledEvent {
    pub intent_hash: B256,
    pub funds_transferred_to: Address,
    pub amount: U256,
    pub is_manual_release: bool,
    pub block_number: u64,
}
