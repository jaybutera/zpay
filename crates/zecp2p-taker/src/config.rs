//! Taker agent configuration.

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// Base mainnet StakeVault behind OrchestratorV3's lifecycle hook.
///
/// Re-exported from `zecp2p-types` so the coordinator and the taker cannot
/// drift apart on which vault holds the stake.
pub use zecp2p_types::config::DEFAULT_STAKE_VAULT;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakerConfig {
    pub network: NetworkConfig,
    pub contracts: ContractConfig,
    pub taker: TakerSettings,
    #[serde(default)]
    pub venmo: VenmoConfig,
    /// Stored Venmo session material for the enclave.
    #[serde(default)]
    pub session: SessionConfig,
    /// Peer TEE attestation service used to prove the Venmo payment.
    #[serde(default)]
    pub attestation: zecp2p_types::config::AttestationConfig,
    /// zk-p2p curator. The taker asks it what a username hashes to, so it can
    /// check the coordinator's answer against the deposit's own payeeDetails
    /// before paying anyone.
    #[serde(default)]
    pub zkp2p: zecp2p_types::config::Zkp2pConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub base_rpc_url: String,
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConfig {
    pub usdc: Address,
    pub zkp2p_escrow: Address,
    pub zkp2p_orchestrator: Address,
    /// OfframpGlue. Deposits from this depositor are the ones this agent takes.
    pub glue_contract: Address,
    /// StakeVault. Defaults to the Base mainnet deployment.
    #[serde(default = "default_stake_vault")]
    pub stake_vault: Address,
}

fn default_stake_vault() -> Address {
    DEFAULT_STAKE_VAULT
        .parse()
        .expect("valid stake vault address")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakerSettings {
    /// Coordinator to ask for the Venmo username behind a deposit.
    ///
    /// The chain carries only the curator's opaque payee hash, so a taker
    /// needs one off-chain lookup to learn who to pay. Anything served here is
    /// already claimable by anyone on-chain.
    #[serde(default)]
    pub coordinator_url: Option<String>,
    /// Bearer token for the coordinator's deposit listing.
    ///
    /// That endpoint serves Venmo usernames, so it is authenticated; a taker
    /// without a token gets 401 and cannot look a deposit up.
    #[serde(default)]
    pub coordinator_token: Option<String>,
    /// Largest intent this agent will take, in USDC units (6 decimals).
    pub max_intent_amount: U256,
    /// Smallest intent worth the gas and the Venmo round trip.
    #[serde(default)]
    pub min_intent_amount: U256,
    /// Seconds between chain polls.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    /// How far back to scan on the first tick.
    #[serde(default = "default_lookback")]
    pub lookback_blocks: u64,
    /// Stake to top the vault up to when free stake runs short, in USDC units.
    /// Zero means never stake automatically; the operator funds the vault.
    #[serde(default)]
    pub auto_stake_target: U256,
    /// Hard ceiling on any single Venmo payment, in whole cents.
    ///
    /// Checked in `auto::money::payment_cents` against the amount derived from
    /// the intent, and it refuses rather than clamps. This is the last line
    /// against a units/dollars confusion, a bad conversion rate, or a
    /// compromised coordinator: 4,875,437 read as dollars rather than 6-decimal
    /// units is $4.8 million, and the cap is what stops that reaching the send
    /// button.
    ///
    /// `u64` rather than `u128` because TOML has no u128: the shipped example
    /// config would not parse, which `config_urls_test` catches.
    #[serde(default = "default_max_payment_cents")]
    pub max_payment_cents: u64,
    /// Where the fill journal lives.
    ///
    /// Written before each irreversible step, so a restart can tell an operator
    /// which fills may have moved money. See `auto::journal`.
    #[serde(default = "default_journal_path")]
    pub journal_path: String,
}

/// $25.00. Deliberately small: a daemon serving $5 orders should have to be
/// told, in writing, before it can send more.
fn default_max_payment_cents() -> u64 {
    2_500
}

fn default_journal_path() -> String {
    "taker-fills.jsonl".to_string()
}

fn default_poll_interval() -> u64 {
    15
}

fn default_lookback() -> u64 {
    5_000
}

/// Where the agent drives an already-logged-in Venmo session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VenmoConfig {
    /// Chrome DevTools Protocol endpoint of a browser the operator already
    /// logged into Venmo on. The agent attaches to the open tab; it never
    /// handles credentials.
    pub cdp_url: String,
    /// Note attached to the payment. zk-p2p matches the payment by amount and
    /// recipient, so this is for the recipient's benefit only.
    #[serde(default = "default_note")]
    pub note: String,
    /// Abort if the page has not settled within this many seconds.
    #[serde(default = "default_venmo_timeout")]
    pub timeout_seconds: u64,
}

fn default_note() -> String {
    "thanks".to_string()
}

fn default_venmo_timeout() -> u64 {
    120
}

/// The stored Venmo session the enclave replays, and how stale it may get.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session-material file: the `account.venmo.com` Cookie header and the
    /// numeric sender id. Written 0600 and never logged.
    ///
    /// A stored cookie is usable across many fills: zk-p2p's attestation client
    /// documents that the service enforces no capture-age limit and no one-use
    /// replay limit, and that verification depends only on the upstream session
    /// still being active. The same document notes the flip side, which is why
    /// this file is as sensitive as a password file: a leaked encrypted JWE is
    /// valid for the upstream session's lifetime.
    #[serde(default = "default_session_path")]
    pub path: String,
    /// Refuse to signal on session material older than this.
    ///
    /// The service imposes no such limit; this is the operator's caution. It is
    /// checked before `signalIntent`, because a dead cookie found after the
    /// Venmo payment means the fiat is gone and only `cancelIntent` recovers
    /// the stake.
    #[serde(default = "default_session_max_age_hours")]
    pub max_age_hours: i64,
}

fn default_session_path() -> String {
    "venmo-session.json".to_string()
}

fn default_session_max_age_hours() -> i64 {
    12
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            path: default_session_path(),
            max_age_hours: default_session_max_age_hours(),
        }
    }
}

impl Default for VenmoConfig {
    fn default() -> Self {
        Self {
            cdp_url: "http://127.0.0.1:9222".to_string(),
            note: default_note(),
            timeout_seconds: default_venmo_timeout(),
        }
    }
}

impl TakerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read taker config '{path}': {e}"))?;
        let mut config: Self = toml::from_str(&contents)?;

        if let Ok(url) = std::env::var("BASE_RPC_URL") {
            config.network.base_rpc_url = url;
        }
        if let Ok(addr) = std::env::var("GLUE_CONTRACT_ADDRESS") {
            // .env.example ships this as the literal placeholder "0x...", and a
            // stray dotenv file should not silently break a good config file.
            let addr = addr.trim();
            if !addr.is_empty() && addr != "0x..." {
                config.contracts.glue_contract = addr.parse().map_err(|_| {
                    anyhow::anyhow!("GLUE_CONTRACT_ADDRESS is not a valid address: {addr}")
                })?;
            }
        }
        if let Ok(url) = std::env::var("VENMO_CDP_URL") {
            config.venmo.cdp_url = url;
        }
        if let Ok(url) = std::env::var("ATTESTATION_URL") {
            config.attestation.service_url = url;
        }
        if let Ok(url) = std::env::var("ZKP2P_API_URL") {
            config.zkp2p.api_url = url;
        }
        if let Ok(token) = std::env::var("COORDINATOR_TAKER_TOKEN") {
            let token = token.trim().to_string();
            if !token.is_empty() {
                config.taker.coordinator_token = Some(token);
            }
        }
        if let Ok(addr) = std::env::var("ATTESTATION_VERIFIER_ADDRESS") {
            config.attestation.verifier = addr.parse().map_err(|_| {
                anyhow::anyhow!("ATTESTATION_VERIFIER_ADDRESS is not a valid address: {addr}")
            })?;
        }
        if let Ok(addr) = std::env::var("STAKE_VAULT_ADDRESS") {
            config.contracts.stake_vault = addr.parse().map_err(|_| {
                anyhow::anyhow!("STAKE_VAULT_ADDRESS is not a valid address: {addr}")
            })?;
        }

        config.validate_urls()?;

        Ok(config)
    }

    /// Require https for every service URL this config will fetch from.
    ///
    /// NEW-4 in the 2026-08-31 re-audit. MEDIUM-3's fix added
    /// `zecp2p_types::Config::validate_urls` and wired it into the coordinator's
    /// `load_with_env`. `TakerConfig::load` is a separate implementation and
    /// called nothing: `BASE_RPC_URL`, `ATTESTATION_URL` and `ZKP2P_API_URL`
    /// were applied from the environment with no scheme check at all, and
    /// `dotenvy::dotenv()` runs unconditionally, so a stray `.env` was enough.
    ///
    /// `ZKP2P_API_URL` is the one that matters most, and it is the one the
    /// earlier fix left open. The whole of NEW-2's payee cross-check rests on
    /// that endpoint: anyone who can answer a plaintext request to it returns
    /// any `hashedOnchainId` they like, the hash matches the deposit, and the
    /// taker pays the attacker's Venmo handle with its own dollars.
    ///
    /// Loopback stays allowed; the local mocks and the fork rehearsal use it.
    pub fn validate_urls(&self) -> anyhow::Result<()> {
        use zecp2p_types::config::validate_service_url;

        validate_service_url("network.base_rpc_url", &self.network.base_rpc_url)?;
        validate_service_url("zkp2p.api_url", &self.zkp2p.api_url)?;
        validate_service_url("attestation.service_url", &self.attestation.service_url)?;
        if let Some(url) = &self.taker.coordinator_url {
            validate_service_url("taker.coordinator_url", url)?;
        }
        Ok(())
    }
}
