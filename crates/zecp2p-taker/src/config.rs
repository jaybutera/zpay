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
    /// The native Zcash escrow rail, which runs alongside the Base one rather
    /// than replacing it.
    ///
    /// Absent by default, and absence means the rail is off. A daemon that
    /// enabled the second settlement system because a config file was silent
    /// would start watching a chain the operator never configured, so this is
    /// opt-in and the CLI says so when it is missing.
    #[serde(default)]
    pub zec: Option<ZecConfig>,
}

/// Where the native escrow rail reads its chain and its policy.
///
/// None of this is shared with the Base rail: different chain, different node,
/// different deadlines. What *is* shared is everything downstream of
/// `max_payment_cents`, which stays on [`TakerSettings`] because it is the
/// operator's ceiling on any single Venmo payment regardless of what settles it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZecConfig {
    /// Zcash RPC endpoint. The escrow crate reads depth, branch id and the
    /// escrow output through this, and broadcasts the release to it.
    pub rpc_url: String,
    /// HTTP basic auth, as a local `zcashd` requires. A hosted endpoint that
    /// keys on a header uses `api_key_header` instead.
    #[serde(default)]
    pub rpc_user: Option<String>,
    #[serde(default)]
    pub rpc_password: Option<String>,
    /// A header a hosted provider keys on, for example `x-api-key`.
    #[serde(default)]
    pub rpc_api_key_header: Option<String>,
    #[serde(default)]
    pub rpc_api_key: Option<String>,
    /// `main` or `test`. Mainnet is not the default: a rail that defaulted to
    /// the chain with real coin on it would be one typo from spending it.
    pub network: String,
    /// The attestor that publishes the outcome scalar.
    pub attestor_url: String,
    /// The attestor's public key, pinned. A mainnet run without this is
    /// refused: an unpinned attestor is one that can announce under a key the
    /// LP has never seen, and a pre-signature encrypted under an attacker's
    /// outcome point is one the attacker can decrypt.
    #[serde(default)]
    pub attestor_pubkey: Option<String>,
    /// Hours of refund delay, from which every deadline is derived.
    ///
    /// A wall-clock quantity rather than a block count, because Zcash's block
    /// time is a parameter: NU7 proposes 25 s, at which the same 24 hours is
    /// three times the blocks.
    #[serde(default = "default_refund_hours")]
    pub refund_hours: u32,
    /// Block time in seconds, for turning `refund_hours` into heights.
    #[serde(default = "default_block_seconds")]
    pub block_seconds: u32,
    /// Where the escrow crate's run records live. Each escrow's pre-signature
    /// is read back from here rather than regenerated; regenerating draws a
    /// fresh nonce and the record would then disagree with the mined release.
    #[serde(default = "default_zec_state_dir")]
    pub state_dir: String,
}

fn default_refund_hours() -> u32 {
    24
}

/// Zcash mainnet block time today.
fn default_block_seconds() -> u32 {
    75
}

fn default_zec_state_dir() -> String {
    "~/.zecp2p".to_string()
}

impl ZecConfig {
    /// The escrow policy this rail runs under, derived rather than hard-coded.
    pub fn policy(&self) -> anyhow::Result<zecp2p_escrow::deadlines::EscrowPolicy> {
        zecp2p_escrow::deadlines::EscrowPolicy::from_refund_hours(
            self.block_seconds,
            self.refund_hours,
        )
        .map_err(|e| anyhow::anyhow!("the zec rail's deadlines are not usable: {e}"))
    }

    pub fn network(&self) -> anyhow::Result<zecp2p_escrow::rpc::Network> {
        match self.network.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Ok(zecp2p_escrow::rpc::Network::Main),
            "test" | "testnet" => Ok(zecp2p_escrow::rpc::Network::Test),
            other => anyhow::bail!(
                "zec.network is {other:?}; it must be \"main\" or \"test\""
            ),
        }
    }

    /// Refuse a mainnet rail that has not pinned its attestor.
    ///
    /// The escrow's `paid_path` makes the same refusal, and it is repeated here
    /// because this is the earlier of the two moments: a daemon that starts
    /// watching mainnet unpinned has already accepted work it cannot safely
    /// finish.
    pub fn validate(&self) -> anyhow::Result<()> {
        let network = self.network()?;
        self.policy()?;
        zecp2p_types::config::validate_service_url("zec.rpc_url", &self.rpc_url)?;
        zecp2p_types::config::validate_service_url("zec.attestor_url", &self.attestor_url)?;
        if network == zecp2p_escrow::rpc::Network::Main && self.attestor_pubkey.is_none() {
            anyhow::bail!(
                "zec.attestor_pubkey is unset on a mainnet rail. A pre-signature \
                 encrypted under an unpinned attestor's outcome point can be decrypted \
                 by whoever holds that key; pin it before watching mainnet."
            );
        }
        Ok(())
    }

    pub fn rpc_config(&self) -> anyhow::Result<zecp2p_escrow::rpc::RpcConfig> {
        let mut config =
            zecp2p_escrow::rpc::RpcConfig::public(self.rpc_url.clone(), self.network()?);
        config.user = self.rpc_user.clone();
        config.password = self.rpc_password.clone();
        if let (Some(header), Some(key)) = (&self.rpc_api_key_header, &self.rpc_api_key) {
            config.api_key_header = Some((header.clone(), key.clone()));
        }
        Ok(config)
    }
}

/// Expand a leading `~` the way the rest of this config's paths are written.
fn shellexpand_home(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => path.to_string(),
        },
        None => path.to_string(),
    }
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
    /// Where the Venmo sign-in credentials live, for unattended re-login.
    ///
    /// A separate file from this one, and not committed: this config is shipped
    /// as `config.taker.example.toml` and carries no secrets, while that file
    /// carries a live Venmo password. Keeping them apart is what lets the
    /// example be committed at all.
    ///
    /// Absent means no re-login: the health check still runs and still reports
    /// a dead session, it just cannot repair one. That is the shipped default,
    /// because a daemon that types a password into a page it discovered is a
    /// step past one that reads an open tab, and it should be taken on purpose.
    #[serde(default = "default_credentials_path")]
    pub credentials_path: Option<String>,
}

/// The path the example config points at. Optional so an operator who has not
/// created the file gets the daemon they had before rather than a start-up
/// failure; `Credentials::load` is what refuses a file that exists but is wrong.
fn default_credentials_path() -> Option<String> {
    Some("config/venmo.local.toml".to_string())
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
    /// The numeric Venmo sender id whose feed the enclave reads.
    ///
    /// Needed when `path` holds a bare Cookie header rather than JSON, which is
    /// the shape a human has after copying it out of devtools. The @handle is
    /// not this: the enclave wants the numeric account id.
    #[serde(default)]
    pub sender_id: Option<String>,
    /// The User-Agent the cookie was captured under.
    ///
    /// Venmo ties a session to it closely enough that a mismatched agent can
    /// fail the enclave's replay.
    #[serde(default)]
    pub user_agent: Option<String>,
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
            sender_id: None,
            user_agent: None,
        }
    }
}

impl Default for VenmoConfig {
    fn default() -> Self {
        Self {
            cdp_url: "http://127.0.0.1:9222".to_string(),
            note: default_note(),
            timeout_seconds: default_venmo_timeout(),
            credentials_path: default_credentials_path(),
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

    /// Load the Venmo sign-in credentials, if there are any to load.
    ///
    /// Three outcomes rather than two, and the middle one is the point:
    ///
    /// - no path configured, or the file does not exist: `Ok(None)`. The daemon
    ///   runs exactly as it did before this feature, health-checking and
    ///   reporting without repairing.
    /// - the file exists and is usable: `Ok(Some(..))`.
    /// - the file exists and is wrong: `Err`. A file that is present but holds
    ///   the placeholder, or a mode anyone can read, is a mistake worth failing
    ///   at startup for. Silently downgrading it to "no credentials" would hide
    ///   the misconfiguration until the first expiry, with nobody watching.
    pub fn venmo_credentials(&self) -> anyhow::Result<Option<crate::auto::login::Credentials>> {
        let Some(path) = self.venmo.credentials_path.as_deref() else {
            return Ok(None);
        };
        let path = shellexpand_home(path);
        if !std::path::Path::new(&path).exists() {
            return Ok(None);
        }
        crate::auto::login::Credentials::load(&path).map(Some)
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
        // The second rail's endpoints get the same treatment as the first's.
        // `zec.rpc_url` is the one that matters most here: it is what says
        // whether the escrow reached depth and which branch is in force, and a
        // plaintext answer to either is an answer an attacker can write.
        if let Some(zec) = &self.zec {
            zec.validate()?;
        }
        Ok(())
    }
}
