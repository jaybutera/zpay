//! Configuration types for zecp2p

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// Main configuration for zecp2p
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network configuration
    pub network: NetworkConfig,
    /// Contract addresses
    pub contracts: ContractConfig,
    /// NEAR Intents configuration
    pub near: NearConfig,
    /// zk-p2p curator API configuration
    #[serde(default)]
    pub zkp2p: Zkp2pConfig,
    /// Keeper loop timing
    #[serde(default)]
    pub keeper: KeeperConfig,
    /// The fee the main route quotes and the settlement takes
    #[serde(default)]
    pub fee: FeeConfig,
    /// Peer/zk-p2p TEE attestation service
    #[serde(default)]
    pub attestation: AttestationConfig,
    /// Coordinator server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
}

/// Network RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Base mainnet RPC URL
    pub base_rpc_url: String,
    /// Base Sepolia testnet RPC URL (for testing)
    pub base_sepolia_rpc_url: Option<String>,
    /// Chain ID (8453 for Base mainnet, 84532 for Sepolia)
    pub chain_id: u64,
}

/// Contract addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConfig {
    /// USDC token address on Base
    pub usdc: Address,
    /// zk-p2p Escrow contract address
    pub zkp2p_escrow: Address,
    /// zk-p2p Orchestrator contract address
    pub zkp2p_orchestrator: Address,
    /// zk-p2p StakeVault. OrchestratorV3's lifecycle hook locks taker stake
    /// here, so a taker that is not allowlisted must fund it before signalling.
    #[serde(default = "default_stake_vault")]
    pub stake_vault: Address,
    /// GlueContract address (deployed by developer)
    pub glue_contract: Option<Address>,
}

/// Base mainnet StakeVault behind OrchestratorV3's lifecycle hook.
pub const DEFAULT_STAKE_VAULT: &str = "0x47c26258222e2f96424bD2B21bf173f0DA5034C7";

fn default_stake_vault() -> Address {
    DEFAULT_STAKE_VAULT.parse().expect("valid stake vault address")
}

/// NEAR Intents API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearConfig {
    /// 1Click API base URL
    pub api_url: String,
    /// Default timeout for NEAR Intent settlement (seconds)
    pub default_timeout: u64,
}

/// zk-p2p curator API configuration
///
/// The curator is zk-p2p's off-chain service. Makers register their payout
/// identifier with it and receive the `hashedOnchainId` that goes on-chain as
/// `payeeDetails`. There is no local formula for that hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zkp2pConfig {
    /// Curator API base URL
    pub api_url: String,
    /// Extra fields to send with `POST /v3/sign`.
    ///
    /// That endpoint requires thirteen fields and names none of them in its
    /// validation errors. Twelve are known and sent by
    /// `zecp2p_taker::auto::gating`; the thirteenth is not identified yet, and
    /// this map lets it be supplied from config the first time a live signed
    /// call names it, rather than needing a release. Empty by default.
    #[serde(default)]
    pub gating_extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Default for Zkp2pConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.zkp2p.xyz".to_string(),
            gating_extra: Default::default(),
        }
    }
}

/// Keeper loop timing
///
/// The fee the abstraction charges for doing the work.
///
/// The protocol is open and the convenient front door charges, which is the
/// same shape Uniswap's interface fee has. Both routes pay it and the advanced
/// route gets no discount: on backend A the fee is taken inside
/// `processOfframp` and cannot be waived per session anyway, so a per-route
/// price would be a number the contract disagrees with.
///
/// It is quoted as one labelled line in a net quote, never as a rate the
/// sender has to apply themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Basis points taken from the gross payout. 15 bps is 0.15%, which is
    /// what the launch page advertises.
    #[serde(default = "default_fee_bps")]
    pub bps: u32,
    /// Where the accrued fee is swept. Unset means the fee is quoted but no
    /// recipient is configured yet, which is the state before the treasury
    /// contract work lands.
    #[serde(default)]
    pub recipient: Option<Address>,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self { bps: default_fee_bps(), recipient: None }
    }
}

fn default_fee_bps() -> u32 {
    15
}

impl FeeConfig {
    /// The label the sender reads on the quote line. Always the same words, so
    /// the fee is recognisable across the quote, the receipt and the launch
    /// page.
    pub fn label(&self) -> String {
        let whole = self.bps / 100;
        let frac = self.bps % 100;
        if frac == 0 {
            format!("zpay fee ({whole}%)")
        } else {
            format!("zpay fee ({whole}.{:02}%)", frac)
        }
    }

    /// The fee on a gross payout, in cents, rounded up.
    ///
    /// Rounding up rather than down means the quote never promises the sender
    /// a net the contract's own rounding cannot deliver. At 15 bps a $5 order
    /// pays a cent, which is the smallest the rail can move.
    pub fn cents_on(&self, gross_cents: u64) -> u64 {
        let bps = self.bps as u64;
        gross_cents.saturating_mul(bps).div_ceil(10_000)
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    #[test]
    fn the_label_is_the_launch_pages_number() {
        assert_eq!(FeeConfig::default().label(), "zpay fee (0.15%)");
        assert_eq!(FeeConfig { bps: 25, recipient: None }.label(), "zpay fee (0.25%)");
        assert_eq!(FeeConfig { bps: 100, recipient: None }.label(), "zpay fee (1%)");
    }

    /// Rounding up, so the net quoted is a net that can actually be paid.
    #[test]
    fn the_fee_rounds_up_to_the_cent() {
        let f = FeeConfig::default();
        // $25.00 at 15 bps is 3.75 cents.
        assert_eq!(f.cents_on(2500), 4);
        // $5.00 at 15 bps is 0.75 cents.
        assert_eq!(f.cents_on(500), 1);
        // Exactly divisible stays exact.
        assert_eq!(f.cents_on(10_000), 15);
        assert_eq!(f.cents_on(0), 0);
    }

    /// A tiny order still pays something rather than riding free, and the
    /// arithmetic does not overflow on an absurd one.
    #[test]
    fn small_and_huge_amounts_both_behave() {
        let f = FeeConfig::default();
        assert_eq!(f.cents_on(1), 1);
        assert!(f.cents_on(u64::MAX) > 0);
    }
}

/// The loop wakes on `poll_interval_seconds`, gives up on a session it drives
/// on Base after `session_timeout_seconds`, and gives a session still waiting
/// on the NEAR leg `near_intent_timeout_seconds` instead. The NEAR default is
/// longer than the Base one because 1Click keeps a deposit address live for
/// about three days and refunds an under-deposit by that deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperConfig {
    /// Seconds between keeper ticks
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    /// Seconds before a session the coordinator drives on Base is failed
    #[serde(default = "default_session_timeout")]
    pub session_timeout_seconds: i64,
    /// Seconds before a session still awaiting the NEAR leg is failed
    #[serde(default = "default_near_timeout")]
    pub near_intent_timeout_seconds: i64,
    /// Blocks to scan back when no cursor is stored yet
    #[serde(default = "default_event_lookback")]
    pub event_lookback_blocks: u64,
    /// Allow more than one offramp session to be in flight at once.
    ///
    /// Off by default. The glue holds every session's USDC in one pot and an
    /// ERC-20 transfer names no session, so which session a delivery belongs to
    /// is decided off-chain from what 1Click reports settled. Running one
    /// session at a time means a mistake in that attribution has no second
    /// user's money to reach. Turning this on is a deliberate choice to rely on
    /// the settled-amount rule alone.
    #[serde(default)]
    pub allow_concurrent_sessions: bool,
}

fn default_poll_interval() -> u64 {
    15
}
fn default_session_timeout() -> i64 {
    3600
}
fn default_near_timeout() -> i64 {
    302_400
}
fn default_event_lookback() -> u64 {
    1000
}

impl Default for KeeperConfig {
    fn default() -> Self {
        Self {
            poll_interval_seconds: default_poll_interval(),
            session_timeout_seconds: default_session_timeout(),
            near_intent_timeout_seconds: default_near_timeout(),
            event_lookback_blocks: default_event_lookback(),
            allow_concurrent_sessions: false,
        }
    }
}

/// Peer (zk-p2p) TEE attestation service
///
/// A Venmo payment "proof" is an EIP-712 signature from an AWS Nitro enclave.
/// The signature is bound to `chain_id` plus `verifier`, so both must match the
/// chain the claim is settled on. The enclave signs only for Base mainnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Attestation service base URL
    pub service_url: String,
    /// UnifiedPaymentVerifierV3, the EIP-712 verifyingContract
    pub verifier: Address,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            service_url: "https://attestation-service.zkp2p.xyz".to_string(),
            verifier: "0xC6F4a193576C60892a47e111Bb5706c30162502B"
                .parse()
                .expect("valid verifier address"),
        }
    }
}

/// Coordinator server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Shared bearer token takers present to read `/deposits/open`.
    ///
    /// That endpoint is the one place a Venmo username leaves the coordinator,
    /// so it is not public. `None` is allowed only on a loopback bind; the
    /// coordinator refuses to start bound anywhere else without one.
    #[serde(default)]
    pub taker_token: Option<String>,
    /// How recently a deposit must have been updated to appear in the listing.
    #[serde(default = "default_deposit_listing_max_age")]
    pub deposit_listing_max_age_seconds: i64,
    /// Browser origins allowed to call the API cross-origin. Empty by default:
    /// the CLI and the taker send no Origin header and are unaffected.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_deposit_listing_max_age() -> i64 {
    3600
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            taker_token: None,
            deposit_listing_max_age_seconds: default_deposit_listing_max_age(),
            allowed_origins: Vec::new(),
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database path
    pub path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                base_rpc_url: "https://mainnet.base.org".to_string(),
                base_sepolia_rpc_url: Some("https://sepolia.base.org".to_string()),
                chain_id: 8453,
            },
            contracts: ContractConfig {
                // USDC on Base mainnet
                usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
                    .parse()
                    .unwrap(),
                // zk-p2p EscrowV2 on Base
                zkp2p_escrow: "0x777777779d229cdF3110e9de47943791c26300Ef"
                    .parse()
                    .unwrap(),
                // zk-p2p OrchestratorV3 on Base
                zkp2p_orchestrator: "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
                    .parse()
                    .unwrap(),
                stake_vault: default_stake_vault(),
                glue_contract: None,
            },
            near: NearConfig {
                api_url: "https://1click.chaindefuser.com".to_string(),
                default_timeout: 600,
            },
            zkp2p: Zkp2pConfig::default(),
            keeper: KeeperConfig::default(),
            fee: FeeConfig::default(),
            attestation: AttestationConfig::default(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
                taker_token: None,
                deposit_listing_max_age_seconds: default_deposit_listing_max_age(),
                allowed_origins: Vec::new(),
            },
            database: DatabaseConfig {
                path: "zecp2p.db".to_string(),
            },
        }
    }
}

/// Require https for a service URL, unless it points at this machine.
///
/// `BASE_RPC_URL`, `NEAR_API_URL`, `ZKP2P_API_URL` and `ATTESTATION_URL` are all
/// env-overridable, and `dotenvy::dotenv()` runs unconditionally, so a stray
/// `.env` in the working directory used to be enough to point any of them at
/// `http://attacker.example/`. The 1Click endpoint decides which Zcash address a
/// user is told to send funds to, and the curator endpoint decides the payee hash
/// that goes on chain, so neither is something to fetch over plaintext.
///
/// Loopback stays allowed, because the local mocks and the fork rehearsal use it.
pub fn validate_service_url(name: &'static str, url: &str) -> Result<(), ConfigError> {
    let trimmed = url.trim();

    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| ConfigError::InsecureUrl(name, trimmed.to_string()))?;

    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    // Strip the port, and the brackets around an IPv6 literal.
    let host = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };

    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);

    match scheme {
        "https" => Ok(()),
        "http" if is_loopback => Ok(()),
        _ => Err(ConfigError::InsecureUrl(name, trimmed.to_string())),
    }
}

impl Config {
    /// Check every service URL this config will actually fetch from.
    pub fn validate_urls(&self) -> Result<(), ConfigError> {
        validate_service_url("network.base_rpc_url", &self.network.base_rpc_url)?;
        if let Some(url) = &self.network.base_sepolia_rpc_url {
            validate_service_url("network.base_sepolia_rpc_url", url)?;
        }
        validate_service_url("near.api_url", &self.near.api_url)?;
        validate_service_url("zkp2p.api_url", &self.zkp2p.api_url)?;
        validate_service_url("attestation.service_url", &self.attestation.service_url)?;
        Ok(())
    }

    /// Load configuration from a TOML file
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.to_string(), e))?;
        toml::from_str(&contents).map_err(ConfigError::Parse)
    }

    /// Load configuration with environment variable overrides
    pub fn load_with_env(path: &str) -> Result<Self, ConfigError> {
        let mut config = Self::load(path)?;

        // Override with environment variables if present
        if let Ok(url) = std::env::var("BASE_RPC_URL") {
            config.network.base_rpc_url = url;
        }
        if let Ok(url) = std::env::var("BASE_SEPOLIA_RPC_URL") {
            config.network.base_sepolia_rpc_url = Some(url);
        }
        if let Ok(url) = std::env::var("NEAR_API_URL") {
            config.near.api_url = url;
        }
        if let Ok(url) = std::env::var("ZKP2P_API_URL") {
            config.zkp2p.api_url = url;
        }
        if let Ok(url) = std::env::var("ATTESTATION_URL") {
            config.attestation.service_url = url;
        }
        if let Ok(addr) = std::env::var("ATTESTATION_VERIFIER_ADDRESS") {
            config.attestation.verifier = addr
                .parse()
                .map_err(|_| ConfigError::InvalidAddress(addr))?;
        }
        if let Ok(addr) = std::env::var("STAKE_VAULT_ADDRESS") {
            config.contracts.stake_vault = addr
                .parse()
                .map_err(|_| ConfigError::InvalidAddress(addr))?;
        }
        if let Ok(token) = std::env::var("COORDINATOR_TAKER_TOKEN") {
            let token = token.trim().to_string();
            if !token.is_empty() {
                config.server.taker_token = Some(token);
            }
        }
        if let Ok(secs) = std::env::var("KEEPER_POLL_INTERVAL_SECONDS") {
            config.keeper.poll_interval_seconds = secs
                .parse()
                .map_err(|_| ConfigError::InvalidNumber("KEEPER_POLL_INTERVAL_SECONDS", secs))?;
        }
        // The .env.example ships GLUE_CONTRACT_ADDRESS as the literal
        // placeholder "0x...". A stray dotenv file carrying it should not stop
        // a coordinator whose config file already names a real address.
        if let Ok(addr) = std::env::var("GLUE_CONTRACT_ADDRESS") {
            let addr = addr.trim().to_string();
            if !addr.is_empty() && addr != "0x..." {
                config.contracts.glue_contract = Some(
                    addr.parse()
                        .map_err(|_| ConfigError::InvalidAddress(addr))?,
                );
            }
        }

        config.validate_urls()?;

        Ok(config)
    }
}

/// Configuration loading errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file '{0}': {1}")]
    Io(String, std::io::Error),
    #[error("Failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("{0} is not a number: {1}")]
    InvalidNumber(&'static str, String),
    #[error(
        "{0} must be https (or http on loopback), got '{1}'. This endpoint decides \
         where a user's funds go; it is not something to fetch over plaintext."
    )]
    InsecureUrl(&'static str, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MEDIUM-3: every service URL was env-overridable with no scheme check, and
    /// `dotenvy::dotenv()` runs unconditionally, so a stray `.env` could point
    /// 1Click (which supplies the ZEC deposit address) at an attacker.
    #[test]
    fn plaintext_service_urls_are_refused() {
        for bad in [
            "http://attacker.example/",
            "http://1click.chaindefuser.com",
            "ftp://example.com",
            "not a url",
            "",
        ] {
            assert!(
                validate_service_url("near.api_url", bad).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn https_and_loopback_are_accepted() {
        assert!(validate_service_url("near.api_url", "https://1click.chaindefuser.com").is_ok());
        assert!(validate_service_url("near.api_url", "https://example.com:8443/path").is_ok());
        // The local mocks and the fork rehearsal need these.
        assert!(validate_service_url("network.base_rpc_url", "http://127.0.0.1:8545").is_ok());
        assert!(validate_service_url("network.base_rpc_url", "http://localhost:8545").is_ok());
        assert!(validate_service_url("network.base_rpc_url", "http://[::1]:8545").is_ok());
    }

    /// The `[keeper]` and `[attestation]` sections are optional, so a config
    /// file written before they existed still loads.
    #[test]
    fn a_config_without_the_new_sections_still_loads() {
        let toml = r#"
[network]
base_rpc_url = "https://mainnet.base.org"
chain_id = 8453
[contracts]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
zkp2p_escrow = "0x777777779d229cdF3110e9de47943791c26300Ef"
zkp2p_orchestrator = "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
[near]
api_url = "https://1click.chaindefuser.com"
default_timeout = 600
[server]
host = "127.0.0.1"
port = 3000
[database]
path = "zecp2p.db"
"#;
        let cfg: Config = toml::from_str(toml).expect("should parse");
        assert_eq!(cfg.keeper.poll_interval_seconds, 15);
        assert_eq!(cfg.keeper.near_intent_timeout_seconds, 302_400);
        assert_eq!(
            cfg.attestation.service_url,
            "https://attestation-service.zkp2p.xyz"
        );
        assert_eq!(
            cfg.contracts.stake_vault.to_string().to_lowercase(),
            DEFAULT_STAKE_VAULT.to_lowercase()
        );
    }

    /// A generated config, with every section present, round trips.
    #[test]
    fn a_fully_specified_config_overrides_every_default() {
        let toml = r#"
[network]
base_rpc_url = "https://example.invalid"
chain_id = 8453
[contracts]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
zkp2p_escrow = "0x777777779d229cdF3110e9de47943791c26300Ef"
zkp2p_orchestrator = "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
stake_vault = "0x0000000000000000000000000000000000000042"
glue_contract = "0x0000000000000000000000000000000000000007"
[near]
api_url = "https://near.invalid"
default_timeout = 900
[zkp2p]
api_url = "https://curator.invalid"
[attestation]
service_url = "https://enclave.invalid"
verifier = "0x0000000000000000000000000000000000000099"
[keeper]
poll_interval_seconds = 30
session_timeout_seconds = 7200
near_intent_timeout_seconds = 400000
event_lookback_blocks = 250
[server]
host = "0.0.0.0"
port = 8080
[database]
path = "/tmp/x.db"
"#;
        let cfg: Config = toml::from_str(toml).expect("should parse");
        assert_eq!(cfg.keeper.poll_interval_seconds, 30);
        assert_eq!(cfg.keeper.event_lookback_blocks, 250);
        assert_eq!(cfg.attestation.service_url, "https://enclave.invalid");
        assert_eq!(cfg.near.default_timeout, 900);
        assert!(cfg.contracts.glue_contract.is_some());
    }
}
