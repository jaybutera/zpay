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
}

impl Default for Zkp2pConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.zkp2p.xyz".to_string(),
        }
    }
}

/// Keeper loop timing
///
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
            attestation: AttestationConfig::default(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
            },
            database: DatabaseConfig {
                path: "zecp2p.db".to_string(),
            },
        }
    }
}

impl Config {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
