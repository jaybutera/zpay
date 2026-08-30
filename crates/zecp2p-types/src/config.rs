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
    /// GlueContract address (deployed by developer)
    pub glue_contract: Option<Address>,
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
                glue_contract: None,
            },
            near: NearConfig {
                api_url: "https://1click.chaindefuser.com".to_string(),
                default_timeout: 600,
            },
            zkp2p: Zkp2pConfig::default(),
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
        if let Ok(addr) = std::env::var("GLUE_CONTRACT_ADDRESS") {
            config.contracts.glue_contract = Some(
                addr.parse()
                    .map_err(|_| ConfigError::InvalidAddress(addr))?,
            );
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
}
