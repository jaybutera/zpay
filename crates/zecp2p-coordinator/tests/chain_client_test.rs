//! Integration tests for the chain client
//!
//! These tests verify we can connect to Base and query the chain.
//! Tests marked #[ignore] require network access.

use zecp2p_coordinator::chain::ChainClient;
use zecp2p_types::Config;

fn test_config() -> Config {
    Config {
        network: zecp2p_types::config::NetworkConfig {
            base_rpc_url: "https://mainnet.base.org".to_string(),
            base_sepolia_rpc_url: Some("https://sepolia.base.org".to_string()),
            chain_id: 8453, // Base mainnet
        },
        contracts: zecp2p_types::config::ContractConfig {
            usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
                .parse()
                .unwrap(),
            // These are real zk-p2p contract addresses on Base
            zkp2p_escrow: "0x59Cf3c90E8e7D27773b5E468D1a24B247db9B78d"
                .parse()
                .unwrap(),
            zkp2p_orchestrator: "0x88888883Ed048FF0a415271B28b2F52d431810D0"
                .parse()
                .unwrap(),
            glue_contract: None,
        },
        near: zecp2p_types::config::NearConfig {
            api_url: "https://1click.chaindefuser.com".to_string(),
            default_timeout: 600,
        },
        zkp2p: zecp2p_types::config::Zkp2pConfig::default(),
        server: zecp2p_types::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: ":memory:".to_string(),
        },
    }
}

/// Test that we can create a chain client and get the current block number
#[tokio::test]
#[ignore]
async fn test_get_block_number() {
    let config = test_config();
    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    let block = client.current_block().await.expect("Failed to get block number");

    // Block number should be reasonable (Base launched mid-2023)
    assert!(block > 10_000_000, "Block number should be greater than 10M");
    println!("Current Base block: {}", block);
}

/// Test that we can query USDC balance
#[tokio::test]
#[ignore]
async fn test_get_usdc_balance() {
    let config = test_config();
    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    // Query balance of zk-p2p escrow contract (likely has some USDC)
    let escrow_addr = "0x59Cf3c90E8e7D27773b5E468D1a24B247db9B78d"
        .parse()
        .unwrap();
    let balance = client
        .usdc_balance(escrow_addr)
        .await
        .expect("Failed to get USDC balance");

    // The escrow may have zero balance at any given time, but the call should succeed
    println!("zk-p2p Escrow USDC balance: {} (raw)", balance);
}

/// Test that we can query a zk-p2p deposit
#[tokio::test]
#[ignore]
async fn test_get_deposit() {
    let config = test_config();
    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    // Try to get deposit ID 1 (may or may not exist)
    let result = client.get_deposit(alloy::primitives::U256::from(1)).await;

    // The call should succeed (may return empty deposit if ID doesn't exist)
    match result {
        Ok(deposit) => {
            println!("Deposit 1 depositor: {}", deposit.depositor);
            println!("Deposit 1 amount: {}", deposit.amount);
        }
        Err(e) => {
            // Some errors are expected (e.g., deposit doesn't exist)
            println!("Could not get deposit 1: {}", e);
        }
    }
}

/// Test getter methods return configured addresses
#[tokio::test]
async fn test_address_getters() {
    let config = test_config();
    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    assert_eq!(
        client.usdc_address().to_string().to_lowercase(),
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    );
    assert_eq!(
        client.zkp2p_escrow().to_string().to_lowercase(),
        "0x59cf3c90e8e7d27773b5e468d1a24b247db9b78d"
    );
    assert_eq!(
        client.zkp2p_orchestrator().to_string().to_lowercase(),
        "0x88888883ed048ff0a415271b28b2f52d431810d0"
    );
}

/// Test that glue_contract returns error when not configured
#[tokio::test]
async fn test_glue_contract_not_configured() {
    let config = test_config();
    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    let result = client.glue_contract();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not configured"));
}

/// Test that glue_contract returns address when configured
#[tokio::test]
async fn test_glue_contract_configured() {
    let mut config = test_config();
    let glue_addr = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();
    config.contracts.glue_contract = Some(glue_addr);

    let client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    let result = client.glue_contract();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), glue_addr);
}
