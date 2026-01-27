//! Shared test utilities for e2e tests
//!
//! Provides common infrastructure for running local e2e tests with anvil.

#![allow(dead_code)]

use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Anvil's default private key for account[0]
pub const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Test user address (anvil account[1])
pub const TEST_USER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// Test user private key (anvil account[1])
pub const TEST_USER_PRIVATE_KEY: &str =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Atomic counter for unique port allocation
static PORT_COUNTER: AtomicU16 = AtomicU16::new(8700);

/// RAII wrapper for anvil process
pub struct AnvilInstance {
    process: Child,
    rpc_url: String,
    port: u16,
}

impl AnvilInstance {
    /// Start a new anvil instance on a unique port
    pub fn start() -> Self {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);

        let process = Command::new("anvil")
            .args(["--port", &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start anvil");

        std::thread::sleep(Duration::from_secs(2));

        Self {
            process,
            rpc_url: format!("http://localhost:{}", port),
            port,
        }
    }

    /// Get the RPC URL for this anvil instance
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl Drop for AnvilInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Deploy contracts using forge script and return (usdc, escrow, glue) addresses
pub fn deploy_contracts(rpc_url: &str) -> (Address, Address, Address) {
    let project_root = std::env::current_dir()
        .expect("Failed to get current dir")
        .parent()
        .expect("Failed to get parent")
        .parent()
        .expect("Failed to get workspace root")
        .to_path_buf();

    let contracts_dir = project_root.join("contracts");

    let output = Command::new("forge")
        .current_dir(&contracts_dir)
        .args([
            "script",
            "script/DeployLocal.s.sol:DeployLocal",
            "--rpc-url",
            rpc_url,
            "--broadcast",
        ])
        .output()
        .expect("Failed to run forge script");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "forge script failed:\nstderr: {}\nstdout: {}",
            stderr, stdout
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut usdc_addr = None;
    let mut escrow_addr = None;
    let mut glue_addr = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("MockUSDC deployed at:") {
            usdc_addr = Some(extract_address(trimmed));
        } else if trimmed.starts_with("MockEscrow deployed at:") {
            escrow_addr = Some(extract_address(trimmed));
        } else if trimmed.starts_with("OfframpGlue deployed at:") {
            glue_addr = Some(extract_address(trimmed));
        }
    }

    (
        usdc_addr.expect("MockUSDC address not found in output"),
        escrow_addr.expect("MockEscrow address not found in output"),
        glue_addr.expect("OfframpGlue address not found in output"),
    )
}

fn extract_address(line: &str) -> Address {
    line.split_whitespace()
        .rfind(|s| s.starts_with("0x") && s.len() == 42)
        .expect("No valid address found")
        .parse()
        .expect("Invalid address")
}

/// Get a read-only provider for the given RPC URL
pub async fn get_provider(rpc_url: &str) -> impl Provider {
    ProviderBuilder::new().connect_http(rpc_url.parse().expect("valid url"))
}

/// Get a provider with signing capabilities
pub async fn get_signing_provider(rpc_url: &str, private_key: &str) -> impl Provider {
    let signer: PrivateKeySigner = private_key.parse().expect("valid key");
    let wallet = EthereumWallet::from(signer);
    ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().expect("valid url"))
}
