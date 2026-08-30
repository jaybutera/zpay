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

// ============ Mock zk-p2p curator ============

/// Mock of the zk-p2p curator endpoints the coordinator uses:
/// `POST /v2/makers/validate` and `POST /v2/makers/create`.
///
/// The real curator issues an opaque `hashedOnchainId`. The mock derives a
/// deterministic one from the username so tests can assert on it via
/// [`MockZkp2pServer::expected_hash`].
pub struct MockZkp2pServer {
    port: u16,
    state: MockZkp2pState,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Default)]
pub struct MockZkp2pState {
    /// When set, validate answers `false` and create answers HTTP 400
    reject: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// When set, create returns a hashedOnchainId that is not 32 bytes
    malformed_hash: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// When set, both endpoints answer HTTP 500
    server_error: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Every offchainId that was registered, in order
    registered: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockPayeeRequest {
    processor_name: String,
    offchain_id: String,
}

impl MockZkp2pServer {
    pub async fn start() -> Self {
        use axum::{routing::post, Router};

        let state = MockZkp2pState::default();
        let app = Router::new()
            .route("/v2/makers/validate", post(mock_zkp2p_validate))
            .route("/v2/makers/create", post(mock_zkp2p_create))
            .with_state(state.clone());

        // Bind port 0 so parallel tests never collide
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock zkp2p server");
        let port = listener.local_addr().expect("local addr").port();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        Self {
            port,
            state,
            shutdown_tx: Some(shutdown_tx),
            handle,
        }
    }

    pub fn api_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The hash the mock issues for a username (after `@` stripping)
    pub fn expected_hash(offchain_id: &str) -> alloy::primitives::B256 {
        alloy::primitives::keccak256(format!("mock-zkp2p-payee:{}", offchain_id).as_bytes())
    }

    pub fn registered(&self) -> Vec<String> {
        self.state.registered.lock().unwrap().clone()
    }

    pub fn set_reject(&self, reject: bool) {
        self.state
            .reject
            .store(reject, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_malformed_hash(&self, malformed: bool) {
        self.state
            .malformed_hash
            .store(malformed, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_server_error(&self, error: bool) {
        self.state
            .server_error
            .store(error, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for MockZkp2pServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.handle.abort();
    }
}

async fn mock_zkp2p_validate(
    axum::extract::State(state): axum::extract::State<MockZkp2pState>,
    axum::Json(req): axum::Json<MockPayeeRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use std::sync::atomic::Ordering;
    if state.server_error.load(Ordering::SeqCst) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"success": false, "message": "boom"})),
        );
    }
    let ok = req.processor_name == "venmo"
        && !req.offchain_id.is_empty()
        && !req.offchain_id.starts_with('@')
        && !state.reject.load(Ordering::SeqCst);
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "message": if ok { "Maker data is valid" } else { "Maker data is invalid" },
            "responseObject": ok,
            "statusCode": 200
        })),
    )
}

async fn mock_zkp2p_create(
    axum::extract::State(state): axum::extract::State<MockZkp2pState>,
    axum::Json(req): axum::Json<MockPayeeRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use std::sync::atomic::Ordering;
    if state.server_error.load(Ordering::SeqCst) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"success": false, "message": "boom"})),
        );
    }
    if req.processor_name != "venmo" || req.offchain_id.is_empty() || state.reject.load(Ordering::SeqCst)
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "success": false,
                "message": "Invalid maker data",
                "responseObject": null,
                "statusCode": 400,
                "errorCode": "invalid_maker_data"
            })),
        );
    }
    state.registered.lock().unwrap().push(req.offchain_id.clone());
    let hashed = if state.malformed_hash.load(Ordering::SeqCst) {
        "hashed-id-1".to_string()
    } else {
        format!("{:?}", MockZkp2pServer::expected_hash(&req.offchain_id))
    };
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "message": "Maker created",
            "responseObject": {
                "id": 1,
                "processorName": "venmo",
                "offchainId": req.offchain_id,
                "hashedOnchainId": hashed,
                "createdAt": "2026-08-29T00:00:00.000Z"
            },
            "statusCode": 200
        })),
    )
}
