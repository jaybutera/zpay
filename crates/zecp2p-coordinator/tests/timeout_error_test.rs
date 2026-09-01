//! Tests for timeout scenarios and error handling
//!
//! These tests verify the coordinator handles edge cases correctly:
//! 1. Session timeout detection (1 hour default)
//! 2. NEAR API failure scenarios
//! 3. Error paths in state machine
//!
//! Run with: cargo test --package zecp2p-coordinator --test timeout_error_test -- --ignored --nocapture

mod test_utils;

use alloy::primitives::{Address, U256};
use axum::{http::StatusCode, routing::post, Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration as StdDuration;
use tempfile::TempDir;
use test_utils::{MockZkp2pServer, KEEPER_PRIVATE_KEY};
use tokio::net::TcpListener;
use zecp2p_types::OfframpStatus;

/// Atomic counters for unique port allocation
static ANVIL_PORT: AtomicU16 = AtomicU16::new(8700);
static NEAR_PORT: AtomicU16 = AtomicU16::new(9700);

/// Test user address (anvil account[1])
const TEST_USER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// RAII wrapper for anvil process
struct AnvilInstance {
    process: Child,
    rpc_url: String,
    #[allow(dead_code)]
    port: u16,
}

impl AnvilInstance {
    fn start() -> Self {
        let port = ANVIL_PORT.fetch_add(1, Ordering::SeqCst);

        let process = Command::new("anvil")
            .args(["--port", &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start anvil");

        std::thread::sleep(StdDuration::from_secs(2));

        Self {
            process,
            rpc_url: format!("http://localhost:{}", port),
            port,
        }
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl Drop for AnvilInstance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Deploy contracts using the standard local script
fn deploy_contracts(rpc_url: &str) -> (Address, Address, Address) {
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
        usdc_addr.expect("MockUSDC address not found"),
        escrow_addr.expect("MockEscrow address not found"),
        glue_addr.expect("OfframpGlue address not found"),
    )
}

fn extract_address(line: &str) -> Address {
    line.split_whitespace()
        .rfind(|s| s.starts_with("0x") && s.len() == 42)
        .expect("No valid address found")
        .parse()
        .expect("Invalid address")
}

/// Mock NEAR API server that can return errors
struct MockNearServerWithErrors {
    port: u16,
    #[allow(dead_code)]
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<()>,
}

/// Configuration for mock NEAR server behavior
#[derive(Clone)]
struct MockNearConfig {
    /// If true, return error for quote requests
    quote_should_fail: std::sync::Arc<std::sync::RwLock<bool>>,
    /// If true, return error for status requests
    status_should_fail: std::sync::Arc<std::sync::RwLock<bool>>,
    /// Status to return
    status_response: std::sync::Arc<std::sync::RwLock<String>>,
}

impl MockNearConfig {
    fn new() -> Self {
        Self {
            quote_should_fail: std::sync::Arc::new(std::sync::RwLock::new(false)),
            status_should_fail: std::sync::Arc::new(std::sync::RwLock::new(false)),
            status_response: std::sync::Arc::new(std::sync::RwLock::new("PENDING".to_string())),
        }
    }

    fn set_quote_should_fail(&self, fail: bool) {
        *self.quote_should_fail.write().unwrap() = fail;
    }

    fn set_status_should_fail(&self, fail: bool) {
        *self.status_should_fail.write().unwrap() = fail;
    }

    fn set_status(&self, status: &str) {
        *self.status_response.write().unwrap() = status.to_string();
    }
}

impl MockNearServerWithErrors {
    async fn start() -> (Self, MockNearConfig) {
        let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let config = MockNearConfig::new();
        let config_clone = config.clone();

        let app = Router::new()
            .route("/v0/quote", post(mock_quote_handler_with_errors))
            .route("/v0/status", axum::routing::get(mock_status_handler_with_errors))
            .with_state(config_clone);

        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(addr).await.expect("bind mock server");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        tokio::time::sleep(StdDuration::from_millis(100)).await;

        (
            Self {
                port,
                shutdown_tx,
                handle,
            },
            config,
        )
    }

    fn api_url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockQuoteResponse {
    correlation_id: String,
    quote: MockQuote,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockQuote {
    amount_out: String,
    min_amount_out: String,
    time_estimate: i64,
    deposit_address: String,
    deadline: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteRequest {
    amount: String,
    #[allow(dead_code)]
    recipient: String,
}

async fn mock_quote_handler_with_errors(
    axum::extract::State(config): axum::extract::State<MockNearConfig>,
    Json(request): Json<QuoteRequest>,
) -> Result<Json<MockQuoteResponse>, (StatusCode, String)> {
    if *config.quote_should_fail.read().unwrap() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "NEAR Intent service unavailable".to_string(),
        ));
    }

    let zatoshi: u64 = request.amount.parse().unwrap_or(50_000_000);
    let usdc_out = (zatoshi as f64 / 100_000_000.0 * 30.0 * 1_000_000.0) as u64;
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);

    Ok(Json(MockQuoteResponse {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        quote: MockQuote {
            amount_out: usdc_out.to_string(),
            min_amount_out: (usdc_out * 99 / 100).to_string(),
            time_estimate: 300,
            deposit_address: format!("t1MockZecDeposit{}", rand::random::<u32>()),
            deadline: deadline.to_rfc3339(),
        },
    }))
}

#[derive(Deserialize)]
struct StatusQuery {
    #[serde(rename = "depositAddress")]
    #[allow(dead_code)]
    deposit_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockStatusResponse {
    status: String,
    source_transaction_hash: Option<String>,
    destination_transaction_hash: Option<String>,
    amount_out: Option<String>,
    error: Option<String>,
}

async fn mock_status_handler_with_errors(
    axum::extract::State(config): axum::extract::State<MockNearConfig>,
    axum::extract::Query(_query): axum::extract::Query<StatusQuery>,
) -> Result<Json<MockStatusResponse>, (StatusCode, String)> {
    if *config.status_should_fail.read().unwrap() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "NEAR status service temporarily unavailable".to_string(),
        ));
    }

    let status = config.status_response.read().unwrap().clone();

    Ok(Json(MockStatusResponse {
        status,
        source_transaction_hash: Some("0xmocksourcetx".to_string()),
        destination_transaction_hash: Some("0xmockdesttx".to_string()),
        amount_out: Some("15000000".to_string()),
        error: None,
    }))
}

/// Create a test configuration
fn create_test_config(
    anvil_url: &str,
    near_url: &str,
    zkp2p_url: &str,
    usdc: Address,
    escrow: Address,
    glue: Address,
    db_path: &str,
) -> zecp2p_types::Config {
    zecp2p_types::Config {
        network: zecp2p_types::config::NetworkConfig {
            base_rpc_url: anvil_url.to_string(),
            base_sepolia_rpc_url: Some(anvil_url.to_string()),
            chain_id: 31337,
        },
        contracts: zecp2p_types::config::ContractConfig {
            usdc,
            zkp2p_escrow: escrow,
            zkp2p_orchestrator: escrow,
            stake_vault: zecp2p_types::config::DEFAULT_STAKE_VAULT.parse().unwrap(),
            glue_contract: Some(glue),
        },
        near: zecp2p_types::config::NearConfig {
            api_url: near_url.to_string(),
            default_timeout: 600,
        },
        zkp2p: zecp2p_types::config::Zkp2pConfig {
            api_url: zkp2p_url.to_string(),
        },
        keeper: zecp2p_types::config::KeeperConfig::default(),
        attestation: zecp2p_types::config::AttestationConfig::default(),
        server: zecp2p_types::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            ..Default::default()
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: db_path.to_string(),
        },
    }
}

/// Test infrastructure
struct TestInfra {
    #[allow(dead_code)]
    anvil: AnvilInstance,
    #[allow(dead_code)]
    near_server: MockNearServerWithErrors,
    #[allow(dead_code)]
    zkp2p_server: MockZkp2pServer,
    near_config: MockNearConfig,
    #[allow(dead_code)]
    usdc_addr: Address,
    #[allow(dead_code)]
    escrow_addr: Address,
    #[allow(dead_code)]
    glue_addr: Address,
    config: zecp2p_types::Config,
    _temp_dir: TempDir,
}

impl TestInfra {
    async fn setup() -> Self {
        let anvil = AnvilInstance::start();
        println!("Anvil started at {}", anvil.rpc_url());

        let (usdc_addr, escrow_addr, glue_addr) = deploy_contracts(anvil.rpc_url());
        println!("Contracts deployed");

        let (near_server, near_config) = MockNearServerWithErrors::start().await;
        println!("Mock NEAR server at {}", near_server.api_url());

        let zkp2p_server = MockZkp2pServer::start().await;
        println!("Mock zk-p2p curator at {}", zkp2p_server.api_url());

        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string();

        let config = create_test_config(
            anvil.rpc_url(),
            &near_server.api_url(),
            &zkp2p_server.api_url(),
            usdc_addr,
            escrow_addr,
            glue_addr,
            &db_path,
        );

        Self {
            anvil,
            near_server,
            zkp2p_server,
            near_config,
            usdc_addr,
            escrow_addr,
            glue_addr,
            config,
            _temp_dir: temp_dir,
        }
    }
}

/// Test that sessions timeout after 1 hour
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_session_timeout_detection() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing Session Timeout Detection ===\n");

    // Step 1: Create a session
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "timeouttest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);
    assert_eq!(session.status, OfframpStatus::NearIntentPending);

    // Step 2: Manually update the created_at to be >1 hour ago
    // This simulates a session that has been sitting idle for too long
    println!("\nStep 2: Simulating timeout by backdating created_at...");

    // We need to update directly in the database since OfframpSession::created_at is set at creation
    //
    // A session still waiting on the ZEC deposit gets the longer
    // `keeper.near_intent_timeout_seconds` budget (3.5 days by default), not the
    // 1-hour session budget, because that leg is bounded by 1Click's deposit
    // deadline rather than by anything the coordinator controls. Backdate past
    // the budget that actually applies.
    let near_intent_budget =
        Duration::seconds(zecp2p_types::config::KeeperConfig::default().near_intent_timeout_seconds);
    let old_created_at = Utc::now() - near_intent_budget - Duration::hours(1);
    sqlx::query(
        "UPDATE sessions SET created_at = ? WHERE id = ?",
    )
    .bind(old_created_at.to_rfc3339())
    .bind(session.id.to_string())
    .execute(&sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", infra.config.database.path)).await.unwrap())
    .await
    .expect("update created_at");

    // Reload session from DB (cache won't have the change)
    // Force cache update by getting from DB directly
    let db2 = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    let reloaded_session = db2.get_session(session.id).await.unwrap().unwrap();
    state.update_session(&reloaded_session).await.expect("update cache");

    println!("  Original created_at: {}", session.created_at);
    println!("  Backdated to: {}", old_created_at);

    // Step 3: Run keeper tick - it should detect the timeout
    println!("\nStep 3: Running keeper tick to detect timeout...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    // Wait for one keeper tick (15 seconds) plus buffer
    tokio::time::sleep(StdDuration::from_secs(18)).await;

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    // Step 4: Verify session is now failed due to timeout
    println!("\nStep 4: Verifying session is marked as failed...");
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("  Final status: {:?}", final_session.status);
    println!("  Error: {:?}", final_session.error);

    assert_eq!(final_session.status, OfframpStatus::Failed);
    let error_msg = final_session.error.as_ref().unwrap().to_lowercase();
    assert!(
        error_msg.contains("timeout") || error_msg.contains("timed out"),
        "Error should mention timeout, got: {}",
        final_session.error.as_ref().unwrap()
    );

    println!("\n=== Session timeout detection test passed! ===");
}

/// Test that NEAR API failures are handled gracefully
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_near_api_failure_during_quote() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing NEAR API Failure During Quote ===\n");

    // Configure mock to fail
    println!("Step 1: Configuring NEAR mock to return errors...");
    infra.near_config.set_quote_should_fail(true);

    // Step 2: Try to create offramp - should fail
    println!("\nStep 2: Attempting to create offramp (should fail)...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "nearfailtest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let result = state.create_offramp(request).await;
    assert!(result.is_err(), "Expected error when NEAR API fails");

    let err = result.unwrap_err();
    println!("  Got expected error: {}", err);

    // The error should indicate NEAR Intents failure
    let err_str = format!("{:?}", err);
    assert!(
        err_str.contains("NearIntents") || err_str.contains("NEAR") || err_str.contains("500"),
        "Error should indicate NEAR API failure"
    );

    println!("\n=== NEAR API failure during quote test passed! ===");
}

/// Test that NEAR status API failures during keeper loop are handled gracefully
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_near_status_failure_during_keeper() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing NEAR Status Failure During Keeper ===\n");

    // Step 1: Create a session normally
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "statusfailtest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);
    assert_eq!(session.status, OfframpStatus::NearIntentPending);

    // Step 2: Configure status API to fail
    println!("\nStep 2: Configuring NEAR status to return errors...");
    infra.near_config.set_status_should_fail(true);

    // Step 3: Run keeper tick - it should handle the error gracefully
    println!("\nStep 3: Running keeper tick (status call will fail)...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    // Wait for one keeper tick
    tokio::time::sleep(StdDuration::from_secs(18)).await;

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    // Step 4: Verify session is still in pending state (not crashed)
    println!("\nStep 4: Verifying session is still in valid state...");
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("  Final status: {:?}", final_session.status);

    // Session should still be pending (NEAR status error should be handled gracefully)
    assert_eq!(final_session.status, OfframpStatus::NearIntentPending);
    assert!(final_session.error.is_none(), "Session should not have error set from transient status failure");

    println!("\n=== NEAR status failure during keeper test passed! ===");
}

/// Test that terminal states prevent further processing
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_terminal_state_no_processing() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing Terminal State No Processing ===\n");

    // Step 1: Create a session
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "terminaltest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);

    // Step 2: Manually mark session as Fulfilled (terminal state)
    println!("\nStep 2: Marking session as Fulfilled (terminal state)...");
    let mut terminal_session = state.get_session(session.id).await.unwrap().unwrap();
    terminal_session.set_status(OfframpStatus::Fulfilled);
    state.update_session(&terminal_session).await.unwrap();

    let updated_at_before = terminal_session.updated_at;
    println!("  Updated at: {}", updated_at_before);

    // Step 3: Configure NEAR status to SUCCESS - this would normally trigger processing
    println!("\nStep 3: Setting NEAR status to SUCCESS...");
    infra.near_config.set_status("SUCCESS");

    // Step 4: Run keeper tick
    println!("\nStep 4: Running keeper tick...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    tokio::time::sleep(StdDuration::from_secs(18)).await;

    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    // Step 5: Verify session unchanged
    println!("\nStep 5: Verifying session unchanged...");
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("  Final status: {:?}", final_session.status);

    // Session should still be Fulfilled with no changes
    assert_eq!(final_session.status, OfframpStatus::Fulfilled);
    // Note: get_active_sessions() filters out terminal states, so keeper won't even process it

    println!("\n=== Terminal state no processing test passed! ===");
}

/// Test concurrent reads while keeper is updating sessions
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_concurrent_reads_during_keeper() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing Concurrent Reads During Keeper ===\n");

    // Step 1: Create a session
    println!("Step 1: Creating session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "concurrentread".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);

    // Step 2: Start keeper loop
    println!("\nStep 2: Starting keeper loop...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    // Step 3: Perform many concurrent reads while keeper runs
    println!("\nStep 3: Performing 100 concurrent reads while keeper runs...");
    let mut handles = vec![];
    for _ in 0..100 {
        let state_clone = state.clone();
        let session_id = session.id;
        let h = tokio::spawn(async move {
            // Small random delay to increase chance of race
            tokio::time::sleep(StdDuration::from_millis(rand::random::<u64>() % 50)).await;
            state_clone.get_session(session_id).await
        });
        handles.push(h);
    }

    let mut success_count = 0;
    for h in handles {
        match h.await {
            Ok(Ok(Some(_session))) => success_count += 1,
            Ok(Ok(None)) => println!("  Warning: session not found"),
            Ok(Err(e)) => println!("  Warning: error reading session: {}", e),
            Err(e) => println!("  Warning: task panicked: {}", e),
        }
    }
    println!("  Successfully read session {} times", success_count);

    // All reads should succeed
    assert_eq!(success_count, 100, "All reads should succeed");

    // Step 4: Shutdown keeper
    println!("\nStep 4: Shutting down keeper...");
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    // Step 5: Verify session is still consistent
    println!("\nStep 5: Verifying session is consistent...");
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("  Final status: {:?}", final_session.status);

    // Session should still be in NearIntentPending (NEAR never returned SUCCESS)
    assert_eq!(final_session.status, OfframpStatus::NearIntentPending);

    println!("\n=== Concurrent reads during keeper test passed! ===");
}

/// Test cache and database stay consistent under concurrent updates
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_cache_db_consistency() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing Cache-DB Consistency ===\n");

    // Create a session
    println!("Step 1: Creating session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "consistencytest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create");
    println!("  Session ID: {}", session.id);

    // Verify session is in cache by reading via state
    let cached = state.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(cached.status, OfframpStatus::NearIntentPending);
    println!("  Session in cache: {:?}", cached.status);

    // Read directly from database to verify consistency
    let db2 = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    let db_session = db2.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(db_session.status, OfframpStatus::NearIntentPending);
    println!("  Session in DB: {:?}", db_session.status);

    // Update via state (should update both cache and DB)
    println!("\nStep 2: Updating session via state...");
    let mut updated = state.get_session(session.id).await.unwrap().unwrap();
    updated.received_usdc = Some(U256::from(15_000_000u64));
    updated.set_status(OfframpStatus::UsdcReceived);
    state.update_session(&updated).await.expect("update");

    // Verify cache is updated
    let cached2 = state.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(cached2.status, OfframpStatus::UsdcReceived);
    println!("  Cache updated: {:?}", cached2.status);

    // Verify DB is updated
    let db_session2 = db2.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(db_session2.status, OfframpStatus::UsdcReceived);
    println!("  DB updated: {:?}", db_session2.status);

    // Verify data consistency
    assert_eq!(cached2.received_usdc, db_session2.received_usdc);
    println!("  received_usdc consistent: {:?}", cached2.received_usdc);

    println!("\n=== Cache-DB consistency test passed! ===");
}

/// Test session at exact timeout boundary
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_session_at_timeout_boundary() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near);

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        near_client,
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    println!("\n=== Testing Session at Timeout Boundary ===\n");

    // Create a session
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "boundarytest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");

    // Session timeout is 3600 seconds (1 hour)
    // Set created_at to exactly 59 minutes ago - should NOT timeout
    let just_under_timeout = Utc::now() - Duration::minutes(59);

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", infra.config.database.path))
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET created_at = ? WHERE id = ?")
        .bind(just_under_timeout.to_rfc3339())
        .bind(session.id.to_string())
        .execute(&pool)
        .await
        .unwrap();

    // Reload to cache
    let db2 = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    let reloaded = db2.get_session(session.id).await.unwrap().unwrap();
    state.update_session(&reloaded).await.unwrap();

    println!("Session created_at set to {} (59 minutes ago)", just_under_timeout);

    // Run keeper
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    tokio::time::sleep(StdDuration::from_secs(18)).await;

    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    // Session should NOT be failed (still under 60 minute threshold)
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("Final status: {:?}", final_session.status);

    assert_eq!(
        final_session.status,
        OfframpStatus::NearIntentPending,
        "Session at 59 minutes should NOT timeout"
    );

    println!("\n=== Session at timeout boundary test passed! ===");
}
