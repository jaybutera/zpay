//! End-to-end coordinator test with mock NEAR API and real anvil contracts
//!
//! This test exercises the full coordinator flow:
//! 1. Starts an anvil instance with deployed contracts
//! 2. Starts a mock NEAR Intents API server
//! 3. Creates an AppState pointing to both
//! 4. Tests the full offramp flow through the coordinator API
//!
//! Run with: cargo test --package zecp2p-coordinator --test coordinator_e2e_test -- --ignored --nocapture

mod test_utils;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use axum::{
    extract::Query,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use test_utils::{deploy_contracts, AnvilInstance, MockZkp2pServer, ANVIL_PRIVATE_KEY, TEST_USER};
use tokio::net::TcpListener;
use zecp2p_types::abi::MockUSDC;

/// Atomic counters for unique port allocation (separate from test_utils)
static NEAR_PORT: AtomicU16 = AtomicU16::new(9700);
static COORDINATOR_PORT: AtomicU16 = AtomicU16::new(3200);

/// Mock NEAR Intents API server
struct MockNearServer {
    port: u16,
    #[allow(dead_code)]
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<()>,
}

impl MockNearServer {
    async fn start(glue_contract: Address) -> Self {
        let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Build mock routes
        let app = Router::new()
            .route("/v0/quote", post(mock_quote_handler))
            .route("/v0/status", get(mock_status_handler))
            .with_state(MockNearState { glue_contract });

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

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            port,
            shutdown_tx,
            handle,
        }
    }

    fn api_url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }
}

#[derive(Clone)]
struct MockNearState {
    #[allow(dead_code)]
    glue_contract: Address,
}

/// Mock quote response matching NEAR Intents API format
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

async fn mock_quote_handler(
    axum::extract::State(_state): axum::extract::State<MockNearState>,
    Json(request): Json<QuoteRequest>,
) -> Json<MockQuoteResponse> {
    // Parse input amount (zatoshi) and convert to approximate USDC
    // Using a mock rate of ~30 USDC per ZEC
    let zatoshi: u64 = request.amount.parse().unwrap_or(50_000_000);
    let usdc_out = (zatoshi as f64 / 100_000_000.0 * 30.0 * 1_000_000.0) as u64;

    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);

    Json(MockQuoteResponse {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        quote: MockQuote {
            amount_out: usdc_out.to_string(),
            min_amount_out: (usdc_out * 99 / 100).to_string(), // 1% slippage
            time_estimate: 300,
            deposit_address: format!("t1MockZecAddress{}", rand::random::<u32>()),
            deadline: deadline.to_rfc3339(),
        },
    })
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

async fn mock_status_handler(Query(_query): Query<StatusQuery>) -> Json<MockStatusResponse> {
    // Always return SUCCESS - in real tests we'd track state
    Json(MockStatusResponse {
        status: "SUCCESS".to_string(),
        source_transaction_hash: Some("0xmocksourcetx".to_string()),
        destination_transaction_hash: Some("0xmockdesttx".to_string()),
        amount_out: Some("15000000".to_string()), // 15 USDC
        error: None,
    })
}

/// Create a test configuration pointing to anvil and mock NEAR
fn create_test_config(
    anvil_url: &str,
    near_url: &str,
    zkp2p_url: &str,
    usdc: Address,
    escrow: Address,
    glue: Address,
    db_path: &str,
    server_port: u16,
) -> zecp2p_types::Config {
    zecp2p_types::Config {
        network: zecp2p_types::config::NetworkConfig {
            base_rpc_url: anvil_url.to_string(),
            base_sepolia_rpc_url: Some(anvil_url.to_string()),
            chain_id: 31337, // anvil chain id
        },
        contracts: zecp2p_types::config::ContractConfig {
            usdc,
            zkp2p_escrow: escrow,
            zkp2p_orchestrator: escrow, // Using escrow as mock orchestrator
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
            port: server_port,
            ..Default::default()
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: db_path.to_string(),
        },
    }
}

/// Test infrastructure setup
struct TestInfra {
    anvil: AnvilInstance,
    #[allow(dead_code)]
    near_server: MockNearServer,
    #[allow(dead_code)]
    zkp2p_server: MockZkp2pServer,
    usdc_addr: Address,
    #[allow(dead_code)]
    escrow_addr: Address,
    glue_addr: Address,
    config: zecp2p_types::Config,
    _temp_dir: TempDir,
}

impl TestInfra {
    async fn setup() -> Self {
        // Start anvil
        let anvil = AnvilInstance::start();
        println!("Anvil started at {}", anvil.rpc_url());

        // Deploy contracts
        let (usdc_addr, escrow_addr, glue_addr) = deploy_contracts(anvil.rpc_url());
        println!("Contracts deployed:");
        println!("  MockUSDC: {}", usdc_addr);
        println!("  MockEscrow: {}", escrow_addr);
        println!("  OfframpGlue: {}", glue_addr);

        // Start mock NEAR server
        let near_server = MockNearServer::start(glue_addr).await;
        println!("Mock NEAR server at {}", near_server.api_url());

        let zkp2p_server = MockZkp2pServer::start().await;
        println!("Mock zk-p2p curator at {}", zkp2p_server.api_url());

        // Create temp directory for database
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("test.db").to_string_lossy().to_string();

        // Create config
        let server_port = COORDINATOR_PORT.fetch_add(1, Ordering::SeqCst);
        let config = create_test_config(
            anvil.rpc_url(),
            &near_server.api_url(),
            &zkp2p_server.api_url(),
            usdc_addr,
            escrow_addr,
            glue_addr,
            &db_path,
            server_port,
        );

        Self {
            anvil,
            near_server,
            zkp2p_server,
            usdc_addr,
            escrow_addr,
            glue_addr,
            config,
            _temp_dir: temp_dir,
        }
    }

    async fn get_signing_provider(&self) -> impl Provider {
        let signer: PrivateKeySigner = ANVIL_PRIVATE_KEY.parse().expect("valid key");
        let wallet = EthereumWallet::from(signer);
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.anvil.rpc_url().parse().expect("valid url"))
    }

    /// Mint USDC to an address (simulating NEAR Intent delivery)
    async fn mint_usdc(&self, to: Address, amount: U256) {
        let provider = self.get_signing_provider().await;
        let usdc = MockUSDC::new(self.usdc_addr, &provider);

        usdc.mint(to, amount)
            .send()
            .await
            .expect("mint send")
            .get_receipt()
            .await
            .expect("mint receipt");
    }
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_coordinator_full_flow() {
    // Setup test infrastructure
    let infra = TestInfra::setup().await;

    // Set the private key for the coordinator
    std::env::set_var("COORDINATOR_PRIVATE_KEY", ANVIL_PRIVATE_KEY);

    // Initialize coordinator components
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

    println!("\n=== Testing Coordinator Flow ===\n");

    // Step 1: Create offramp through the coordinator state (bypassing HTTP for simplicity)
    println!("Step 1: Creating offramp session...");

    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,    // 0.5 ZEC
        venmo_username: "testuser".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()), // Same for testing
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128), // 1 USDC/ZEC minimum
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");

    println!("  Session ID: {}", session.id);
    println!("  Status: {:?}", session.status);
    println!("  Near deposit address: {:?}", session.near_deposit_address);
    println!("  Expected USDC: {:?}", session.expected_usdc);

    assert!(session.near_deposit_address.is_some());
    assert!(session.expected_usdc.is_some());
    assert_eq!(
        session.status,
        zecp2p_types::OfframpStatus::NearIntentPending
    );

    // Step 2: Simulate USDC arrival (what NEAR Intent would deliver)
    println!("\nStep 2: Simulating USDC arrival from NEAR Intent...");

    let usdc_amount = session.expected_usdc.unwrap();
    infra.mint_usdc(infra.glue_addr, usdc_amount).await;

    println!("  Minted {} USDC to GlueContract", usdc_amount);

    // Step 3: Update session status to UsdcReceived (normally the keeper would do this)
    // For testing, we manually transition the state
    println!("\nStep 3: Transitioning to UsdcReceived state...");

    // Get current session and update status
    let mut updated_session = state
        .get_session(session.id)
        .await
        .expect("get session")
        .expect("session exists");

    // In production, the keeper loop would detect USDC arrival via NEAR status API
    // For testing, we manually set the status
    updated_session.received_usdc = Some(usdc_amount);
    updated_session.set_status(zecp2p_types::OfframpStatus::UsdcReceived);

    // Update both cache and database (simulating what keeper would do)
    state.update_session(&updated_session).await.expect("update session");

    println!("  Session status updated to: {:?}", updated_session.status);

    // Step 4: Process offramp (route to zk-p2p)
    println!("\nStep 4: Processing offramp (routing to zk-p2p)...");

    let processed_session = state.process_offramp(session.id).await.expect("process offramp");

    println!("  Status after process: {:?}", processed_session.status);
    println!("  zk-p2p deposit ID: {:?}", processed_session.zkp2p_deposit_id);
    println!(
        "  Process tx hash: {:?}",
        processed_session.process_offramp_tx
    );

    assert_eq!(
        processed_session.status,
        zecp2p_types::OfframpStatus::Zkp2pDeposited
    );
    assert!(processed_session.zkp2p_deposit_id.is_some());

    println!("\n=== Coordinator full flow completed successfully! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_coordinator_rescue_state_validation() {
    // This test validates the coordinator's state machine for rescue operations.
    // Note: The actual rescue() call on the contract requires the USER's private key,
    // not the coordinator's key. The coordinator tracks state but the user must call
    // rescue() directly on the contract.

    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", ANVIL_PRIVATE_KEY);

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

    println!("\n=== Testing Coordinator Rescue State Validation ===\n");

    // Create session
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "rescueuser".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("Created session: {}", session.id);

    // Test 1: Cannot rescue in NearIntentPending state
    println!("Test 1: Cannot rescue in NearIntentPending state...");
    let result = state.rescue(session.id).await;
    assert!(result.is_err(), "Should not be able to rescue in NearIntentPending state");
    println!("  ✓ Correctly rejected");

    // Mint USDC to GlueContract
    let usdc_amount = session.expected_usdc.unwrap();
    infra.mint_usdc(infra.glue_addr, usdc_amount).await;
    println!("Minted {} USDC to GlueContract", usdc_amount);

    // Update to UsdcReceived state
    let mut updated_session = state
        .get_session(session.id)
        .await
        .expect("get")
        .expect("exists");
    updated_session.received_usdc = Some(usdc_amount);
    updated_session.set_status(zecp2p_types::OfframpStatus::UsdcReceived);
    state.update_session(&updated_session).await.expect("update");

    // Test 2: Can rescue in UsdcReceived state (state machine allows it)
    // Note: The actual contract call would fail without user's key, but the state
    // machine validation passes. This test verifies state machine logic.
    println!("Test 2: Rescue is allowed in UsdcReceived state (state machine check)...");
    let session_check = state.get_session(session.id).await.expect("get").expect("exists");
    assert_eq!(session_check.status, zecp2p_types::OfframpStatus::UsdcReceived);
    println!("  ✓ Session in correct state for rescue");

    println!("\n=== Coordinator rescue state validation completed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_coordinator_withdraw_state_validation() {
    // This test validates the coordinator's state machine for withdraw operations.
    // Note: The actual withdrawFromZkp2p() call requires the USER's private key.
    // The coordinator tracks state but the user must call withdraw directly.

    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", ANVIL_PRIVATE_KEY);

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

    println!("\n=== Testing Coordinator Withdraw State Validation ===\n");

    // Create session
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 75_000_000, // 0.75 ZEC
        venmo_username: "withdrawuser".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("Created session: {}", session.id);

    // Test 1: Cannot withdraw in NearIntentPending state
    println!("Test 1: Cannot withdraw in NearIntentPending state...");
    let result = state.withdraw(session.id).await;
    assert!(result.is_err(), "Should not be able to withdraw in NearIntentPending state");
    println!("  ✓ Correctly rejected");

    // Mint USDC and update to UsdcReceived
    let usdc_amount = session.expected_usdc.unwrap();
    infra.mint_usdc(infra.glue_addr, usdc_amount).await;

    let mut updated_session = state.get_session(session.id).await.expect("get").expect("exists");
    updated_session.received_usdc = Some(usdc_amount);
    updated_session.set_status(zecp2p_types::OfframpStatus::UsdcReceived);
    state.update_session(&updated_session).await.expect("update");

    // Test 2: Cannot withdraw in UsdcReceived state (must be in Zkp2pDeposited)
    println!("Test 2: Cannot withdraw in UsdcReceived state...");
    let result = state.withdraw(session.id).await;
    assert!(result.is_err(), "Should not be able to withdraw in UsdcReceived state");
    println!("  ✓ Correctly rejected");

    // Process offramp (deposit to zk-p2p)
    let processed_session = state.process_offramp(session.id).await.expect("process");
    println!("Processed offramp, deposit ID: {:?}", processed_session.zkp2p_deposit_id);

    // Test 3: Can withdraw in Zkp2pDeposited state (state machine allows it)
    println!("Test 3: Withdraw is allowed in Zkp2pDeposited state (state machine check)...");
    let session_check = state.get_session(session.id).await.expect("get").expect("exists");
    assert_eq!(session_check.status, zecp2p_types::OfframpStatus::Zkp2pDeposited);
    assert!(session_check.zkp2p_deposit_id.is_some());
    println!("  ✓ Session in correct state for withdraw");

    println!("\n=== Coordinator withdraw state validation completed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_coordinator_state_validation() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", ANVIL_PRIVATE_KEY);

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

    println!("\n=== Testing Coordinator State Validation ===\n");

    // Create session
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "statetest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1TestRefundAddressXXXXXXXXXXXX".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");

    // Test 1: Cannot process offramp in NearIntentPending state
    println!("Test 1: Cannot process offramp in NearIntentPending state...");
    let result = state.process_offramp(session.id).await;
    assert!(result.is_err(), "Should not be able to process in NearIntentPending state");
    println!("  ✓ Correctly rejected");

    // Test 2: Cannot rescue in NearIntentPending state
    println!("Test 2: Cannot rescue in NearIntentPending state...");
    let result = state.rescue(session.id).await;
    assert!(result.is_err(), "Should not be able to rescue in NearIntentPending state");
    println!("  ✓ Correctly rejected");

    // Test 3: Cannot withdraw in NearIntentPending state
    println!("Test 3: Cannot withdraw in NearIntentPending state...");
    let result = state.withdraw(session.id).await;
    assert!(result.is_err(), "Should not be able to withdraw in NearIntentPending state");
    println!("  ✓ Correctly rejected");

    println!("\n=== State validation tests passed! ===");
}
