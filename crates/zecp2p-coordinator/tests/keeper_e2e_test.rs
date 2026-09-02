//! Keeper-driven end-to-end tests with event-driven state transitions
//!
//! This test addresses the gaps in local e2e testing:
//! 1. Keeper loop auto-detection of USDC arrival (instead of calling processOfframp directly)
//! 2. Event-driven state transitions (IntentSignaled, IntentFulfilled events)
//! 3. Tests the coordinator's actual behavior rather than just contract interfaces
//!
//! Run with: cargo test --package zecp2p-coordinator --test keeper_e2e_test -- --ignored --nocapture

mod test_utils;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use test_utils::{MockZkp2pServer, ANVIL_PRIVATE_KEY, KEEPER_PRIVATE_KEY};
use tokio::net::TcpListener;
use zecp2p_types::abi::{
    usd_currency_code, venmo_payment_method, MockEscrowWithOrchestrator, MockUSDC,
};

/// Atomic counters for unique port allocation
static ANVIL_PORT: AtomicU16 = AtomicU16::new(8900);
static NEAR_PORT: AtomicU16 = AtomicU16::new(9900);

/// Test user address (anvil account[1])
const TEST_USER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// Test user private key (anvil account[1])
const TEST_USER_PRIVATE_KEY: &str =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// RAII wrapper for anvil process
struct AnvilInstance {
    process: Child,
    rpc_url: String,
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

        std::thread::sleep(Duration::from_secs(2));

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

/// Deploy contracts using the enhanced script with Orchestrator mock
fn deploy_enhanced_contracts(rpc_url: &str) -> (Address, Address, Address) {
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
            "script/DeployLocalEnhanced.s.sol:DeployLocalEnhanced",
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
        } else if trimmed.starts_with("MockEscrowWithOrchestrator deployed at:") {
            escrow_addr = Some(extract_address(trimmed));
        } else if trimmed.starts_with("OfframpGlue deployed at:") {
            glue_addr = Some(extract_address(trimmed));
        }
    }

    (
        usdc_addr.expect("MockUSDC address not found"),
        escrow_addr.expect("MockEscrowWithOrchestrator address not found"),
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

/// Get a provider with signing capabilities
async fn get_signing_provider(rpc_url: &str, private_key: &str) -> impl Provider {
    let signer: PrivateKeySigner = private_key.parse().expect("valid key");
    let wallet = EthereumWallet::from(signer);
    ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse().expect("valid url"))
}

/// Mock NEAR Intents API server with stateful tracking
struct MockNearServer {
    port: u16,
    #[allow(dead_code)]
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<()>,
}

/// State shared across mock NEAR handlers
#[derive(Clone)]
struct MockNearState {
    #[allow(dead_code)]
    glue_contract: Address,
    /// Track deposit addresses and their completion status
    status_response: std::sync::Arc<std::sync::RwLock<String>>,
    /// What `swapDetails.amountOut` reports once the swap settles.
    ///
    /// The quote handler fills this in with what it quoted, so by default a
    /// swap settles for exactly its quote. A test that wants an under-fill,
    /// which 50 bps of quote slippage makes ordinary, sets it lower.
    settled_amount: std::sync::Arc<std::sync::RwLock<String>>,
}

impl MockNearState {
    fn new(glue_contract: Address) -> Self {
        Self {
            glue_contract,
            status_response: std::sync::Arc::new(std::sync::RwLock::new("PENDING".to_string())),
            settled_amount: std::sync::Arc::new(std::sync::RwLock::new("0".to_string())),
        }
    }

    fn set_status(&self, status: &str) {
        *self.status_response.write().unwrap() = status.to_string();
    }

    /// Make the swap settle for `amount` USDC units instead of the full quote.
    #[allow(dead_code)]
    fn set_settled_amount(&self, amount: &str) {
        *self.settled_amount.write().unwrap() = amount.to_string();
    }
}

impl MockNearServer {
    async fn start(glue_contract: Address) -> (Self, MockNearState) {
        let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let state = MockNearState::new(glue_contract);
        let state_clone = state.clone();

        let app = Router::new()
            .route("/v0/quote", post(mock_quote_handler))
            .route("/v0/status", get(mock_status_handler))
            .with_state(state_clone);

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

        tokio::time::sleep(Duration::from_millis(100)).await;

        (
            Self {
                port,
                shutdown_tx,
                handle,
            },
            state,
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

async fn mock_quote_handler(
    axum::extract::State(state): axum::extract::State<MockNearState>,
    Json(request): Json<QuoteRequest>,
) -> Json<MockQuoteResponse> {
    let zatoshi: u64 = request.amount.parse().unwrap_or(50_000_000);
    let usdc_out = (zatoshi as f64 / 100_000_000.0 * 30.0 * 1_000_000.0) as u64;
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);

    // Unless a test says otherwise, the swap settles for exactly what it quoted.
    *state.settled_amount.write().unwrap() = usdc_out.to_string();

    Json(MockQuoteResponse {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        quote: MockQuote {
            amount_out: usdc_out.to_string(),
            min_amount_out: (usdc_out * 99 / 100).to_string(),
            time_estimate: 300,
            deposit_address: format!("t1MockZecDeposit{}", rand::random::<u32>()),
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

/// The 1Click status shape, as the live API sends it.
///
/// This mock used to put `amountOut` and the chain hashes at the top level.
/// They are not there: they live inside `swapDetails`, and the chain hashes are
/// arrays of `{hash, explorerUrl}` objects rather than bare strings. The
/// recorded fixtures under `tests/fixtures/` are the record of that, and
/// `near.rs` parses accordingly, so the mock's fields silently deserialized to
/// `None`.
///
/// That did not matter while the keeper decided a credit from the glue's
/// balance. It matters now: the keeper credits what 1Click reports settled, so a
/// mock that reports nothing is a session that is never credited. A mock written
/// to our own convenience cannot catch a mismatch between us and the API.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockStatusResponse {
    status: String,
    swap_details: MockSwapDetails,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockSwapDetails {
    amount_out: Option<String>,
    refunded_amount: Option<String>,
    origin_chain_tx_hashes: Vec<MockTxHash>,
    destination_chain_tx_hashes: Vec<MockTxHash>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockTxHash {
    hash: String,
    explorer_url: String,
}

fn mock_tx(hash: &str) -> MockTxHash {
    MockTxHash {
        hash: hash.to_string(),
        explorer_url: String::new(),
    }
}

async fn mock_status_handler(
    axum::extract::State(state): axum::extract::State<MockNearState>,
    axum::extract::Query(_query): axum::extract::Query<StatusQuery>,
) -> Json<MockStatusResponse> {
    let status = state.status_response.read().unwrap().clone();
    let settled = state.settled_amount.read().unwrap().clone();

    // Before the swap settles there is no amountOut and no destination hash,
    // which is what a real PENDING_DEPOSIT and PROCESSING look like.
    let delivered = status == "SUCCESS";

    Json(MockStatusResponse {
        status,
        swap_details: MockSwapDetails {
            amount_out: delivered.then_some(settled),
            refunded_amount: Some("0".to_string()),
            origin_chain_tx_hashes: vec![mock_tx("0xmocksourcetx")],
            destination_chain_tx_hashes: if delivered {
                vec![mock_tx("0xmockdesttx")]
            } else {
                vec![]
            },
        },
    })
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
            zkp2p_orchestrator: escrow, // Using combined mock
            stake_vault: zecp2p_types::config::DEFAULT_STAKE_VAULT.parse().unwrap(),
            glue_contract: Some(glue),
        },
        near: zecp2p_types::config::NearConfig {
            api_url: near_url.to_string(),
            default_timeout: 600,
        },
        zkp2p: zecp2p_types::config::Zkp2pConfig {
            api_url: zkp2p_url.to_string(),
            ..Default::default()
        },
        keeper: zecp2p_types::config::KeeperConfig::default(),
        attestation: zecp2p_types::config::AttestationConfig::default(),
        server: zecp2p_types::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000, // Not used in these tests
            ..Default::default()
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: db_path.to_string(),
        },
    }
}

/// Test infrastructure for keeper-driven tests
struct TestInfra {
    anvil: AnvilInstance,
    #[allow(dead_code)]
    near_server: MockNearServer,
    #[allow(dead_code)]
    zkp2p_server: MockZkp2pServer,
    near_state: MockNearState,
    usdc_addr: Address,
    escrow_addr: Address,
    glue_addr: Address,
    config: zecp2p_types::Config,
    _temp_dir: TempDir,
}

impl TestInfra {
    async fn setup() -> Self {
        let anvil = AnvilInstance::start();
        println!("Anvil started at {} (port {})", anvil.rpc_url(), anvil.port);

        let (usdc_addr, escrow_addr, glue_addr) = deploy_enhanced_contracts(anvil.rpc_url());
        println!("Contracts deployed:");
        println!("  MockUSDC: {}", usdc_addr);
        println!("  MockEscrowWithOrchestrator: {}", escrow_addr);
        println!("  OfframpGlue: {}", glue_addr);

        let (near_server, near_state) = MockNearServer::start(glue_addr).await;
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
            near_state,
            usdc_addr,
            escrow_addr,
            glue_addr,
            config,
            _temp_dir: temp_dir,
        }
    }

    async fn get_signing_provider(&self) -> impl Provider {
        get_signing_provider(self.anvil.rpc_url(), ANVIL_PRIVATE_KEY).await
    }

    async fn get_user_provider(&self) -> impl Provider {
        get_signing_provider(self.anvil.rpc_url(), TEST_USER_PRIVATE_KEY).await
    }

    /// Deliver USDC and assign it to a session, the way the keeper does.
    ///
    /// Tests that fast-forward a session past the keeper's own detection have to
    /// do this themselves: a bare mint leaves the money unassigned, which no
    /// session may spend. That separation is what stops concurrent sessions
    /// taking each other's funds, so processOfframp rightly refuses without it.
    async fn deliver_usdc_for(&self, session_id: alloy::primitives::B256, amount: U256) {
        self.mint_usdc(self.glue_addr, amount).await;

        let provider = self.get_signing_provider().await;
        let glue = zecp2p_types::abi::OfframpGlue::new(self.glue_addr, &provider);
        glue.creditSession(session_id, amount)
            .send()
            .await
            .expect("creditSession send")
            .get_receipt()
            .await
            .expect("creditSession receipt");
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

/// Test the keeper loop auto-detecting USDC arrival and processing the offramp
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_keeper_auto_processes_on_usdc_arrival() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

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

    println!("\n=== Testing Keeper Auto-Processing ===\n");

    // Step 1: Create offramp session
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "keepertest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    // The payee hash must be the curator-issued one, not a local keccak of the username
    assert_eq!(
        session.payee_details_hash,
        MockZkp2pServer::expected_hash(&session.request.venmo_username),
        "payee_details_hash must come from the zk-p2p curator"
    );
    assert_eq!(
        infra.zkp2p_server.registered(),
        vec![session.request.venmo_username.clone()],
        "the Venmo username must be registered with the curator exactly once"
    );
    println!("  Session ID: {}", session.id);
    println!("  Status: {:?}", session.status);
    assert_eq!(
        session.status,
        zecp2p_types::OfframpStatus::NearIntentPending
    );

    // Step 2: Start keeper loop in background with shutdown signal
    println!("\nStep 2: Starting keeper loop...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state
            .run_keeper_loop_with_shutdown(shutdown_rx)
            .await
    });

    // Step 3: Simulate USDC arrival by minting to GlueContract
    println!("\nStep 3: Simulating USDC arrival (minting to GlueContract)...");
    let usdc_amount = session.expected_usdc.unwrap();
    infra.mint_usdc(infra.glue_addr, usdc_amount).await;
    println!("  Minted {} USDC to GlueContract", usdc_amount);

    // Step 4: Update NEAR status to SUCCESS (simulating NEAR Intent completion)
    println!("\nStep 4: Updating NEAR status to SUCCESS...");
    infra.near_state.set_status("SUCCESS");

    // Step 5: Wait for keeper to detect and process
    // Keeper poll interval is 15 seconds, so we need to wait longer (up to ~35s for two ticks)
    println!("\nStep 5: Waiting for keeper to auto-process (up to 40s)...");
    let mut processed = false;
    for i in 0..20 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current_session = state
            .get_session(session.id)
            .await
            .expect("get session")
            .expect("session exists");

        println!(
            "  Check {}: Status = {:?}",
            i + 1,
            current_session.status
        );

        if current_session.status == zecp2p_types::OfframpStatus::Zkp2pDeposited {
            processed = true;
            println!("  ✓ Keeper auto-processed offramp!");
            println!("  zk-p2p deposit ID: {:?}", current_session.zkp2p_deposit_id);
            break;
        }
    }

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    assert!(processed, "Keeper should have auto-processed the offramp");
    println!("\n=== Keeper auto-processing test passed! ===");
}

/// Test the full event-driven flow: USDC arrival → process → IntentSignaled → IntentFulfilled
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_full_event_driven_flow() {
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

    println!("\n=== Testing Full Event-Driven Flow ===\n");

    // Step 1: Create offramp session
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "eventtest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);

    // Step 2: Mint USDC to GlueContract and update status
    println!("\nStep 2: Simulating USDC arrival...");
    let usdc_amount = session.expected_usdc.unwrap();
    infra.deliver_usdc_for(session.session_id, usdc_amount).await;
    infra.near_state.set_status("SUCCESS");

    // Step 3: Manually update session to UsdcReceived (simulating what keeper does)
    let mut updated_session = state
        .get_session(session.id)
        .await
        .expect("get")
        .expect("exists");
    updated_session.received_usdc = Some(usdc_amount);
    updated_session.set_status(zecp2p_types::OfframpStatus::UsdcReceived);
    state.update_session(&updated_session).await.expect("update");
    println!("  Status: UsdcReceived");

    // Step 4: Process offramp (creates zk-p2p deposit)
    println!("\nStep 3: Processing offramp (depositing to zk-p2p)...");
    let processed_session = state
        .process_offramp(session.id)
        .await
        .expect("process offramp");
    println!("  Status: {:?}", processed_session.status);
    println!("  Deposit ID: {:?}", processed_session.zkp2p_deposit_id);
    assert_eq!(
        processed_session.status,
        zecp2p_types::OfframpStatus::Zkp2pDeposited
    );

    let deposit_id = processed_session.zkp2p_deposit_id.unwrap();

    // Step 5: Simulate taker signaling intent (using MockEscrowWithOrchestrator)
    println!("\nStep 4: Simulating taker signaling intent...");
    let user_provider = infra.get_user_provider().await;
    let orchestrator =
        MockEscrowWithOrchestrator::new(infra.escrow_addr, &user_provider);

    let intent_hash = orchestrator
        .signalIntent(
            deposit_id,
            TEST_USER.parse::<Address>().unwrap(),
            usdc_amount,
            venmo_payment_method(),
            usd_currency_code(),
            U256::from(1_000_000_000_000_000_000u128),
        )
        .send()
        .await
        .expect("signal intent send")
        .get_receipt()
        .await
        .expect("signal intent receipt");

    println!("  Intent signaled, tx: {:?}", intent_hash.transaction_hash);

    // Verify the event was emitted by checking the chain client
    let provider = infra.get_signing_provider().await;
    let current_block = provider.get_block_number().await.expect("get block");

    // Check for IntentSignaled events
    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");
    let events = chain_client
        .get_intent_signaled_events(deposit_id, 0, current_block)
        .await
        .expect("get events");

    assert!(!events.is_empty(), "Should have IntentSignaled event");
    let event = &events[0];
    println!("  IntentSignaled event detected:");
    println!("    intent_hash: {:?}", event.intent_hash);
    println!("    deposit_id: {}", event.deposit_id);
    println!("    amount: {}", event.amount);

    // Step 6: Simulate taker fulfilling intent
    println!("\nStep 5: Simulating taker fulfilling intent...");
    orchestrator
        .fulfillIntent(event.intent_hash)
        .send()
        .await
        .expect("fulfill intent send")
        .get_receipt()
        .await
        .expect("fulfill intent receipt");

    // Check for IntentFulfilled events
    let current_block = provider.get_block_number().await.expect("get block");
    let fulfill_events = chain_client
        .get_intent_fulfilled_events(event.intent_hash, 0, current_block)
        .await
        .expect("get fulfill events");

    assert!(
        !fulfill_events.is_empty(),
        "Should have IntentFulfilled event"
    );
    let fulfill_event = &fulfill_events[0];
    println!("  IntentFulfilled event detected:");
    println!(
        "    funds_transferred_to: {:?}",
        fulfill_event.funds_transferred_to
    );
    println!("    amount: {}", fulfill_event.amount);

    println!("\n=== Full event-driven flow test passed! ===");
}

/// Test that the keeper correctly transitions state based on IntentSignaled events
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_keeper_detects_intent_signaled() {
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

    println!("\n=== Testing Keeper IntentSignaled Detection ===\n");

    // Create and process session manually to reach Zkp2pDeposited state
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "intenttest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create");
    let usdc_amount = session.expected_usdc.unwrap();
    infra.deliver_usdc_for(session.session_id, usdc_amount).await;
    infra.near_state.set_status("SUCCESS");

    // Fast-forward to UsdcReceived
    let mut s = state.get_session(session.id).await.unwrap().unwrap();
    s.received_usdc = Some(usdc_amount);
    s.set_status(zecp2p_types::OfframpStatus::UsdcReceived);
    state.update_session(&s).await.unwrap();

    // Process to Zkp2pDeposited
    let processed = state.process_offramp(session.id).await.expect("process");
    let deposit_id = processed.zkp2p_deposit_id.unwrap();
    println!("Session deposited to zk-p2p, deposit_id: {}", deposit_id);

    // Start keeper loop
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state
            .run_keeper_loop_with_shutdown(shutdown_rx)
            .await
    });

    // Signal intent on the deposit
    println!("Signaling intent...");
    let user_provider = infra.get_user_provider().await;
    let orchestrator = MockEscrowWithOrchestrator::new(infra.escrow_addr, &user_provider);

    orchestrator
        .signalIntent(
            deposit_id,
            TEST_USER.parse::<Address>().unwrap(),
            usdc_amount,
            venmo_payment_method(),
            usd_currency_code(),
            U256::from(1_000_000_000_000_000_000u128),
        )
        .send()
        .await
        .expect("signal")
        .get_receipt()
        .await
        .expect("receipt");

    // Wait for keeper to detect
    println!("Waiting for keeper to detect IntentSignaled...");
    let mut detected = false;
    for i in 0..10 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        println!(
            "  Check {}: Status = {:?}, intent_hash = {:?}",
            i + 1,
            current.status,
            current.zkp2p_intent_hash
        );

        if current.status == zecp2p_types::OfframpStatus::IntentSignaled {
            detected = true;
            println!("  ✓ Keeper detected IntentSignaled!");
            break;
        }
    }

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    assert!(detected, "Keeper should have detected IntentSignaled event");
    println!("\n=== Keeper IntentSignaled detection test passed! ===");
}

/// Test the complete flow from creation through fulfillment
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_keeper_detects_intent_fulfilled() {
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

    println!("\n=== Testing Keeper IntentFulfilled Detection ===\n");

    // Setup: Create, fund, process session
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "fulfilltest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create");
    let usdc_amount = session.expected_usdc.unwrap();
    infra.deliver_usdc_for(session.session_id, usdc_amount).await;
    infra.near_state.set_status("SUCCESS");

    let mut s = state.get_session(session.id).await.unwrap().unwrap();
    s.received_usdc = Some(usdc_amount);
    s.set_status(zecp2p_types::OfframpStatus::UsdcReceived);
    state.update_session(&s).await.unwrap();

    let processed = state.process_offramp(session.id).await.expect("process");
    let deposit_id = processed.zkp2p_deposit_id.unwrap();

    // Signal intent
    let user_provider = infra.get_user_provider().await;
    let orchestrator = MockEscrowWithOrchestrator::new(infra.escrow_addr, &user_provider);

    let _receipt = orchestrator
        .signalIntent(
            deposit_id,
            TEST_USER.parse::<Address>().unwrap(),
            usdc_amount,
            venmo_payment_method(),
            usd_currency_code(),
            U256::from(1_000_000_000_000_000_000u128),
        )
        .send()
        .await
        .expect("signal")
        .get_receipt()
        .await
        .expect("receipt");

    // Get intent hash from logs
    let chain_client2 = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create");
    let provider = infra.get_signing_provider().await;
    let block = provider.get_block_number().await.unwrap();
    let events = chain_client2
        .get_intent_signaled_events(deposit_id, 0, block)
        .await
        .unwrap();
    let intent_hash = events[0].intent_hash;

    // Manually update session to IntentSignaled (simulating keeper detection)
    let mut s = state.get_session(session.id).await.unwrap().unwrap();
    s.zkp2p_intent_hash = Some(intent_hash);
    s.set_status(zecp2p_types::OfframpStatus::IntentSignaled);
    state.update_session(&s).await.unwrap();
    println!("Session in IntentSignaled state, intent_hash: {:?}", intent_hash);

    // Start keeper loop
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state
            .run_keeper_loop_with_shutdown(shutdown_rx)
            .await
    });

    // Fulfill intent
    println!("Fulfilling intent...");
    orchestrator
        .fulfillIntent(intent_hash)
        .send()
        .await
        .expect("fulfill")
        .get_receipt()
        .await
        .expect("receipt");

    // Wait for keeper to detect
    println!("Waiting for keeper to detect IntentFulfilled...");
    let mut detected = false;
    for i in 0..10 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        println!("  Check {}: Status = {:?}", i + 1, current.status);

        if current.status == zecp2p_types::OfframpStatus::Fulfilled {
            detected = true;
            println!("  ✓ Keeper detected IntentFulfilled!");
            break;
        }
    }

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    assert!(detected, "Keeper should have detected IntentFulfilled event");
    println!("\n=== Keeper IntentFulfilled detection test passed! ===");
}

/// Comprehensive end-to-end test: Complete flow from session creation through fulfillment
/// driven ENTIRELY by the keeper loop - NO manual state updates.
///
/// This test exercises the full system behavior:
/// 1. Create offramp session via coordinator
/// 2. NEAR Intents mock returns quote, session enters NearIntentPending
/// 3. Simulate USDC delivery to GlueContract
/// 4. NEAR status API returns SUCCESS
/// 5. Keeper detects USDC arrival, transitions to UsdcReceived
/// 6. Keeper auto-processes offramp, transitions to Zkp2pDeposited
/// 7. Taker signals intent on zk-p2p
/// 8. Keeper detects IntentSignaled event, transitions to IntentSignaled
/// 9. Taker fulfills intent (simulating payment proof verification)
/// 10. Keeper detects IntentFulfilled event, transitions to Fulfilled
///
/// The only external actions are USDC minting and taker contract calls -
/// all state transitions are driven by the keeper's event monitoring.
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_complete_keeper_driven_flow() {
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

    println!("\n=== COMPREHENSIVE KEEPER-DRIVEN E2E TEST ===\n");
    println!("This test exercises the COMPLETE flow with NO manual state updates.");
    println!("All state transitions are driven by the keeper's event monitoring.\n");

    // Step 1: Create offramp session
    println!("Step 1: Creating offramp session...");
    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000, // 0.5 ZEC
        venmo_username: "completeflowtest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: Some(TEST_USER.parse().unwrap()),
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128), // 1.0 (18 decimals)
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    println!("  Session ID: {}", session.id);
    println!("  Initial status: {:?}", session.status);
    println!("  NEAR deposit address: {:?}", session.near_deposit_address);
    println!("  Expected USDC: {:?}", session.expected_usdc);
    assert_eq!(
        session.status,
        zecp2p_types::OfframpStatus::NearIntentPending
    );

    let usdc_amount = session.expected_usdc.unwrap();

    // Step 2: Start keeper loop in background
    println!("\nStep 2: Starting keeper loop in background...");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper_state
            .run_keeper_loop_with_shutdown(shutdown_rx)
            .await
    });

    // Step 3: Simulate USDC delivery from NEAR Intents
    println!("\nStep 3: Simulating USDC delivery from NEAR Intents...");
    infra.mint_usdc(infra.glue_addr, usdc_amount).await;
    println!("  Minted {} USDC to GlueContract", usdc_amount);

    // Step 4: Update NEAR status to SUCCESS
    println!("\nStep 4: Setting NEAR status to SUCCESS...");
    infra.near_state.set_status("SUCCESS");

    // Step 5: Wait for keeper to detect USDC arrival AND auto-process to Zkp2pDeposited
    println!("\nStep 5: Waiting for keeper to auto-process to Zkp2pDeposited...");
    let mut zkp2p_deposited = false;
    let mut deposit_id = U256::ZERO;
    for i in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        println!(
            "  Check {}: Status = {:?}, deposit_id = {:?}",
            i + 1,
            current.status,
            current.zkp2p_deposit_id
        );

        if current.status == zecp2p_types::OfframpStatus::Zkp2pDeposited {
            zkp2p_deposited = true;
            deposit_id = current.zkp2p_deposit_id.unwrap();
            println!("  ✓ Keeper auto-processed to Zkp2pDeposited!");
            println!("  zk-p2p deposit ID: {}", deposit_id);
            break;
        }
    }
    assert!(
        zkp2p_deposited,
        "Keeper should have auto-processed to Zkp2pDeposited"
    );

    // Step 6: Taker signals intent (this is an external action, not done by keeper)
    println!("\nStep 6: Taker signaling intent on zk-p2p...");
    let user_provider = infra.get_user_provider().await;
    let orchestrator = MockEscrowWithOrchestrator::new(infra.escrow_addr, &user_provider);

    let intent_receipt = orchestrator
        .signalIntent(
            deposit_id,
            TEST_USER.parse::<Address>().unwrap(),
            usdc_amount,
            venmo_payment_method(),
            usd_currency_code(),
            U256::from(1_000_000_000_000_000_000u128),
        )
        .send()
        .await
        .expect("signal intent")
        .get_receipt()
        .await
        .expect("receipt");
    println!("  Intent signaled, tx: {:?}", intent_receipt.transaction_hash);

    // Step 7: Wait for keeper to detect IntentSignaled
    println!("\nStep 7: Waiting for keeper to detect IntentSignaled event...");
    let mut intent_signaled = false;
    let mut intent_hash = alloy::primitives::B256::ZERO;
    for i in 0..15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        println!(
            "  Check {}: Status = {:?}, intent_hash = {:?}",
            i + 1,
            current.status,
            current.zkp2p_intent_hash
        );

        if current.status == zecp2p_types::OfframpStatus::IntentSignaled {
            intent_signaled = true;
            intent_hash = current.zkp2p_intent_hash.unwrap();
            println!("  ✓ Keeper detected IntentSignaled!");
            println!("  Intent hash: {:?}", intent_hash);
            break;
        }
    }
    assert!(
        intent_signaled,
        "Keeper should have detected IntentSignaled event"
    );

    // Step 8: Taker fulfills intent (external action - simulating payment proof verification)
    println!("\nStep 8: Taker fulfilling intent (simulating payment proof)...");
    orchestrator
        .fulfillIntent(intent_hash)
        .send()
        .await
        .expect("fulfill intent")
        .get_receipt()
        .await
        .expect("receipt");
    println!("  Intent fulfilled");

    // Step 9: Wait for keeper to detect IntentFulfilled
    println!("\nStep 9: Waiting for keeper to detect IntentFulfilled event...");
    let mut fulfilled = false;
    for i in 0..15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        println!("  Check {}: Status = {:?}", i + 1, current.status);

        if current.status == zecp2p_types::OfframpStatus::Fulfilled {
            fulfilled = true;
            println!("  ✓ Keeper detected IntentFulfilled!");
            println!("  Session is now FULFILLED - offramp complete!");
            break;
        }
    }

    // Shutdown keeper
    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    assert!(fulfilled, "Keeper should have detected IntentFulfilled event");

    // Final verification
    let final_session = state.get_session(session.id).await.unwrap().unwrap();
    println!("\n=== FINAL SESSION STATE ===");
    println!("  ID: {}", final_session.id);
    println!("  Status: {:?}", final_session.status);
    println!("  NEAR deposit address: {:?}", final_session.near_deposit_address);
    println!("  Expected USDC: {:?}", final_session.expected_usdc);
    println!("  Received USDC: {:?}", final_session.received_usdc);
    println!("  zk-p2p deposit ID: {:?}", final_session.zkp2p_deposit_id);
    println!("  zk-p2p intent hash: {:?}", final_session.zkp2p_intent_hash);

    assert_eq!(final_session.status, zecp2p_types::OfframpStatus::Fulfilled);
    assert!(final_session.zkp2p_deposit_id.is_some());
    assert!(final_session.zkp2p_intent_hash.is_some());

    println!("\n=== COMPREHENSIVE KEEPER-DRIVEN E2E TEST PASSED! ===");
    println!("The complete offramp flow (ZEC → USDC → Venmo) was executed");
    println!("with ALL state transitions driven by the keeper loop.");
}

/// NEW-1 end to end, against a real deployment on anvil.
///
/// A swap that settles below its quote is the ordinary case: `create_offramp`
/// asks for the quote with 50 bps of slippage, so 1Click guarantees only
/// `minAmountOut` and the fill lands somewhere in that band. The keeper used to
/// credit `min(unassigned, expected)`, which topped the session up to its full
/// quote out of whatever else was in the pot.
///
/// Here the swap settles a dollar under, and more than that arrives on the glue,
/// standing in for a concurrent session's money sitting in the same pot. The
/// session must be credited what its own swap settled for, and the surplus must
/// still be unassigned afterwards, where it is available to whoever it belongs
/// to. Under the old rule it would have been swept into this session's slice.
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_a_short_settlement_credits_the_fill_and_leaves_the_rest_unassigned() {
    let infra = TestInfra::setup().await;
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let db = zecp2p_coordinator::db::Database::new(&infra.config.database.path)
        .await
        .expect("create db");
    db.run_migrations().await.expect("run migrations");

    let chain_client = zecp2p_coordinator::chain::ChainClient::new(&infra.config)
        .await
        .expect("create chain client");

    let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
        infra.config.clone(),
        db,
        chain_client,
        zecp2p_coordinator::near::NearIntentsClient::new(&infra.config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&infra.config.zkp2p),
    ));

    let request = zecp2p_types::OfframpRequest {
        zec_amount: 50_000_000,
        venmo_username: "shortfilltest".to_string(),
        user_address: TEST_USER.parse().unwrap(),
        taker_address: None,
        zec_refund_address: "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        timeout_seconds: 600,
    };

    let session = state.create_offramp(request).await.expect("create offramp");
    let expected = session.expected_usdc.expect("quoted");
    let floor = session.min_output_usdc.expect("floor");

    // The swap fills short of the quote but inside the guaranteed band, halfway
    // between the floor and the quote. That band is what the slippage on the
    // quote buys, and landing in it is the ordinary outcome, not an edge case.
    let settled = floor + (expected - floor) / U256::from(2u64);
    assert!(settled > floor && settled < expected, "an under-fill inside the band");
    infra.near_state.set_settled_amount(&settled.to_string());

    // The full quote's worth of USDC lands on the glue: this session's own
    // short fill, plus another session's money in the same shared pot.
    infra.mint_usdc(infra.glue_addr, expected).await;
    let surplus = expected - settled;

    infra.near_state.set_status("SUCCESS");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper_state = state.clone();
    let keeper = tokio::spawn(async move {
        keeper_state.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    let mut credited = None;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let current = state.get_session(session.id).await.unwrap().unwrap();
        if current.received_usdc.is_some() {
            credited = current.received_usdc;
            break;
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = keeper.await;

    let credited = credited.expect("an under-fill above the floor must still be credited");
    assert_eq!(
        credited, settled,
        "the session gets what its own swap settled for, not what the pot held"
    );
    assert!(
        credited < expected,
        "crediting the quote is the bug: {credited} should be under {expected}"
    );

    // The rest is still nobody's, so it is there for the session it arrived for.
    // The old rule would have folded it into this session's slice.
    let unassigned = state
        .chain
        .glue_unassigned_balance()
        .await
        .expect("read unassigned balance");
    assert_eq!(
        unassigned, surplus,
        "the surplus must stay unassigned rather than being swept into this session"
    );

    // And the contract agrees about what this session owns.
    let on_chain = state
        .chain
        .get_session(session.session_id)
        .await
        .expect("read session");
    assert!(
        on_chain.credited == settled || on_chain.deposited == settled,
        "the contract should hold {settled}, has credited={} deposited={}",
        on_chain.credited,
        on_chain.deposited
    );
}
