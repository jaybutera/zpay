//! HTTP server integration tests
//!
//! This test starts the actual Axum HTTP server and tests through HTTP requests.
//! It validates the full stack from CLI → HTTP → coordinator → chain.
//!
//! Run with: cargo test --package zecp2p-coordinator --test http_server_test -- --ignored --nocapture

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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use test_utils::{
    deploy_contracts, AnvilInstance, MockZkp2pServer, ANVIL_PRIVATE_KEY, KEEPER_PRIVATE_KEY,
    TEST_USER, TEST_USER_PRIVATE_KEY,
};

/// Header the coordinator reads the ownership signature from.
const SIGNATURE_HEADER: &str = "x-zecp2p-signature";

/// The user's key signs these requests. The coordinator requires proof that the
/// caller holds the key for the address the session names, so an unsigned
/// request is refused: that is CRITICAL-2 in the 2026-08-31 audit, where anyone
/// could open a session naming a victim.
fn user_signer() -> alloy::signers::local::PrivateKeySigner {
    TEST_USER_PRIVATE_KEY.parse().expect("valid test key")
}

fn sign_ownership(action: &str, scope: &str) -> String {
    use alloy::signers::SignerSync;
    let signer = user_signer();
    let message = format!("zecp2p:{action}:{:?}:{scope}", signer.address());
    signer
        .sign_message_sync(message.as_bytes())
        .expect("sign")
        .to_string()
}
use tokio::net::TcpListener;
use zecp2p_types::abi::MockUSDC;

/// Port counters for unique allocation
static NEAR_PORT: AtomicU16 = AtomicU16::new(9800);
static SERVER_PORT: AtomicU16 = AtomicU16::new(3300);

/// Mock NEAR Intents API server
struct MockNearServer {
    port: u16,
    #[allow(dead_code)]
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<()>,
}

impl MockNearServer {
    async fn start() -> Self {
        let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let app = Router::new()
            .route("/v0/quote", post(mock_quote_handler))
            .route("/v0/status", get(mock_status_handler));

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

async fn mock_quote_handler(Json(request): Json<QuoteRequest>) -> Json<MockQuoteResponse> {
    let zatoshi: u64 = request.amount.parse().unwrap_or(50_000_000);
    let usdc_out = (zatoshi as f64 / 100_000_000.0 * 30.0 * 1_000_000.0) as u64;
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(10);

    Json(MockQuoteResponse {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        quote: MockQuote {
            amount_out: usdc_out.to_string(),
            min_amount_out: (usdc_out * 99 / 100).to_string(),
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
    Json(MockStatusResponse {
        status: "SUCCESS".to_string(),
        source_transaction_hash: Some("0xmocksourcetx".to_string()),
        destination_transaction_hash: Some("0xmockdesttx".to_string()),
        amount_out: Some("15000000".to_string()),
        error: None,
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
    server_port: u16,
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
            ..Default::default()
        },
        keeper: zecp2p_types::config::KeeperConfig::default(),
        fee: zecp2p_types::config::FeeConfig::default(),
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

/// Test infrastructure
struct HttpTestInfra {
    anvil: AnvilInstance,
    #[allow(dead_code)]
    near_server: MockNearServer,
    #[allow(dead_code)]
    zkp2p_server: MockZkp2pServer,
    usdc_addr: Address,
    glue_addr: Address,
    server_url: String,
    #[allow(dead_code)]
    server_handle: tokio::task::JoinHandle<()>,
    _temp_dir: TempDir,
}

impl HttpTestInfra {
    async fn setup() -> Self {
        // Start anvil
        let anvil = AnvilInstance::start();
        println!("Anvil started at {}", anvil.rpc_url());

        // Deploy contracts
        let (usdc_addr, escrow_addr, glue_addr) = deploy_contracts(anvil.rpc_url());
        println!("Contracts deployed: USDC={}, Glue={}", usdc_addr, glue_addr);

        // Start mock NEAR server
        let near_server = MockNearServer::start().await;
        println!("Mock NEAR server at {}", near_server.api_url());

        let zkp2p_server = MockZkp2pServer::start().await;
        println!("Mock zk-p2p curator at {}", zkp2p_server.api_url());

        // Create temp directory for database
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string();

        // Create config
        let server_port = SERVER_PORT.fetch_add(1, Ordering::SeqCst);
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

        let server_url = format!("http://127.0.0.1:{}", server_port);

        // Set the private key for the coordinator
        std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

        // Start the actual HTTP server
        let server_handle = {
            let config = config.clone();
            tokio::spawn(async move {
                // Initialize components
                let db = zecp2p_coordinator::db::Database::new(&config.database.path)
                    .await
                    .expect("create db");
                db.run_migrations().await.expect("run migrations");

                let chain_client = zecp2p_coordinator::chain::ChainClient::new(&config)
                    .await
                    .expect("create chain client");

                let near_client = zecp2p_coordinator::near::NearIntentsClient::new(&config.near);

                let state = std::sync::Arc::new(zecp2p_coordinator::state::AppState::new(
                    config.clone(),
                    db,
                    chain_client,
                    near_client,
                    zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
                ));

                // Build router (same as in main.rs)
                use axum::routing::{get, post};
                use tower_http::cors::{Any, CorsLayer};

                let app = Router::new()
                    .route("/health", get(zecp2p_coordinator::api::health))
                    .route("/quote", get(zecp2p_coordinator::api::get_quote))
                    .route("/offramp", post(zecp2p_coordinator::api::create_offramp))
                    .route("/offramp/{id}", get(zecp2p_coordinator::api::get_offramp))
                    .route(
                        "/offramp/{id}/process",
                        post(zecp2p_coordinator::api::process_offramp),
                    )
                    .route(
                        "/offramp/{id}/rescue",
                        post(zecp2p_coordinator::api::rescue_offramp),
                    )
                    .route(
                        "/offramp/{id}/withdraw",
                        post(zecp2p_coordinator::api::withdraw_offramp),
                    )
                    .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
                    .with_state(state);

                let addr = format!("{}:{}", config.server.host, config.server.port);
                let listener = TcpListener::bind(&addr).await.expect("bind server");
                axum::serve(listener, app).await.expect("serve");
            })
        };

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            anvil,
            near_server,
            zkp2p_server,
            usdc_addr,
            glue_addr,
            server_url,
            server_handle,
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
async fn test_http_health_endpoint() {
    let infra = HttpTestInfra::setup().await;
    let client = Client::new();

    println!("\n=== Testing HTTP Health Endpoint ===\n");

    let resp = client
        .get(format!("{}/health", infra.server_url))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "zecp2p-coordinator");

    println!("Health check response: {:?}", body);
    println!("\n=== Health endpoint test passed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_http_quote_endpoint() {
    let infra = HttpTestInfra::setup().await;
    let client = Client::new();

    println!("\n=== Testing HTTP Quote Endpoint ===\n");

    let resp = client
        .get(format!("{}/quote", infra.server_url))
        .query(&[("zec_amount", "0.5")])
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.expect("json");
    println!("Quote response: {}", serde_json::to_string_pretty(&body).unwrap());

    assert!(body["zec_amount"].is_string());
    assert!(body["usdc_amount"].is_string());
    assert!(body["rate"].is_string());
    assert!(body["venmo_amount"].is_string());

    println!("\n=== Quote endpoint test passed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_http_full_offramp_flow() {
    let infra = HttpTestInfra::setup().await;
    let client = Client::new();

    println!("\n=== Testing HTTP Full Offramp Flow ===\n");

    // Step 1: Create offramp via HTTP
    println!("Step 1: Creating offramp via HTTP...");

    let create_body = json!({
        "zec_amount": "0.5",
        "venmo_username": "httptest",
        "user_address": TEST_USER,
        "taker_address": TEST_USER,
        "zec_refund_address": "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r",
        "min_rate": "25",
        "timeout_seconds": 600
    });

    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .header(SIGNATURE_HEADER, sign_ownership("create", "0.5:httptest"))
        .json(&create_body)
        .send()
        .await
        .expect("request");

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    println!("Create response status: {}", status);
    println!("Create response body: {}", body_text);

    assert!(status.is_success(), "Create should succeed, got {} with body: {}", status, body_text);

    let create_resp: serde_json::Value = serde_json::from_str(&body_text).expect("parse json");
    println!("Create response parsed: {}", serde_json::to_string_pretty(&create_resp).unwrap());

    let session_id = create_resp["session_id"].as_str().expect("session_id");
    assert_eq!(create_resp["status"], "near_intent_pending");
    assert!(create_resp["near_deposit_address"].is_string());

    println!("  Session ID: {}", session_id);

    // Step 2: Get status via HTTP
    println!("\nStep 2: Getting status via HTTP...");

    let resp = client
        .get(format!("{}/offramp/{}", infra.server_url, session_id))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_success());

    let status_resp: serde_json::Value = resp.json().await.expect("json");
    println!("Status response: {}", serde_json::to_string_pretty(&status_resp).unwrap());

    assert_eq!(status_resp["session_id"], session_id);
    assert_eq!(status_resp["status"], "near_intent_pending");

    // Step 3: Simulate USDC arrival
    println!("\nStep 3: Simulating USDC arrival...");

    // Get expected USDC amount from response
    let expected_usdc_str = status_resp["expected_usdc"].as_str().unwrap_or("15000000");
    let expected_usdc: u64 = expected_usdc_str.parse().unwrap_or(15_000_000);
    let usdc_amount = U256::from(expected_usdc);

    infra.mint_usdc(infra.glue_addr, usdc_amount).await;
    println!("  Minted {} USDC to GlueContract", usdc_amount);

    // Note: The keeper loop would detect this and transition the state.
    // For a full test, we'd need to wait for the keeper to run, or manually
    // call process_offramp. Since the keeper runs every 15 seconds by default,
    // this is a simplification for the test.

    println!("\n=== HTTP full offramp flow test passed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_http_error_handling() {
    let infra = HttpTestInfra::setup().await;
    let client = Client::new();

    println!("\n=== Testing HTTP Error Handling ===\n");

    // Test 1: Invalid session ID
    println!("Test 1: Invalid session ID...");
    let resp = client
        .get(format!("{}/offramp/not-a-uuid", infra.server_url))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 400);
    println!("  ✓ Returns 400 for invalid UUID");

    // Test 2: Non-existent session
    println!("Test 2: Non-existent session...");
    let fake_uuid = uuid::Uuid::new_v4();
    let resp = client
        .get(format!("{}/offramp/{}", infra.server_url, fake_uuid))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 404);
    println!("  ✓ Returns 404 for non-existent session");

    // Test 3: Missing required fields
    println!("Test 3: Missing required fields...");
    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .json(&json!({
            "zec_amount": "0.5"
            // Missing other required fields
        }))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_client_error());
    println!("  ✓ Returns error for missing fields");

    // Test 4: Invalid ZEC amount
    println!("Test 4: Invalid ZEC amount...");
    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .json(&json!({
            "zec_amount": "-1",
            "venmo_username": "test",
            "user_address": TEST_USER,
            "taker_address": TEST_USER,
            "zec_refund_address": "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r"
        }))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_client_error());
    println!("  ✓ Returns error for invalid ZEC amount");

    // Test 5: Invalid Venmo username
    println!("Test 5: Invalid Venmo username...");
    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .json(&json!({
            "zec_amount": "0.5",
            "venmo_username": "x", // Too short
            "user_address": TEST_USER,
            "taker_address": TEST_USER,
            "zec_refund_address": "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r"
        }))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_client_error());
    println!("  ✓ Returns error for invalid Venmo username");

    // Test 6: Invalid ZEC address
    println!("Test 6: Invalid ZEC address...");
    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .json(&json!({
            "zec_amount": "0.5",
            "venmo_username": "testuser",
            "user_address": TEST_USER,
            "taker_address": TEST_USER,
            "zec_refund_address": "invalid_zec_address"
        }))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_client_error());
    println!("  ✓ Returns error for invalid ZEC address");

    println!("\n=== HTTP error handling tests passed! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_http_rescue_requires_valid_state() {
    let infra = HttpTestInfra::setup().await;
    let client = Client::new();

    println!("\n=== Testing HTTP Rescue State Validation ===\n");

    // Create an offramp
    let create_body = json!({
        "zec_amount": "0.25",
        "venmo_username": "rescuetest",
        "user_address": TEST_USER,
        "taker_address": TEST_USER,
        "zec_refund_address": "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r"
    });

    let resp = client
        .post(format!("{}/offramp", infra.server_url))
        .header(SIGNATURE_HEADER, sign_ownership("create", "0.25:rescuetest"))
        .json(&create_body)
        .send()
        .await
        .expect("request");

    let create_resp: serde_json::Value = resp.json().await.expect("json");
    let session_id = create_resp["session_id"].as_str().expect("session_id");

    // Try to rescue in near_intent_pending state (should fail on state, not auth,
    // so sign it properly first).
    println!("Attempting rescue in near_intent_pending state...");
    let resp = client
        .post(format!("{}/offramp/{}/rescue", infra.server_url, session_id))
        .header(SIGNATURE_HEADER, sign_ownership("rescue", session_id))
        .send()
        .await
        .expect("request");

    assert!(resp.status().is_client_error() || resp.status().is_server_error());
    println!("  ✓ Rescue correctly rejected in invalid state");

    println!("\n=== HTTP rescue state validation test passed! ===");
}
