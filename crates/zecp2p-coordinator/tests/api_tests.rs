//! API integration tests for the coordinator
//!
//! These tests verify the REST API endpoints work correctly.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceExt;
use zecp2p_coordinator::{
    api, auth, chain::ChainClient, db::Database, near::NearIntentsClient, state::AppState,
    zkp2p::Zkp2pClient,
};
use zecp2p_types::Config;


/// A fixed test key, and the address the request bodies below name as the user.
///
/// `POST /offramp` now requires the caller to prove it holds the key for the
/// address it names, so every body that reaches validation has to be signed.
fn test_signer() -> alloy::signers::local::PrivateKeySigner {
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        .parse()
        .expect("valid test key")
}

fn test_user_address() -> String {
    format!("{:?}", test_signer().address())
}

/// The `x-zecp2p-signature` header for a create request over this body.
fn create_signature(zec_amount: &str, venmo_username: &str) -> String {
    use alloy::signers::SignerSync;
    let signer = test_signer();
    let scope = format!("{}:{}", zec_amount.trim(), venmo_username.trim());
    let message = auth::ownership_message("create", signer.address(), &scope);
    signer
        .sign_message_sync(message.as_bytes())
        .expect("sign")
        .to_string()
}

/// Create a test configuration
fn test_config() -> Config {
    // Use testnet configuration for tests
    Config {
        network: zecp2p_types::config::NetworkConfig {
            base_rpc_url: "https://sepolia.base.org".to_string(),
            base_sepolia_rpc_url: Some("https://sepolia.base.org".to_string()),
            chain_id: 84532, // Base Sepolia
        },
        contracts: zecp2p_types::config::ContractConfig {
            usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .unwrap(),
            zkp2p_escrow: "0x6a5e11c3D87e22b828d02ee65a4e8f322BF6B97E"
                .parse()
                .unwrap(),
            zkp2p_orchestrator: "0x7D563c65456deF11c1Fdb9510eB745D5a780F5Fd"
                .parse()
                .unwrap(),
            stake_vault: zecp2p_types::config::DEFAULT_STAKE_VAULT.parse().unwrap(),
            glue_contract: None,
        },
        near: zecp2p_types::config::NearConfig {
            api_url: "https://1click.chaindefuser.com".to_string(),
            default_timeout: 600,
        },
        zkp2p: zecp2p_types::config::Zkp2pConfig::default(),
        keeper: zecp2p_types::config::KeeperConfig::default(),
        fee: zecp2p_types::config::FeeConfig::default(),
        attestation: zecp2p_types::config::AttestationConfig::default(),
        server: zecp2p_types::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            ..Default::default()
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: ":memory:".to_string(),
        },
    }
}

/// Create a test app with in-memory database
async fn create_test_app() -> Router {
    build_test_app(test_config()).await
}

/// The same app, with a taker token configured, for the `/deposits/open` tests.
async fn create_test_app_with_taker_token(token: &str) -> Router {
    let mut config = test_config();
    config.server.taker_token = Some(token.to_string());
    build_test_app(config).await
}

async fn build_test_app(config: Config) -> Router {
    let db = Database::new(":memory:").await.expect("Failed to create test database");
    db.run_migrations().await.expect("Failed to run migrations");

    // Use a mock chain client that doesn't require real credentials
    let chain_client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    let near_client = NearIntentsClient::new(&config.near);
    let zkp2p_client = Zkp2pClient::new(&config.zkp2p);

    let state = Arc::new(AppState::new(config, db, chain_client, near_client, zkp2p_client));

    Router::new()
        .route("/health", get(api::health))
        .route("/quote", get(api::get_quote))
        .route("/offramp", post(api::create_offramp))
        .route("/offramp/{id}", get(api::get_offramp))
        .route("/offramp/{id}/process", post(api::process_offramp))
        .route("/deposits/open", get(api::list_open_deposits))
        .route("/offramp/{id}/rescue", post(api::rescue_offramp))
        .route("/offramp/{id}/withdraw", post(api::withdraw_offramp))
        .with_state(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_test_app().await;

    let response = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "zecp2p-coordinator");
}

#[tokio::test]
async fn test_get_offramp_not_found() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/offramp/00000000-0000-0000-0000-000000000000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_get_offramp_invalid_id() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/offramp/not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].as_str().unwrap().contains("Invalid session ID"));
}

#[tokio::test]
async fn test_quote_requires_zec_amount() {
    let app = create_test_app().await;

    // Missing zec_amount parameter
    let response = app
        .oneshot(Request::builder().uri("/quote").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Axum returns 400 for missing required query params
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_offramp_requires_body() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Empty body should fail
    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn test_create_offramp_validates_addresses() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": "not-an-address",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Invalid user address"));
}

#[tokio::test]
async fn test_create_offramp_validates_zec_amount() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "not-a-number",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Invalid ZEC amount"));
}

#[tokio::test]
async fn test_process_offramp_session_not_found() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp/00000000-0000-0000-0000-000000000000/process")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_offramp_validates_zec_address() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": test_user_address(),
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "invalid_address"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .header(auth::SIGNATURE_HEADER, create_signature("0.5", "testuser"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // The API boundary now delegates to the one authoritative validator in
    // near.rs, which phrases this as "not a Zcash transparent address".
    let message = json["error"].as_str().unwrap();
    assert!(
        message.contains("refund address"),
        "expected a refund-address rejection, got: {message}"
    );
}

#[tokio::test]
async fn test_create_offramp_requires_zec_address() {
    let app = create_test_app().await;

    // Missing zec_refund_address should fail JSON parsing
    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890"
        // zec_refund_address is missing
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Missing required field should fail (JSON deserialization error)
    assert!(response.status().is_client_error());
}

#[tokio::test]
async fn test_create_offramp_validates_venmo_username_too_short() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "x",  // Too short
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("too short"));
}

#[tokio::test]
async fn test_create_offramp_validates_venmo_username_invalid_chars() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "test@user!",  // Invalid characters
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("invalid characters"));
}

#[tokio::test]
async fn test_create_offramp_validates_zec_amount_zero() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("greater than 0"));
}

#[tokio::test]
async fn test_create_offramp_validates_zec_address_length() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": test_user_address(),
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1TooShort"  // Valid prefix but wrong length
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .header(auth::SIGNATURE_HEADER, create_signature("0.5", "testuser"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("length"));
}

#[tokio::test]
async fn test_create_offramp_validates_min_rate_negative() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": test_user_address(),
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA",
        "min_rate": "-10"  // Negative rate
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .header(auth::SIGNATURE_HEADER, create_signature("0.5", "testuser"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // A sign is not a digit, so "-10" is refused as malformed rather than as a
    // non-positive number; either way it never becomes a rate.
    let message = json["error"].as_str().unwrap();
    assert!(
        message.contains("min_rate"),
        "expected a min_rate rejection, got: {message}"
    );
}

/// An offramp with no taker is the normal case now: zk-p2p deposits are open to
/// any staked taker, so the request must not be rejected for omitting one.
#[tokio::test]
async fn test_create_offramp_accepts_a_request_with_no_taker() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // This test app has no chain and no curator behind it, so the request
    // cannot succeed either way. What matters is why it fails: it must get past
    // address validation and die on the curator, not complain about the taker.
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("taker"),
        "a missing taker must not be an error, got: {text}"
    );
}

/// A malformed taker address is still an error when one is supplied.
#[tokio::test]
async fn test_create_offramp_still_rejects_a_bad_taker() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "not-an-address",
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ================================================================
// Regression tests for the 2026-08-31 audit findings on the API surface.
// ================================================================

/// CRITICAL-2, the entry point. `POST /offramp` took a caller-supplied
/// `user_address` with no authentication at all, so an attacker could open a
/// session naming a victim, and separately could loop the endpoint to drain the
/// keeper's gas for free (HIGH-4).
#[tokio::test]
async fn creating_an_offramp_without_a_signature_is_refused() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": test_user_address(),
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// CRITICAL-2, the naming-a-victim shape: the attacker holds their own key but
/// puts the victim's address in the body.
#[tokio::test]
async fn opening_a_session_that_names_someone_elses_address_is_refused() {
    use alloy::signers::SignerSync;

    let app = create_test_app().await;

    let attacker = alloy::signers::local::PrivateKeySigner::random();
    let victim = test_signer().address();

    // The attacker signs the message naming the victim, with the attacker's key.
    let scope = format!("{}:{}", "0.5", "testuser");
    let message = auth::ownership_message("create", victim, &scope);
    let signature = attacker.sign_message_sync(message.as_bytes()).unwrap();

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": format!("{victim:?}"),
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                .header(auth::SIGNATURE_HEADER, signature.to_string())
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A signature for one offramp must not open a different one.
#[tokio::test]
async fn a_create_signature_does_not_transfer_to_another_amount() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "5.0",
        "venmo_username": "testuser",
        "user_address": test_user_address(),
        "zec_refund_address": "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/offramp")
                .header("Content-Type", "application/json")
                // Signed for 0.5 ZEC, sent for 5.0.
                .header(auth::SIGNATURE_HEADER, create_signature("0.5", "testuser"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// HIGH-3. `/deposits/open` published every user's Venmo handle, amount and
/// timestamp to anyone who asked. It now needs the taker token.
#[tokio::test]
async fn the_deposit_listing_needs_a_token() {
    let app = create_test_app_with_taker_token("s3cret").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/deposits/open")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "no token must not list handles"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/deposits/open")
                .header("Authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token too");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/deposits/open")
                .header("Authorization", "Bearer s3cret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "the right token works");
}

/// Rescue moves the session's money, so it takes the session owner's signature.
#[tokio::test]
async fn rescue_without_a_signature_is_refused() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/offramp/{}/rescue", uuid::Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // No session exists, so a missing signature must not be reported as "not
    // found" in a way that lets an attacker enumerate; either way it is refused.
    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::NOT_FOUND,
        "unexpected status {}",
        response.status()
    );
}
