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
use zecp2p_coordinator::{api, chain::ChainClient, db::Database, near::NearIntentsClient, state::AppState};
use zecp2p_types::Config;

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
            glue_contract: None,
        },
        near: zecp2p_types::config::NearConfig {
            api_url: "https://1click.chaindefuser.com".to_string(),
            default_timeout: 600,
        },
        server: zecp2p_types::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
        },
        database: zecp2p_types::config::DatabaseConfig {
            path: ":memory:".to_string(),
        },
    }
}

/// Create a test app with in-memory database
async fn create_test_app() -> Router {
    let config = test_config();
    let db = Database::new(":memory:").await.expect("Failed to create test database");
    db.run_migrations().await.expect("Failed to run migrations");

    // Use a mock chain client that doesn't require real credentials
    let chain_client = ChainClient::new_readonly(&config)
        .await
        .expect("Failed to create chain client");

    let near_client = NearIntentsClient::new(&config.near);

    let state = Arc::new(AppState::new(config, db, chain_client, near_client));

    Router::new()
        .route("/health", get(api::health))
        .route("/quote", get(api::get_quote))
        .route("/offramp", post(api::create_offramp))
        .route("/offramp/{id}", get(api::get_offramp))
        .route("/offramp/{id}/process", post(api::process_offramp))
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
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "invalid_address"
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
        .contains("Invalid ZEC refund address"));
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
        "user_address": "0x1234567890123456789012345678901234567890",
        "taker_address": "0x1234567890123456789012345678901234567890",
        "zec_refund_address": "t1TooShort"  // Valid prefix but wrong length
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
    assert!(json["error"].as_str().unwrap().contains("length"));
}

#[tokio::test]
async fn test_create_offramp_validates_min_rate_negative() {
    let app = create_test_app().await;

    let body = serde_json::json!({
        "zec_amount": "0.5",
        "venmo_username": "testuser",
        "user_address": "0x1234567890123456789012345678901234567890",
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
    assert!(json["error"].as_str().unwrap().contains("positive"));
}
