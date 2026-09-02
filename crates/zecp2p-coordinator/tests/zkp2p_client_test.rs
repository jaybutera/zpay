//! Tests for the zk-p2p curator client against a mock curator.
//!
//! No anvil or network access needed.

mod test_utils;

use test_utils::MockZkp2pServer;
use zecp2p_coordinator::zkp2p::{parse_payee_hash, Zkp2pClient};
use zecp2p_types::config::Zkp2pConfig;

fn client_for(server: &MockZkp2pServer) -> Zkp2pClient {
    Zkp2pClient::new(&Zkp2pConfig {
        // Trailing slash must be tolerated
        api_url: format!("{}/", server.api_url()),
        ..Default::default()
    })
}

#[tokio::test]
async fn register_returns_curator_hash_not_local_keccak() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);

    let hash = client.register_venmo_payee("Alice-Smith").await.expect("register");

    assert_eq!(hash, MockZkp2pServer::expected_hash("Alice-Smith"));
    assert_ne!(
        hash,
        alloy::primitives::keccak256(b"Alice-Smith"),
        "hash must not be keccak256(username)"
    );
    assert_eq!(server.registered(), vec!["Alice-Smith".to_string()]);
}

#[tokio::test]
async fn register_strips_leading_at_and_keeps_casing() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);

    let hash = client.register_venmo_payee("@Alice-Smith").await.expect("register");

    assert_eq!(hash, MockZkp2pServer::expected_hash("Alice-Smith"));
    assert_eq!(server.registered(), vec!["Alice-Smith".to_string()]);
}

#[tokio::test]
async fn validate_reports_curator_verdict() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);

    assert!(client.validate_venmo_payee("alice").await.expect("validate"));

    server.set_reject(true);
    assert!(!client.validate_venmo_payee("alice").await.expect("validate"));

    // Empty usernames never reach the network
    assert!(!client.validate_venmo_payee("  @ ").await.expect("validate"));
}

#[tokio::test]
async fn register_fails_when_curator_rejects() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);
    server.set_reject(true);

    let err = client.register_venmo_payee("alice").await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("400"), "error should carry the HTTP status: {msg}");
    assert!(msg.contains("Invalid maker data"), "error should carry the curator message: {msg}");
    assert!(server.registered().is_empty());
}

#[tokio::test]
async fn register_fails_on_malformed_hash() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);
    server.set_malformed_hash(true);

    let err = client.register_venmo_payee("alice").await.unwrap_err();
    assert!(
        err.to_string().contains("malformed hashedOnchainId"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn register_fails_on_server_error() {
    let server = MockZkp2pServer::start().await;
    let client = client_for(&server);
    server.set_server_error(true);

    assert!(client.register_venmo_payee("alice").await.is_err());
    assert!(client.validate_venmo_payee("alice").await.is_err());
}

#[tokio::test]
async fn register_fails_when_curator_is_unreachable() {
    let client = Zkp2pClient::new(&Zkp2pConfig {
        api_url: "http://127.0.0.1:1".to_string(),
        ..Default::default()
    });
    assert!(client.register_venmo_payee("alice").await.is_err());
}

#[test]
fn parse_payee_hash_matches_onchain_format() {
    // A real Venmo payeeDetails from an EscrowV2 deposit on Base
    let onchain = "0x24968a0c92cfc5a596bd27420340cfc9b35a36d2cda8ca82b6beed0f9bb1c51a";
    let parsed = parse_payee_hash(onchain).expect("parse");
    assert_eq!(format!("{:?}", parsed), onchain);
}
