//! Database integration tests

use alloy::primitives::{Address, U256};
use tempfile::TempDir;
use zecp2p_coordinator::db::Database;
use zecp2p_types::{OfframpRequest, OfframpSession, OfframpStatus};

async fn setup_db() -> (Database, TempDir) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let db = Database::new(db_path.to_str().unwrap()).await.unwrap();
    db.run_migrations().await.unwrap();
    (db, tmp)
}

fn create_test_request() -> OfframpRequest {
    OfframpRequest {
        zec_amount: 100_000_000, // 1 ZEC
        venmo_username: "testuser".to_string(),
        user_address: Address::ZERO,
        taker_address: Address::ZERO,
        zec_refund_address: "t1TestZcashAddress123".to_string(),
        min_rate: U256::from(30_000000_000000_000000u128), // 30 USDC/ZEC
        timeout_seconds: 600,
    }
}

#[tokio::test]
async fn test_insert_and_get_session() {
    let (db, _tmp) = setup_db().await;

    let request = create_test_request();
    let session = OfframpSession::new(request);

    db.insert_session(&session).await.unwrap();

    let retrieved = db.get_session(session.id).await.unwrap();
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, session.id);
    assert_eq!(retrieved.status, OfframpStatus::Created);
    assert_eq!(retrieved.request.zec_amount, 100_000_000);
    assert_eq!(retrieved.request.venmo_username, "testuser");
}

#[tokio::test]
async fn test_update_session() {
    let (db, _tmp) = setup_db().await;

    let request = create_test_request();
    let mut session = OfframpSession::new(request);

    db.insert_session(&session).await.unwrap();

    // Update status
    session.set_status(OfframpStatus::NearIntentPending);
    session.near_deposit_address = Some("zcash_addr_123".to_string());

    db.update_session(&session).await.unwrap();

    let retrieved = db.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(retrieved.status, OfframpStatus::NearIntentPending);
    assert_eq!(
        retrieved.near_deposit_address,
        Some("zcash_addr_123".to_string())
    );
}

#[tokio::test]
async fn test_get_active_sessions() {
    let (db, _tmp) = setup_db().await;

    // Insert multiple sessions in various states
    let mut s1 = OfframpSession::new(create_test_request());
    s1.set_status(OfframpStatus::NearIntentPending);
    db.insert_session(&s1).await.unwrap();

    let mut s2 = OfframpSession::new(create_test_request());
    s2.set_status(OfframpStatus::Fulfilled);
    db.insert_session(&s2).await.unwrap();

    let mut s3 = OfframpSession::new(create_test_request());
    s3.set_status(OfframpStatus::Zkp2pDeposited);
    db.insert_session(&s3).await.unwrap();

    let active = db.get_active_sessions().await.unwrap();

    // Should only return s1 and s3 (not s2 which is fulfilled)
    assert_eq!(active.len(), 2);

    let ids: Vec<_> = active.iter().map(|s| s.id).collect();
    assert!(ids.contains(&s1.id));
    assert!(!ids.contains(&s2.id));
    assert!(ids.contains(&s3.id));
}

#[tokio::test]
async fn test_kv_store() {
    let (db, _tmp) = setup_db().await;

    // Key doesn't exist yet
    let val = db.get_kv("test_key").await.unwrap();
    assert!(val.is_none());

    // Set a value
    db.set_kv("test_key", "test_value").await.unwrap();
    let val = db.get_kv("test_key").await.unwrap();
    assert_eq!(val, Some("test_value".to_string()));

    // Update the value
    db.set_kv("test_key", "updated_value").await.unwrap();
    let val = db.get_kv("test_key").await.unwrap();
    assert_eq!(val, Some("updated_value".to_string()));
}

#[tokio::test]
async fn test_session_with_all_fields() {
    let (db, _tmp) = setup_db().await;

    let request = create_test_request();
    let mut session = OfframpSession::new(request);

    // Set all optional fields
    session.expected_usdc = Some(U256::from(30_000000u64)); // 30 USDC
    session.received_usdc = Some(U256::from(29_500000u64)); // 29.5 USDC
    session.near_deposit_address = Some("zcash_addr_abc".to_string());
    session.near_tx_hash = Some("near_tx_123".to_string());
    session.zkp2p_deposit_id = Some(U256::from(42u64));
    session.zkp2p_intent_hash = Some(alloy::primitives::keccak256(b"test_intent"));
    session.create_session_tx = Some(alloy::primitives::keccak256(b"create_tx"));
    session.process_offramp_tx = Some(alloy::primitives::keccak256(b"process_tx"));
    session.error = Some("test error".to_string());
    session.set_status(OfframpStatus::Failed);

    db.insert_session(&session).await.unwrap();

    let retrieved = db.get_session(session.id).await.unwrap().unwrap();

    assert_eq!(retrieved.expected_usdc, session.expected_usdc);
    assert_eq!(retrieved.received_usdc, session.received_usdc);
    assert_eq!(retrieved.near_deposit_address, session.near_deposit_address);
    assert_eq!(retrieved.near_tx_hash, session.near_tx_hash);
    assert_eq!(retrieved.zkp2p_deposit_id, session.zkp2p_deposit_id);
    assert_eq!(retrieved.zkp2p_intent_hash, session.zkp2p_intent_hash);
    assert_eq!(retrieved.create_session_tx, session.create_session_tx);
    assert_eq!(retrieved.process_offramp_tx, session.process_offramp_tx);
    assert_eq!(retrieved.error, session.error);
    assert_eq!(retrieved.status, OfframpStatus::Failed);
}
