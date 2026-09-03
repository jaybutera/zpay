//! NEW-1, defence in depth: only one offramp session may be in flight at once.
//!
//! The real fix for NEW-1 is that the keeper credits what 1Click reports this
//! session's own swap settled for, rather than drawing from the shared
//! unassigned pool. That attribution is off-chain by necessity: the glue holds
//! every session's USDC in one balance and an ERC-20 transfer carries no
//! session id, so the contract can bound a credit but cannot check whose money
//! arrived.
//!
//! This gate is the second line. With one session in flight the pot is that
//! session's own money, so a mistake in the attribution rule has no other
//! user's funds to reach. It lives in `create_offramp` rather than in an
//! operator's head, because the keeper's own tick is what would move the money.

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use zecp2p_coordinator::{
    chain::ChainClient, db::Database, near::NearIntentsClient, state::AppState, zkp2p::Zkp2pClient,
};
use zecp2p_types::{Config, OfframpRequest, OfframpSession, OfframpStatus};

fn base_config() -> Config {
    Config {
        network: zecp2p_types::config::NetworkConfig {
            base_rpc_url: "https://sepolia.base.org".to_string(),
            base_sepolia_rpc_url: None,
            chain_id: 84532,
        },
        contracts: zecp2p_types::config::ContractConfig {
            usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".parse().unwrap(),
            zkp2p_escrow: "0x6a5e11c3D87e22b828d02ee65a4e8f322BF6B97E".parse().unwrap(),
            zkp2p_orchestrator: "0x7D563c65456deF11c1Fdb9510eB745D5a780F5Fd".parse().unwrap(),
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

async fn state_with(config: Config) -> Arc<AppState> {
    let db = Database::new(":memory:").await.expect("test database");
    db.run_migrations().await.expect("migrations");
    let chain = ChainClient::new_readonly(&config).await.expect("chain client");
    let near = NearIntentsClient::new(&config.near);
    let zkp2p = Zkp2pClient::new(&config.zkp2p);
    Arc::new(AppState::new(config, db, chain, near, zkp2p))
}

fn a_request() -> OfframpRequest {
    OfframpRequest {
        zec_amount: 100_000_000,
        venmo_username: "alice".to_string(),
        user_address: Address::repeat_byte(0xA1),
        taker_address: None,
        zec_refund_address: "t1Kx6cVPqiHZAd4qBmvhkYTpaYPMcQ8Sxpz".to_string(),
        min_rate: U256::from(1_000_000_000_000_000_000u128),
        target_payment_cents: None,
        timeout_seconds: 600,
    }
}

/// Put a session in the database at `status`, the way `create_offramp` would.
async fn seed_session(state: &Arc<AppState>, status: OfframpStatus) -> OfframpSession {
    let mut session = OfframpSession::new(a_request(), alloy::primitives::keccak256(b"payee"));
    session.expected_usdc = Some(U256::from(100_000_000u64));
    session.min_output_usdc = Some(U256::from(99_500_000u64));
    session.set_status(status);
    state.db.insert_session(&session).await.expect("insert");
    session
}

#[tokio::test]
async fn with_nothing_in_flight_a_new_session_is_allowed() {
    let state = state_with(base_config()).await;
    state
        .refuse_if_a_session_is_in_flight()
        .await
        .expect("an empty coordinator opens sessions");
}

/// Every non-terminal stage blocks a second session, because at any of them the
/// session may still be owed USDC on the glue or already own a slice of it.
#[tokio::test]
async fn any_session_still_in_flight_blocks_a_second_one() {
    for status in [
        OfframpStatus::Created,
        OfframpStatus::NearIntentPending,
        OfframpStatus::UsdcReceived,
        OfframpStatus::Zkp2pDeposited,
        OfframpStatus::IntentSignaled,
    ] {
        let state = state_with(base_config()).await;
        let existing = seed_session(&state, status).await;

        let err = state
            .refuse_if_a_session_is_in_flight()
            .await
            .expect_err(&format!("{status} must block a second session"));

        let message = err.to_string();
        assert!(
            message.contains(&existing.id.to_string()),
            "the refusal should name the session that is blocking: {message}"
        );
        assert!(
            message.contains("one offramp at a time"),
            "the refusal should say why: {message}"
        );
    }
}

/// A finished session holds nothing on the glue and must not block the next
/// user. Rescued and withdrawn matter as much as fulfilled: both are how a
/// failed session gives its USDC back.
#[tokio::test]
async fn a_finished_session_does_not_block_the_next_one() {
    for status in [
        OfframpStatus::Fulfilled,
        OfframpStatus::Failed,
        OfframpStatus::Rescued,
        OfframpStatus::Withdrawn,
    ] {
        let state = state_with(base_config()).await;
        seed_session(&state, status).await;

        state
            .refuse_if_a_session_is_in_flight()
            .await
            .unwrap_or_else(|e| panic!("{status} is terminal and must not block: {e}"));
    }
}

/// The gate is the default, and turning it off is a deliberate config change.
#[tokio::test]
async fn the_gate_is_on_unless_the_operator_turns_it_off() {
    assert!(
        !zecp2p_types::config::KeeperConfig::default().allow_concurrent_sessions,
        "one session at a time has to be the default"
    );

    let mut config = base_config();
    config.keeper.allow_concurrent_sessions = true;
    let state = state_with(config).await;
    seed_session(&state, OfframpStatus::UsdcReceived).await;

    state
        .refuse_if_a_session_is_in_flight()
        .await
        .expect("an operator who opted in gets concurrency back");
}

/// The shape the audit's NEW-1 needed: two sessions with USDC in flight at the
/// same time. With the gate on, the second one is never opened, so the pot the
/// keeper attributes from only ever holds one session's money.
#[tokio::test]
async fn the_scenario_new1_needed_cannot_be_set_up() {
    let state = state_with(base_config()).await;

    // Alice's session is live and waiting on her swap.
    seed_session(&state, OfframpStatus::NearIntentPending).await;

    // Bob tries to open one while her USDC is in flight.
    let refused = state.refuse_if_a_session_is_in_flight().await;
    assert!(refused.is_err(), "Bob's session must not open alongside Alice's");

    // Once Alice's is done, Bob's opens normally.
    let mut alice = state
        .db
        .get_active_sessions()
        .await
        .expect("active sessions")
        .remove(0);
    alice.set_status(OfframpStatus::Fulfilled);
    state.db.update_session(&alice).await.expect("update");

    state
        .refuse_if_a_session_is_in_flight()
        .await
        .expect("Bob's turn");
}
