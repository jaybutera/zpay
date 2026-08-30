//! zecp2p-coordinator: REST API server for orchestrating ZEC → Venmo offramps
//!
//! This coordinator:
//! - Registers sessions with GlueContract
//! - Initiates NEAR Intents for ZEC → USDC swaps
//! - Monitors for USDC arrival
//! - Triggers GlueContract to route to zk-p2p
//! - Monitors zk-p2p for fulfillment

mod api;
mod chain;
mod db;
mod error;
mod near;
mod state;
mod zkp2p;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zecp2p_types::Config;

use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zecp2p_coordinator=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config_path = std::env::var("ZECP2P_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load_with_env(&config_path)?;

    // Validate configuration
    validate_config(&config)?;

    tracing::info!("Starting zecp2p-coordinator");
    tracing::info!("Chain ID: {}", config.network.chain_id);
    tracing::info!("GlueContract: {:?}", config.contracts.glue_contract);

    // Initialize database
    let db = db::Database::new(&config.database.path).await?;
    db.run_migrations().await?;

    // Initialize chain clients
    let chain_client = chain::ChainClient::new(&config).await?;

    // Initialize NEAR Intents client
    let near_client = near::NearIntentsClient::new(&config.near);

    // Initialize zk-p2p curator client (payee registration)
    let zkp2p_client = zkp2p::Zkp2pClient::new(&config.zkp2p);
    tracing::info!("zk-p2p curator: {}", config.zkp2p.api_url);

    // Build application state
    let state = Arc::new(AppState::new(
        config.clone(),
        db,
        chain_client,
        near_client,
        zkp2p_client,
    ));

    // Build router with middleware layers
    // Note: Layers are applied bottom-to-top, so request flow is:
    // 1. SetRequestId (generates/reads X-Request-Id)
    // 2. PropagateRequestId (adds X-Request-Id to response)
    // 3. TraceLayer (logs with request context)
    // 4. CORS (handles preflight)
    // 5. Handler
    let app = Router::new()
        .route("/health", get(api::health))
        .route("/quote", get(api::get_quote))
        .route("/offramp", post(api::create_offramp))
        .route("/offramp/{id}", get(api::get_offramp))
        .route("/offramp/{id}/process", post(api::process_offramp))
        .route("/offramp/{id}/rescue", post(api::rescue_offramp))
        .route("/offramp/{id}/withdraw", post(api::withdraw_offramp))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state.clone());

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start keeper loop with graceful shutdown support
    let state_clone = state.clone();
    let keeper_shutdown_rx = shutdown_rx.clone();
    let keeper_handle = tokio::spawn(async move {
        state_clone.run_keeper_loop_with_shutdown(keeper_shutdown_rx).await
    });

    // Start server with graceful shutdown
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await?;

    // Wait for keeper loop to finish
    tracing::info!("Waiting for keeper loop to finish...");
    let _ = keeper_handle.await;

    tracing::info!("Shutdown complete");
    Ok(())
}

/// Validate configuration at startup
fn validate_config(config: &Config) -> Result<()> {
    // Check that required addresses are valid
    if config.contracts.usdc.is_zero() {
        anyhow::bail!("USDC address is not configured");
    }
    if config.contracts.zkp2p_escrow.is_zero() {
        anyhow::bail!("zk-p2p Escrow address is not configured");
    }
    if config.contracts.zkp2p_orchestrator.is_zero() {
        anyhow::bail!("zk-p2p Orchestrator address is not configured");
    }

    // Warn if GlueContract is not configured (it's needed for full functionality)
    if config.contracts.glue_contract.is_none() {
        tracing::warn!("GlueContract address not configured - some operations will fail");
    }

    // Validate chain ID
    if config.network.chain_id != 8453 && config.network.chain_id != 84532 {
        tracing::warn!(
            "Unexpected chain ID: {}. Expected 8453 (Base mainnet) or 84532 (Base Sepolia)",
            config.network.chain_id
        );
    }

    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Signal all components to shut down
    let _ = shutdown_tx.send(true);
}
