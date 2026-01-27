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

use std::sync::Arc;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
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

    tracing::info!("Starting zecp2p-coordinator");
    tracing::info!("Chain ID: {}", config.network.chain_id);

    // Initialize database
    let db = db::Database::new(&config.database.path).await?;
    db.run_migrations().await?;

    // Initialize chain clients
    let chain_client = chain::ChainClient::new(&config).await?;

    // Initialize NEAR Intents client
    let near_client = near::NearIntentsClient::new(&config.near);

    // Build application state
    let state = Arc::new(AppState::new(config.clone(), db, chain_client, near_client));

    // Build router
    let app = Router::new()
        .route("/health", get(api::health))
        .route("/quote", get(api::get_quote))
        .route("/offramp", post(api::create_offramp))
        .route("/offramp/{id}", get(api::get_offramp))
        .route("/offramp/{id}/process", post(api::process_offramp))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Start background tasks
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = state_clone.run_keeper_loop().await {
            tracing::error!("Keeper loop error: {}", e);
        }
    });

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
