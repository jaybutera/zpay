//! The attestor daemon, spec section 6.
//!
//! Round 5 finding R5-5: `service::router` was called from one test and from
//! nothing else. There was no binary, no `axum::serve`, no bearer-token
//! configuration, and no code that generated or loaded `d`. This is that.
//!
//! ```text
//! ZECP2P_ATTESTOR_DB=attestor.sqlite \
//! ZECP2P_ATTESTOR_KEY=attestor.key \
//! ZECP2P_ATTESTOR_TOKEN=<shared bearer token> \
//! ZECP2P_RPC_URL=https://api.tatum.io/v3/blockchain/node/zcash-testnet \
//! ZECP2P_RPC_NETWORK=test \
//! ZECP2P_BIND=127.0.0.1:8480 \
//!   cargo run -p zecp2p-attestor
//! ```
//!
//! The key file is created on first boot with mode 0600 and never overwritten.
//! Losing it means every outstanding escrow is unreleasable and every user
//! refunds at `T`; that is the safe direction, but it is a real outage, so the
//! file is what an operator backs up - and, per R5-2, it is as sensitive as the
//! database.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use secp256k1_zkp::SecretKey;

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::service::{router, AttestorService};
use zecp2p_attestor::SystemClock;
use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

/// Loads `d`, or creates it on first boot.
///
/// Spec section 6: "The attestor key `d` is generated at first boot and in
/// Phase 7 sealed to the enclave." Until then it is a file, and the permissions
/// are part of the contract rather than an afterthought.
fn load_or_create_key(path: &str) -> SecretKey {
    if Path::new(path).exists() {
        let text = std::fs::read_to_string(path).expect("read attestor key");
        let bytes = hex::decode(text.trim()).expect("attestor key is 64 hex characters");
        return SecretKey::from_slice(&bytes).expect("attestor key is a valid scalar");
    }

    let key = SecretKey::new(&mut secp256k1_zkp::rand::thread_rng());
    std::fs::write(path, hex::encode(key.secret_bytes())).expect("write attestor key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict attestor key permissions");
    }

    tracing::info!(path, "generated a new attestor key on first boot");
    key
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db_path = env("ZECP2P_ATTESTOR_DB");
    let key_path = env("ZECP2P_ATTESTOR_KEY");
    let token = env("ZECP2P_ATTESTOR_TOKEN");
    let rpc_url = env("ZECP2P_RPC_URL");
    let bind = std::env::var("ZECP2P_BIND").unwrap_or_else(|_| "127.0.0.1:8480".into());
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };

    if token.len() < 16 {
        panic!("ZECP2P_ATTESTOR_TOKEN must be at least 16 characters");
    }

    let d = load_or_create_key(&key_path);
    let db = SqliteEventStore::open(&db_path).expect("open attestor database");

    // `RpcChainClient` builds a blocking reqwest client, which panics if it is
    // constructed inside a tokio runtime (R5-4). Build it on a blocking thread.
    let mut cfg = RpcConfig::public(rpc_url.clone(), network);
    cfg.timeout = Duration::from_secs(45);
    let chain = tokio::task::spawn_blocking(move || RpcChainClient::new(cfg))
        .await
        .expect("build the chain client")
        .expect("chain client");

    let service = Arc::new(AttestorService::new(
        db,
        d,
        chain,
        SystemClock,
        token,
        env!("CARGO_PKG_VERSION").to_string(),
    ));

    tracing::info!(
        p = %hex::encode(service.public_key().serialize()),
        network = ?network,
        rpc = %rpc_url,
        db = %db_path,
        "attestor starting"
    );

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    tracing::info!(%bind, "listening");

    axum::serve(listener, router(service))
        .await
        .expect("serve");
}
