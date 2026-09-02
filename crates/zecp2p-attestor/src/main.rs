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

use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

    // R6-4: `std::fs::write` creates at 0666 masked by the umask and only then
    // narrows it, so `d` is world-readable for an instant - long enough for a
    // reader with an inotify watch. `create_new` also closes the exists-then-
    // create race above.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).expect("create attestor key file");
    f.write_all(hex::encode(key.secret_bytes()).as_bytes())
        .expect("write attestor key");
    f.sync_all().expect("sync attestor key");

    tracing::info!(path, "generated a new attestor key on first boot");
    key
}

/// Refuses to start on a secret file any other account can read.
///
/// R6-3: the SQLite file, its WAL and its shm were created 0644, and `k` sits in
/// that file in plaintext until signing - with the later published `s` that is
/// `d`. This laptop is shared.
#[cfg(unix)]
fn require_owner_only(path: &str, what: &str) {
    let mode = std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {what} at {path}: {e}"))
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        panic!(
            "{what} at {path} is mode {mode:o}; it holds key material and must be 0600. \
             Fix it with: chmod 600 {path}"
        );
    }
}

/// Creates the database file at 0600 before SQLite first opens it.
///
/// SQLite gives the WAL and the shm the main file's permissions, so getting the
/// main file right before the first open fixes all three.
fn precreate_db(path: &str) {
    if !Path::new(path).exists() {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(path).expect("create attestor database file");
    }
    #[cfg(unix)]
    require_owner_only(path, "the attestor database");
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

    // Umask first: SQLite creates the WAL and shm itself, and a 002 umask would
    // otherwise make them group-writable (R6-3).
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    let d = load_or_create_key(&key_path);
    #[cfg(unix)]
    require_owner_only(&key_path, "the attestor key");

    precreate_db(&db_path);
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
