//! The configs this repo actually ships have to load.
//!
//! `load_with_env` now refuses a plaintext service URL, which is the point
//! (MEDIUM-3: a stray .env could redirect 1Click, and 1Click supplies the ZEC
//! deposit address). This guards against that check being tightened past what
//! the real configs use.

use zecp2p_types::Config;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn the_mainnet_config_loads() {
    let path = workspace_root().join("config.toml");
    let config = Config::load(path.to_str().unwrap()).expect("config.toml parses");
    config
        .validate_urls()
        .expect("config.toml must pass URL validation");
}

#[test]
fn the_testnet_config_loads() {
    let path = workspace_root().join("config.testnet.toml");
    let config = Config::load(path.to_str().unwrap()).expect("config.testnet.toml parses");
    config
        .validate_urls()
        .expect("config.testnet.toml must pass URL validation");
}
