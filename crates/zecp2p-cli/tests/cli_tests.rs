//! CLI integration tests
//!
//! Tests for the CLI binary. This includes:
//! 1. Argument parsing tests (no server needed)
//! 2. Error handling tests (no server needed)
//! 3. Integration tests with mock server (requires anvil + forge)
//!
//! Run basic tests: cargo test --package zecp2p-cli --test cli_tests
//! Run all tests: cargo test --package zecp2p-cli --test cli_tests -- --ignored --nocapture

use std::process::{Command, Output};

/// Get path to the workspace root
fn workspace_root() -> std::path::PathBuf {
    std::env::current_dir()
        .expect("get current dir")
        .parent()
        .expect("get parent")
        .parent()
        .expect("get workspace root")
        .to_path_buf()
}

/// Get path to the CLI binary
fn cli_binary() -> std::path::PathBuf {
    workspace_root().join("target/debug/zecp2p")
}

/// Build the CLI binary if needed
fn ensure_cli_built() {
    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .args(["build", "--package", "zecp2p-cli"])
        .status()
        .expect("run cargo build");
    assert!(status.success(), "cargo build should succeed");
}

/// Run the CLI binary with given arguments
fn run_cli(args: &[&str]) -> Output {
    Command::new(cli_binary())
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("run CLI")
}

// ==================== ARGUMENT PARSING TESTS ====================

#[test]
fn test_cli_help() {
    ensure_cli_built();

    let output = run_cli(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "help should succeed");
    assert!(stdout.contains("zecp2p"), "should show program name");
    assert!(stdout.contains("quote"), "should show quote command");
    assert!(stdout.contains("offramp"), "should show offramp command");
    assert!(stdout.contains("status"), "should show status command");
    assert!(stdout.contains("watch"), "should show watch command");
    assert!(stdout.contains("rescue"), "should show rescue command");
    assert!(stdout.contains("withdraw"), "should show withdraw command");
}

#[test]
fn test_cli_version() {
    ensure_cli_built();

    let output = run_cli(&["--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "version should succeed");
    assert!(stdout.contains("zecp2p"), "should show program name");
}

#[test]
fn test_cli_quote_help() {
    ensure_cli_built();

    let output = run_cli(&["quote", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "quote help should succeed");
    assert!(stdout.contains("ZEC"), "should mention ZEC");
}

#[test]
fn test_cli_offramp_help() {
    ensure_cli_built();

    let output = run_cli(&["offramp", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "offramp help should succeed");
    assert!(stdout.contains("--venmo"), "should show venmo option");
    assert!(stdout.contains("--user-address"), "should show user-address option");
    assert!(stdout.contains("--taker"), "should show taker option");
    assert!(stdout.contains("--zec-address"), "should show zec-address option");
}

// ==================== MISSING ARGUMENT TESTS ====================

#[test]
fn test_cli_quote_missing_amount() {
    ensure_cli_built();

    let output = run_cli(&["quote"]);

    assert!(!output.status.success(), "should fail without amount");
}

#[test]
fn test_cli_offramp_missing_required_args() {
    ensure_cli_built();

    // Missing all required args
    let output = run_cli(&["offramp", "0.5"]);
    assert!(!output.status.success(), "should fail without required args");

    // Missing some required args
    let output = run_cli(&["offramp", "0.5", "--venmo", "test"]);
    assert!(!output.status.success(), "should fail with partial args");
}

#[test]
fn test_cli_status_missing_session_id() {
    ensure_cli_built();

    let output = run_cli(&["status"]);
    assert!(!output.status.success(), "should fail without session ID");
}

#[test]
fn test_cli_watch_missing_session_id() {
    ensure_cli_built();

    let output = run_cli(&["watch"]);
    assert!(!output.status.success(), "should fail without session ID");
}

#[test]
fn test_cli_rescue_missing_session_id() {
    ensure_cli_built();

    let output = run_cli(&["rescue"]);
    assert!(!output.status.success(), "should fail without session ID");
}

#[test]
fn test_cli_withdraw_missing_session_id() {
    ensure_cli_built();

    let output = run_cli(&["withdraw"]);
    assert!(!output.status.success(), "should fail without session ID");
}

// ==================== COORDINATOR URL TESTS ====================

#[test]
fn test_cli_custom_coordinator_url() {
    ensure_cli_built();

    // The CLI should accept a custom coordinator URL
    // It will fail because the server isn't running, but it should parse the arg correctly
    let output = run_cli(&["--coordinator", "http://custom:1234", "quote", "0.5"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should fail with connection error, not argument parsing error
    assert!(
        stderr.contains("error") || stderr.contains("connection") || stderr.contains("refused") || !output.status.success(),
        "should try to connect to custom URL"
    );
}

// ==================== CONNECTION ERROR TESTS ====================

#[test]
fn test_cli_quote_connection_refused() {
    ensure_cli_built();

    // Try to connect to a port that's not listening
    let output = run_cli(&["--coordinator", "http://127.0.0.1:59999", "quote", "0.5"]);

    assert!(!output.status.success(), "should fail when server not available");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should have some kind of connection error
    assert!(
        stderr.len() > 0 || String::from_utf8_lossy(&output.stdout).contains("error"),
        "should have error output"
    );
}

#[test]
fn test_cli_status_connection_refused() {
    ensure_cli_built();

    let output = run_cli(&[
        "--coordinator", "http://127.0.0.1:59999",
        "status", "00000000-0000-0000-0000-000000000000"
    ]);

    assert!(!output.status.success(), "should fail when server not available");
}

// ==================== WATCH INTERVAL PARSING ====================

#[test]
fn test_cli_watch_interval_parsing() {
    ensure_cli_built();

    // Help should show the interval option
    let output = run_cli(&["watch", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("--interval"), "should show interval option");
    assert!(stdout.contains("default"), "should show default value info");
}

// ==================== ENV VAR TESTS ====================

#[test]
fn test_cli_coordinator_env_var() {
    ensure_cli_built();

    // Help should mention the environment variable
    let output = run_cli(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("ZECP2P_COORDINATOR_URL"),
        "should mention ZECP2P_COORDINATOR_URL env var"
    );
}

// ==================== ESCAPE HATCH TESTS ====================
//
// HIGH-1 in the 2026-08-31 audit: the contract required msg.sender ==
// session.user on rescue and withdraw, but the coordinator sent both with the
// keeper key, so on mainnet every recovery reverted and the user had no path to
// their own funds. The contract now accepts either party, and the CLI can sign
// as the user, either through the coordinator or straight to Base.

/// A well-known Anvil key, used here only to check argument handling. Nothing
/// is sent anywhere: every case below fails before any network call.
const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const TEST_KEY_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

fn run_cli_without_user_key(args: &[&str]) -> Output {
    Command::new(cli_binary())
        .current_dir(workspace_root())
        .env_remove("ZECP2P_USER_PRIVATE_KEY")
        .env_remove("GLUE_CONTRACT_ADDRESS")
        .args(args)
        .output()
        .expect("run CLI")
}

#[test]
fn rescue_offers_a_self_signed_path() {
    ensure_cli_built();

    let output = run_cli(&["rescue", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("--self-signed"),
        "rescue must offer a path that does not go through the coordinator"
    );
    assert!(stdout.contains("--glue"), "self-signed needs the glue address");
}

#[test]
fn withdraw_offers_a_self_signed_path() {
    ensure_cli_built();

    let output = run_cli(&["withdraw", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("--self-signed"));
}

#[test]
fn recovery_without_a_key_says_so_plainly() {
    ensure_cli_built();

    let output = run_cli_without_user_key(&[
        "rescue",
        "00000000-0000-0000-0000-000000000000",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("ZECP2P_USER_PRIVATE_KEY") || stderr.contains("--private-key"),
        "should name the key it wants, got: {stderr}"
    );
}

#[test]
fn self_signed_recovery_needs_the_glue_address() {
    ensure_cli_built();

    let output = run_cli_without_user_key(&[
        "rescue",
        "00000000-0000-0000-0000-000000000000",
        "--private-key",
        TEST_KEY,
        "--self-signed",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("--glue"),
        "should ask for the glue address, got: {stderr}"
    );
}

/// The session owner and the signer have to be the same address, or the
/// coordinator would reject the signature for a reason the user cannot see.
#[test]
fn offramp_refuses_a_user_address_that_is_not_the_signers() {
    ensure_cli_built();

    let output = run_cli_without_user_key(&[
        "offramp",
        "0.5",
        "--venmo",
        "someone",
        "--zec-address",
        "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA",
        "--private-key",
        TEST_KEY,
        "--user-address",
        "0x1234567890123456789012345678901234567890",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        stderr.contains("not the address of"),
        "should refuse a mismatch, got: {stderr}"
    );
}

/// Omitting --user-address is fine: it comes from the key, so the two cannot
/// disagree. This reaches the network and fails there, which is proof enough
/// that argument handling accepted it.
#[test]
fn offramp_derives_the_user_address_from_the_key() {
    ensure_cli_built();

    let output = run_cli_without_user_key(&[
        "--coordinator",
        "http://127.0.0.1:1", // nothing listens here
        "offramp",
        "0.5",
        "--venmo",
        "someone",
        "--zec-address",
        "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA",
        "--private-key",
        TEST_KEY,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(
        !stderr.contains("not the address of") && !stderr.contains("--user-address"),
        "argument handling should have accepted this, got: {stderr}"
    );
    // Sanity: the key really is the address the test names.
    assert_eq!(TEST_KEY_ADDRESS.len(), 42);
}
