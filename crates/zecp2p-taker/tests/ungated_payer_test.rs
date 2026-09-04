//! No live payment from a path that cannot take the payment slot.
//!
//! R5-2: `run` and `test-pay --send-for-real` drove the browser with no journal
//! read and no journal write. The slot is what keeps this taker and
//! `zecp2p-v2coordinator` from paying the same Venmo account at once, and the
//! config comments told operators the two were bound - which for those two
//! paths was false.
//!
//! These drive the built binary, because the refusal has to hold at the command
//! line, which is where an operator meets it.

use std::process::Command;

fn taker() -> std::path::PathBuf {
    // The integration test binary sits next to the one under test.
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("zecp2p-taker")
}

fn config() -> std::path::PathBuf {
    let mut root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("config.taker.example.toml")
}

/// Runs the taker and returns (stdout + stderr, success).
fn run(args: &[&str]) -> (String, bool) {
    let out = Command::new("timeout")
        .arg("30")
        .arg(taker())
        .args(args)
        .env("ZECP2P_TAKER_CONFIG", config())
        // A key it will never use: every path under test refuses before it
        // reaches a chain, and the binary wants one to start.
        .env("TAKER_PRIVATE_KEY", format!("0x{}", "11".repeat(32)))
        .output()
        .expect("the taker binary runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (text, out.status.success())
}

#[test]
fn run_refuses_to_send_for_real() {
    let (text, ok) = run(&["run"]);
    assert!(!ok, "`run` sent money without taking the payment slot:\n{text}");
    assert!(
        text.contains("payment slot"),
        "the refusal must say why:\n{text}"
    );
    assert!(
        text.contains("auto"),
        "the refusal must name the command that is gated:\n{text}"
    );
}

#[test]
fn test_pay_refuses_to_send_for_real() {
    let (text, ok) = run(&[
        "test-pay",
        "--recipient",
        "alice",
        "--amount",
        "1.00",
        "--send-for-real",
    ]);
    assert!(
        !ok,
        "`test-pay --send-for-real` sent money without taking the slot:\n{text}"
    );
    assert!(text.contains("payment slot"), "{text}");
}

// A dry-run case is deliberately not tested here: `run --dry-run` reaches the
// chain and blocks on an RPC that this machine does not have, so the test would
// hang rather than assert. What matters is covered above - the refusal fires on
// the sending paths - and the refusal is placed so it cannot catch a dry run:
// `run` checks `if !dry_run`, and `test-pay` checks `if send_for_real`.
