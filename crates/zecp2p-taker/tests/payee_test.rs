//! NEW-2: the taker's payee cross-check against the zk-p2p curator.
//!
//! The check itself was correctly built and fail-closed. What it sent was a
//! body the curator does not accept, `{processorName, depositData:
//! {venmoUsername}}`, so `curator_hash_for` bailed on every deposit and the
//! taker refused to pay anyone. Fail-closed cost availability rather than money,
//! but it also meant this code had never once run against the live API. The
//! taker crate had no `tests/` directory at all.
//!
//! Verified against the live curator on 2026-08-31, read-only, no funds moved:
//!
//! ```text
//! POST https://api.zkp2p.xyz/v2/makers/validate
//!   {"processorName":"venmo","offchainId":"test-payee"}
//!   -> {"success":true,"message":"Maker data is valid","responseObject":true}
//!   {"processorName":"venmo","depositData":{"venmoUsername":"test-payee"}}
//!   -> {"success":true,"message":"Maker data is invalid","responseObject":false}
//! ```

mod mock_curator;

use alloy::primitives::B256;
use mock_curator::MockCurator;
use zecp2p_taker::payee;

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

/// The regression. A username the curator knows resolves to its hash, which
/// means the body the taker sends is one the curator accepts.
#[tokio::test]
async fn a_known_username_resolves_to_the_curators_hash() {
    let curator = MockCurator::start().await;

    let hash = payee::curator_hash_for(&http(), &curator.url(), "test-payee")
        .await
        .expect("the curator must accept the body the taker sends");

    assert_eq!(hash, MockCurator::expected_hash("test-payee"));
}

/// The body itself, asserted on the wire. This is the test whose absence let
/// NEW-2 ship: the shape has to be flat `offchainId`, not nested `depositData`.
#[tokio::test]
async fn the_request_body_is_the_flat_offchain_id_shape() {
    let curator = MockCurator::start().await;
    let log = curator.log();

    payee::curator_hash_for(&http(), &curator.url(), "test-payee")
        .await
        .expect("resolve");

    let calls = log.calls();
    assert!(!calls.is_empty(), "the curator was never called");

    for (path, body) in &calls {
        assert_eq!(
            body.get("processorName").and_then(|v| v.as_str()),
            Some("venmo"),
            "{path} must name the processor"
        );
        assert_eq!(
            body.get("offchainId").and_then(|v| v.as_str()),
            Some("test-payee"),
            "{path} must carry a flat offchainId"
        );
        assert!(
            body.get("depositData").is_none(),
            "{path} must not send the nested depositData shape the curator refuses"
        );
        assert!(
            body.get("venmoUsername").is_none(),
            "{path} must not send venmoUsername"
        );
    }
}

/// The `@` and surrounding whitespace come off before the curator sees it. The
/// curator matches the account's exact casing, so only those are stripped.
#[tokio::test]
async fn the_username_is_normalized_before_it_is_sent() {
    let curator = MockCurator::start().await;
    let log = curator.log();

    let hash = payee::curator_hash_for(&http(), &curator.url(), "  @test-payee ")
        .await
        .expect("resolve");

    assert_eq!(hash, MockCurator::expected_hash("test-payee"));
    for (_, body) in log.calls() {
        assert_eq!(
            body.get("offchainId").and_then(|v| v.as_str()),
            Some("test-payee")
        );
    }
}

/// Read before write. The hash only comes back from a registering endpoint, so
/// a handle the curator has never seen must be refused at `/v2/makers/validate`
/// rather than created by the probe.
#[tokio::test]
async fn an_unknown_username_is_refused_without_registering_it() {
    let curator = MockCurator::start().await;
    let log = curator.log();

    let err = payee::curator_hash_for(&http(), &curator.url(), "unknown-handle")
        .await
        .expect_err("an unregistered handle must not resolve");

    assert!(
        err.to_string().contains("does not recognise"),
        "unexpected error: {err}"
    );
    assert_eq!(
        log.paths(),
        vec!["/v2/makers/validate".to_string()],
        "the write endpoint must not be touched for an unknown handle"
    );
}

/// And the ordering holds for a known one too: validate first, create second.
#[tokio::test]
async fn the_read_probe_runs_before_the_write() {
    let curator = MockCurator::start().await;
    let log = curator.log();

    payee::curator_hash_for(&http(), &curator.url(), "test-payee")
        .await
        .expect("resolve");

    assert_eq!(
        log.paths(),
        vec![
            "/v2/makers/validate".to_string(),
            "/v2/makers/create".to_string()
        ]
    );
}

/// The curator answering "invalid" is HTTP 200 with `success: true`, not an
/// error status. A check that only looked at the status code would sail past it.
#[tokio::test]
async fn a_curator_that_reports_the_maker_invalid_is_a_refusal_not_a_pass() {
    let curator = MockCurator::start().await;

    let known = payee::curator_knows(&http(), &curator.url(), "test-payee")
        .await
        .expect("call");
    assert!(known);

    let unknown = payee::curator_knows(&http(), &curator.url(), "unknown-handle")
        .await
        .expect("call succeeds at the HTTP level");
    assert!(!unknown, "responseObject:false must read as 'no'");
}

/// A curator that cannot be reached must fail the check, never pass it. This is
/// the property that made NEW-2 cost availability instead of money.
#[tokio::test]
async fn an_unreachable_curator_fails_closed() {
    // Port 1 on loopback: nothing listens.
    let err = payee::curator_hash_for(&http(), "http://127.0.0.1:1", "test-payee")
        .await
        .expect_err("an unreachable curator must not resolve to anything");
    assert!(err.to_string().contains("could not reach"), "{err}");
}

/// Shape validation still runs before anything leaves the process, so a hostile
/// coordinator's string never reaches the curator or a URL.
#[tokio::test]
async fn a_username_that_could_not_be_a_handle_never_reaches_the_curator() {
    let curator = MockCurator::start().await;
    let log = curator.log();

    for bad in ["a", "alice?amount=500", "alice bob", "alice/../bob"] {
        assert!(
            payee::curator_hash_for(&http(), &curator.url(), bad)
                .await
                .is_err(),
            "{bad:?} must be refused"
        );
    }
    assert!(
        log.calls().is_empty(),
        "nothing malformed should have been sent to the curator"
    );
}

/// End to end at the level that matters: the resolved hash is compared against
/// the deposit's own `payeeDetails`, and a mismatch stops the payment.
#[tokio::test]
async fn the_check_refuses_a_coordinator_naming_the_wrong_payee() {
    let curator = MockCurator::start().await;

    // The deposit will settle against Alice.
    let deposit_payee = MockCurator::expected_hash("test-payee");

    // Honest coordinator.
    let resolved = payee::curator_hash_for(&http(), &curator.url(), "test-payee")
        .await
        .expect("resolve");
    payee::require_match("test-payee", resolved, deposit_payee)
        .expect("the right payee must be accepted");

    // Hostile coordinator naming its own handle for the same deposit.
    let attacker = payee::curator_hash_for(&http(), &curator.url(), "attacker-handle")
        .await
        .expect("resolve");
    let err = payee::require_match("attacker-handle", attacker, deposit_payee)
        .expect_err("a payee the deposit will not settle against must be refused");
    assert!(err.to_string().contains("Not paying"), "{err}");
}

/// A malformed `hashedOnchainId` is refused rather than turned into a bytes32
/// that would silently never match.
#[test]
fn a_malformed_curator_hash_is_refused() {
    assert!(payee::parse_payee_hash("0x1234").is_err());
    assert!(payee::parse_payee_hash(&format!("0x{}", "0".repeat(64))).is_err());
    assert!(payee::parse_payee_hash("hashed-id-1").is_err());
    assert_eq!(
        payee::parse_payee_hash(&format!("0x{}", "ab".repeat(32))).unwrap(),
        B256::from([0xab; 32])
    );
}
