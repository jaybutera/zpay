//! Contract test: the real client against the mock 1Click server.
//!
//! This is the pairing the dry runs depend on. If the mock drifts from the
//! shapes the client parses, this fails without needing a fork or a funded key.

use std::process::{Child, Command};

use zecp2p_coordinator::near::{IntentStatus, NearIntentsClient};
use zecp2p_types::config::NearConfig;

struct Mock {
    child: Child,
    port: u16,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn start_mock(port: u16) -> Mock {
    let root = env!("CARGO_MANIFEST_DIR");
    let script = format!("{}/../../scripts/dryrun/mock_near.py", root);
    let child = Command::new("python3")
        .arg(script)
        .arg("--port")
        .arg(port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start mock_near.py");
    std::thread::sleep(std::time::Duration::from_millis(1200));
    Mock { child, port }
}

fn client(port: u16) -> NearIntentsClient {
    NearIntentsClient::new(&NearConfig {
        api_url: format!("http://127.0.0.1:{}", port),
        default_timeout: 600,
    })
}

async fn set_status(port: u16, status: &str) {
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/admin/status", port))
        .json(&serde_json::json!({ "status": status }))
        .send()
        .await
        .expect("set mock status");
    assert!(resp.status().is_success(), "mock rejected status {}", status);
}

#[tokio::test]
async fn test_client_parses_mock_quote_and_status() {
    let mock = start_mock(4187);
    let client = client(mock.port);

    let request = NearIntentsClient::zec_to_usdc_base_request(
        10_000_000,
        "0x1234567890123456789012345678901234567890",
        "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
        Some(50),
    );

    // The mock answers 201, as the live endpoint does.
    let quote = client.get_quote(request).await.expect("quote parses");
    assert!(quote.deposit_address.starts_with("t1"));
    assert!(quote.expected_output.parse::<u64>().unwrap() > 0);

    // An address the mock never issued is a soft miss, not an error.
    assert!(client
        .get_status("t1neverquoted")
        .await
        .expect("404 is not an error")
        .is_none());

    let pending = client
        .get_status(&quote.deposit_address)
        .await
        .expect("status parses")
        .expect("known address");
    assert_eq!(pending.status, IntentStatus::PendingDeposit);
    assert!(pending.destination_tx_hash.is_none());

    // The hashes and settled amount must survive the swapDetails nesting.
    set_status(mock.port, "SUCCESS").await;
    let done = client
        .get_status(&quote.deposit_address)
        .await
        .expect("status parses")
        .expect("known address");

    assert_eq!(done.status, IntentStatus::Success);
    assert_eq!(
        done.source_tx_hash.as_deref(),
        Some("mock-zec-txid"),
        "origin hash lost in the swapDetails nesting"
    );
    assert!(
        done.destination_tx_hash.is_some(),
        "destination hash lost in the swapDetails nesting"
    );
    assert!(done.output_amount.is_some(), "amountOut lost in the nesting");
}

#[tokio::test]
async fn test_client_reads_refund_from_mock() {
    let mock = start_mock(4188);
    let client = client(mock.port);

    let request = NearIntentsClient::zec_to_usdc_base_request(
        10_000_000,
        "0x1234567890123456789012345678901234567890",
        "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
        Some(50),
    );
    let quote = client.get_quote(request).await.expect("quote parses");

    set_status(mock.port, "REFUNDED").await;
    let refunded = client
        .get_status(&quote.deposit_address)
        .await
        .expect("status parses")
        .expect("known address");

    assert_eq!(refunded.status, IntentStatus::Refunded);
    assert!(refunded.status.is_terminal());
    assert!(
        refunded.refunded_amount.is_some(),
        "refundedAmount lost in the swapDetails nesting"
    );
}

/// An under-deposit keeps the session waiting rather than failing it.
#[tokio::test]
async fn test_incomplete_deposit_is_not_terminal() {
    let mock = start_mock(4189);
    let client = client(mock.port);

    let request = NearIntentsClient::zec_to_usdc_base_request(
        10_000_000,
        "0x1234567890123456789012345678901234567890",
        "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx",
        Some(50),
    );
    let quote = client.get_quote(request).await.expect("quote parses");

    set_status(mock.port, "INCOMPLETE_DEPOSIT").await;
    let status = client
        .get_status(&quote.deposit_address)
        .await
        .expect("status parses")
        .expect("known address");

    assert_eq!(status.status, IntentStatus::IncompleteDeposit);
    assert!(!status.status.is_terminal());
    assert!(status.status.is_pending());
}

/// The mock enforces the bridge minimum the same way the live API does.
#[tokio::test]
async fn test_mock_enforces_bridge_minimum() {
    let mock = start_mock(4190);

    // Bypass client-side validation to confirm the mock itself answers 400.
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/v0/quote", mock.port))
        .json(&serde_json::json!({"amount": "1000", "slippageTolerance": 50}))
        .send()
        .await
        .expect("mock reachable");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap_or_default();
    assert!(body.contains("52000"), "got: {}", body);
}
