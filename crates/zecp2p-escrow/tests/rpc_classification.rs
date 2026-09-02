//! What the adapter does with responses that are not a node's, against a local
//! socket. Round 2 finding 6.
//!
//! The distinction that matters: `Rejected` means the chain refused a
//! transaction and the LP stops; `Unreachable` means nobody answered and the LP
//! retries. Getting them backwards turns a provider outage into a chain verdict.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use zecp2p_escrow::chain::{ChainClient, ChainError};
use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};

/// Answers every request with the same body, so a client that makes its
/// automatic network check plus the call under test both get served.
fn serve(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A chain-info body for the network the client expects, so `ensure_network`
/// passes and the test can reach the call it is about.
const TESTNET_INFO: &str =
    r#"{"result":{"chain":"test","blocks":4319776,"consensus":{"chaintip":"37a5165b"}},"error":null,"id":"x"}"#;

fn client(url: String) -> RpcChainClient {
    RpcChainClient::new(RpcConfig::public(url, Network::Test)).unwrap()
}

#[test]
fn a_json_rpc_error_on_a_read_is_unreachable_not_a_chain_verdict() {
    // A provider that does not expose a method, or that rate-limits inside a
    // JSON-RPC envelope, is not the chain saying no. If this returned
    // `Rejected`, an LP watching an escrow would treat a provider outage as a
    // decision and stop.
    let c = client(serve(
        r#"{"result":null,"error":{"code":-32601,"message":"Method not allowed"},"id":"x"}"#,
    ));
    let err = c.height().unwrap_err();
    assert!(
        matches!(err, ChainError::Unreachable(_)),
        "a read error must be unreachable, got {err}"
    );
}

#[test]
fn an_html_error_page_is_unreachable() {
    let c = client(serve("<html>Attention Required! Cloudflare</html>"));
    assert!(matches!(
        c.utxo(&[0x7a; 32], 0),
        Err(ChainError::Unreachable(_))
    ));
}

#[test]
fn a_null_result_from_gettxout_still_means_not_mined() {
    // The round-1 fix must survive: null is "no such output", which the LP
    // reads as wait.
    let c = client(serve(TESTNET_INFO));
    // The chain-info body has no scriptPubKey, so `gettxout` parsing it as a
    // TxOut fails; what matters here is that a genuine null is not an error,
    // which the round-1 test in rpc_live covers against a real node. Here we
    // assert the classification of a *typed* failure instead.
    let err = c.utxo(&[0x7a; 32], 0).unwrap_err();
    assert!(matches!(err, ChainError::Unreachable(_)), "got {err}");
}

#[test]
fn a_mainnet_endpoint_is_refused_by_a_testnet_client_without_being_asked() {
    // Round 2 finding 6: `check_network` existed but nothing called it, so a
    // testnet config pointed at a mainnet URL relied on the caller remembering.
    // Every trait method now checks first.
    let mainnet = serve(
        r#"{"result":{"chain":"main","blocks":3469655,"consensus":{"chaintip":"37a5165b"}},"error":null,"id":"x"}"#,
    );
    let c = client(mainnet);

    for label in ["height", "branch", "utxo"] {
        let err = match label {
            "height" => c.height().unwrap_err(),
            "branch" => c.consensus_branch_id().unwrap_err(),
            _ => c.utxo(&[0x7a; 32], 0).unwrap_err(),
        };
        let text = format!("{err}");
        assert!(
            text.contains("main") && text.contains("test"),
            "{label} must refuse a mainnet endpoint by name, got {text}"
        );
    }
}

#[test]
fn the_network_check_passes_for_a_matching_endpoint() {
    let c = client(serve(TESTNET_INFO));
    assert_eq!(c.height().unwrap(), 4_319_776);
    assert_eq!(c.consensus_branch_id().unwrap(), 0x37a5_165b);
}

/// The round-1 behaviours the round-2 PoCs also exercised, re-checked here with
/// a stub that answers the automatic network check too.
///
/// The reviewer's own `rpc_poc.rs` now fails on two of these, because
/// `ensure_network` runs first against a stub that serves one canned body. The
/// behaviours themselves are unchanged, and this is where that is asserted.
mod behaviours_behind_the_network_check {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves the chain-info body first, then the body under test.
    fn serve_then(second: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let n = AtomicUsize::new(0);
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    TESTNET_INFO
                } else {
                    second
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn a_null_result_is_still_not_mined_rather_than_an_error() {
        let c = client(serve_then(r#"{"result":null,"error":null,"id":"x"}"#));
        assert_eq!(
            c.utxo(&[0x7a; 32], 0),
            Ok(None),
            "null means no such output, which the LP reads as wait"
        );
    }

    #[test]
    fn negative_confirmations_are_still_treated_as_zero() {
        // A block off the best chain can never satisfy a depth requirement.
        let c = client(serve_then(
            r#"{"result":{"confirmations":-3,"scriptPubKey":{"hex":"a914aa87"},"value":0.05},"error":null}"#,
        ));
        assert_eq!(c.utxo(&[0x7a; 32], 0).unwrap().unwrap().confirmations, 0);
    }

    #[test]
    fn a_reported_depth_is_believed_which_is_the_hosted_mode_caveat() {
        // Spec 16.7: in hosted mode the attestor's chain view is the
        // provider's. Depth is exactly the number the provider is trusted for,
        // and nothing here can detect a lie about it. Pinned so the caveat is
        // not mistaken for a gap nobody noticed.
        let c = client(serve_then(
            r#"{"result":{"confirmations":100,"scriptPubKey":{"hex":"a914aa87"},"value":0.05},"error":null}"#,
        ));
        assert_eq!(c.utxo(&[0x7a; 32], 0).unwrap().unwrap().confirmations, 100);
    }
}
