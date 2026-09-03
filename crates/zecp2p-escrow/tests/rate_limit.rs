//! R12-1: the hosted endpoint's rate limit must not abort a run.
//!
//! The keyless hosted endpoint answers 5 requests per sliding 60 s window and
//! 429 after that, and the runner and the attestor share that window. A single
//! `attest` makes more calls than that. Staged in review, the first run
//! panicked on a 503 wrapping a 429 *after* the $1.25 had been sent, the
//! second obtained the scalar but had its broadcast refused as the sixth call,
//! and only the third mined the release.
//!
//! These tests stand a real socket in front of the adapter and answer the
//! measured sequences, so they exercise the retry where it actually lives: the
//! HTTP layer, not a mocked `ChainClient`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zecp2p_escrow::chain::{ChainClient, ChainError};
use zecp2p_escrow::rpc::{is_rate_limited, Network, RpcChainClient, RpcConfig};

/// One scripted HTTP response.
struct Reply {
    status: &'static str,
    body: String,
}

impl Reply {
    fn rate_limited_429() -> Self {
        Self {
            status: "429 Too Many Requests",
            body: "{\"error\":\"Too Many Requests\"}".into(),
        }
    }

    /// The shape that actually aborted the staged run: a gateway 503 whose
    /// body carries the upstream 429.
    fn rate_limited_503() -> Self {
        Self {
            status: "503 Service Unavailable",
            body: "upstream error: HTTP 429 Too Many Requests".into(),
        }
    }

    fn ok(result: &str) -> Self {
        Self {
            status: "200 OK",
            body: format!("{{\"result\":{result},\"error\":null,\"id\":\"zecp2p\"}}"),
        }
    }
}

/// Serves a fixed script of replies, one per request, then 200s forever.
fn serve(script: Vec<Reply>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);

    std::thread::spawn(move || {
        let mut script = script.into_iter();
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            // Read just enough to not block the client's write.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);

            let reply = script
                .next()
                .unwrap_or_else(|| Reply::ok("{\"chain\":\"main\",\"blocks\":3470000,\"consensus\":{\"chaintip\":\"37a5165b\"}}"));
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                reply.status,
                reply.body.len(),
                reply.body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    (url, seen)
}

/// Every trait method runs `ensure_network` first, which is itself a call and
/// so consumes a script entry. Prepending the network answer keeps each test's
/// script describing only the call it is about.
fn network_ok() -> Reply {
    Reply::ok("{\"chain\":\"main\",\"blocks\":3470000,\"consensus\":{\"chaintip\":\"37a5165b\"}}")
}

fn client(url: String, slept: Arc<Mutex<Vec<Duration>>>) -> RpcChainClient {
    let mut cfg = RpcConfig::hosted(url, Network::Main);
    cfg.timeout = Duration::from_secs(5);
    cfg.broadcast_timeout = Duration::from_secs(5);
    RpcChainClient::new(cfg)
        .expect("client")
        // Record the waits instead of taking them, so the test proves the
        // sequence rather than sitting through three real minutes.
        .with_sleep(move |d| slept.lock().unwrap().push(d))
}

/// The measured shape: a plain 429, then success.
#[test]
fn a_429_is_waited_out_rather_than_failing_the_call() {
    let (url, seen) = serve(vec![
        network_ok(),
        Reply::rate_limited_429(),
        Reply::ok("{\"chain\":\"main\",\"blocks\":3470123,\"consensus\":{\"chaintip\":\"37a5165b\"}}"),
    ]);
    let slept = Arc::new(Mutex::new(Vec::new()));
    let chain = client(url, Arc::clone(&slept));

    let height = chain.height().expect("the call must succeed, not panic");
    assert_eq!(height, 3470123);
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "the network check, the 429, then the retry"
    );
    assert_eq!(
        *slept.lock().unwrap(),
        vec![Duration::from_secs(60)],
        "one full window waited"
    );
}

/// The one that aborted the staged run: the limit arrives as a 503 whose body
/// names the upstream 429. Matching only the status code would miss it.
#[test]
fn a_503_wrapping_a_429_is_also_waited_out() {
    let (url, seen) = serve(vec![
        network_ok(),
        Reply::rate_limited_503(),
        Reply::ok("{\"chain\":\"main\",\"blocks\":3470124,\"consensus\":{\"chaintip\":\"37a5165b\"}}"),
    ]);
    let slept = Arc::new(Mutex::new(Vec::new()));
    let chain = client(url, Arc::clone(&slept));

    assert_eq!(chain.height().expect("must succeed"), 3470124);
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    assert_eq!(slept.lock().unwrap().len(), 1);
}

/// The full staged sequence against one call: the window is saturated by the
/// attestor twice over before it clears.
#[test]
fn a_run_survives_repeated_limits_within_the_retry_budget() {
    let (url, _) = serve(vec![
        network_ok(),
        Reply::rate_limited_429(),
        Reply::rate_limited_503(),
        Reply::rate_limited_429(),
        Reply::ok("{\"chain\":\"main\",\"blocks\":3470125,\"consensus\":{\"chaintip\":\"37a5165b\"}}"),
    ]);
    let slept = Arc::new(Mutex::new(Vec::new()));
    let chain = client(url, Arc::clone(&slept));

    assert_eq!(chain.height().expect("must succeed"), 3470125);
    assert_eq!(
        slept.lock().unwrap().len(),
        3,
        "three waits, the configured budget"
    );
}

/// Past the budget the caller must hear about it, as an availability problem
/// rather than a node verdict: an LP must never read a rate limit as "the
/// escrow does not exist".
#[test]
fn an_endless_limit_gives_up_as_unreachable() {
    let (url, _) = serve(vec![
        network_ok(),
        Reply::rate_limited_429(),
        Reply::rate_limited_429(),
        Reply::rate_limited_429(),
        Reply::rate_limited_429(),
        Reply::rate_limited_429(),
    ]);
    let slept = Arc::new(Mutex::new(Vec::new()));
    let chain = client(url, Arc::clone(&slept));

    match chain.height() {
        Err(ChainError::Unreachable(m)) => assert!(m.contains("429"), "got: {m}"),
        other => panic!("expected Unreachable, got {other:?}"),
    }
    assert!(
        ChainError::Unreachable(String::new()).is_retryable(),
        "a rate limit must stay retryable, never a verdict"
    );
}

/// `Retry-After` wins over the default when the provider sends one.
#[test]
fn retry_after_is_honoured_and_capped() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut first = true;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = if first {
                first = false;
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 2\r\n\r\n{}"
                    .to_string()
            } else {
                let body = "{\"result\":{\"chain\":\"main\",\"blocks\":10,\"consensus\":{\"chaintip\":\"37a5165b\"}},\"error\":null}";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let slept = Arc::new(Mutex::new(Vec::new()));
    let chain = client(url, Arc::clone(&slept));
    assert_eq!(chain.height().expect("must succeed"), 10);
    assert_eq!(
        *slept.lock().unwrap(),
        vec![Duration::from_secs(7)],
        "the provider's own figure, not the 60 s default"
    );
}

/// A genuine node outage must not be mistaken for a rate limit and retried
/// for three minutes.
#[test]
fn a_real_5xx_is_not_treated_as_a_rate_limit() {
    assert!(!is_rate_limited(503, "upstream connect error"));
    assert!(!is_rate_limited(500, "internal error"));
    assert!(is_rate_limited(429, ""));
    assert!(is_rate_limited(503, "HTTP 429 Too Many Requests"));
    assert!(is_rate_limited(502, "rate limit exceeded"));
}

/// R13-3: the digits alone are not enough. A 5xx that happens to carry 429 in
/// a height, an amount or a txid is a node that is down, and retrying it
/// three times costs three minutes against a deadline.
#[test]
fn a_coincidental_429_in_an_unrelated_error_is_not_a_rate_limit() {
    for body in [
        "could not find transparent input UTXO at height 3471429",
        "insufficient funds: 429000 zat available",
        "no such transaction 429aa71d4b4f2e5835379786b4bceb34c04e716b8e788239a0a3cef8cbe6b2f15",
        "internal error 4290",
        "block 429 is not on the best chain",
    ] {
        assert!(
            !is_rate_limited(503, body),
            "{body:?} is an outage, not a rate limit"
        );
    }
}

/// The shapes a provider actually uses to say it, which must still match.
#[test]
fn the_real_rate_limit_shapes_still_match() {
    for body in [
        "upstream error: HTTP 429 Too Many Requests",
        "{\"status\": 429}",
        "{\"code\": 429}",
        "Too Many Requests",
        "rate limit exceeded, retry later",
        "upstream returned 429",
    ] {
        assert!(is_rate_limited(503, body), "{body:?} is a rate limit");
    }
}

/// R13-1: the attestor reads the chain through the same rate-limited endpoint
/// and waits out a 429 *inside* the request, so the client that calls it must
/// outlast that wait. At 60 s the budget expired at exactly the moment the
/// attestor was sleeping, and a cold attestor at step 5 hit this every time:
/// the run exited calling a timeout a refusal and told the operator to re-run
/// the prover, with the fiat already sent and nothing signed.
#[test]
fn the_attestor_client_outlasts_the_attestors_own_rate_limit_waits() {
    use zecp2p_escrow::lp_client::ATTESTOR_TIMEOUT;
    use zecp2p_escrow::rpc::{DEFAULT_RATE_LIMIT_RETRIES, DEFAULT_RATE_LIMIT_WAIT};

    let worst_case = DEFAULT_RATE_LIMIT_WAIT * DEFAULT_RATE_LIMIT_RETRIES;
    assert!(
        ATTESTOR_TIMEOUT > worst_case,
        "the attestor may sleep {worst_case:?} waiting out limits, but its client \
         gives up after {ATTESTOR_TIMEOUT:?}"
    );
}

/// A timeout is not a refusal, and must stay retryable: an LP that reads it as
/// a verdict abandons an escrow it has already paid for.
#[test]
fn a_timeout_is_retryable_and_distinct_from_a_refusal() {
    use zecp2p_escrow::lp_client::LpClientError;

    let timed_out = LpClientError::TimedOut("timed out".into());
    assert!(timed_out.is_retryable());
    assert!(!matches!(timed_out, LpClientError::Refused { .. }));

    // A 4xx is the attestor having looked and said no; that one is final.
    assert!(!LpClientError::Refused {
        status: 400,
        message: "different intent".into()
    }
    .is_retryable());
}
