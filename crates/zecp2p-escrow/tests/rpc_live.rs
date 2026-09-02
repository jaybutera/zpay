//! Live tests against a Zcash JSON-RPC endpoint.
//!
//! These are `#[ignore]` because they need network and are rate-limited by the
//! hosted development endpoint. Run them with:
//!
//! ```text
//! ZECP2P_RPC_URL=https://api.tatum.io/v3/blockchain/node/zcash-testnet \
//!   cargo test -p zecp2p-escrow --test rpc_live -- --ignored --test-threads 1
//! ```
//!
//! They are the standing check that the adapter which will point at our own
//! zebrad speaks the dialect a real node answers. Against a hosted provider
//! they prove the adapter, not the chain: see spec section 14.

use std::time::Duration;

use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};

fn client() -> Option<RpcChainClient> {
    let url = std::env::var("ZECP2P_RPC_URL").ok()?;
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    let mut config = RpcConfig::public(url, network);
    // The hosted endpoint allows a handful of requests a minute, so give each
    // one room rather than failing on a slow response.
    config.timeout = Duration::from_secs(45);
    RpcChainClient::new(config).ok()
}

/// NU6.3 / Ironwood, which both mainnet and testnet were on when this was
/// written.
const NU6_3: u32 = 0x37a5_165b;

/// Retries through a hosted provider's rate limit.
///
/// A 429 is an availability problem, not a verdict from the chain, and the
/// adapter already classifies it as `Unreachable`. Retrying here keeps a
/// provider's quota from reading as a protocol failure. A real node needs none
/// of this.
fn with_retry<T>(
    label: &str,
    mut f: impl FnMut() -> Result<T, zecp2p_escrow::chain::ChainError>,
) -> T {
    let mut last = None;
    for attempt in 0..6 {
        match f() {
            Ok(v) => return v,
            Err(e) => {
                let text = format!("{e}");
                if !text.contains("429") {
                    panic!("{label}: {e}");
                }
                last = Some(text);
                std::thread::sleep(Duration::from_secs(15 * (attempt + 1)));
            }
        }
    }
    panic!("{label}: still rate limited after retries: {last:?}");
}

/// One test rather than five, because the hosted development endpoint allows
/// five requests a minute and a test binary that trips its own quota reports
/// failures that say nothing about the code.
#[test]
#[ignore = "needs network and a rate-limited endpoint"]
fn the_adapter_speaks_the_dialect_a_real_node_answers() {
    let Some(c) = client() else {
        panic!("set ZECP2P_RPC_URL to run this");
    };

    // 1. The endpoint serves the network we think it does. Pointing a testnet
    //    config at a mainnet URL is a typo that spends real money.
    with_retry("check_network", || c.check_network());

    // 2. The branch id is read from the node, per spec 4.3. The assertion is
    //    weak on the value and strong on the shape: if the chain advances to an
    //    upgrade this build does not know, the escrow's transaction version and
    //    sighash need re-checking before anything is signed.
    let branch = with_retry("consensus_branch_id", || c.consensus_branch_id());
    assert_ne!(branch, 0, "a zero branch id would produce an unusable sighash");
    let known = [
        0xc2d6_d0b4u32, // NU5
        0xc8e7_1055,    // NU6
        0x4dec_4df0,    // NU6.1
        0x5437_f330,    // NU6.2
        NU6_3,          // Ironwood
    ];
    assert!(
        known.contains(&branch),
        "node reports branch {branch:#x}, which this build does not know"
    );

    // 3. A plausible height.
    let height = with_retry("height", || c.height());
    assert!(
        height > 3_000_000,
        "height {height} is implausibly low for either Zcash network"
    );

    // 4. An outpoint that exists on no chain reads as absent, not as an error.
    //    The LP's watcher treats absent as "wait" and unreachable as something
    //    to escalate, so conflating them would page someone every time a lock
    //    was merely unmined.
    let missing = with_retry("utxo", || c.utxo(&[0u8; 32], 0));
    assert!(missing.is_none(), "an unknown outpoint must read as absent");

    // 5. The mempool path reaches a verdict, without spending anything.
    let err = c
        .broadcast(&[0x00])
        .expect_err("a one-byte transaction cannot be valid");
    assert!(
        matches!(err, zecp2p_escrow::chain::ChainError::Rejected(_)),
        "a malformed transaction must come back as the node's rejection, not \
         as an unreachable node: {err}"
    );
}
