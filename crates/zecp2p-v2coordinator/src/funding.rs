//! Finding the output that funded an escrow, when nobody told us its txid.
//!
//! The escrow crate's `ChainClient` has four methods and none of them is "what
//! has this address received": every tool in that crate learns the outpoint
//! from a human who pastes it in. A coordinator cannot do that. The whole
//! promise of the page is that the sender pays from any wallet and is asked
//! nothing about the escrow, so the coordinator has to find the output itself.
//!
//! That is the only reason this module exists, and it is deliberately the
//! *only* thing it does. What a scanner returns is an outpoint and nothing
//! else. Whether the output is really the escrow's - right script, right
//! amount, deep enough - is decided afterwards by `lp::evaluate` reading
//! `ChainClient::utxo`, which is the reviewed code with the money argument in
//! it. A scanner that returned a wrong outpoint produces a refusal there, not
//! a payment.
//!
//! # Two strategies, because no single RPC works everywhere
//!
//! `getaddressutxos` is one call and exactly the right question, but zcashd
//! only answers it with `addressindex=1` and zebrad does not implement it at
//! all. Walking blocks works on every node and needs nothing enabled. So both
//! are here, the block walk is the default, and which one is in use is
//! reported at startup rather than discovered when an order stalls.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

use zecp2p_escrow::rpc::RpcConfig;

/// One funding output, as a scanner found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundOutput {
    /// Internal byte order, which is what the terms and `ChainClient` use.
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount_zat: u64,
}

/// How the coordinator finds the output that paid an escrow address.
///
/// Blocking, like everything else that talks to the node, so it is called from
/// `spawn_blocking` alongside the escrow crate's own client.
pub trait FundingScanner: Send + Sync {
    /// Outputs paying `script_pubkey`, at or after `from_height`.
    ///
    /// Returning more than one is normal and not an error: a sender may pay
    /// twice, or pay the wrong amount and top up. The caller picks.
    fn outputs_paying(
        &self,
        script_pubkey: &[u8],
        address: &str,
        from_height: u32,
    ) -> Result<Vec<FoundOutput>>;

    /// The same search, also reporting the highest block it actually searched.
    ///
    /// The caller persists that height and passes it back as `from_height` next
    /// time, so a repeated scan reads only the blocks that have arrived since.
    /// The default keeps every scanner that does not walk blocks working
    /// unchanged: `None` means "no cursor to keep", and the caller then behaves
    /// exactly as it did before this method existed.
    ///
    /// A scanner must only report a height it has genuinely searched. Reporting
    /// one it skipped would let the caller advance past the block holding the
    /// funding, and the escrow would look unfunded forever.
    fn outputs_paying_through(
        &self,
        script_pubkey: &[u8],
        address: &str,
        from_height: u32,
    ) -> Result<(Vec<FoundOutput>, Option<u32>)> {
        Ok((self.outputs_paying(script_pubkey, address, from_height)?, None))
    }
}

/// Picks the output an escrow should settle against.
///
/// The exact amount wins, whatever else is there. This matters: a sender who
/// pays the wrong amount and then pays again leaves two outputs at the address,
/// and settling against the wrong one means the release is built over an amount
/// the user never pre-signed. Preferring the exact match makes the common
/// recovery work; taking nothing when none matches leaves the escrow refundable
/// rather than half-settled.
pub fn choose_funding(found: &[FoundOutput], amount_zat: u64) -> Option<FoundOutput> {
    found.iter().copied().find(|o| o.amount_zat == amount_zat)
}

/// A JSON-RPC client for the calls the escrow crate does not expose.
///
/// `RpcChainClient::call` is private, so a scanner cannot borrow it. This is a
/// second, smaller client over the same configuration, and it is used for
/// nothing but discovery.
pub struct NodeRpc {
    url: String,
    user: Option<String>,
    password: Option<String>,
    api_key_header: Option<(String, String)>,
    timeout: std::time::Duration,
    /// Built on first use, not in the constructor.
    ///
    /// `reqwest::blocking::Client::builder().build()` starts a runtime of its
    /// own, and doing that on a tokio worker thread panics with "Cannot drop a
    /// runtime in a context where blocking is not allowed". The coordinator
    /// builds its state inside `async fn main`, so constructing the client
    /// there took the whole process down at startup. Every call into this
    /// client already happens inside `spawn_blocking`, which is where the
    /// client may safely be created.
    http: std::sync::OnceLock<reqwest::blocking::Client>,
}

impl std::fmt::Debug for NodeRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Credentials are secrets.
        f.debug_struct("NodeRpc").field("url", &self.url).finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl NodeRpc {
    pub fn new(config: &RpcConfig) -> Result<Self> {
        Ok(Self {
            url: config.url.clone(),
            user: config.user.clone(),
            password: config.password.clone(),
            api_key_header: config.api_key_header.clone(),
            timeout: config.timeout,
            http: std::sync::OnceLock::new(),
        })
    }

    /// The blocking client, built on the thread that first needs it.
    fn http(&self) -> Result<&reqwest::blocking::Client> {
        if let Some(c) = self.http.get() {
            return Ok(c);
        }
        let built = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .context("could not build the discovery HTTP client")?;
        // A race here just discards one client; both are equivalent.
        let _ = self.http.set(built);
        Ok(self.http.get().expect("the client was just set"))
    }

    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "zecp2p-v2coordinator",
            "method": method,
            "params": params,
        });
        let mut req = self.http()?.post(&self.url).json(&body);
        if let (Some(u), Some(p)) = (&self.user, &self.password) {
            req = req.basic_auth(u, Some(p));
        }
        if let Some((header, key)) = &self.api_key_header {
            req = req.header(header.as_str(), key.as_str());
        }
        let resp = req
            .send()
            .with_context(|| format!("{method} could not reach the node"))?;
        let status = resp.status();
        let text = resp.text().with_context(|| format!("{method} answer unreadable"))?;
        if !status.is_success() {
            anyhow::bail!("{method} returned HTTP {status}: {}", truncate(&text));
        }
        let parsed: RpcResponse<T> = serde_json::from_str(&text)
            .with_context(|| format!("{method} answered something that is not JSON-RPC: {}", truncate(&text)))?;
        if let Some(e) = parsed.error {
            anyhow::bail!("{method} failed: {} (code {})", e.message, e.code);
        }
        parsed
            .result
            .ok_or_else(|| anyhow::anyhow!("{method} returned no result"))
    }

    /// Whether this node answers `getaddressutxos`.
    ///
    /// Asked once at startup so an operator learns the node lacks
    /// `addressindex` then, rather than from an order that never leaves
    /// `awaiting_zec`.
    pub fn supports_address_index(&self) -> bool {
        // A valid-but-unfunded address answers with an empty list; a node
        // without the index answers a method or parameter error.
        self.call::<serde_json::Value>(
            "getaddressutxos",
            serde_json::json!([{ "addresses": [] }]),
        )
        .is_ok()
    }

    pub fn height(&self) -> Result<u32> {
        #[derive(Deserialize)]
        struct Info {
            blocks: u32,
        }
        let info: Info = self.call("getblockchaininfo", serde_json::json!([]))?;
        Ok(info.blocks)
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

/// `getaddressutxos`: one call, and the right question.
#[derive(Debug)]
pub struct AddressIndexScanner {
    rpc: Arc<NodeRpc>,
}

impl AddressIndexScanner {
    pub fn new(rpc: Arc<NodeRpc>) -> Self {
        Self { rpc }
    }
}

#[derive(Debug, Deserialize)]
struct AddressUtxo {
    txid: String,
    #[serde(rename = "outputIndex")]
    output_index: u32,
    satoshis: i64,
    #[serde(default)]
    height: i64,
}

impl FundingScanner for AddressIndexScanner {
    fn outputs_paying(
        &self,
        _script_pubkey: &[u8],
        address: &str,
        from_height: u32,
    ) -> Result<Vec<FoundOutput>> {
        let utxos: Vec<AddressUtxo> = self
            .rpc
            .call(
                "getaddressutxos",
                serde_json::json!([{ "addresses": [address] }]),
            )
            .context("getaddressutxos failed; this node may not have addressindex=1")?;

        let mut out = Vec::new();
        for u in utxos {
            // A mempool entry reports height 0 or -1 depending on the node; it
            // is still worth returning, because the caller's own depth check
            // decides whether it counts.
            if u.height > 0 && (u.height as u64) < u64::from(from_height) {
                continue;
            }
            if u.satoshis < 0 {
                continue;
            }
            out.push(FoundOutput {
                txid: zecp2p_escrow::rpc::txid_from_display(&u.txid)
                    .map_err(|e| anyhow::anyhow!("getaddressutxos returned a bad txid: {e}"))?,
                vout: u.output_index,
                amount_zat: u.satoshis as u64,
            });
        }
        Ok(out)
    }
}

/// Walks blocks and matches the escrow's scriptPubKey.
///
/// Works on any node, including zebrad, and needs nothing enabled. The cost is
/// one `getblock` per block since the order opened, which is why the caller
/// bounds the walk with a lookback rather than scanning from genesis.
#[derive(Debug)]
pub struct BlockScanScanner {
    rpc: Arc<NodeRpc>,
    max_blocks: u32,
}

impl BlockScanScanner {
    pub fn new(rpc: Arc<NodeRpc>, max_blocks: u32) -> Self {
        Self { rpc, max_blocks }
    }
}

#[derive(Debug, Deserialize)]
struct VerboseBlock {
    tx: Vec<VerboseTx>,
}

#[derive(Debug, Deserialize)]
struct VerboseTx {
    txid: String,
    vout: Vec<VerboseVout>,
}

#[derive(Debug, Deserialize)]
struct VerboseVout {
    /// zcashd prints `valueZat`; some builds print `valueSat`. Either is the
    /// exact integer, and preferring it avoids the float round-trip entirely.
    #[serde(default, alias = "valueSat")]
    #[serde(rename = "valueZat")]
    value_zat: Option<i64>,
    /// The float form every node prints. Used only when no integer field is.
    #[serde(default)]
    value: Option<f64>,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: VerboseScript,
}

#[derive(Debug, Deserialize)]
struct VerboseScript {
    #[serde(default)]
    hex: String,
    #[serde(default)]
    addresses: Vec<String>,
}

impl VerboseVout {
    fn zat(&self) -> Result<u64> {
        if let Some(v) = self.value_zat {
            if v < 0 {
                anyhow::bail!("a negative output value");
            }
            return Ok(v as u64);
        }
        let v = self
            .value
            .ok_or_else(|| anyhow::anyhow!("an output with no value"))?;
        zecp2p_escrow::rpc::zec_to_zat(v).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

impl FundingScanner for BlockScanScanner {
    fn outputs_paying(
        &self,
        script_pubkey: &[u8],
        address: &str,
        from_height: u32,
    ) -> Result<Vec<FoundOutput>> {
        Ok(self
            .outputs_paying_through(script_pubkey, address, from_height)?
            .0)
    }

    /// Walks blocks and reports the tip it reached.
    ///
    /// `searched_through` is only ever the tip it read at the start, and only
    /// when every block in the window was read. A block the node refused leaves
    /// the cursor unreported, so the next sweep covers that block again rather
    /// than stepping over it - the funding could be inside it.
    fn outputs_paying_through(
        &self,
        script_pubkey: &[u8],
        address: &str,
        from_height: u32,
    ) -> Result<(Vec<FoundOutput>, Option<u32>)> {
        let tip = self.rpc.height().context("could not read the node height")?;
        let want_hex = hex::encode(script_pubkey);
        let start = from_height.max(tip.saturating_sub(self.max_blocks));
        let mut found = Vec::new();
        let mut every_block_read = true;

        for height in start..=tip {
            let block: VerboseBlock = match self
                .rpc
                .call("getblock", serde_json::json!([height.to_string(), 2]))
            {
                Ok(b) => b,
                // A block that cannot be read is not proof the escrow is
                // unfunded, so the walk keeps going and the caller retries the
                // whole scan on its next poll.
                Err(e) => {
                    tracing::debug!(height, error = %e, "skipping a block the node would not serve");
                    every_block_read = false;
                    continue;
                }
            };
            for tx in block.tx {
                for out in tx.vout {
                    let matches = (!out.script_pub_key.hex.is_empty()
                        && out.script_pub_key.hex.eq_ignore_ascii_case(&want_hex))
                        || out
                            .script_pub_key
                            .addresses
                            .iter()
                            .any(|a| a == address);
                    if !matches {
                        continue;
                    }
                    let amount_zat = out.zat().with_context(|| {
                        format!("output {}:{} has no readable value", tx.txid, out.n)
                    })?;
                    found.push(FoundOutput {
                        txid: zecp2p_escrow::rpc::txid_from_display(&tx.txid)
                            .map_err(|e| anyhow::anyhow!("getblock returned a bad txid: {e}"))?,
                        vout: out.n,
                        amount_zat,
                    });
                }
            }
        }
        // Only a fully-read window yields a cursor. `tip` is the height read
        // before the walk, so a block mined during it is simply next sweep's
        // work rather than one this cursor claims to have covered.
        Ok((found, every_block_read.then_some(tip)))
    }
}

/// A scanner a test drives directly.
#[derive(Debug, Default)]
pub struct FakeScanner {
    outputs: std::sync::Mutex<Vec<(Vec<u8>, FoundOutput)>>,
}

impl FakeScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pay(&self, script_pubkey: &[u8], output: FoundOutput) {
        self.outputs
            .lock()
            .expect("fake scanner lock")
            .push((script_pubkey.to_vec(), output));
    }
}

impl FundingScanner for FakeScanner {
    fn outputs_paying(
        &self,
        script_pubkey: &[u8],
        _address: &str,
        _from_height: u32,
    ) -> Result<Vec<FoundOutput>> {
        Ok(self
            .outputs
            .lock()
            .expect("fake scanner lock")
            .iter()
            .filter(|(spk, _)| spk.as_slice() == script_pubkey)
            .map(|(_, o)| *o)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(txid_byte: u8, vout: u32, amount: u64) -> FoundOutput {
        FoundOutput {
            txid: [txid_byte; 32],
            vout,
            amount_zat: amount,
        }
    }

    #[test]
    fn the_exact_amount_is_chosen_over_anything_else() {
        // A sender who underpays and then pays properly leaves two outputs.
        // Settling against the short one would build a release over an amount
        // the user never pre-signed.
        let found = vec![out(1, 0, 90_000), out(2, 1, 200_000), out(3, 0, 500_000)];
        let chosen = choose_funding(&found, 200_000).expect("the exact match is there");
        assert_eq!(chosen.txid, [2u8; 32]);
        assert_eq!(chosen.vout, 1);
    }

    #[test]
    fn nothing_is_chosen_when_nothing_matches() {
        // Leaving the escrow unfunded keeps it refundable at T. Picking the
        // nearest output would settle a trade nobody agreed to.
        let found = vec![out(1, 0, 90_000), out(2, 0, 199_999)];
        assert_eq!(choose_funding(&found, 200_000), None);
        assert_eq!(choose_funding(&[], 200_000), None);
    }

    #[test]
    fn the_fake_scanner_answers_only_for_the_script_it_was_paid() {
        let scanner = FakeScanner::new();
        let ours = vec![0xa9, 0x14, 0x01];
        let theirs = vec![0xa9, 0x14, 0x02];
        scanner.pay(&ours, out(7, 0, 120_000));

        assert_eq!(scanner.outputs_paying(&ours, "t2x", 0).unwrap().len(), 1);
        assert!(scanner.outputs_paying(&theirs, "t2y", 0).unwrap().is_empty());
    }
}

#[cfg(test)]
mod scan_cursor_tests {
    use super::*;

    /// The resume point `watch_funding` computes from a stored cursor.
    ///
    /// Mirrors the expression in `driver::watch_funding` so the boundary is
    /// checked here rather than only inside an integration run: an off-by-one
    /// the wrong way skips the block the funding is in.
    fn resume_from(scanned_through: Option<u32>, opened_height: u32) -> u32 {
        match scanned_through {
            Some(done) => done.saturating_add(1).max(opened_height),
            None => opened_height,
        }
    }

    #[test]
    fn no_cursor_scans_from_where_the_order_opened() {
        assert_eq!(resume_from(None, 900), 900);
    }

    #[test]
    fn a_cursor_resumes_at_the_next_unsearched_block() {
        // 950 has been searched, so 951 is the first block that has not.
        assert_eq!(resume_from(Some(950), 900), 951);
    }

    #[test]
    fn a_cursor_never_walks_back_before_the_order_opened() {
        // A cursor below `opened_height` cannot happen through the normal path,
        // but if a record were ever restored oddly, resuming below the open
        // height would only re-read blocks that predate the order.
        assert_eq!(resume_from(Some(10), 900), 900);
    }

    #[test]
    fn a_cursor_at_the_tip_asks_only_for_the_next_block() {
        // The steady state: nothing new mined, so the window is one block wide
        // rather than the whole lookback. This is the saving.
        assert_eq!(resume_from(Some(1_000), 900), 1_001);
    }

    #[test]
    fn the_default_scanner_reports_no_cursor_and_keeps_working() {
        // A scanner that does not walk blocks (address index, or the fake)
        // keeps the pre-cursor behaviour: results, and nothing to persist.
        let s = FakeScanner::default();
        let script = vec![0x51u8];
        s.pay(
            &script,
            FoundOutput { txid: [3u8; 32], vout: 0, amount_zat: 120_000 },
        );
        let (found, cursor) = s
            .outputs_paying_through(&script, "taddr", 0)
            .expect("the fake scanner answers");
        assert_eq!(found.len(), 1);
        assert_eq!(cursor, None, "no cursor means the caller does not advance one");
    }
}
