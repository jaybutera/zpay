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

    /// Outputs paying `script_pubkey` that are in the mempool, unconfirmed.
    ///
    /// This exists for exactly one purpose: learning the funding **outpoint**
    /// early enough that the user's page is still open to sign over it. The
    /// release digest commits to the outpoint (ZIP 244 S.2g), so nothing can be
    /// signed until it is known - and it is known the moment the transaction is
    /// broadcast, seconds after the user presses send, rather than a block
    /// later.
    ///
    /// What comes back is **not** evidence of funding. A mempool entry can be
    /// replaced, evicted, or never mined. It is used to announce and to collect
    /// a signature, never to decide that an escrow is paid: `advance_funded`
    /// still reads `chain.utxo`, which asks `gettxout` with `include_mempool`
    /// false, and `lp::evaluate` re-checks the depth again before any dollars
    /// move. A signature over an outpoint that never confirms is simply never
    /// decrypted, and the escrow refunds at T exactly as if nothing had
    /// happened.
    ///
    /// The default is empty, so a scanner that cannot see the mempool - or a
    /// node without `getrawmempool` - behaves exactly as it did before.
    fn outputs_paying_in_mempool(
        &self,
        _script_pubkey: &[u8],
        _address: &str,
    ) -> Result<Vec<FoundOutput>> {
        Ok(Vec::new())
    }

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
    /// exact integer, and preferring one avoids the float round-trip entirely.
    ///
    /// They are two fields rather than one field with an alias. An alias makes
    /// both names write the same field, and serde rejects a second write as a
    /// duplicate - so a node that prints BOTH (NOWNodes does, measured
    /// 2026-09-05: `value`, `valueZat` and `valueSat` all present) fails to
    /// deserialize every block it serves. The scan then skips every block,
    /// never reports a cursor, and no funding is ever seen. A provider sending
    /// one name or the other, or both, must all work.
    #[serde(default, rename = "valueZat")]
    value_zat: Option<i64>,
    #[serde(default, rename = "valueSat")]
    value_sat: Option<i64>,
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
        // Integer first and in a fixed order, so a node printing both names
        // gives the same answer as one printing either. They carry the same
        // number; the order only decides which is read, never what is paid.
        if let Some(v) = self.value_zat.or(self.value_sat) {
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
    /// Walks `getrawmempool` looking for an output that pays this escrow.
    ///
    /// The mempool is small - tens of transactions on Zcash - so this reads
    /// each one and stops at the first sighting. A node that does not serve
    /// `getrawmempool`, or that errors, yields nothing rather than failing the
    /// sweep: this is an optimisation on when a signature can be collected, and
    /// losing it costs a block of latency, not correctness.
    fn outputs_paying_in_mempool(
        &self,
        script_pubkey: &[u8],
        address: &str,
    ) -> Result<Vec<FoundOutput>> {
        let txids: Vec<String> = match self.rpc.call("getrawmempool", serde_json::json!([])) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, "the node would not list its mempool");
                return Ok(Vec::new());
            }
        };

        let want_hex = hex::encode(script_pubkey);
        let mut found = Vec::new();
        for txid in txids.iter().take(MEMPOOL_SCAN_LIMIT) {
            let tx: VerboseTx = match self
                .rpc
                .call("getrawtransaction", serde_json::json!([txid, 1]))
            {
                Ok(t) => t,
                // A transaction can leave the mempool between the list and the
                // read. That is not an error, it is the mempool.
                Err(e) => {
                    tracing::debug!(%txid, error = %e, "a mempool transaction could not be read");
                    continue;
                }
            };
            for out in &tx.vout {
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
                let amount_zat = match out.zat() {
                    Ok(z) => z,
                    Err(e) => {
                        tracing::debug!(%txid, error = %e, "a mempool output had no readable value");
                        continue;
                    }
                };
                let txid_bytes = match zecp2p_escrow::rpc::txid_from_display(&tx.txid) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::debug!(%txid, error = %e, "a mempool transaction had a bad txid");
                        continue;
                    }
                };
                found.push(FoundOutput {
                    txid: txid_bytes,
                    vout: out.n,
                    amount_zat,
                });
            }
        }
        Ok(found)
    }

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

/// The most mempool transactions one sweep will read.
///
/// Zcash's mempool is small; this is a bound against a node that reports a
/// pathological one, not a tuning knob. Missing a sighting costs a block of
/// latency and nothing else.
const MEMPOOL_SCAN_LIMIT: usize = 200;

/// A scanner a test drives directly.
#[derive(Debug, Default)]
pub struct FakeScanner {
    outputs: std::sync::Mutex<Vec<(Vec<u8>, FoundOutput)>>,
    /// Outputs the scanner reports as *unconfirmed*, in the mempool only.
    mempool: std::sync::Mutex<Vec<(Vec<u8>, FoundOutput)>>,
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

    /// An output paying `script_pubkey` that is in the mempool and not in any
    /// block. `outputs_paying` will not report it; `outputs_paying_in_mempool`
    /// will.
    pub fn pay_mempool(&self, script_pubkey: &[u8], output: FoundOutput) {
        self.mempool
            .lock()
            .expect("fake scanner lock")
            .push((script_pubkey.to_vec(), output));
    }

    /// Stops the scanner reporting anything, without unwinding the chain.
    ///
    /// This is what a real scan does once `scanned_through` passes the block
    /// the funding is in: the output is still on chain and still spendable, the
    /// scan simply no longer looks at the block holding it. Distinct from a
    /// reorg, where the output is genuinely gone.
    pub fn forget(&self) {
        self.outputs.lock().expect("fake scanner lock").clear();
    }
}

impl FundingScanner for FakeScanner {
    fn outputs_paying_in_mempool(
        &self,
        script_pubkey: &[u8],
        _address: &str,
    ) -> Result<Vec<FoundOutput>> {
        Ok(self
            .mempool
            .lock()
            .expect("fake scanner lock")
            .iter()
            .filter(|(spk, _)| spk.as_slice() == script_pubkey)
            .map(|(_, o)| *o)
            .collect())
    }

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

#[cfg(test)]
mod vout_value_shapes {
    //! One vout, three providers, one answer.
    //!
    //! A block is refused whole if any vout in it will not deserialize, and a
    //! refused block is a block the scan skips - so it reports no cursor, never
    //! advances, and never sees the funding. That is not a parse detail: it is
    //! the difference between a user's ZEC being noticed and sitting there.

    use super::VerboseVout;

    fn vout(body: &str) -> VerboseVout {
        serde_json::from_str(body).expect("the vout should deserialize")
    }

    /// NOWNodes prints `value`, `valueZat` AND `valueSat` on every output.
    ///
    /// Captured from https://zec.nownodes.io on 2026-09-05 at mainnet block
    /// 3,472,501. With `valueSat` aliased onto `valueZat` this was
    /// `duplicate field valueZat` and every mainnet block was skipped.
    #[test]
    fn a_vout_carrying_both_integer_names_is_read() {
        let v = vout(
            r#"{"value":1.26245368,"valueZat":126245368,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// zcashd's own name, alone.
    #[test]
    fn a_vout_with_only_value_zat_is_read() {
        let v = vout(
            r#"{"value":1.26245368,"valueZat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// The other build's name, alone - the case the alias existed to cover,
    /// which must keep working now the alias is gone.
    #[test]
    fn a_vout_with_only_value_sat_is_read() {
        let v = vout(
            r#"{"value":1.26245368,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// No integer at all: the float is the only source left.
    #[test]
    fn a_vout_with_only_the_float_falls_back_to_it() {
        let v = vout(
            r#"{"value":1.26245368,"n":0,
                "scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// Every shape must agree. A provider swap must not change what a user is
    /// judged to have sent.
    #[test]
    fn every_provider_shape_yields_the_same_zatoshis() {
        let both = vout(
            r#"{"value":1.26245368,"valueZat":126245368,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        let zat_only = vout(
            r#"{"value":1.26245368,"valueZat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        let sat_only = vout(
            r#"{"value":1.26245368,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        let float_only = vout(
            r#"{"value":1.26245368,"n":0,
                "scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        let want = 126_245_368u64;
        for (name, v) in [
            ("both", &both),
            ("valueZat", &zat_only),
            ("valueSat", &sat_only),
            ("float", &float_only),
        ] {
            assert_eq!(v.zat().unwrap(), want, "{name} disagreed");
        }
    }

    /// The integer wins over the float, whichever integer name carries it.
    /// The float is the lossy one; reading it when an exact figure is present
    /// would round a user's funding.
    #[test]
    fn the_integer_is_preferred_over_the_float() {
        // A deliberately mismatched float proves which field was read.
        let v = vout(
            r#"{"value":9.99999999,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// A whole NOWNodes-shaped block deserializes, which is what the scan
    /// actually does - a vout that parses alone is no use if the block around
    /// it does not.
    #[test]
    fn a_nownodes_shaped_block_deserializes_whole() {
        let block: super::VerboseBlock = serde_json::from_str(
            r#"{"hash":"0000","confirmations":7,"height":3472501,"tx":[
                 {"txid":"aa","vout":[
                   {"value":1.26245368,"valueZat":126245368,"valueSat":126245368,
                    "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}},
                   {"value":0.0001,"valueZat":10000,"valueSat":10000,
                    "n":1,"scriptPubKey":{"hex":"a914","addresses":["t3y"]}}]}]}"#,
        )
        .expect("a NOWNodes block should deserialize");
        assert_eq!(block.tx.len(), 1);
        assert_eq!(block.tx[0].vout.len(), 2);
        assert_eq!(block.tx[0].vout[0].zat().unwrap(), 126_245_368);
        assert_eq!(block.tx[0].vout[1].zat().unwrap(), 10_000);
    }

    /// Two integer names carrying different numbers is a broken node. Which one
    /// wins is fixed and documented rather than arbitrary - and it cannot
    /// mis-settle either way, because this number is only ever a filter.
    /// `choose_funding` demands the exact quoted amount, and `driver` then
    /// re-derives the real value with `gettxout` before anything settles. So a
    /// disagreement stalls the order, refundable, and never pays out a wrong
    /// figure. This pins that, so a later change to the field order is a
    /// deliberate one rather than a silent change to custody behaviour.
    #[test]
    fn disagreeing_integer_names_read_value_zat_and_cannot_mis_settle() {
        let v = vout(
            r#"{"value":1.26245368,"valueZat":1,"valueSat":126245368,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 1, "valueZat is the documented winner");

        // 1 is not the quoted amount, so nothing is chosen and nothing settles.
        let found = [super::FoundOutput {
            txid: [0u8; 32],
            vout: 0,
            amount_zat: v.zat().unwrap(),
        }];
        assert_eq!(super::choose_funding(&found, 126_245_368), None);
    }

    /// A zero integer is a real reading, not a missing one.
    ///
    /// `Option::or` keeps `Some(0)`, which is what we want: a zero-value output
    /// is legitimate (coinbase and nonstandard outputs carry one), and it can
    /// never match a nonzero quote anyway.
    #[test]
    fn a_zero_integer_is_read_rather_than_falling_through_to_the_float() {
        let v = vout(
            r#"{"value":1.26245368,"valueZat":0,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 0);
    }

    /// An explicit JSON `null` is an absent integer, not a zero.
    #[test]
    fn an_explicit_null_integer_falls_through_to_the_float() {
        let v = vout(
            r#"{"value":1.26245368,"valueZat":null,
                "n":0,"scriptPubKey":{"hex":"76a914","addresses":["t1x"]}}"#,
        );
        assert_eq!(v.zat().unwrap(), 126_245_368);
    }

    /// A negative integer is still refused, whichever name carries it.
    #[test]
    fn a_negative_value_is_refused_under_either_name() {
        for body in [
            r#"{"valueZat":-1,"n":0,"scriptPubKey":{"hex":"76a914","addresses":[]}}"#,
            r#"{"valueSat":-1,"n":0,"scriptPubKey":{"hex":"76a914","addresses":[]}}"#,
        ] {
            let v = vout(body);
            assert!(v.zat().is_err(), "a negative value must be refused: {body}");
        }
    }
}
