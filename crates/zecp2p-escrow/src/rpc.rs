//! A `ChainClient` over Zcash JSON-RPC.
//!
//! This speaks the `zcashd`/`zebrad` RPC dialect, so the same adapter points at
//! a hosted endpoint today and at our own node later by changing one URL. It
//! makes no request that a plain node cannot answer.
//!
//! # The trust stance
//!
//! Running against a hosted API is a development posture, not the production
//! trust model. A hosted provider can lie about height, confirmations, or
//! whether an output exists, and this adapter cannot detect that. What it does
//! do is verify everything the protocol itself defines: the scriptPubKey bytes
//! are compared against the script we derived, the amount against the terms,
//! and the branch id against what the transaction was built for. So a provider
//! that reports the wrong *escrow* is caught; a provider that reports the wrong
//! *chain* is not. Section 14 of the spec says which criteria that leaves open.
//!
//! One consequence is worth stating separately, because it is the one that
//! costs money. **In hosted mode the attestor's chain view is the provider's
//! too.** The confirmation depth of section 7 is exactly the number the
//! provider is trusted for, so a provider that invented a confirmed output
//! could induce the attestor to sign for an escrow that does not exist - and
//! the LP, having already paid Venmo, is the party out of pocket. That is not a
//! reason to distrust any particular provider; it is a reason the production
//! attestor runs its own node.

use std::time::Duration;

use serde::Deserialize;

use crate::chain::{ChainClient, ChainError, Utxo};

/// Which network an endpoint serves. Checked against what the node reports, so
/// a testnet run cannot silently be pointed at mainnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    /// The value `getblockchaininfo` reports in its `chain` field.
    pub fn chain_field(&self) -> &'static str {
        match self {
            Network::Main => "main",
            Network::Test => "test",
        }
    }
}

/// How long to wait on a `sendrawtransaction` whose input the node cannot find.
///
/// R7-6: zebra holds such a submission for 60 s before answering `could not
/// find transparent input UTXO`, and the adapter's 30 s default timed out
/// first. That is not a corner case: an LP broadcasting a release against a
/// node one block behind the funding transaction hits exactly this, and reads
/// a timeout instead of the node's answer. Broadcast therefore gets its own,
/// longer budget.
pub const DEFAULT_BROADCAST_TIMEOUT: Duration = Duration::from_secs(90);

/// How many rate-limit waits one call will sit through before giving up.
///
/// The hosted endpoint's window is 60 s wide, so three retries covers a call
/// that arrives at the very start of a saturated window and then contends with
/// the attestor for the next two. Past that something other than pacing is
/// wrong and the caller should hear about it.
pub const DEFAULT_RATE_LIMIT_RETRIES: u32 = 3;

/// The wait when the response carries no `Retry-After`, which the measured
/// endpoint does not send. Its window is 5 requests per sliding 60 s, so a
/// full minute is what actually clears it; a shorter wait just burns another
/// request against the same window.
pub const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub url: String,
    /// Optional HTTP basic auth, as a local `zcashd` requires.
    pub user: Option<String>,
    pub password: Option<String>,
    /// Optional header for hosted providers that key on one, for example
    /// `x-api-key`.
    pub api_key_header: Option<(String, String)>,
    pub network: Network,
    /// Budget for reads.
    pub timeout: Duration,
    /// Budget for `sendrawtransaction`, which a node may sit on far longer
    /// than a read. See [`DEFAULT_BROADCAST_TIMEOUT`].
    pub broadcast_timeout: Duration,
    /// How many times to wait out a rate limit before giving up on one call.
    ///
    /// R12-1: the keyless hosted endpoint answers 5 requests per sliding
    /// minute and 429 after that, and the runner and the attestor share that
    /// window. A single `attest` makes more calls than that, so without this
    /// the run panics partway through, *after* the fiat has been sent. Zero
    /// disables the wait.
    pub rate_limit_retries: u32,
    /// How long to wait when the response carries no `Retry-After`.
    pub rate_limit_wait: Duration,
}

impl RpcConfig {
    /// A keyless endpoint, which is how the hosted development setup runs.
    pub fn public(url: impl Into<String>, network: Network) -> Self {
        Self {
            url: url.into(),
            user: None,
            password: None,
            api_key_header: None,
            network,
            timeout: Duration::from_secs(30),
            broadcast_timeout: DEFAULT_BROADCAST_TIMEOUT,
            rate_limit_retries: DEFAULT_RATE_LIMIT_RETRIES,
            rate_limit_wait: DEFAULT_RATE_LIMIT_WAIT,
        }
    }

    /// A hosted endpoint sized for a mainnet run.
    ///
    /// Reads on the hosted endpoint answer in about 0.22 s (measured
    /// 2026-09-02), so the read budget is generous rather than tight. Broadcast
    /// is the one that matters: zebra holds a spend whose input it cannot find
    /// for 60 s (R7-6), and a hosted provider adds its own hop, so the budget is
    /// 120 s.
    ///
    /// The provider's own limit is 5 requests a minute keyless. No timeout can
    /// fix that, but the adapter waits the window out and retries rather than
    /// failing the call: see `rate_limit_retries`. R12-1 staged the alternative
    /// and a single `attest` panicked partway through, after the fiat was
    /// already sent.
    pub fn hosted(url: impl Into<String>, network: Network) -> Self {
        Self {
            url: url.into(),
            user: None,
            password: None,
            api_key_header: None,
            network,
            timeout: Duration::from_secs(60),
            broadcast_timeout: Duration::from_secs(120),
            rate_limit_retries: DEFAULT_RATE_LIMIT_RETRIES,
            rate_limit_wait: DEFAULT_RATE_LIMIT_WAIT,
        }
    }

    /// A local node with cookie or `rpcuser` auth. This is the shape the real
    /// zebrad box will use, and nothing else about the adapter changes.
    pub fn local(url: impl Into<String>, user: &str, password: &str, network: Network) -> Self {
        Self {
            url: url.into(),
            user: Some(user.to_string()),
            password: Some(password.to_string()),
            api_key_header: None,
            network,
            timeout: Duration::from_secs(30),
            broadcast_timeout: DEFAULT_BROADCAST_TIMEOUT,
            rate_limit_retries: DEFAULT_RATE_LIMIT_RETRIES,
            rate_limit_wait: DEFAULT_RATE_LIMIT_WAIT,
        }
    }
}

pub struct RpcChainClient {
    config: RpcConfig,
    http: reqwest::blocking::Client,
    /// A second client with the longer broadcast budget, so a read cannot
    /// inherit it and a broadcast cannot be cut short by the read budget.
    broadcast_http: reqwest::blocking::Client,
    /// Set once the endpoint has confirmed it serves the configured network, so
    /// the check happens automatically rather than relying on a caller to
    /// remember it (round 2 finding 6).
    network_checked: std::sync::atomic::AtomicBool,
    /// How the client waits out a rate limit. Injectable so a test can prove
    /// the retry sequence without sitting through three real minutes.
    sleep: Box<dyn Fn(Duration) + Send + Sync>,
}

impl std::fmt::Debug for RpcChainClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Credentials must not reach a log (criterion 14 is about our own keys,
        // but an RPC password in a trace is the same class of mistake).
        f.debug_struct("RpcChainClient")
            .field("url", &self.config.url)
            .field("network", &self.config.network)
            .field("authenticated", &self.config.user.is_some())
            .field(
                "network_checked",
                &self
                    .network_checked
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Deserialize, Debug)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
    blocks: u32,
    consensus: Consensus,
}

#[derive(Deserialize)]
struct Consensus {
    /// The branch id in force at the chain tip, as 8 hex characters.
    chaintip: String,
}

#[derive(Deserialize)]
struct TxOut {
    confirmations: i64,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
    /// ZEC as a JSON number. Converted to zatoshis by the caller, carefully:
    /// see `zec_to_zat`.
    value: f64,
}

#[derive(Deserialize)]
struct ScriptPubKey {
    hex: String,
}

impl RpcChainClient {
    pub fn new(config: RpcConfig) -> Result<Self, ChainError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ChainError::Unreachable(e.to_string()))?;
        let broadcast_http = reqwest::blocking::Client::builder()
            .timeout(config.broadcast_timeout)
            .build()
            .map_err(|e| ChainError::Unreachable(e.to_string()))?;
        Ok(Self {
            config,
            http,
            broadcast_http,
            network_checked: std::sync::atomic::AtomicBool::new(false),
            sleep: Box::new(std::thread::sleep),
        })
    }

    /// Which endpoint this client talks to.
    ///
    /// For a caller holding several endpoints - see the coordinator's node pool
    /// - so it can say in a log which one answered. The string is the
    /// configured URL and may carry a key in its path, so a caller putting it
    /// anywhere a user or a log aggregator can read must redact it first.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Replaces the rate-limit wait, so a test can assert the retry sequence
    /// without sitting through three real minutes. The recorded durations are
    /// what the client would have slept.
    pub fn with_sleep(mut self, sleep: impl Fn(Duration) + Send + Sync + 'static) -> Self {
        self.sleep = Box::new(sleep);
        self
    }

    /// Runs [`check_network`] once, then remembers.
    ///
    /// Every trait method calls this first. Without it, pointing a testnet
    /// config at a mainnet URL is a typo that spends real money and nothing
    /// catches it unless the caller happens to have called `check_network`.
    fn ensure_network(&self) -> Result<(), ChainError> {
        use std::sync::atomic::Ordering;
        if self.network_checked.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.check_network()?;
        self.network_checked.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Confirms the endpoint serves the network the caller expects.
    ///
    /// Without this, pointing a testnet config at a mainnet URL is a
    /// configuration typo that spends real money.
    pub fn check_network(&self) -> Result<(), ChainError> {
        let info: ChainInfo = self.call("getblockchaininfo", serde_json::json!([]))?;
        if info.chain != self.config.network.chain_field() {
            return Err(ChainError::Unreachable(format!(
                "endpoint serves the {} chain, but this client is configured for {}",
                info.chain,
                self.config.network.chain_field()
            )));
        }
        Ok(())
    }

    fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ChainError> {
        self.call_with(&self.http, method, params)
    }

    fn call_with<T: serde::de::DeserializeOwned>(
        &self,
        http: &reqwest::blocking::Client,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ChainError> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "zecp2p",
            "method": method,
            "params": params,
        });

        // R12-1: the hosted endpoint allows 5 keyless requests per sliding
        // minute, and the runner and the attestor share that window. A single
        // `attest` makes more calls than that, so a rate limit hit partway
        // through used to abort the run *after* the fiat had been sent. Waiting
        // the window out and retrying is the only thing that makes the runbook
        // true as written; the alternative is asking an operator to count
        // seconds between commands with money already gone.
        let mut waits_left = self.config.rate_limit_retries;
        let (status, text) = loop {
            let mut req = http.post(&self.config.url).json(&body);
            if let (Some(u), Some(p)) = (&self.config.user, &self.config.password) {
                req = req.basic_auth(u, Some(p));
            }
            if let Some((name, value)) = &self.config.api_key_header {
                req = req.header(name.as_str(), value.as_str());
            }

            let response = req
                .send()
                .map_err(|e| ChainError::Unreachable(format!("{method}: {e}")))?;

            let status = response.status();
            let retry_after = retry_after_of(response.headers());
            let text = response
                .text()
                .map_err(|e| ChainError::Unreachable(format!("{method}: {e}")))?;

            if waits_left > 0 && is_rate_limited(status.as_u16(), &text) {
                waits_left -= 1;
                let wait = retry_after.unwrap_or(self.config.rate_limit_wait);
                (self.sleep)(wait);
                continue;
            }
            break (status, text);
        };

        if !status.is_success() {
            // A hosted provider's rate limit arrives here, and it is an
            // availability problem rather than a node verdict: the LP must not
            // read it as "the escrow does not exist".
            return Err(ChainError::Unreachable(format!(
                "{method}: HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            )));
        }

        let parsed: RpcResponse<T> = serde_json::from_str(&text).map_err(|e| {
            ChainError::Unreachable(format!(
                "{method}: could not parse response: {e}: {}",
                text.chars().take(200).collect::<String>()
            ))
        })?;

        if let Some(err) = parsed.error {
            // `Rejected` means *the chain refused this transaction*, and the LP
            // treats it as a verdict rather than something to retry. Only
            // `sendrawtransaction` can produce one. An error on a read call is
            // the provider or the node failing to answer - a method it does not
            // expose, a malformed request - and must read as unreachable, or a
            // provider outage would look like a chain decision (round 2
            // finding 6).
            let text = format!("{} (code {})", err.message, err.code);
            return Err(if method == "sendrawtransaction" {
                if is_not_yet(&err.message) {
                    ChainError::NotYet(text)
                } else {
                    ChainError::Rejected(text)
                }
            } else {
                ChainError::Unreachable(format!("{method}: {text}"))
            });
        }

        parsed
            .result
            .ok_or_else(|| ChainError::Unreachable(format!("{method}: null result and no error")))
    }

    /// As [`call`], but a `null` result is a legitimate answer rather than a
    /// fault.
    ///
    /// `gettxout` answers `null` for an output that does not exist or has been
    /// spent, and that is the common case for an escrow the LP is still waiting
    /// on. Routing it through `call` would report a working node as unreachable,
    /// and an unreachable node is what the LP escalates on - so a lock that had
    /// simply not been mined yet would page someone.
    fn call_nullable<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Option<T>, ChainError> {
        match self.call::<serde_json::Value>(method, params) {
            Ok(serde_json::Value::Null) => Ok(None),
            Ok(value) => serde_json::from_value(value)
                .map(Some)
                .map_err(|e| ChainError::Unreachable(format!("{method}: {e}"))),
            Err(ChainError::Unreachable(msg)) if msg.ends_with("null result and no error") => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Whether a `sendrawtransaction` refusal means "not yet" rather than "no".
///
/// R8-3: both of zebra's answers for an input it cannot find are temporary. The
/// first costs 60 s (measured); the second comes from its rejection cache and
/// is instant. Either clears when the missing input is mined, so a caller that
/// has already paid the fiat must retry rather than give up.
/// Whether this response is the provider's rate limit rather than a node
/// answer.
///
/// R12-1 measured both shapes from the hosted endpoint: a plain HTTP 429, and
/// a 503 whose body carries the upstream 429. Matching only the status code
/// would miss the second, which is the one that actually aborted the staged
/// `attest` run.
pub fn is_rate_limited(status: u16, body: &str) -> bool {
    if status == 429 {
        return true;
    }
    // A gateway wrapping the upstream limit. Only treat a 5xx this way when the
    // body names the limit, so a genuine node outage is not retried as one.
    //
    // R13-3: matching the bare digits "429" anywhere was too loose. A block
    // height like 3471429, an amount like 429000 or a txid beginning 429a
    // would all have bought three 60 s sleeps against a node that was simply
    // down. "429" now counts only as a standalone token, never as part of a
    // longer number or word.
    if (500..=599).contains(&status) {
        let b = body.to_lowercase();
        if b.contains("too many requests") || b.contains("rate limit") || b.contains("ratelimit")
        {
            return true;
        }
        return names_status_429(&b);
    }
    false
}

/// Whether the body names 429 *as an HTTP status*.
///
/// Standalone digits are not enough on their own: "block 429 is not on the
/// best chain" is an outage and "upstream returned 429" is a rate limit, and
/// both carry a bare 429. So the number must be its own token (never part of
/// a height like 3471429 or an amount like 429000) *and* sit next to a word
/// that makes it a status. Anything else is treated as an outage, which is the
/// safe way to be wrong: a missed rate limit costs one failed call, while a
/// misread outage costs three 60 s sleeps against a deadline.
fn names_status_429(haystack: &str) -> bool {
    const STATUS_WORDS: [&str; 7] = [
        "http", "status", "code", "returned", "error", "response", "upstream",
    ];
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(pos) = haystack[from..].find("429") {
        let start = from + pos;
        let end = start + 3;
        let standalone = (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
            && (end >= bytes.len() || !bytes[end].is_ascii_alphanumeric());
        if standalone {
            // Look back a short way for a word that makes this a status rather
            // than a height or an amount.
            let window = &haystack[start.saturating_sub(24)..start];
            if STATUS_WORDS.iter().any(|w| window.contains(w)) {
                return true;
            }
        }
        from = start + 3;
    }
    false
}

/// `Retry-After`, when the provider sends one, as either seconds or an HTTP
/// date. Capped so a hostile or confused value cannot park the run for hours
/// with a deadline approaching.
fn retry_after_of(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    const MAX: u64 = 120;
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let secs = raw.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(secs.min(MAX)))
}

/// Whether the node is saying it already holds this transaction.
///
/// zebra and zcashd both answer a re-broadcast this way, and neither is a
/// failure: the transaction is in the mempool or already mined.
pub fn is_already_accepted(message: &str) -> bool {
    let m = message.to_lowercase();
    m.contains("transaction already exists")
        || m.contains("already in mempool")
        || m.contains("already exists in mempool")
        || m.contains("committed to the best chain")
        || m.contains("txn-already-known")
        || m.contains("txn-already-in-mempool")
}

/// The txid of a signed transaction we are about to send or have just sent.
fn zecp2p_txid_of(raw_tx: &[u8]) -> Result<[u8; 32], ChainError> {
    crate::tx::txid_of_signed(raw_tx)
        .map_err(|e| ChainError::Unreachable(format!("could not parse our own release: {e}")))
}

fn is_not_yet(message: &str) -> bool {
    let m = message.to_lowercase();
    m.contains("could not find transparent input utxo")
        || m.contains("will be rejected from the mempool until the next chain tip block")
        || m.contains("already queued for download")
}

/// Converts a ZEC amount reported as a JSON number into zatoshis.
///
/// The RPC reports `value` in ZEC as a float, and 1.25 ZEC is not exactly
/// representable in binary floating point. Rounding to the nearest zatoshi is
/// correct because every real amount *is* an exact number of zatoshis; the
/// float is a lossy rendering of an integer, so rounding recovers it. Truncating
/// would turn 1.25 into 124999999 zat on some values and silently fail the
/// amount check.
pub fn zec_to_zat(value: f64) -> Result<u64, ChainError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ChainError::Unreachable(format!(
            "node reported a nonsensical amount: {value}"
        )));
    }
    let zat = (value * 1e8).round();
    if zat > u64::MAX as f64 {
        return Err(ChainError::Unreachable(format!(
            "node reported an amount out of range: {value}"
        )));
    }
    Ok(zat as u64)
}

/// Zcash RPC renders a txid as big-endian hex, the reverse of the byte order
/// used inside a transaction. Getting this backwards asks the node about an
/// outpoint that does not exist, which reads as "not yet mined" and stalls the
/// LP forever.
pub fn txid_to_rpc_hex(txid: &[u8; 32]) -> String {
    let mut reversed = *txid;
    reversed.reverse();
    hex::encode(reversed)
}

/// Parses a txid as a human reads it: the order every explorer, `getblock` and
/// `getrawtransaction` prints.
///
/// Round 10 finding 2: `escrow_e2e` and `fund_escrow` reversed their argument
/// while `paid_path` took it raw, so the same escrow needed two different
/// strings depending on the command, and the runbook documented the wrong one
/// for `refund`. Getting it backwards is not loud - the tool reports "the
/// escrow output must exist" or the attestor answers a 503 the LP is told to
/// retry - so every tool now takes this one order and converts internally.
pub fn txid_from_display(s: &str) -> Result<[u8; 32], ChainError> {
    rpc_hex_to_txid(s)
}

/// Renders a txid the way a human reads it, and the way every tool here now
/// accepts it. The same string round-trips through [`txid_from_display`].
pub fn txid_to_display(txid: &[u8; 32]) -> String {
    txid_to_rpc_hex(txid)
}

/// The inverse of [`txid_to_rpc_hex`].
pub fn rpc_hex_to_txid(s: &str) -> Result<[u8; 32], ChainError> {
    let bytes = hex::decode(s)
        .map_err(|e| ChainError::Unreachable(format!("bad txid hex from node: {e}")))?;
    if bytes.len() != 32 {
        return Err(ChainError::Unreachable(format!(
            "node returned a {}-byte txid",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out.reverse();
    Ok(out)
}

impl RpcChainClient {
    /// The scriptSig of a mined transaction's first input.
    ///
    /// For criterion 6: `sig_u` has to come out of the transaction the chain
    /// holds, not out of the runner's own memory, or the check proves only that
    /// the runner is self-consistent.
    pub fn release_script_sig(&self, txid_rpc_order: &str) -> Result<Vec<u8>, ChainError> {
        Ok(self.release_details(txid_rpc_order)?.script_sig)
    }

    /// What a mined release actually spends and pays.
    ///
    /// R11-8 / R12-5: `verify` recovered the outcome secret from a scriptSig
    /// without ever checking that the transaction it came from spends *this*
    /// escrow or pays the LP. Any transaction whose first input carried a
    /// two-signature scriptSig would have satisfied it, so a passing
    /// `CRITERION 6 HOLDS` proved less than it appeared to.
    pub fn release_details(&self, txid_rpc_order: &str) -> Result<ReleaseDetails, ChainError> {
        #[derive(serde::Deserialize)]
        struct Tx {
            vin: Vec<Vin>,
            vout: Vec<Vout>,
        }
        #[derive(serde::Deserialize)]
        struct Vin {
            txid: Option<String>,
            vout: Option<u32>,
            #[serde(rename = "scriptSig")]
            script_sig: ScriptSig,
        }
        #[derive(serde::Deserialize)]
        struct ScriptSig {
            hex: String,
        }
        #[derive(serde::Deserialize)]
        struct Vout {
            value: f64,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: Spk,
        }
        #[derive(serde::Deserialize)]
        struct Spk {
            hex: String,
        }

        let tx: Tx = self.call(
            "getrawtransaction",
            serde_json::json!([txid_rpc_order, 1]),
        )?;
        let vin = tx
            .vin
            .first()
            .ok_or_else(|| ChainError::Unreachable("the transaction has no inputs".into()))?;
        let script_sig = hex::decode(&vin.script_sig.hex)
            .map_err(|e| ChainError::Unreachable(format!("bad scriptSig hex: {e}")))?;
        if tx.vout.is_empty() {
            return Err(ChainError::Unreachable(
                "the transaction has no outputs".into(),
            ));
        }
        let mut outputs = Vec::with_capacity(tx.vout.len());
        for o in &tx.vout {
            outputs.push(ReleaseOutput {
                script_pubkey: hex::decode(&o.script_pubkey.hex)
                    .map_err(|e| ChainError::Unreachable(format!("bad scriptPubKey hex: {e}")))?,
                value_zat: zec_to_zat(o.value)?,
            });
        }

        Ok(ReleaseDetails {
            script_sig,
            spends_txid: vin.txid.clone(),
            spends_vout: vin.vout,
            outputs,
        })
    }
}

/// The parts of a mined release `verify` checks against the terms.
#[derive(Debug, Clone)]
pub struct ReleaseDetails {
    pub script_sig: Vec<u8>,
    /// The outpoint the first input spends, as the node prints it.
    pub spends_txid: Option<String>,
    pub spends_vout: Option<u32>,
    /// Every output, in the order the transaction carries them.
    ///
    /// All of them, not just the first. A fee-bearing release pays the LP and
    /// then the treasury, and a verify that read only `vout[0]` would report a
    /// release as sound without ever looking at where the platform cut went -
    /// which is the one output nobody else is watching.
    pub outputs: Vec<ReleaseOutput>,
}

/// One output of a mined release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseOutput {
    pub script_pubkey: Vec<u8>,
    pub value_zat: u64,
}

impl ReleaseDetails {
    /// The first output's script, which is the counterparty leg.
    pub fn pays_script_pubkey(&self) -> &[u8] {
        self.outputs.first().map(|o| o.script_pubkey.as_slice()).unwrap_or(&[])
    }

    /// The first output's value.
    pub fn pays_zat(&self) -> u64 {
        self.outputs.first().map(|o| o.value_zat).unwrap_or(0)
    }
}

impl ChainClient for RpcChainClient {
    fn height(&self) -> Result<u32, ChainError> {
        self.ensure_network()?;
        let info: ChainInfo = self.call("getblockchaininfo", serde_json::json!([]))?;
        Ok(info.blocks)
    }

    fn consensus_branch_id(&self) -> Result<u32, ChainError> {
        self.ensure_network()?;
        // Spec 4.3: read from the node, never hard-coded.
        let info: ChainInfo = self.call("getblockchaininfo", serde_json::json!([]))?;
        u32::from_str_radix(&info.consensus.chaintip, 16).map_err(|e| {
            ChainError::Unreachable(format!(
                "node reported an unparseable branch id {:?}: {e}",
                info.consensus.chaintip
            ))
        })
    }

    fn utxo(&self, txid: &[u8; 32], vout: u32) -> Result<Option<Utxo>, ChainError> {
        self.ensure_network()?;
        // `gettxout` returns null for an output that does not exist or has been
        // spent, and by default does not consider the mempool - which is what
        // the escrow wants, since an unconfirmed lock is not a lock.
        let out: Option<TxOut> = self.call_nullable(
            "gettxout",
            serde_json::json!([txid_to_rpc_hex(txid), vout, false]),
        )?;

        let Some(out) = out else { return Ok(None) };

        let script_pubkey = hex::decode(&out.script_pub_key.hex).map_err(|e| {
            ChainError::Unreachable(format!("node returned a bad scriptPubKey: {e}"))
        })?;

        // A negative confirmation count means the containing block is not on
        // the best chain. Treating that as zero is the safe reading: it can
        // never satisfy a depth requirement.
        let confirmations = u32::try_from(out.confirmations).unwrap_or(0);

        Ok(Some(Utxo {
            script_pubkey,
            amount_zat: zec_to_zat(out.value)?,
            confirmations,
        }))
    }

    fn broadcast(&self, raw_tx: &[u8]) -> Result<[u8; 32], ChainError> {
        self.ensure_network()?;
        let sent: Result<String, ChainError> = self.call_with(
            &self.broadcast_http,
            "sendrawtransaction",
            serde_json::json!([hex::encode(raw_tx)]),
        );
        match sent {
            Ok(txid) => rpc_hex_to_txid(&txid),
            // R11-5 / R10-7: a node saying it already has this transaction is
            // reporting success. Both answers mean the release is on chain or
            // in the mempool, which is exactly what we wanted; treating them as
            // rejections told the LP to "rerun attest to resend" a release that
            // had already been mined. The node returns no txid with these, so
            // compute it from the bytes we just sent.
            Err(ChainError::Rejected(text)) if is_already_accepted(&text) => {
                zecp2p_txid_of(raw_tx)
            }
            Err(e) => Err(e),
        }
    }
}
