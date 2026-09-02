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
    pub timeout: Duration,
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
        }
    }
}

pub struct RpcChainClient {
    config: RpcConfig,
    http: reqwest::blocking::Client,
}

impl std::fmt::Debug for RpcChainClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Credentials must not reach a log (criterion 14 is about our own keys,
        // but an RPC password in a trace is the same class of mistake).
        f.debug_struct("RpcChainClient")
            .field("url", &self.config.url)
            .field("network", &self.config.network)
            .field("authenticated", &self.config.user.is_some())
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
        Ok(Self { config, http })
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
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "zecp2p",
            "method": method,
            "params": params,
        });

        let mut req = self.http.post(&self.config.url).json(&body);
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
        let text = response
            .text()
            .map_err(|e| ChainError::Unreachable(format!("{method}: {e}")))?;

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
            // A node's own verdict. `sendrawtransaction` reports an invalid
            // signature here, which is what criterion 12 is asking to see.
            return Err(ChainError::Rejected(format!(
                "{} (code {})",
                err.message, err.code
            )));
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

impl ChainClient for RpcChainClient {
    fn height(&self) -> Result<u32, ChainError> {
        let info: ChainInfo = self.call("getblockchaininfo", serde_json::json!([]))?;
        Ok(info.blocks)
    }

    fn consensus_branch_id(&self) -> Result<u32, ChainError> {
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
        let txid: String =
            self.call("sendrawtransaction", serde_json::json!([hex::encode(raw_tx)]))?;
        rpc_hex_to_txid(&txid)
    }
}
