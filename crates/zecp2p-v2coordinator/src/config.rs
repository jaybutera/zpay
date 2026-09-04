//! What the coordinator is told, and what it refuses to start without.
//!
//! The refusals are the point of this module. A coordinator that started with
//! a missing attestor pin, an unbounded payment cap or an open handle list
//! would run, and would lose money in a way that looked like normal operation.
//! So every one of those is checked once, at load, with a message that names
//! the key to set.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use zecp2p_escrow::address::AddrNetwork;
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::funding::AddressNetwork;
use zecp2p_escrow::rpc::{Network, RpcConfig};

/// The whole configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoordinatorConfig {
    pub server: ServerConfig,
    pub zec: ZecConfig,
    pub attestor: AttestorConfig,
    pub lp: LpConfig,
    pub quote: QuoteConfig,
    pub serve: ServeConfig,
    #[serde(default)]
    pub venmo: VenmoConfig,
    #[serde(default)]
    pub zkp2p: Zkp2pConfig,
    #[serde(default)]
    pub attestation: AttestationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Where orders are persisted. An order that is not on disk before its
    /// address is shown is an escrow nobody can release or account for.
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    /// Origins allowed to call the API from a browser. Empty means same-origin
    /// only, which is what a deployment serving the page itself wants.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// The fill journal, which is also the payment slot.
    ///
    /// **This must be the same file the taker writes** (`taker.journal_path`)
    /// on any machine where both run. The slot exists because there is one
    /// Venmo balance and one feed; two daemons holding two journals hold two
    /// slots, and each will happily pay while the other is paying. That was
    /// R2-6: the defaults were `taker-fills.jsonl` and `fills.jsonl`, so the
    /// protection was real within each process and absent between them.
    ///
    /// Left unset it defaults under `state_dir`, which is correct only for a
    /// coordinator running alone.
    ///
    /// A leading `~/` is expanded, the way the taker expands its own
    /// `journal_path` - R3-6: documenting the difference was not enough, since
    /// a tilde in one file and a tilde in the other would have been two
    /// journals and two slots.
    #[serde(default)]
    pub journal_path: Option<String>,
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    3000
}
fn default_state_dir() -> String {
    "~/.zecp2p/v2coordinator".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZecConfig {
    pub rpc_url: String,
    #[serde(default)]
    pub rpc_user: Option<String>,
    #[serde(default)]
    pub rpc_password: Option<String>,
    #[serde(default)]
    pub rpc_api_key_header: Option<String>,
    /// The provider's API key, for a hosted endpoint that keys on a header.
    ///
    /// Prefer `rpc_api_key_env` over putting the key here. This config file is
    /// world-readable on the hub (644), and a key in it is a key every local
    /// account can read; the LP scalar is kept out of it for the same reason.
    #[serde(default)]
    pub rpc_api_key: Option<String>,
    /// Name of an environment variable holding the API key.
    ///
    /// Read in preference to `rpc_api_key`, so the key reaches the process
    /// through a 600 EnvironmentFile rather than through the config. Set but
    /// empty is treated as unset: an env file that failed to render should look
    /// like no key, not like a key that is the empty string.
    #[serde(default)]
    pub rpc_api_key_env: Option<String>,
    /// `main` or `test`. Never defaulted: a coordinator that guessed its
    /// network would quote mainnet prices against a testnet chain.
    pub network: String,
    #[serde(default = "default_refund_hours")]
    pub refund_hours: u32,
    #[serde(default = "default_block_seconds")]
    pub block_seconds: u32,
    /// How the funding output is discovered. See `funding.rs`.
    #[serde(default)]
    pub scanner: ScannerKind,
    /// How far back a block scan will walk when an order is reopened.
    #[serde(default = "default_scan_lookback")]
    pub scan_lookback_blocks: u32,
}

fn default_refund_hours() -> u32 {
    24
}
fn default_block_seconds() -> u32 {
    75
}
fn default_scan_lookback() -> u32 {
    200
}

/// Which funding-discovery strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    /// Walk blocks with `getblock` verbosity 2. Works on any node.
    #[default]
    BlockScan,
    /// `getaddressutxos`, which needs zcashd with `addressindex=1`.
    AddressIndex,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestorConfig {
    pub url: String,
    /// The bearer token for `/announce` and `/attest`.
    pub token: String,
    /// The attestor's public key, hex. Required on mainnet.
    ///
    /// The coordinator relays the announcement to the page, so a coordinator
    /// free to name the attestor could name one whose scalar it holds, and
    /// decrypt the user's pre-signature without ever paying. Pinning it here
    /// means the relay is checked against something configured out of band.
    #[serde(default)]
    pub pubkey: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LpConfig {
    /// Where the LP takes its leg of the release. A transparent address.
    pub payout_address: String,
    /// Environment variable holding the LP private key, 64 hex.
    #[serde(default = "default_key_env")]
    pub key_env: String,
    /// Keystore directory, used when `key_env` is unset.
    #[serde(default)]
    pub keystore_dir: Option<String>,
    #[serde(default = "default_key_label")]
    pub key_label: String,
}

fn default_key_env() -> String {
    "ZECP2P_LP_PRIV".into()
}
fn default_key_label() -> String {
    "v2coordinator-lp".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuoteConfig {
    /// USD per ZEC. A coordinator with no price cannot quote; there is no
    /// default, because a wrong default prices every trade.
    pub rate_usd_per_zec: f64,
    /// The platform fee in basis points. Zero disables the treasury output.
    #[serde(default = "default_fee_bps")]
    pub fee_bps: u64,
    #[serde(default = "default_min_zat")]
    pub min_zat: u64,
    pub max_zat: u64,
    /// How long a quote is honoured.
    #[serde(default = "default_quote_seconds")]
    pub quote_seconds: u64,
    /// The ceiling on a single Venmo payment, in cents. The last line against
    /// a units/dollars confusion; `money::payment_cents` refuses above it.
    pub max_payment_cents: u64,
    /// The most orders that may be open at once.
    ///
    /// An order costs a file, a scan of an address on every sweep, and a slot
    /// in the operator's attention. Nothing stops a caller opening them in a
    /// loop, and they cannot be evicted: an order this process forgets is an
    /// escrow whose release nobody can assemble, so the bound goes at the door.
    #[serde(default = "default_max_open_orders")]
    pub max_open_orders: usize,
    /// The most open orders for any one Venmo handle.
    #[serde(default = "default_max_open_per_handle")]
    pub max_open_per_handle: usize,
}

fn default_fee_bps() -> u64 {
    zecp2p_escrow::treasury::PLATFORM_FEE_BPS
}
fn default_min_zat() -> u64 {
    zecp2p_escrow::client::MINIMUM_ESCROW_ZAT
}
fn default_quote_seconds() -> u64 {
    300
}
fn default_max_open_orders() -> usize {
    200
}
fn default_max_open_per_handle() -> usize {
    5
}

/// Whose escrows this coordinator will front fiat for.
///
/// The Base rail calls this `only_user` and defaults it to "everyone", with a
/// warning. That default is the liquidity business entered by accident, so
/// here it is inverted: an empty handle list with `allow_any_handle` unset
/// refuses every order, and the operator has to say who it serves.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServeConfig {
    #[serde(default)]
    pub allow_any_handle: bool,
    #[serde(default)]
    pub handles: Vec<String>,
    /// Whether the fiat leg actually clicks send. `false` drives the browser
    /// and stops at the irreversible step.
    #[serde(default)]
    pub live_payments: bool,
}

impl ServeConfig {
    /// Whether this coordinator will open an order for `handle`.
    pub fn serves(&self, handle: &str) -> bool {
        if self.allow_any_handle {
            return true;
        }
        self.handles
            .iter()
            .any(|h| h.trim().trim_start_matches('@').eq_ignore_ascii_case(handle))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VenmoConfig {
    #[serde(default = "default_cdp")]
    pub cdp_url: String,
    #[serde(default = "default_note")]
    pub note: String,
    #[serde(default = "default_venmo_timeout")]
    pub timeout_seconds: u64,
    /// The stored enclave session material.
    #[serde(default = "default_session_path")]
    pub session_path: String,
    #[serde(default = "default_session_age")]
    pub session_max_age_hours: i64,
    #[serde(default)]
    pub sender_id: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

impl Default for VenmoConfig {
    fn default() -> Self {
        Self {
            cdp_url: default_cdp(),
            note: default_note(),
            timeout_seconds: default_venmo_timeout(),
            session_path: default_session_path(),
            session_max_age_hours: default_session_age(),
            sender_id: None,
            user_agent: None,
        }
    }
}

fn default_cdp() -> String {
    "http://127.0.0.1:9222".into()
}
fn default_note() -> String {
    "thanks".into()
}
fn default_venmo_timeout() -> u64 {
    120
}
fn default_session_path() -> String {
    "venmo-session.json".into()
}
fn default_session_age() -> i64 {
    12
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Zkp2pConfig {
    #[serde(default = "default_curator")]
    pub api_url: String,
}

impl Default for Zkp2pConfig {
    fn default() -> Self {
        Self {
            api_url: default_curator(),
        }
    }
}

fn default_curator() -> String {
    "https://api.zkp2p.xyz".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationConfig {
    #[serde(default = "default_attestation_url")]
    pub service_url: String,
    /// The `UnifiedPaymentVerifier` the enclave signs for.
    #[serde(default = "default_verifier")]
    pub verifier: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    /// The repository root, which is where the pinned prover script lives.
    #[serde(default)]
    pub repo_root: Option<String>,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            service_url: default_attestation_url(),
            verifier: default_verifier(),
            chain_id: default_chain_id(),
            repo_root: None,
        }
    }
}

fn default_attestation_url() -> String {
    "https://attestation-service.zkp2p.xyz".into()
}
fn default_verifier() -> String {
    format!(
        "0x{}",
        hex::encode(zecp2p_escrow::attestation::DOMAIN_VERIFYING_CONTRACT)
    )
}
fn default_chain_id() -> u64 {
    zecp2p_escrow::attestation::DOMAIN_CHAIN_ID
}

impl CoordinatorConfig {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read the config at {path}"))?;
        let mut config: Self =
            toml::from_str(&text).with_context(|| format!("could not parse {path}"))?;
        config.apply_env();
        config.validate()?;
        Ok(config)
    }

    /// Secrets come from the environment, never from a file that might be
    /// committed.
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("ZECP2P_ATTESTOR_TOKEN") {
            if !v.is_empty() {
                self.attestor.token = v;
            }
        }
        if let Ok(v) = std::env::var("ZECP2P_ATTESTOR_URL") {
            if !v.is_empty() {
                self.attestor.url = v;
            }
        }
        if let Ok(v) = std::env::var("ZECP2P_RPC_URL") {
            if !v.is_empty() {
                self.zec.rpc_url = v;
            }
        }
        if let Ok(v) = std::env::var("ZKP2P_API_URL") {
            if !v.is_empty() {
                self.zkp2p.api_url = v;
            }
        }
    }

    pub fn network(&self) -> Result<Network> {
        match self.zec.network.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Ok(Network::Main),
            "test" | "testnet" | "regtest" => Ok(Network::Test),
            other => bail!("zec.network is {other:?}; it must be \"main\" or \"test\""),
        }
    }

    /// The decoding network, which is what `treasury` and `AcceptedQuote` take.
    pub fn addr_network(&self) -> Result<AddrNetwork> {
        Ok(match self.network()? {
            Network::Main => AddrNetwork::Main,
            Network::Test => AddrNetwork::Test,
        })
    }

    /// The encoding network, which is what `funding::escrow_address` takes.
    /// Two enums for the two directions; the escrow crate keeps them separate.
    pub fn address_network(&self) -> Result<AddressNetwork> {
        Ok(match self.network()? {
            Network::Main => AddressNetwork::Main,
            Network::Test => AddressNetwork::Test,
        })
    }

    pub fn policy(&self) -> Result<EscrowPolicy> {
        EscrowPolicy::from_refund_hours(self.zec.block_seconds, self.zec.refund_hours)
            .map_err(|e| anyhow::anyhow!("zec.refund_hours and zec.block_seconds disagree: {e}"))
    }

    pub fn rpc_config(&self) -> Result<RpcConfig> {
        let network = self.network()?;
        let mut rpc = match (&self.zec.rpc_user, &self.zec.rpc_password) {
            (Some(u), Some(p)) => RpcConfig::local(self.zec.rpc_url.clone(), u, p, network),
            _ => RpcConfig::hosted(self.zec.rpc_url.clone(), network),
        };
        if let (Some(header), Some(key)) = (&self.zec.rpc_api_key_header, self.rpc_api_key()) {
            rpc.api_key_header = Some((header.clone(), key));
        }
        Ok(rpc)
    }

    /// The RPC API key, from the environment when a variable is named for it.
    ///
    /// `rpc_api_key_env` wins over the inline `rpc_api_key` so a deployment can
    /// keep the key out of a world-readable config without having to delete the
    /// inline field first. An empty or whitespace-only value counts as unset.
    pub fn rpc_api_key(&self) -> Option<String> {
        if let Some(var) = &self.zec.rpc_api_key_env {
            if let Ok(v) = std::env::var(var) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        self.zec
            .rpc_api_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    }

    pub fn state_dir(&self) -> PathBuf {
        expand_home(&self.server.state_dir)
    }

    /// Where the fill journal lives. See [`ServerConfig::journal_path`].
    pub fn journal_path(&self) -> PathBuf {
        match &self.server.journal_path {
            Some(p) => expand_home(p),
            None => self.state_dir().join("fills.jsonl"),
        }
    }

    /// Everything that must be true before the first order is taken.
    pub fn validate(&self) -> Result<()> {
        let network = self.network()?;
        self.policy()?;

        // The mainnet attestor pin. The same refusal the taker makes, and for
        // the same reason: this process relays the announcement to the page,
        // so it must not also be free to choose whose announcement that is.
        if network == Network::Main && self.attestor.pubkey.is_none() {
            bail!(
                "attestor.pubkey is unset on a mainnet coordinator. This process relays \
                 the attestor's announcement to the page, so an unpinned key means the \
                 coordinator could name an attestor whose scalar it holds and decrypt \
                 the user's pre-signature without paying. Pin it before serving mainnet."
            );
        }
        if let Some(p) = &self.attestor.pubkey {
            let raw = hex::decode(p.trim())
                .context("attestor.pubkey is not hex")?;
            secp256k1_zkp::PublicKey::from_slice(&raw)
                .context("attestor.pubkey is not a compressed secp256k1 point")?;
        }

        if self.attestor.token.trim().is_empty() {
            bail!(
                "attestor.token is empty. Set ZECP2P_ATTESTOR_TOKEN; /announce and \
                 /attest both need it, and an escrow that cannot be announced cannot \
                 be released."
            );
        }

        // Who this coordinator fronts fiat for. Unlike the Base rail's
        // `only_user`, silence here refuses rather than serves.
        if !self.serve.allow_any_handle && self.serve.handles.is_empty() {
            bail!(
                "serve.handles is empty and serve.allow_any_handle is false, so this \
                 coordinator would refuse every order. Name the handles it serves, or \
                 set allow_any_handle deliberately - that is the liquidity business, \
                 and it fronts real dollars for strangers."
            );
        }

        if self.quote.max_payment_cents == 0 {
            bail!("quote.max_payment_cents is zero; every payment would be refused");
        }
        if self.quote.max_open_orders == 0 || self.quote.max_open_per_handle == 0 {
            bail!("quote.max_open_orders and max_open_per_handle must be at least 1");
        }
        if !(self.quote.rate_usd_per_zec.is_finite() && self.quote.rate_usd_per_zec > 0.0) {
            bail!("quote.rate_usd_per_zec must be a positive number");
        }
        if self.quote.min_zat < zecp2p_escrow::client::MINIMUM_ESCROW_ZAT {
            bail!(
                "quote.min_zat is {} but the escrow crate refuses anything under {}",
                self.quote.min_zat,
                zecp2p_escrow::client::MINIMUM_ESCROW_ZAT
            );
        }
        if self.quote.max_zat < self.quote.min_zat {
            bail!("quote.max_zat is below quote.min_zat");
        }

        // The LP payout address must decode on this network, or every release
        // pays a script nobody holds a key for.
        zecp2p_escrow::address::script_pubkey_for(
            self.lp.payout_address.trim(),
            self.addr_network()?,
        )
        .map_err(|e| anyhow::anyhow!("lp.payout_address is not usable: {e}"))?;

        // Every service this process trusts must be reachable over TLS. The
        // curator matters most: anyone who can answer a plaintext request to it
        // returns any payee hash they like, and the dollars go to their handle.
        for (name, url) in [
            ("zkp2p.api_url", &self.zkp2p.api_url),
            ("attestation.service_url", &self.attestation.service_url),
            ("attestor.url", &self.attestor.url),
            ("zec.rpc_url", &self.zec.rpc_url),
        ] {
            require_secure_url(name, url)?;
        }

        Ok(())
    }
}

/// Refuses a plaintext URL to anything but loopback.
fn require_secure_url(name: &str, url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        if is_loopback_authority(rest) {
            return Ok(());
        }
        bail!(
            "{name} is {trimmed}, which is plaintext to a host that is not loopback. \
             Anyone who can answer it chooses what this coordinator believes."
        );
    }
    bail!("{name} is {trimmed}, which is not an http(s) URL")
}

/// Whether the authority of a URL names this machine.
///
/// Split out and tested because getting it wrong fails **open**: a host this
/// reads as loopback is a host allowed to answer the curator in plaintext, and
/// whoever answers the curator chooses which Venmo handle gets the dollars.
fn is_loopback_authority(rest: &str) -> bool {
    // Everything before the first `/`, `?` or `#` is the authority.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Credentials, if any, come before the last `@`.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);

    // A bracketed IPv6 literal keeps its colons; anything else loses a port.
    let host = if let Some(end) = host_port.find(']') {
        host_port
            .strip_prefix('[')
            .map(|h| &h[..end.saturating_sub(1)])
            .unwrap_or(host_port)
    } else {
        host_port.split(':').next().unwrap_or_default()
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// `~/x` against `$HOME`, so a config can name a home-relative path.
pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique env var per test: these run in one process on many threads, and
    /// a shared name makes the set/unset pairs race each other.
    fn env_name(tag: &str) -> String {
        format!("ZECP2P_TEST_RPC_KEY_{tag}")
    }

    #[test]
    fn the_key_comes_from_the_environment_when_a_variable_is_named() {
        let mut c = base();
        let var = env_name("FROM_ENV");
        std::env::set_var(&var, "sk-live-from-env");
        c.zec.rpc_api_key_env = Some(var.clone());
        c.zec.rpc_api_key_header = Some("x-api-key".into());

        assert_eq!(c.rpc_api_key().as_deref(), Some("sk-live-from-env"));
        let rpc = c.rpc_config().expect("rpc config");
        assert_eq!(
            rpc.api_key_header,
            Some(("x-api-key".to_string(), "sk-live-from-env".to_string()))
        );
        std::env::remove_var(&var);
    }

    #[test]
    fn the_environment_wins_over_a_key_written_into_the_config() {
        // The point of the env var is keeping the key out of a world-readable
        // file. If a stale inline key could win, that would silently keep using
        // the one in the file.
        let mut c = base();
        let var = env_name("WINS");
        std::env::set_var(&var, "the-env-one");
        c.zec.rpc_api_key_env = Some(var.clone());
        c.zec.rpc_api_key = Some("the-config-one".into());
        assert_eq!(c.rpc_api_key().as_deref(), Some("the-env-one"));
        std::env::remove_var(&var);
    }

    #[test]
    fn an_empty_environment_value_reads_as_no_key_at_all() {
        // An env file that failed to render leaves the variable set and empty.
        // That must look like no key, not like a key that is the empty string:
        // an empty `x-api-key` header is a request the provider rejects, and
        // the failure would look like a bad key rather than a missing one.
        let mut c = base();
        let var = env_name("EMPTY");
        std::env::set_var(&var, "   ");
        c.zec.rpc_api_key_env = Some(var.clone());
        c.zec.rpc_api_key = None;
        assert_eq!(c.rpc_api_key(), None);

        let rpc = c.rpc_config().expect("rpc config");
        assert_eq!(rpc.api_key_header, None, "no header rather than an empty one");
        std::env::remove_var(&var);
    }

    #[test]
    fn a_header_without_a_key_sends_no_header() {
        // Both halves or neither: a header name with nothing behind it would
        // send `x-api-key:` empty on every call.
        let mut c = base();
        c.zec.rpc_api_key_header = Some("x-api-key".into());
        c.zec.rpc_api_key = None;
        c.zec.rpc_api_key_env = None;
        let rpc = c.rpc_config().expect("rpc config");
        assert_eq!(rpc.api_key_header, None);
    }

    fn base() -> CoordinatorConfig {
        CoordinatorConfig {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                state_dir: "/tmp/v2coord-test".into(),
                allowed_origins: vec![],
                journal_path: None,
            },
            zec: ZecConfig {
                rpc_url: "http://127.0.0.1:18232".into(),
                rpc_user: None,
                rpc_password: None,
                rpc_api_key_header: None,
                rpc_api_key: None,
                rpc_api_key_env: None,
                network: "test".into(),
                refund_hours: 24,
                block_seconds: 75,
                scanner: ScannerKind::BlockScan,
                scan_lookback_blocks: 200,
            },
            attestor: AttestorConfig {
                url: "http://127.0.0.1:8480".into(),
                token: "token".into(),
                pubkey: None,
            },
            lp: LpConfig {
                payout_address: "tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn".into(),
                key_env: default_key_env(),
                keystore_dir: None,
                key_label: default_key_label(),
            },
            quote: QuoteConfig {
                rate_usd_per_zec: 40.25,
                fee_bps: 20,
                min_zat: 120_000,
                max_zat: 5_000_000_000,
                quote_seconds: 300,
                max_payment_cents: 2500,
                max_open_orders: default_max_open_orders(),
                max_open_per_handle: default_max_open_per_handle(),
            },
            serve: ServeConfig {
                allow_any_handle: false,
                handles: vec!["alice".into()],
                live_payments: false,
            },
            venmo: VenmoConfig::default(),
            zkp2p: Zkp2pConfig::default(),
            attestation: AttestationConfig::default(),
        }
    }

    #[test]
    fn a_testnet_coordinator_with_the_basics_validates() {
        base().validate().expect("this config is complete");
    }

    #[test]
    fn mainnet_refuses_without_a_pinned_attestor() {
        // The coordinator relays the announcement. An unpinned key means it
        // could relay one whose scalar it holds.
        let mut c = base();
        c.zec.network = "main".into();
        c.lp.payout_address = "t1KsMuAZ3nDPqBcVUiCF6zL2NDHqTMcvKYd".into();
        let err = c.validate().expect_err("mainnet must refuse");
        assert!(
            err.to_string().contains("attestor.pubkey is unset"),
            "the message must name the key to set, got: {err}"
        );
    }

    #[test]
    fn an_empty_serve_list_refuses_rather_than_serving_everyone() {
        // The inverse of the Base rail's `only_user` default. Silence here
        // must not mean "front fiat for strangers".
        let mut c = base();
        c.serve.handles.clear();
        let err = c.validate().expect_err("an empty list must refuse");
        assert!(err.to_string().contains("serve.handles is empty"));

        // And naming the posture explicitly is allowed.
        c.serve.allow_any_handle = true;
        c.validate().expect("an explicit choice is honoured");
    }

    #[test]
    fn the_handle_gate_is_case_insensitive_and_ignores_the_at() {
        let c = base();
        assert!(c.serve.serves("alice"));
        assert!(c.serve.serves("Alice"));
        assert!(!c.serve.serves("mallory"));

        let mut open = base();
        open.serve.allow_any_handle = true;
        assert!(open.serve.serves("anyone-at-all"));
    }

    #[test]
    fn a_plaintext_curator_is_refused_but_loopback_is_not() {
        // NEW-2's hole: anyone answering a plaintext curator request returns
        // any payee hash they like, and the dollars go to their handle.
        let mut c = base();
        c.zkp2p.api_url = "http://api.zkp2p.xyz".into();
        let err = c.validate().expect_err("plaintext must refuse");
        assert!(err.to_string().contains("zkp2p.api_url"));

        c.zkp2p.api_url = "http://127.0.0.1:8080".into();
        c.validate().expect("loopback is how a local run works");
    }

    #[test]
    fn a_payout_address_from_the_wrong_network_is_refused() {
        // A mainnet address on a testnet coordinator decodes to a hash nobody
        // on this chain holds a key for, and every release would be unspendable.
        let mut c = base();
        c.lp.payout_address = "t1KsMuAZ3nDPqBcVUiCF6zL2NDHqTMcvKYd".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn only_real_loopback_authorities_are_allowed_in_plaintext() {
        // This check fails open: a host read as loopback may answer the curator
        // over plaintext, and whoever answers the curator names the Venmo
        // handle the dollars go to.
        for ok in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://localhost:3000/v2",
            "http://[::1]:8480",
            "http://user:pass@127.0.0.1:9000",
        ] {
            assert!(
                require_secure_url("t", ok).is_ok(),
                "{ok} is loopback and should be allowed"
            );
        }

        for bad in [
            // The classic: a hostname that merely *contains* localhost.
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            // Credentials that look like loopback, on a remote host.
            "http://127.0.0.1@evil.com/v2",
            "http://localhost@evil.com",
            // A path that starts with a loopback-looking segment.
            "http://evil.com/127.0.0.1",
            "http://api.zkp2p.xyz",
            "ftp://127.0.0.1",
        ] {
            assert!(
                require_secure_url("t", bad).is_err(),
                "{bad} is not loopback and must be refused"
            );
        }
    }

    #[test]
    fn the_journal_path_is_configurable_so_it_can_be_shared_with_the_taker() {
        // R2-6: the slot is only a slot if both daemons write one file. The
        // coordinator defaulted to `<state_dir>/fills.jsonl` and the taker to
        // `taker-fills.jsonl`, so the protection was real inside each process
        // and absent between them.
        let mut c = base();
        c.server.state_dir = "/tmp/v2coord-test".into();
        assert_eq!(
            c.journal_path(),
            std::path::PathBuf::from("/tmp/v2coord-test/fills.jsonl"),
            "the default lives under state_dir"
        );

        c.server.journal_path = Some("/var/lib/zecp2p/fills.jsonl".into());
        assert_eq!(
            c.journal_path(),
            std::path::PathBuf::from("/var/lib/zecp2p/fills.jsonl"),
            "an explicit path is used as given, so it can name the taker's file"
        );
    }

    #[test]
    fn a_minimum_below_the_crates_own_is_refused() {
        let mut c = base();
        c.quote.min_zat = 1000;
        let err = c.validate().expect_err("below the crate minimum");
        assert!(err.to_string().contains("min_zat"));
    }
}
