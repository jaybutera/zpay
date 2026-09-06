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
    /// Per-order hard deadlines. Finding 3.
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    /// Intake bounds a stranger runs into. Finding 4.
    #[serde(default)]
    pub limits: LimitConfig,
    /// What the rail must hold before this coordinator reserves. Finding 5.
    #[serde(default)]
    pub float: FloatConfig,
    /// Where an operator hears about a stall. Finding 7.
    #[serde(default)]
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// What this coordinator calls itself in an alert.
    ///
    /// An LP may run more than one - a mainnet instance and a testnet one, or
    /// two hosts - and an alert that does not say which one it came from is an
    /// alert the operator has to go and identify. Configured rather than taken
    /// from the hostname, because two coordinators on one host is the case that
    /// needs telling apart. Empty falls back to the network name.
    #[serde(default)]
    pub instance_name: String,
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

    /// Further endpoints to fall back to, in order, when `rpc_url` fails.
    ///
    /// Finding 6: one hosted provider is one incident away from a coordinator
    /// that cannot read a height, and reading a height is what decides when a
    /// user is offered their refund. Each entry is a whole endpoint - its own
    /// URL, credentials and key - because providers do not share an auth
    /// scheme, and an operator running their own node beside a hosted one is
    /// the case this has to serve.
    ///
    /// Order is preference. `rpc_url` is always tried first; these follow it.
    /// Nothing here names a provider: which endpoints an LP uses is theirs.
    #[serde(default)]
    pub fallback_rpc: Vec<FallbackRpc>,

    /// How long to keep retrying an unreachable node at startup before giving
    /// up. Zero means the old behaviour: exit on the first failure.
    ///
    /// Finding 6: exiting made a provider incident during a restart into a
    /// restart loop, and a coordinator that is not running is a coordinator
    /// that does not offer anyone a refund. Waiting is strictly better: every
    /// deadline it serves is measured in tens of minutes.
    #[serde(default = "default_startup_retry_seconds")]
    pub startup_retry_seconds: u64,
}

/// One further RPC endpoint, with its own credentials.
///
/// The fields mirror `ZecConfig`'s because a fallback is a whole endpoint, not
/// a second URL onto the first one's auth. An LP whose primary is a hosted
/// provider keyed on a header and whose secondary is their own zcashd with a
/// cookie needs both shapes at once.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FallbackRpc {
    pub rpc_url: String,
    #[serde(default)]
    pub rpc_user: Option<String>,
    #[serde(default)]
    pub rpc_password: Option<String>,
    #[serde(default)]
    pub rpc_api_key_header: Option<String>,
    #[serde(default)]
    pub rpc_api_key: Option<String>,
    /// Name of an environment variable holding this endpoint's key, preferred
    /// over `rpc_api_key` for the same reason the primary prefers it.
    #[serde(default)]
    pub rpc_api_key_env: Option<String>,
}

/// A fallback endpoint's API key, environment first for the same reason the
/// primary's is: this file is readable by every local account.
fn fallback_api_key(extra: &FallbackRpc) -> Option<String> {
    if let Some(var) = &extra.rpc_api_key_env {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    extra
        .rpc_api_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn default_startup_retry_seconds() -> u64 {
    600
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
    /// USD per ZEC, fixed, when an operator deliberately pins one.
    ///
    /// Absent by default, and absent is the normal deployment: the rate comes
    /// from the live market through [`crate::price`]. This exists for a
    /// regtest or a rehearsal that must not depend on an exchange being up,
    /// and it is logged loudly at startup because a pinned rate is wrong the
    /// moment the market moves. `rate_usd_per_zec = 40.25` against a market
    /// near $1,022 is what this field used to be, unconditionally.
    #[serde(default)]
    pub rate_usd_per_zec: Option<f64>,
    /// The spread taken over the market price, in basis points.
    ///
    /// This is the LP's margin, and before it existed the LP captured none: a
    /// quote converted at the bare rate and the platform earned only
    /// `fee_bps`. The LP fronts dollars against a coin whose price moves while
    /// the escrow is open, so 50 bps (0.5%) is the default - wider than ZEC
    /// moves in the 45 s a price is cached, and narrower than the spread a
    /// user would pay on an exchange with a withdrawal.
    #[serde(default = "default_spread_bps")]
    pub spread_bps: u64,
    /// How long to wait on a price feed before giving up on it, in seconds.
    #[serde(default = "default_price_timeout_seconds")]
    pub price_timeout_seconds: u64,
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

fn default_spread_bps() -> u64 {
    50
}
fn default_price_timeout_seconds() -> u64 {
    10
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

/// Hard deadlines on the steps that can block forever. Finding 3.
///
/// Every one of these bounds a call into something this process does not
/// control: a browser, a child process, an attestation service, a node. The
/// sweep used to inherit whatever they did, so one wedged page stopped every
/// other order's funding scan and deadline check.
///
/// A timeout that fires is not a failure of the trade. It ends *this attempt*
/// so the next sweep can make another one; what it must never do is convert an
/// ambiguous payment into a confident answer, which is why the pay timeout is
/// generous and the ones around it are not.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    /// The ceiling on one whole `advance` for one order.
    ///
    /// The watchdog, not the fine-grained bound. It is longer than the sum of
    /// the specific timeouts below on purpose: it exists to catch a path that
    /// has no specific timeout at all, and firing it should mean a bug rather
    /// than a slow trade.
    #[serde(default = "default_order_advance_seconds")]
    pub order_advance_seconds: u64,

    /// The ceiling on the fiat rail's `pay`.
    ///
    /// The one number here that must not be tightened casually. Interrupting a
    /// browser mid-payment produces exactly the ambiguity the `Paying` journal
    /// line exists for: money that may or may not have moved, which costs an
    /// operator's attention rather than a retry. Sized to be longer than the
    /// rail's own internal waits, so the rail's specific error wins the race
    /// with this and the operator gets a reason rather than "timed out".
    #[serde(default = "default_pay_seconds")]
    pub pay_seconds: u64,

    /// The ceiling on getting a payment attested, which includes the enclave.
    ///
    /// Safe to cut short: attestation is a read, it is retried on the next
    /// sweep, and no money moves either way. The enclave is a `node` child
    /// process that had no timeout at all.
    #[serde(default = "default_attest_seconds")]
    pub attest_seconds: u64,

    /// The ceiling on one attempt at broadcasting a release.
    ///
    /// The broadcast loop retries until the escrow's own broadcast deadline,
    /// which is tens of minutes away, and it does that inside the sweep. This
    /// bounds one attempt; the deadline still bounds the whole effort, and the
    /// next sweep re-enters. An order whose release has not broadcast is not
    /// dropped by this - it is `Paid` on disk and re-entered every sweep.
    #[serde(default = "default_broadcast_seconds")]
    pub broadcast_seconds: u64,

    /// The ceiling on any single node call.
    #[serde(default = "default_node_call_seconds")]
    pub node_call_seconds: u64,

    /// How many orders the sweep advances at once.
    ///
    /// Finding 6: an unbounded fan-out over 200 open orders is hundreds of node
    /// calls arriving together, which is what a hosted provider answers with a
    /// 429. Bounded, the sweep takes longer and finishes; unbounded it is
    /// rate-limited into taking longer anyway, and the limiter's backoff is
    /// measured in minutes.
    #[serde(default = "default_sweep_concurrency")]
    pub sweep_concurrency: usize,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            order_advance_seconds: default_order_advance_seconds(),
            pay_seconds: default_pay_seconds(),
            attest_seconds: default_attest_seconds(),
            broadcast_seconds: default_broadcast_seconds(),
            node_call_seconds: default_node_call_seconds(),
            sweep_concurrency: default_sweep_concurrency(),
        }
    }
}

fn default_order_advance_seconds() -> u64 {
    900
}
fn default_pay_seconds() -> u64 {
    420
}
fn default_attest_seconds() -> u64 {
    180
}
fn default_broadcast_seconds() -> u64 {
    120
}
fn default_node_call_seconds() -> u64 {
    30
}
fn default_sweep_concurrency() -> usize {
    8
}

/// What a caller who has funded nothing can consume. Finding 4.
///
/// Opening an order is free and costs the LP capacity for the length of a
/// refund window. The guards that already exist - the open-order caps and the
/// same-amount-per-handle rule - are all keyed on orders that may never be
/// funded, so a caller with no coin at all can exhaust every one of them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitConfig {
    /// How long an order with no funding sighted may hold capacity.
    ///
    /// After this it is expired: dropped from the open-order counts, the
    /// per-handle count and the duplicate-amount guard, and no longer swept.
    /// It is not deleted - the record stays readable, so a user who funded it
    /// late is told what happened rather than getting a 404.
    ///
    /// The number is a judgement about how long a real user takes between
    /// getting an address and broadcasting to it. Long enough for a hardware
    /// wallet and a coffee; far short of the ~23 hours an unfunded order used
    /// to hold.
    #[serde(default = "default_unfunded_order_minutes")]
    pub unfunded_order_minutes: u64,

    /// Open orders one client address may hold at once. Zero disables.
    ///
    /// Per-IP rather than per-handle because the handle is the *payee*, which
    /// is not a caller identity: whoever opens the order chooses it, so a
    /// per-handle cap bounds who gets served rather than who is calling. An IP
    /// is a weak identity and this is a weak bound; it is the one available at
    /// this layer without asking users to hold an account.
    #[serde(default = "default_max_open_per_client")]
    pub max_open_per_client: usize,

    /// Order-opening requests one client address may make in `window_seconds`.
    /// Zero disables.
    ///
    /// Separate from the open-order cap because they stop different things.
    /// The open-order cap bounds standing capacity; this bounds the rate of
    /// *attempts*, including the ones that are refused - each of which still
    /// costs a quote, a curator call and a store scan.
    #[serde(default = "default_open_rate_per_client")]
    pub open_rate_per_client: u32,

    /// Order-opening requests from everyone in `window_seconds`. Zero disables.
    ///
    /// The backstop for the case the per-client limit cannot see: many clients,
    /// or one client behind many addresses.
    #[serde(default = "default_open_rate_global")]
    pub open_rate_global: u32,

    /// The window both rates are measured over.
    #[serde(default = "default_rate_window_seconds")]
    pub rate_window_seconds: u64,

    /// A header carrying the real client address, for a coordinator behind a
    /// proxy. Empty means trust the socket address.
    ///
    /// Off by default, and it must stay off unless a proxy actually rewrites
    /// it: a caller can set any header they like, so trusting one that is not
    /// overwritten upstream turns the rate limit into a header the attacker
    /// chooses. Which header depends on the LP's own relay, so it is named
    /// here rather than assumed.
    #[serde(default)]
    pub client_ip_header: Option<String>,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            unfunded_order_minutes: default_unfunded_order_minutes(),
            max_open_per_client: default_max_open_per_client(),
            open_rate_per_client: default_open_rate_per_client(),
            open_rate_global: default_open_rate_global(),
            rate_window_seconds: default_rate_window_seconds(),
            client_ip_header: None,
        }
    }
}

fn default_unfunded_order_minutes() -> u64 {
    45
}
fn default_max_open_per_client() -> usize {
    5
}
fn default_open_rate_per_client() -> u32 {
    10
}
fn default_open_rate_global() -> u32 {
    120
}
fn default_rate_window_seconds() -> u64 {
    60
}

/// What the fiat rail must be holding before this coordinator commits. Finding 5.
///
/// Nothing here names a payment provider. The rail reports a balance in cents
/// or reports that it cannot; this is the policy applied to that number, and it
/// is the LP's own risk appetite rather than anything protocol-side.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FloatConfig {
    /// Cents to keep back beyond the payment being made.
    ///
    /// A reserve rather than a floor at zero, because the balance read is a
    /// snapshot: a payment authorised on a balance that exactly covers it can
    /// still fail if anything else moved in between, and a failed payment
    /// mid-flight is the expensive kind.
    #[serde(default = "default_reserve_cents")]
    pub reserve_cents: u64,

    /// Warn when the balance falls below this. Zero disables.
    ///
    /// Distinct from `reserve_cents`: this is the number that should reach a
    /// human while trades are still being served, so the LP tops up before the
    /// refusals start rather than after.
    #[serde(default = "default_low_balance_cents")]
    pub low_balance_cents: u64,

    /// Whether to reserve the payment slot when the balance cannot be read.
    ///
    /// Defaults to permitting it. A rail that cannot report a balance is the
    /// normal case for a rail that has no such concept, and refusing there
    /// would make the balance check a requirement on every future rail rather
    /// than a capability. An LP whose rail *can* report and who wants an
    /// unreadable balance treated as empty sets this false.
    #[serde(default = "default_true")]
    pub pay_when_balance_unknown: bool,

    /// How long a balance reading is reused before the rail is asked again.
    ///
    /// The read costs a request against the rail on every reservation
    /// otherwise, and the balance does not move except when this coordinator
    /// moves it or the operator tops up.
    #[serde(default = "default_balance_cache_seconds")]
    pub balance_cache_seconds: u64,
}

impl Default for FloatConfig {
    fn default() -> Self {
        Self {
            reserve_cents: default_reserve_cents(),
            low_balance_cents: default_low_balance_cents(),
            pay_when_balance_unknown: true,
            balance_cache_seconds: default_balance_cache_seconds(),
        }
    }
}

fn default_reserve_cents() -> u64 {
    0
}
fn default_low_balance_cents() -> u64 {
    0
}
fn default_true() -> bool {
    true
}
fn default_balance_cache_seconds() -> u64 {
    120
}

/// How an operator hears that something is stuck. Finding 7.
///
/// One hook, run as a subprocess, receiving a JSON alert on stdin. A
/// subprocess rather than a built-in Telegram client because the destination is
/// the LP's own: a phone, a pager, a Matrix room, a webhook, a file. Baking one
/// service in would make every other LP's alerting a fork.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertConfig {
    /// The program to run. Empty means alerts are logged and not delivered.
    ///
    /// Run with no shell, so it is a program and its arguments rather than a
    /// command line: an alert body carrying a handle a stranger chose must not
    /// be able to reach `sh -c`.
    #[serde(default)]
    pub notify_command: Vec<String>,

    /// How long the hook may take before it is killed.
    #[serde(default = "default_notify_timeout_seconds")]
    pub notify_timeout_seconds: u64,

    /// The shortest gap between two alerts with the same key.
    ///
    /// The existing session keeper re-alerts every 20 minutes with no state,
    /// which means the first real incident buries the channel. Keyed
    /// suppression makes a stuck order one message and a reminder, not eighty.
    #[serde(default = "default_repeat_minutes")]
    pub repeat_minutes: u64,

    /// How long the payment slot may be held before it is an alert, and before
    /// `/health` calls itself degraded.
    #[serde(default = "default_slot_age_alert_minutes")]
    pub slot_age_minutes: u64,

    /// How long an order may sit paid-but-unreleased before it is an alert.
    ///
    /// This is the window where the dollars have gone and the escrow has not
    /// released, so it is the most expensive state on the board and the one
    /// with no automatic exit.
    #[serde(default = "default_paid_age_alert_minutes")]
    pub paid_age_minutes: u64,

    /// How long since the last completed sweep before it is an alert.
    ///
    /// A sweep that has not finished is not visible in any log line, which is
    /// how a wedged browser looked like nothing at all.
    #[serde(default = "default_sweep_age_alert_minutes")]
    pub sweep_age_minutes: u64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            notify_command: Vec::new(),
            notify_timeout_seconds: default_notify_timeout_seconds(),
            repeat_minutes: default_repeat_minutes(),
            slot_age_minutes: default_slot_age_alert_minutes(),
            paid_age_minutes: default_paid_age_alert_minutes(),
            sweep_age_minutes: default_sweep_age_alert_minutes(),
        }
    }
}

fn default_notify_timeout_seconds() -> u64 {
    20
}
fn default_repeat_minutes() -> u64 {
    30
}
fn default_slot_age_alert_minutes() -> u64 {
    20
}
fn default_paid_age_alert_minutes() -> u64 {
    20
}
fn default_sweep_age_alert_minutes() -> u64 {
    10
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

    /// Every RPC endpoint, primary first, in the order to try them.
    ///
    /// Finding 6. One endpoint was a single point of failure for the read that
    /// decides when a user is offered their refund, and the only recovery was
    /// an operator editing a config and restarting.
    ///
    /// The primary always leads. Fallbacks are tried in the order written,
    /// which is the operator's stated preference - typically their own node
    /// first among the fallbacks, or a second provider with a separate quota.
    pub fn rpc_configs(&self) -> Result<Vec<RpcConfig>> {
        let network = self.network()?;
        let mut all = vec![self.rpc_config()?];
        for extra in &self.zec.fallback_rpc {
            let mut rpc = match (&extra.rpc_user, &extra.rpc_password) {
                (Some(u), Some(p)) => RpcConfig::local(extra.rpc_url.clone(), u, p, network),
                _ => RpcConfig::hosted(extra.rpc_url.clone(), network),
            };
            if let (Some(header), Some(key)) = (&extra.rpc_api_key_header, fallback_api_key(extra))
            {
                rpc.api_key_header = Some((header.clone(), key));
            }
            all.push(rpc);
        }
        Ok(all)
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
        // A pinned rate is optional, but a pinned rate that is nonsense is not:
        // it would price every trade and nothing downstream re-checks it.
        if let Some(rate) = self.quote.rate_usd_per_zec {
            if !(rate.is_finite() && rate > 0.0) {
                bail!("quote.rate_usd_per_zec must be a positive number when it is set");
            }
            if !crate::price::is_plausible(rate) {
                bail!(
                    "quote.rate_usd_per_zec is {rate}, outside the plausible range {}-{}",
                    crate::price::MIN_PLAUSIBLE_USD,
                    crate::price::MAX_PLAUSIBLE_USD
                );
            }
        }
        // A spread at or above 100% would quote zero or a negative price.
        if self.quote.spread_bps >= 10_000 {
            bail!(
                "quote.spread_bps is {}; a spread of 100% or more leaves the user nothing",
                self.quote.spread_bps
            );
        }
        if self.quote.price_timeout_seconds == 0 {
            bail!("quote.price_timeout_seconds is zero; every price read would time out");
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
            timeouts: TimeoutConfig::default(),
            limits: LimitConfig::default(),
            float: FloatConfig::default(),
            alerts: AlertConfig::default(),
            server: ServerConfig {
                instance_name: String::new(),
                host: default_host(),
                port: default_port(),
                state_dir: "/tmp/v2coord-test".into(),
                allowed_origins: vec![],
                journal_path: None,
            },
            zec: ZecConfig {
                fallback_rpc: Vec::new(),
                startup_retry_seconds: 0,
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
                rate_usd_per_zec: Some(40.25),
                spread_bps: 50,
                price_timeout_seconds: 10,
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

    #[test]
    fn no_pinned_rate_is_valid_because_the_feed_supplies_it() {
        let mut c = base();
        c.quote.rate_usd_per_zec = None;
        c.validate()
            .expect("an absent rate is the normal deployment, not an error");
    }

    #[test]
    fn a_pinned_rate_must_still_be_a_plausible_number() {
        for bad in [0.0, -1.0, f64::NAN, 1e12] {
            let mut c = base();
            c.quote.rate_usd_per_zec = Some(bad);
            let err = c
                .validate()
                .expect_err("a nonsense pinned rate must be refused");
            assert!(
                err.to_string().contains("rate_usd_per_zec"),
                "a pinned rate of {bad} gave {err}"
            );
        }
    }

    #[test]
    fn a_spread_of_a_hundred_percent_or_more_is_refused() {
        // At 10,000 bps the user is quoted zero, and above it a negative
        // price. Neither can reach a quote.
        for bad in [10_000u64, 12_000] {
            let mut c = base();
            c.quote.spread_bps = bad;
            let err = c.validate().expect_err("a spread that eats the trade");
            assert!(err.to_string().contains("spread_bps"), "{bad} gave {err}");
        }
        let mut ok = base();
        ok.quote.spread_bps = 9_999;
        ok.validate().expect("just under 100% is still a number");
    }

    #[test]
    fn a_zero_price_timeout_is_refused() {
        let mut c = base();
        c.quote.price_timeout_seconds = 0;
        let err = c.validate().expect_err("a zero timeout refuses every read");
        assert!(err.to_string().contains("price_timeout_seconds"));
    }
}
