//! What the process holds: the LP key, the node, the attestor, the browser.
//!
//! The escrow crate is entirely blocking and this is a tokio binary, so every
//! chain and attestor call goes through `spawn_blocking`. `RpcChainClient` is
//! built inside each closure rather than shared, which is what the taker does
//! and for the same reason: it is not built to cross that boundary.

use std::sync::Arc;

use anyhow::{Context, Result};
use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};

use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::rpc::{RpcChainClient, RpcConfig};

use crate::config::CoordinatorConfig;
use crate::funding::{FundingScanner, NodeRpc};
use crate::store::OrderStore;

/// How long a chain head read stays usable.
///
/// Well under one block (`zec.block_seconds`, 75 s in the deployed config), so
/// a cached head is the same head the node would report, not an older one. The
/// point is the request *rate*: this caps node reads for the head at two a
/// minute no matter how many pages are open, which is what keeps the keyless
/// hosted endpoint under its limit.
pub const CHAIN_HEAD_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long one sweep's mempool listing is reused.
///
/// This is a within-sweep cache, not a stale-tolerance setting: 20 s is under
/// every poll interval this runs at, so orders in the same sweep share one
/// reading and the next sweep takes a fresh one. A missed sighting costs a
/// sweep of latency on collecting a signature, never correctness - the mempool
/// is only ever used to announce, and the funding record still comes from a
/// block.
pub const MEMPOOL_TTL: std::time::Duration = std::time::Duration::from_secs(20);

/// How the coordinator settles the fiat leg.
///
/// A trait so a test can run the whole flow without a browser or an enclave.
/// The production binary builds the browser-backed implementation; nothing
/// here can settle a trade without a real payment unless the test double is
/// deliberately installed.
#[async_trait::async_trait]
pub trait FiatRail: Send + Sync {
    /// Whether this rail could send a payment right now.
    ///
    /// Checked **before** the journal entry and before `pay`, so that a rail
    /// which cannot even start - no browser, no stored session - produces a
    /// wait rather than a failure. That distinction is the difference between
    /// an escrow the user refunds at `T` and an escrow parked in a terminal
    /// state saying "a payment may have left" when nothing could have.
    ///
    /// It must not have side effects, and it must not be treated as a promise:
    /// `pay` can still fail after it passes, and that failure *is* ambiguous.
    async fn preflight(&self) -> Result<()> {
        Ok(())
    }

    /// Sends the dollars. The caller has already written its journal entry.
    async fn pay(&self, leg: &zecp2p_taker::auto::rail::FiatLeg) -> Result<PaidFiat>;

    /// Gets the payment attested by the enclave.
    async fn attest(
        &self,
        leg: &zecp2p_taker::auto::rail::FiatLeg,
    ) -> Result<zecp2p_escrow::lp_client::WireAttestation>;
}

/// What a fiat leg reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidFiat {
    pub cents: u64,
    /// False when the rail stopped at the irreversible step.
    pub fiat_left: bool,
    /// The note this rail actually typed into the payment.
    ///
    /// Recorded rather than re-derived, because the attestation happens on a
    /// later sweep - possibly under a later binary - and what the feed will
    /// hold is what *this* run typed, not what the code reading it would type
    /// now. An order paid by a build that wrote a bare configured note and
    /// attested by a build that appends a tag would otherwise be searched for
    /// under a tag its feed entry does not carry, and every sweep would refuse
    /// with the dollars already gone and the payment slot held.
    ///
    /// `None` from a rail that does not report one, which reads the same way as
    /// an order paid before this field existed: matched on amount and receiver.
    pub note: Option<String>,
}

/// Everything the handlers and the driver share.
pub struct AppState {
    pub config: CoordinatorConfig,
    pub store: OrderStore,
    pub quotes: Arc<std::sync::Mutex<std::collections::HashMap<String, crate::order::Quote>>>,
    pub policy: EscrowPolicy,
    pub rpc: RpcConfig,
    pub scanner: Arc<dyn FundingScanner>,
    pub http: reqwest::Client,
    /// The ZEC/USD price, cached for [`crate::price::PRICE_TTL`].
    ///
    /// Shares the reasoning of `chain_head_cache` below: it holds a value that
    /// was read, never one that was assumed, and it is empty until a real read
    /// succeeds. An empty or expired cache means the coordinator refuses to
    /// quote rather than pricing a trade on a guess.
    pub prices: Arc<crate::price::PriceCache>,
    /// The mempool, read once per sweep and shared by every order in it.
    ///
    /// The mempool scan is per *order*: each unfunded order asks whether the
    /// mempool holds an output paying its escrow. Asking the node separately
    /// for each one meant one list call plus one verbose read per entry, per
    /// order, per sweep - about 10,000 calls a day for a single idle order at a
    /// six-entry mempool, multiplied by the open-order cap of 200. Under a
    /// provider that rate-limits, each of those reads waits inside a blocking
    /// task and the sweep joins all of them.
    ///
    /// The mempool is the same for every order in a sweep, so it is read once
    /// and matched locally. Held only for [`MEMPOOL_TTL`], which is under the
    /// poll interval, so this is a within-sweep cache rather than a value that
    /// can go stale across them.
    mempool_cache: Arc<std::sync::Mutex<Option<(Arc<Vec<crate::funding::MempoolTx>>, std::time::Instant)>>>,
    /// Held across a mempool read so concurrent orders share one.
    ///
    /// The cache alone is not enough. `run` spawns every order of a sweep on a
    /// `JoinSet`, so they arrive together: each finds the slot empty, each
    /// starts its own read, and the count is back to one per order. That is
    /// worst exactly when it matters - a throttled provider makes every read
    /// wait, so every order is still in flight when the next arrives.
    ///
    /// A `tokio::sync::Mutex` because it is held across `await`. It guards no
    /// data; the cache above has its own lock. It exists so the second arrival
    /// waits for the first read rather than starting another.
    mempool_reading: Arc<tokio::sync::Mutex<()>>,
    /// The LP's key. Its public half is in every order and every capability
    /// answer, and the page checks that the two agree.
    l_priv: SecretKey,
    pub l_pub: [u8; 33],
    pub lp_output_script: Vec<u8>,
    /// The attestor key this coordinator pins, when one is configured.
    pub attestor_pubkey: Option<PublicKey>,
    pub fiat: Option<Arc<dyn FiatRail>>,
    pub journal: Arc<zecp2p_taker::auto::journal::Journal>,
    pub secp: Secp256k1<secp256k1_zkp::All>,
    /// One advance at a time per order.
    ///
    /// Two tasks reach `advance` for the same order routinely: the sweep runs
    /// on a timer, and `presign` starts one as soon as the escrow locks. Without
    /// this they both read the same stage, both pass the same guard, and both
    /// pay - or both broadcast. The lock is per order rather than global so a
    /// slow browser on one trade does not stall the sweep on every other.
    advancing: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// The last chain head read, and when it was read.
    ///
    /// Every `/escrow/capabilities` and every `/escrow/quote` needs the height
    /// and the branch id, and without this each one is two calls to the node.
    /// The hosted keyless endpoint answers about five requests a sliding minute
    /// and 429s after that, and `rpc`'s rate-limit handling waits 60 s on a 429.
    /// So under any real traffic the page's own polling exhausted the window and
    /// those endpoints stopped answering inside any sane client timeout.
    ///
    /// A block is `zec.block_seconds` apart (75 s configured), so a head a few
    /// seconds stale is not a different answer, it is the same answer arriving
    /// without a network round trip. `CHAIN_HEAD_TTL` is kept well under one
    /// block for that reason.
    ///
    /// This is a cache and not a substitute for reading the node: it holds a
    /// value that was true, never a value that was guessed, and it is empty
    /// until a real read succeeds. A node that cannot be reached still fails.
    chain_head_cache: Arc<std::sync::Mutex<Option<((u32, u32), std::time::Instant)>>>,
    /// One payment at a time, across every order.
    ///
    /// R2-1: the per-order lock above serialises an order with itself and
    /// nothing else, and the slot check was a *read* of the journal followed by
    /// two `await` points - a chain round-trip and the rail's preflight -
    /// before the matching write. Two orders advancing together both read an
    /// empty journal, both passed, both wrote `Paying`, and both paid. The
    /// reviewer reproduced it: two payments, maximum overlap two.
    ///
    /// A read-then-write on a shared resource needs the read and the write
    /// inside one critical section. This is that section, and it is held from
    /// before the journal is read until the payment's outcome is recorded, so
    /// no second order can observe the gap.
    ///
    /// It is a `Mutex` rather than a semaphore because the invariant is exactly
    /// one: one Venmo balance, and one feed in which two identical payments
    /// cannot be told apart.
    paying: Arc<tokio::sync::Mutex<()>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("l_pub", &hex::encode(self.l_pub))
            .field("network", &self.config.zec.network)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// The global payment lock.
    ///
    /// Held across the whole read-decide-claim-pay-record sequence in
    /// `driver::settle`. Callers must not hold it while doing anything that
    /// does not need to be serialised against other payments: everything under
    /// it is one trade's worth of latency for every other trade.
    pub async fn pay_lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.paying.clone().lock_owned().await
    }

    /// Takes the payment lock if it is free, without waiting.
    ///
    /// One operation rather than a check and then an acquire: a caller that
    /// asked `is it free` and then awaited the lock would have a window between
    /// the two, and skipping on contention is the whole point - the sweep comes
    /// back in seconds, and queueing would pin this task for as long as a
    /// browser drive.
    pub fn try_pay_lock(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.paying.clone().try_lock_owned().ok()
    }

    /// Whether a payment is under way right now. For tests and status.
    pub fn payment_in_progress(&self) -> bool {
        self.paying.try_lock().is_err()
    }

    /// The lock for one order, created on first use.
    pub async fn order_lock(&self, order_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.advancing.lock().await;
        map.entry(order_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// The LP's secret. Private so it is reached only through the signing
    /// helper below, which is the one place it is used.
    pub fn sign_release_digest(&self, digest: &[u8; 32]) -> secp256k1::ecdsa::Signature {
        let secp = secp256k1::Secp256k1::signing_only();
        let key = secp256k1::SecretKey::from_slice(&self.l_priv.secret_bytes())
            .expect("the LP key round-trips through its own bytes");
        secp.sign_ecdsa(&secp256k1::Message::from_digest(*digest), &key)
    }

    /// The cached mempool, if one was read within [`MEMPOOL_TTL`].
    fn cached_mempool(&self) -> Option<Arc<Vec<crate::funding::MempoolTx>>> {
        let slot = self.mempool_cache.lock().ok()?;
        let (txs, read_at) = slot.as_ref()?;
        (read_at.elapsed() < MEMPOOL_TTL).then(|| txs.clone())
    }

    /// The mempool for this sweep, read once and shared by every order in it.
    ///
    /// Returns an empty listing rather than an error when the node will not
    /// serve one: the mempool is an optimisation on *when* a signature can be
    /// collected, and losing it costs a block of latency rather than
    /// correctness.
    pub async fn sweep_mempool(&self) -> Arc<Vec<crate::funding::MempoolTx>> {
        if let Some(txs) = self.cached_mempool() {
            return txs;
        }

        // Single-flight. Whoever gets here first does the read; everyone else
        // waits on this and then finds the cache filled.
        let _reading = self.mempool_reading.lock().await;
        if let Some(txs) = self.cached_mempool() {
            return txs;
        }

        let scanner = self.scanner.clone();
        let read = tokio::task::spawn_blocking(move || scanner.mempool()).await;
        let txs = match read {
            Ok(Ok(txs)) => Arc::new(txs),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "the node would not list its mempool");
                Arc::new(Vec::new())
            }
            Err(e) => {
                tracing::debug!(error = %e, "the mempool read did not complete");
                Arc::new(Vec::new())
            }
        };
        if let Ok(mut slot) = self.mempool_cache.lock() {
            *slot = Some((txs.clone(), std::time::Instant::now()));
        }
        txs
    }

    /// Reads the chain height and branch id, from the cache when it is fresh.
    ///
    /// See [`AppState::chain_head_cache`] for why this is cached at all. Use
    /// [`AppState::chain_head_uncached`] where the caller must see the node.
    pub async fn chain_head(&self) -> Result<(u32, u32)> {
        if let Some(head) = self.cached_chain_head() {
            return Ok(head);
        }
        let head = self.chain_head_uncached().await?;
        if let Ok(mut slot) = self.chain_head_cache.lock() {
            *slot = Some((head, std::time::Instant::now()));
        }
        Ok(head)
    }

    /// The cached head, if one was read less than [`CHAIN_HEAD_TTL`] ago.
    fn cached_chain_head(&self) -> Option<(u32, u32)> {
        self.chain_head_within(CHAIN_HEAD_TTL)
    }

    /// The cached head, if it was read within `max_age`.
    fn chain_head_within(&self, max_age: std::time::Duration) -> Option<(u32, u32)> {
        let slot = self.chain_head_cache.lock().ok()?;
        let (head, read_at) = (*slot)?;
        (read_at.elapsed() < max_age).then_some(head)
    }

    /// Reads the head from the node and makes it the cached value.
    ///
    /// This is what the sweep calls once per tick. Every order it then advances
    /// reads that head through `chain_head` instead of asking the node itself,
    /// which is the difference between two node calls per sweep and two per
    /// order per sweep. The head is genuinely fresh - it was read at the top of
    /// this sweep - so a deadline decision made against it is as current as one
    /// the order made for itself.
    pub async fn refresh_chain_head(&self) -> Result<(u32, u32)> {
        let head = self.chain_head_uncached().await?;
        if let Ok(mut slot) = self.chain_head_cache.lock() {
            *slot = Some((head, std::time::Instant::now()));
        }
        Ok(head)
    }

    /// Reads the chain height and branch id from the node, ignoring the cache.
    pub async fn chain_head_uncached(&self) -> Result<(u32, u32)> {
        let rpc = self.rpc.clone();
        tokio::task::spawn_blocking(move || {
            let chain = RpcChainClient::new(rpc)?;
            let height = ChainClient::height(&chain)?;
            let branch = ChainClient::consensus_branch_id(&chain)?;
            Ok::<_, zecp2p_escrow::chain::ChainError>((height, branch))
        })
        .await
        .context("the Zcash node read did not complete")?
        .map_err(|e| anyhow::anyhow!("could not read the Zcash node: {e}"))
    }

    /// Runs a blocking closure with a fresh chain client.
    pub async fn with_chain<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&RpcChainClient) -> Result<T> + Send + 'static,
    {
        let rpc = self.rpc.clone();
        tokio::task::spawn_blocking(move || {
            let chain = RpcChainClient::new(rpc)
                .map_err(|e| anyhow::anyhow!("could not reach the Zcash node: {e}"))?;
            f(&chain)
        })
        .await
        .context("the Zcash node call did not complete")?
    }

    /// A blocking attestor call.
    pub async fn with_attestor<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&zecp2p_escrow::lp_client::AttestorClient) -> Result<T> + Send + 'static,
    {
        let url = self.config.attestor.url.clone();
        let token = self.config.attestor.token.clone();
        tokio::task::spawn_blocking(move || {
            let client = zecp2p_escrow::lp_client::AttestorClient::new(url, token)
                .map_err(|e| anyhow::anyhow!("could not build the attestor client: {e}"))?;
            f(&client)
        })
        .await
        .context("the attestor call did not complete")?
    }

    pub fn addr_network(&self) -> zecp2p_escrow::address::AddrNetwork {
        self.config
            .addr_network()
            .expect("the network was validated at load")
    }

    pub fn address_network(&self) -> zecp2p_escrow::funding::AddressNetwork {
        self.config
            .address_network()
            .expect("the network was validated at load")
    }

    /// The network string the page reads: `main` or `test`.
    pub fn network_name(&self) -> &'static str {
        match self.config.network().expect("validated at load") {
            zecp2p_escrow::rpc::Network::Main => "main",
            zecp2p_escrow::rpc::Network::Test => "test",
        }
    }
}

/// Builds the shared state, refusing anything that would make a later step
/// lose money.
pub struct AppStateBuilder {
    config: CoordinatorConfig,
    fiat: Option<Arc<dyn FiatRail>>,
    scanner: Option<Arc<dyn FundingScanner>>,
}

impl AppStateBuilder {
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            fiat: None,
            scanner: None,
        }
    }

    pub fn with_fiat(mut self, fiat: Arc<dyn FiatRail>) -> Self {
        self.fiat = Some(fiat);
        self
    }

    pub fn with_scanner(mut self, scanner: Arc<dyn FundingScanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    pub fn build(self) -> Result<Arc<AppState>> {
        let config = self.config;
        config.validate()?;

        let policy = config.policy()?;
        let rpc = config.rpc_config()?;

        let l_priv = load_lp_key(&config)?;
        let secp = Secp256k1::new();
        let l_pub = l_priv.public_key(&secp).serialize();

        let lp_output_script = zecp2p_escrow::address::script_pubkey_for(
            config.lp.payout_address.trim(),
            config.addr_network()?,
        )
        .map_err(|e| anyhow::anyhow!("lp.payout_address is not usable: {e}"))?;

        let attestor_pubkey = match &config.attestor.pubkey {
            Some(p) => Some(
                PublicKey::from_slice(&hex::decode(p.trim()).context("attestor.pubkey is not hex")?)
                    .context("attestor.pubkey is not a compressed point")?,
            ),
            None => None,
        };

        let store = OrderStore::open(config.state_dir())?;

        let scanner = match self.scanner {
            Some(s) => s,
            None => {
                let node = Arc::new(NodeRpc::new(&rpc)?);
                match config.zec.scanner {
                    crate::config::ScannerKind::AddressIndex => {
                        Arc::new(crate::funding::AddressIndexScanner::new(node))
                            as Arc<dyn FundingScanner>
                    }
                    crate::config::ScannerKind::BlockScan => {
                        Arc::new(crate::funding::BlockScanScanner::new(
                            node,
                            config.zec.scan_lookback_blocks,
                        )) as Arc<dyn FundingScanner>
                    }
                }
            }
        };
        // Which strategy is in use, on the record. The scanner choice is a
        // config value and the wrong one is invisible until an order sits at
        // `awaiting_zec` forever, so it is logged rather than discovered.
        tracing::info!(
            scanner = ?config.zec.scanner,
            "funding discovery strategy"
        );

        let journal_path = config.journal_path();
        let journal = zecp2p_taker::auto::journal::Journal::open(&journal_path)
            .with_context(|| format!("could not open the journal at {}", journal_path.display()))?;

        // Where the slot lives, on the record. A deployment that also runs the
        // taker must point both at one file, and the only way an operator finds
        // out otherwise is by paying twice.
        if config.server.journal_path.is_none() {
            tracing::warn!(
                journal = %journal_path.display(),
                "server.journal_path is unset, so the payment slot is this process's own \
                 journal. If zecp2p-taker also runs against this Venmo account, point \
                 both at the same file (taker.journal_path) or each will pay while the \
                 other is paying."
            );
        } else {
            tracing::info!(journal = %journal_path.display(), "payment slot journal");
        }

        Ok(Arc::new(AppState {
            config,
            store,
            quotes: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            policy,
            rpc,
            scanner,
            http: reqwest::Client::new(),
            prices: crate::price::PriceCache::new(),
            mempool_cache: Arc::new(std::sync::Mutex::new(None)),
            mempool_reading: Arc::new(tokio::sync::Mutex::new(())),
            l_priv,
            l_pub,
            lp_output_script,
            attestor_pubkey,
            fiat: self.fiat,
            journal: Arc::new(journal),
            secp,
            advancing: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            chain_head_cache: Arc::new(std::sync::Mutex::new(None)),
            paying: Arc::new(tokio::sync::Mutex::new(())),
        }))
    }
}

/// Loads the LP key from the environment or a keystore.
///
/// There is no development fallback. A coordinator that invented a key would
/// hand out an address whose 2-of-2 branch nobody can complete, and the user's
/// only recovery would be the refund at `T`.
fn load_lp_key(config: &CoordinatorConfig) -> Result<SecretKey> {
    if let Ok(hexkey) = std::env::var(&config.lp.key_env) {
        let trimmed = hexkey.trim();
        if !trimmed.is_empty() {
            let raw = hex::decode(trimmed)
                .with_context(|| format!("{} is not hex", config.lp.key_env))?;
            return SecretKey::from_slice(&raw)
                .with_context(|| format!("{} is not a valid secp256k1 scalar", config.lp.key_env));
        }
    }

    let dir = config.lp.keystore_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no LP key: {} is unset and lp.keystore_dir is not configured. The LP key is \
             half of every escrow this coordinator hands out; there is no default, because \
             a made-up key produces addresses whose release nobody can sign.",
            config.lp.key_env
        )
    })?;

    let keystore = zecp2p_escrow::keystore::Keystore::new(crate::config::expand_home(dir));
    let key = keystore
        .load_or_create(&config.lp.key_label)
        .map_err(|e| anyhow::anyhow!("could not load the LP key: {e}"))?;
    SecretKey::from_slice(&key.secret_bytes()).context("the keystore key is not a valid scalar")
}

#[cfg(test)]
mod chain_head_cache_tests {
    use super::CHAIN_HEAD_TTL;
    use std::time::{Duration, Instant};

    /// The freshness rule `cached_chain_head` applies, exercised on its own.
    ///
    /// `AppState` needs a key, a store and a node to build, so the rule is
    /// checked here rather than through a constructed state; the function under
    /// test in `cached_chain_head` is this comparison and nothing else.
    fn is_fresh(read_at: Instant) -> bool {
        read_at.elapsed() < CHAIN_HEAD_TTL
    }

    #[test]
    fn a_head_read_just_now_is_reused() {
        assert!(is_fresh(Instant::now()));
    }

    #[test]
    fn a_head_older_than_the_ttl_is_refetched() {
        let old = Instant::now() - (CHAIN_HEAD_TTL + Duration::from_secs(1));
        assert!(!is_fresh(old), "a stale head must not be served from cache");
    }

    /// The cache exists to keep the node read rate under the hosted endpoint's
    /// limit. That only holds if the TTL is short enough to stay inside one
    /// block and long enough to cap reads well under the ~5/minute budget that
    /// `rpc::RpcConfig` documents.
    #[test]
    fn the_ttl_caps_reads_below_the_hosted_endpoints_budget() {
        let reads_per_minute = 60.0 / CHAIN_HEAD_TTL.as_secs_f64();
        assert!(
            reads_per_minute <= 5.0,
            "head reads would be {reads_per_minute}/min, at or over the keyless budget"
        );
        // A block is 75 s in the deployed config; a TTL at or above that would
        // mean routinely serving a height the node had already moved past.
        assert!(CHAIN_HEAD_TTL.as_secs() < 75, "TTL must stay inside one block");
    }
}
