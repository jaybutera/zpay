//! The world the coordinator runs against: a chain, an attestor and a curator,
//! all fake, all speaking the protocols the real services speak.
//!
//! This is the harness from `zecp2p-v2coordinator/tests/support`, lifted into a
//! library so a run outside `cargo test` can use it, and widened where volume
//! needs it: the node is shared by every order in a run, it counts the calls
//! made to it, and it can be told to fail or stall on demand so a soak run
//! exercises the paths a happy loop never reaches.
//!
//! What is **not** faked is the cryptography. The attestor draws a real nonce
//! and returns a real `sign_outcome` scalar, the user's pre-signature is a real
//! `pre_sign`, and the release the coordinator broadcasts is a transaction the
//! escrow crate parses. A failure here is a failure of the adaptor seam, not of
//! a mock of it.
//!
//! Nothing in this module can reach a real network. The node is a loopback
//! listener; the curator is a stub; the only money that moves is a number in a
//! `HashMap`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use tokio::sync::Mutex;

/// The testnet consensus branch id (NU5) the harness pins.
///
/// The escrow's ZIP 244 digest commits to this, so a run that used the wrong
/// one would produce signatures that verify nowhere. Pinned rather than read,
/// because the fake node is the thing being asked.
pub const BRANCH_ID: u32 = 0x37a5_165b;

/// What the curator stub answers for every handle.
///
/// The real curator returns a hash the enclave binds the attestation to and
/// that cannot be derived locally. A constant is right here: the harness is not
/// testing the curator, and a per-handle hash would only make the terms differ
/// for a reason nothing downstream checks.
pub const CURATOR_HASH: [u8; 32] = [0x5au8; 32];

/// The height the fake chain starts at. Testnet-shaped, and far enough above
/// zero that a refund height computed from it is a plausible testnet height.
pub const START_HEIGHT: u32 = 3_470_700;

/// A txid in display order, and a vout.
type Outpoint = (String, u32);
/// A scriptPubKey in hex, a value, and a confirmation count.
type NodeUtxo = (String, u64, u32);

/// How the node has been told to misbehave.
///
/// A soak run that only ever sees a healthy node tests one path. These are the
/// two failures the live system actually produced: a provider that rate-limits
/// (`fail_rpc`, which is what a 429 looks like from inside the client) and one
/// that answers slowly enough to cross a timeout (`stall_ms`).
#[derive(Debug, Default)]
pub struct NodeFaults {
    /// Fail every RPC with an error, the way a rate-limited provider does.
    pub fail_rpc: AtomicBool,
    /// Sleep this long before answering. Crosses client timeouts when large.
    pub stall_ms: AtomicU64,
    /// Refuse `sendrawtransaction` while leaving reads working, which is the
    /// shape of a node that accepted the escrow and then rejected the release.
    pub reject_broadcast: AtomicBool,
}

/// What the node has been asked to do, counted.
///
/// The call counts are the throughput number that matters for cost: the live
/// system's Tatum quota was exhausted by the scan, not by the trades, and a
/// harness that cannot see calls per order cannot catch that regression.
#[derive(Debug, Default)]
pub struct NodeCounters {
    pub getblockchaininfo: AtomicUsize,
    pub gettxout: AtomicUsize,
    pub sendrawtransaction: AtomicUsize,
    pub other: AtomicUsize,
    pub failed: AtomicUsize,
}

impl NodeCounters {
    pub fn total(&self) -> usize {
        self.getblockchaininfo.load(Ordering::Relaxed)
            + self.gettxout.load(Ordering::Relaxed)
            + self.sendrawtransaction.load(Ordering::Relaxed)
            + self.other.load(Ordering::Relaxed)
    }
}

struct NodeInner {
    height: Mutex<u32>,
    branch_id: Mutex<u32>,
    utxos: Mutex<HashMap<Outpoint, NodeUtxo>>,
    broadcasts: Mutex<Vec<Vec<u8>>>,
    faults: NodeFaults,
    counters: NodeCounters,
}

/// A Zcash node that answers the calls the escrow crate makes.
pub struct FakeNode {
    pub url: String,
    inner: Arc<NodeInner>,
    _handle: tokio::task::JoinHandle<()>,
}

impl FakeNode {
    pub async fn spawn() -> Self {
        let inner = Arc::new(NodeInner {
            height: Mutex::new(START_HEIGHT),
            branch_id: Mutex::new(BRANCH_ID),
            utxos: Mutex::new(HashMap::new()),
            broadcasts: Mutex::new(Vec::new()),
            faults: NodeFaults::default(),
            counters: NodeCounters::default(),
        });

        let app = axum::Router::new()
            .route("/", axum::routing::post(node_rpc))
            .with_state(inner.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the harness binds a loopback port");
        let addr = listener.local_addr().expect("a bound port has an address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            inner,
            _handle: handle,
        }
    }

    /// Puts an output on the chain at a given depth.
    pub async fn add_utxo(
        &self,
        txid: [u8; 32],
        vout: u32,
        script_pubkey: Vec<u8>,
        amount_zat: u64,
        confirmations: u32,
    ) {
        self.inner.utxos.lock().await.insert(
            (zecp2p_escrow::rpc::txid_to_display(&txid), vout),
            (hex::encode(script_pubkey), amount_zat, confirmations),
        );
    }

    /// Unwinds an output, standing in for a reorg or a spend.
    pub async fn remove_utxo(&self, txid: [u8; 32], vout: u32) {
        self.inner
            .utxos
            .lock()
            .await
            .remove(&(zecp2p_escrow::rpc::txid_to_display(&txid), vout));
    }

    pub async fn broadcasts(&self) -> Vec<Vec<u8>> {
        self.inner.broadcasts.lock().await.clone()
    }

    pub async fn broadcast_count(&self) -> usize {
        self.inner.broadcasts.lock().await.len()
    }

    /// Moves the chain tip, which is how a run reaches `T`.
    pub async fn set_height(&self, height: u32) {
        *self.inner.height.lock().await = height;
    }

    pub async fn height(&self) -> u32 {
        *self.inner.height.lock().await
    }

    /// A network upgrade, which is what changes the ZIP 244 sighash and must
    /// stop a payment that was pre-signed under the old branch.
    pub async fn set_branch_id(&self, branch_id: u32) {
        *self.inner.branch_id.lock().await = branch_id;
    }

    pub fn faults(&self) -> &NodeFaults {
        &self.inner.faults
    }

    pub fn counters(&self) -> &NodeCounters {
        &self.inner.counters
    }
}

#[derive(serde::Deserialize)]
struct RpcCall {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

async fn node_rpc(
    axum::extract::State(inner): axum::extract::State<Arc<NodeInner>>,
    axum::Json(call): axum::Json<RpcCall>,
) -> axum::Json<serde_json::Value> {
    let stall = inner.faults.stall_ms.load(Ordering::Relaxed);
    if stall > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(stall)).await;
    }

    match call.method.as_str() {
        "getblockchaininfo" => inner.counters.getblockchaininfo.fetch_add(1, Ordering::Relaxed),
        "gettxout" => inner.counters.gettxout.fetch_add(1, Ordering::Relaxed),
        "sendrawtransaction" => inner
            .counters
            .sendrawtransaction
            .fetch_add(1, Ordering::Relaxed),
        _ => inner.counters.other.fetch_add(1, Ordering::Relaxed),
    };

    // A rate-limited provider, in the shape the client sees it: a JSON-RPC
    // error rather than a transport failure.
    if inner.faults.fail_rpc.load(Ordering::Relaxed) {
        inner.counters.failed.fetch_add(1, Ordering::Relaxed);
        return axum::Json(serde_json::json!({
            "result": null,
            "error": { "code": -32005, "message": "rate limit exceeded" },
        }));
    }

    let result = match call.method.as_str() {
        "getblockchaininfo" => {
            let branch = *inner.branch_id.lock().await;
            serde_json::json!({
                "chain": "test",
                "blocks": *inner.height.lock().await,
                "consensus": { "chaintip": format!("{branch:08x}") },
            })
        }
        "gettxout" => {
            let txid = call.params[0].as_str().unwrap_or_default().to_string();
            let vout = call.params[1].as_u64().unwrap_or(0) as u32;
            match inner.utxos.lock().await.get(&(txid, vout)) {
                Some((spk, zat, confs)) => serde_json::json!({
                    "confirmations": confs,
                    "value": *zat as f64 / 1e8,
                    "valueZat": zat,
                    "scriptPubKey": { "hex": spk },
                }),
                None => serde_json::Value::Null,
            }
        }
        "sendrawtransaction" => {
            if inner.faults.reject_broadcast.load(Ordering::Relaxed) {
                inner.counters.failed.fetch_add(1, Ordering::Relaxed);
                return axum::Json(serde_json::json!({
                    "result": null,
                    "error": { "code": -26, "message": "tx unpaid action limit exceeded" },
                }));
            }
            let raw = hex::decode(call.params[0].as_str().unwrap_or_default()).unwrap_or_default();
            let txid = zecp2p_escrow::tx::txid_of_signed(&raw)
                .map(|t| zecp2p_escrow::rpc::txid_to_display(&t))
                .unwrap_or_default();
            inner.broadcasts.lock().await.push(raw);
            serde_json::Value::String(txid)
        }
        _ => {
            return axum::Json(serde_json::json!({
                "result": null,
                "error": { "code": -32601, "message": "Method not found" },
            }))
        }
    };
    axum::Json(serde_json::json!({ "result": result, "error": null }))
}

/// An attestor that announces and signs the outcome for real.
pub struct TestAttestor {
    pub url: String,
    inner: Arc<AttestorInner>,
    _handle: tokio::task::JoinHandle<()>,
}

struct AttestorInner {
    d: SecretKey,
    /// One nonce per event, drawn once. A second `R` for the same event is a
    /// different outcome point and would strand the pre-signature made under
    /// the first, so a repeat announcement returns what already exists.
    nonces: Mutex<HashMap<String, SecretKey>>,
    announces: AtomicUsize,
    attests: AtomicUsize,
    /// Refuse to attest, the way an enclave with a missing prover config does.
    /// This is the failure that cost a live run: the payment left and the
    /// attestation could not be produced.
    refuse_attest: AtomicBool,
}

impl Default for TestAttestor {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAttestor {
    pub fn new() -> Self {
        let d = SecretKey::from_slice(&[0xd1u8; 32]).expect("a valid scalar");
        let inner = Arc::new(AttestorInner {
            d,
            nonces: Mutex::new(HashMap::new()),
            announces: AtomicUsize::new(0),
            attests: AtomicUsize::new(0),
            refuse_attest: AtomicBool::new(false),
        });

        let app = axum::Router::new()
            .route("/identity", axum::routing::get(attestor_identity))
            .route("/announce", axum::routing::post(attestor_announce))
            .route("/attest", axum::routing::post(attestor_attest))
            .with_state(inner.clone());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("a bound port has an address");
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("adopts the listener");
            let _ = axum::serve(listener, app).await;
        });

        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            inner,
            _handle: handle,
        }
    }

    pub fn announces(&self) -> usize {
        self.inner.announces.load(Ordering::Relaxed)
    }

    pub fn attests(&self) -> usize {
        self.inner.attests.load(Ordering::Relaxed)
    }

    /// Makes `/attest` refuse, which is the prover-config failure.
    pub fn set_refuse_attest(&self, refuse: bool) {
        self.inner.refuse_attest.store(refuse, Ordering::Relaxed);
    }
}

async fn attestor_identity(
    axum::extract::State(inner): axum::extract::State<Arc<AttestorInner>>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    axum::Json(serde_json::json!({
        "p": hex::encode(inner.d.public_key(&secp).serialize()),
        "build_id": "loadgen-attestor",
    }))
}

#[derive(serde::Deserialize)]
struct AnnounceBody {
    terms: zecp2p_escrow::lp_client::WireTerms,
}

/// The wire terms, back into the canonical form the digest is taken over.
///
/// Every field is parsed rather than defaulted: a malformed announcement should
/// fail here, in the harness, rather than produce a `terms_hash` over zeroes
/// that the pre-signature would then be made against.
fn terms_from_wire(
    w: &zecp2p_escrow::lp_client::WireTerms,
) -> anyhow::Result<zecp2p_escrow::terms::CanonicalTerms> {
    let funding_txid: [u8; 32] = hex::decode(&w.funding_txid)
        .map_err(|e| anyhow::anyhow!("funding_txid is not hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("funding_txid is not 32 bytes"))?;
    let u_pub: [u8; 33] = hex::decode(&w.u_pub)
        .map_err(|e| anyhow::anyhow!("u_pub is not hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("u_pub is not 33 bytes"))?;
    let l_pub: [u8; 33] = hex::decode(&w.l_pub)
        .map_err(|e| anyhow::anyhow!("l_pub is not hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("l_pub is not 33 bytes"))?;
    let payee_hash: [u8; 32] = hex::decode(&w.payee_hash)
        .map_err(|e| anyhow::anyhow!("payee_hash is not hex: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("payee_hash is not 32 bytes"))?;

    Ok(zecp2p_escrow::terms::CanonicalTerms {
        funding_txid,
        vout: w.vout,
        amount_zat: w.amount_zat,
        u_pub,
        l_pub,
        refund_height: w.refund_height,
        usd_amount_6dec: w.usd_amount_6dec,
        rate_18dec: w
            .rate_18dec
            .parse()
            .map_err(|e| anyhow::anyhow!("rate_18dec does not parse: {e}"))?,
        payee_hash,
        lock_confirmed_ms: w.lock_confirmed_ms,
        platform_fee_zat: w.platform_fee_zat,
        treasury_script: hex::decode(&w.treasury_script)
            .map_err(|e| anyhow::anyhow!("treasury_script is not hex: {e}"))?,
    })
}

async fn attestor_announce(
    axum::extract::State(inner): axum::extract::State<Arc<AttestorInner>>,
    axum::Json(body): axum::Json<AnnounceBody>,
) -> axum::Json<serde_json::Value> {
    inner.announces.fetch_add(1, Ordering::Relaxed);
    let secp = Secp256k1::new();
    let terms = match terms_from_wire(&body.terms) {
        Ok(t) => t,
        Err(e) => return axum::Json(serde_json::json!({ "error": e.to_string() })),
    };
    let event_id = zecp2p_escrow::dlc::event_id(&terms.funding_txid, terms.vout);
    let event_hex = hex::encode(event_id);
    let terms_hash = hex::encode(terms.terms_hash());

    let mut nonces = inner.nonces.lock().await;
    // Drawn at random, once per event. The real attestor is idempotent here and
    // so is this: a repeat returns the nonce the first announcement drew.
    let k = nonces.entry(event_hex.clone()).or_insert_with(|| loop {
        let mut raw = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut raw);
        if let Ok(key) = SecretKey::from_slice(&raw) {
            return key;
        }
    });

    axum::Json(serde_json::json!({
        "event_id": event_hex,
        "r": hex::encode(k.public_key(&secp).serialize()),
        "p": hex::encode(inner.d.public_key(&secp).serialize()),
        "terms_hash": terms_hash,
    }))
}

#[derive(serde::Deserialize)]
struct AttestBody {
    event_id: String,
    terms: zecp2p_escrow::lp_client::WireTerms,
}

async fn attestor_attest(
    axum::extract::State(inner): axum::extract::State<Arc<AttestorInner>>,
    axum::Json(body): axum::Json<AttestBody>,
) -> axum::Json<serde_json::Value> {
    inner.attests.fetch_add(1, Ordering::Relaxed);
    if inner.refuse_attest.load(Ordering::Relaxed) {
        return axum::Json(serde_json::json!({
            "error": "no prover configured for this deployment"
        }));
    }
    let secp = Secp256k1::new();
    let terms = match terms_from_wire(&body.terms) {
        Ok(t) => t,
        Err(e) => return axum::Json(serde_json::json!({ "error": e.to_string() })),
    };
    let nonces = inner.nonces.lock().await;
    let Some(k) = nonces.get(&body.event_id) else {
        return axum::Json(serde_json::json!({ "error": "no such event" }));
    };
    let Ok(event_id) = hex::decode(&body.event_id).map(<[u8; 32]>::try_from) else {
        return axum::Json(serde_json::json!({ "error": "event_id is not hex" }));
    };
    let Ok(event_id) = event_id else {
        return axum::Json(serde_json::json!({ "error": "event_id is not 32 bytes" }));
    };
    match zecp2p_escrow::dlc::sign_outcome(&secp, k, &inner.d, &event_id, &terms.terms_hash()) {
        Ok(s) => axum::Json(serde_json::json!({ "s": hex::encode(s.secret_bytes()) })),
        Err(e) => axum::Json(serde_json::json!({ "error": format!("{e}") })),
    }
}

/// A curator stub, so nothing in a run reaches the live zk-p2p API.
pub struct FakeCurator {
    pub url: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl Default for FakeCurator {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeCurator {
    pub fn new() -> Self {
        let app = axum::Router::new()
            .route(
                "/v2/makers/validate",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({ "success": true, "responseObject": true }))
                }),
            )
            .route(
                "/v2/makers/create",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "success": true,
                        "responseObject": {
                            "hashedOnchainId": format!("0x{}", hex::encode(CURATOR_HASH)),
                        },
                    }))
                }),
            );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("a bound port has an address");
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("adopts the listener");
            let _ = axum::serve(listener, app).await;
        });

        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            _handle: handle,
        }
    }
}

/// A user with a key, who pre-signs the way the page does.
///
/// **This is where distinct escrow addresses come from.** The escrow address is
/// `escrow_address(u_pub, l_pub, refund_height, amount_zat, network)`, so a
/// fresh keypair per order derives a fresh address with no pool to manage and
/// no state to keep. Reusing one key across a run would collide every order
/// that shared an amount and a refund height onto one address, and the funding
/// scan would then find one escrow's output while looking for another's.
pub struct TestUser {
    pub u_priv: SecretKey,
    pub u_pub: [u8; 33],
}

impl Default for TestUser {
    fn default() -> Self {
        Self::new()
    }
}

impl TestUser {
    pub fn new() -> Self {
        let mut raw = [0u8; 32];
        let u_priv = loop {
            rand::Rng::fill(&mut rand::thread_rng(), &mut raw);
            if let Ok(key) = SecretKey::from_slice(&raw) {
                break key;
            }
        };
        let secp = Secp256k1::new();
        Self {
            u_pub: u_priv.public_key(&secp).serialize(),
            u_priv,
        }
    }

    /// The outcome point for an announcement, computed from public data alone.
    fn outcome_point(&self, announced: &serde_json::Value) -> anyhow::Result<PublicKey> {
        let secp = Secp256k1::new();
        let field = |name: &str| -> anyhow::Result<Vec<u8>> {
            let s = announced[name]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("the announcement has no {name}"))?;
            hex::decode(s).map_err(|e| anyhow::anyhow!("{name} is not hex: {e}"))
        };
        let r = PublicKey::from_slice(&field("R")?)?;
        let p = PublicKey::from_slice(&field("P")?)?;
        let event_id: [u8; 32] = field("event_id")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("event_id is not 32 bytes"))?;
        let terms_hash: [u8; 32] = field("terms_hash")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("terms_hash is not 32 bytes"))?;
        zecp2p_escrow::dlc::outcome_point(&secp, &r, &p, &event_id, &terms_hash)
            .map_err(|e| anyhow::anyhow!("the outcome point does not compute: {e}"))
    }

    /// Pre-signs this order's release the way `prepareEscrow` does: the digest
    /// is rebuilt from the order's own terms and split, never taken on trust
    /// from the response.
    pub fn pre_sign(
        &self,
        order: &zecp2p_v2coordinator::order::Order,
        announced: &serde_json::Value,
    ) -> anyhow::Result<secp256k1_zkp::EcdsaAdaptorSignature> {
        let digest = order.release_digest()?;
        let secp = Secp256k1::new();
        let y = self.outcome_point(announced)?;
        Ok(zecp2p_escrow::dlc::pre_sign(&secp, &digest, &self.u_priv, &y))
    }

    /// Signs the refund the way the page does at `T`: `u` alone, spending the
    /// timeout branch to a transparent address.
    pub fn sign_refund(
        &self,
        order: &zecp2p_v2coordinator::order::Order,
        funding_txid: &[u8; 32],
        vout: u32,
        to_address: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let terms = zecp2p_escrow::tx::EscrowTerms {
            funding_txid: *funding_txid,
            vout,
            amount_zat: order.quote.amount_zat,
            u_pub: order.u_pub,
            l_pub: order.l_pub,
            refund_height: order.refund_height,
            consensus_branch_id: order.consensus_branch_id,
        };
        let user_script = zecp2p_escrow::address::script_pubkey_for(
            to_address,
            zecp2p_escrow::address::AddrNetwork::Test,
        )
        .map_err(|e| anyhow::anyhow!("the refund address does not parse: {e}"))?;
        let redeem = terms
            .redeem_script()
            .map_err(|e| anyhow::anyhow!("the redeem script does not build: {e}"))?;
        let fee = zecp2p_escrow::fees::refund_fee_to_transparent_zat(redeem.len());
        let tx = zecp2p_escrow::tx::build_refund(&terms, &user_script, fee)
            .map_err(|e| anyhow::anyhow!("the refund does not build: {e}"))?;
        let digest = tx
            .sighash()
            .map_err(|e| anyhow::anyhow!("the refund digest does not compute: {e}"))?;

        let secp = secp256k1::Secp256k1::new();
        let key = secp256k1::SecretKey::from_slice(&self.u_priv.secret_bytes())?;
        let sig = secp.sign_ecdsa(&secp256k1::Message::from_digest(digest), &key);
        let script_sig = zecp2p_escrow::script::refund_script_sig(
            &zecp2p_escrow::tx::encode_signature(&sig),
            &redeem,
        );
        zecp2p_escrow::tx::serialize_refund(&terms, &user_script, fee, &script_sig)
            .map_err(|e| anyhow::anyhow!("the refund does not serialize: {e}"))
    }
}
