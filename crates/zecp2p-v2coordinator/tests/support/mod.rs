//! The harness: a chain, an attestor, a curator and a fiat rail, all fake, all
//! speaking the real protocols.
//!
//! The crypto is not faked. The test user's pre-signature is made with the
//! escrow crate's own `pre_sign` over a digest it computes the way the page
//! does, and the test attestor's scalar is a real `sign_outcome`. So a test
//! that passes here is a test of the adaptor seam, not of a mock of it.

use std::collections::HashMap;
use std::sync::Arc;

use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use tokio::sync::Mutex;

use zecp2p_v2coordinator::config::*;
use zecp2p_v2coordinator::funding::FundingScanner;
use zecp2p_v2coordinator::order::Order;
use zecp2p_v2coordinator::state::{AppState, AppStateBuilder, FiatRail, PaidFiat};

pub const BRANCH_ID: u32 = 0x37a5_165b;
/// What the curator stub answers for every handle.
pub const CURATOR_HASH: [u8; 32] = [0x5au8; 32];

/// A Zcash node that answers the four calls the escrow crate makes, plus the
/// one the coordinator's startup check makes.
pub struct FakeNode {
    pub url: String,
    inner: Arc<NodeInner>,
    _handle: tokio::task::JoinHandle<()>,
}

/// A txid in display order, and a vout.
type Outpoint = (String, u32);
/// A scriptPubKey in hex, a value, and a confirmation count.
type NodeUtxo = (String, u64, u32);

struct NodeInner {
    height: Mutex<u32>,
    utxos: Mutex<HashMap<Outpoint, NodeUtxo>>,
    broadcasts: Mutex<Vec<Vec<u8>>>,
}

impl FakeNode {
    pub async fn spawn() -> Self {
        let inner = Arc::new(NodeInner {
            height: Mutex::new(3_470_700),
            utxos: Mutex::new(HashMap::new()),
            broadcasts: Mutex::new(Vec::new()),
        });

        let app = axum::Router::new()
            .route("/", axum::routing::post(node_rpc))
            .with_state(inner.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            inner,
            _handle: handle,
        }
    }

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

    pub async fn broadcasts(&self) -> Vec<Vec<u8>> {
        self.inner.broadcasts.lock().await.clone()
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
    let result = match call.method.as_str() {
        "getblockchaininfo" => serde_json::json!({
            "chain": "test",
            "blocks": *inner.height.lock().await,
            "consensus": { "chaintip": format!("{BRANCH_ID:08x}") },
        }),
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
    _handle: tokio::task::JoinHandle<()>,
}

struct AttestorInner {
    d: SecretKey,
    /// One nonce per event, drawn once. A second `R` for the same event would
    /// be a different outcome point and would strand the pre-signature.
    nonces: Mutex<HashMap<String, (SecretKey, String)>>,
}

impl TestAttestor {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let d = SecretKey::from_slice(&[0xd1u8; 32]).unwrap();
        let p = d.public_key(&secp);
        let inner = Arc::new(AttestorInner {
            d,
            nonces: Mutex::new(HashMap::new()),
        });

        let app = axum::Router::new()
            .route("/identity", axum::routing::get(attestor_identity))
            .route("/announce", axum::routing::post(attestor_announce))
            .route("/attest", axum::routing::post(attestor_attest))
            .with_state(inner.clone());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let _ = axum::serve(listener, app).await;
        });

        let _ = p;
        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            _handle: handle,
        }
    }
}

async fn attestor_identity(
    axum::extract::State(inner): axum::extract::State<Arc<AttestorInner>>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    axum::Json(serde_json::json!({
        "p": hex::encode(inner.d.public_key(&secp).serialize()),
        "build_id": "test-attestor",
    }))
}

#[derive(serde::Deserialize)]
struct AnnounceBody {
    terms: zecp2p_escrow::lp_client::WireTerms,
}

fn terms_from_wire(w: &zecp2p_escrow::lp_client::WireTerms) -> zecp2p_escrow::terms::CanonicalTerms {
    zecp2p_escrow::terms::CanonicalTerms {
        funding_txid: hex::decode(&w.funding_txid).unwrap().try_into().unwrap(),
        vout: w.vout,
        amount_zat: w.amount_zat,
        u_pub: hex::decode(&w.u_pub).unwrap().try_into().unwrap(),
        l_pub: hex::decode(&w.l_pub).unwrap().try_into().unwrap(),
        refund_height: w.refund_height,
        usd_amount_6dec: w.usd_amount_6dec,
        rate_18dec: w.rate_18dec.parse().unwrap(),
        payee_hash: hex::decode(&w.payee_hash).unwrap().try_into().unwrap(),
        lock_confirmed_ms: w.lock_confirmed_ms,
        platform_fee_zat: w.platform_fee_zat,
        treasury_script: hex::decode(&w.treasury_script).unwrap(),
    }
}

async fn attestor_announce(
    axum::extract::State(inner): axum::extract::State<Arc<AttestorInner>>,
    axum::Json(body): axum::Json<AnnounceBody>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    let terms = terms_from_wire(&body.terms);
    let event_id = zecp2p_escrow::dlc::event_id(&terms.funding_txid, terms.vout);
    let event_hex = hex::encode(event_id);
    let terms_hash = hex::encode(terms.terms_hash());

    let mut nonces = inner.nonces.lock().await;
    // Idempotent, as the real attestor is: a repeat returns what exists.
    let (k, _) = nonces.entry(event_hex.clone()).or_insert_with(|| {
        let mut raw = [0u8; 32];
        raw[0] = 0x7a;
        raw[31] = (nonces_len_seed() % 251) as u8 + 1;
        (SecretKey::from_slice(&raw).unwrap(), terms_hash.clone())
    });
    let r = k.public_key(&secp);

    axum::Json(serde_json::json!({
        "event_id": event_hex,
        "r": hex::encode(r.serialize()),
        "p": hex::encode(inner.d.public_key(&secp).serialize()),
        "terms_hash": terms_hash,
    }))
}

fn nonces_len_seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed)
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
    let secp = Secp256k1::new();
    let terms = terms_from_wire(&body.terms);
    let nonces = inner.nonces.lock().await;
    let Some((k, _)) = nonces.get(&body.event_id) else {
        return axum::Json(serde_json::json!({ "error": "no such event" }));
    };
    let event_id: [u8; 32] = hex::decode(&body.event_id).unwrap().try_into().unwrap();
    let s = zecp2p_escrow::dlc::sign_outcome(&secp, k, &inner.d, &event_id, &terms.terms_hash())
        .expect("the outcome signs");
    axum::Json(serde_json::json!({ "s": hex::encode(s.secret_bytes()) }))
}

/// A user with a key, who pre-signs the way the page does.
pub struct TestUser {
    pub u_priv: SecretKey,
    pub u_pub: [u8; 33],
}

impl TestUser {
    pub fn new() -> Self {
        use rand::Rng;
        let mut raw = [0u8; 32];
        rand::thread_rng().fill(&mut raw);
        let u_priv = SecretKey::from_slice(&raw).expect("a valid scalar");
        let secp = Secp256k1::new();
        Self {
            u_pub: u_priv.public_key(&secp).serialize(),
            u_priv,
        }
    }

    /// The outcome point for an announcement, computed from public data alone.
    fn outcome_point(&self, announced: &serde_json::Value) -> PublicKey {
        let secp = Secp256k1::new();
        let r = PublicKey::from_slice(
            &hex::decode(announced["R"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let p = PublicKey::from_slice(
            &hex::decode(announced["P"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let event_id: [u8; 32] = hex::decode(announced["event_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let terms_hash: [u8; 32] = hex::decode(announced["terms_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        zecp2p_escrow::dlc::outcome_point(&secp, &r, &p, &event_id, &terms_hash).unwrap()
    }

    /// Pre-signs this order's release, as `prepareEscrow` does: the digest is
    /// rebuilt from the order's own terms and split, never taken on trust.
    pub fn pre_sign(
        &self,
        order: &Order,
        _attestor: &TestAttestor,
        announced: &serde_json::Value,
    ) -> secp256k1_zkp::EcdsaAdaptorSignature {
        let digest = order.release_digest().expect("the release builds");
        let secp = Secp256k1::new();
        let y = self.outcome_point(announced);
        zecp2p_escrow::dlc::pre_sign(&secp, &digest, &self.u_priv, &y)
    }

    /// Pre-signs an arbitrary digest, for the tests that prove the gate holds.
    pub fn pre_sign_over_digest(
        &self,
        digest: &[u8; 32],
        _order: &Order,
        _attestor: &TestAttestor,
        announced: &serde_json::Value,
    ) -> secp256k1_zkp::EcdsaAdaptorSignature {
        let secp = Secp256k1::new();
        let y = self.outcome_point(announced);
        zecp2p_escrow::dlc::pre_sign(&secp, digest, &self.u_priv, &y)
    }
}

/// A rail that cannot pay, the way a signed-out browser cannot.
pub struct UnavailableRail;

#[async_trait::async_trait]
impl FiatRail for UnavailableRail {
    async fn preflight(&self) -> anyhow::Result<()> {
        anyhow::bail!("no stored Venmo session")
    }

    async fn pay(&self, _leg: &zecp2p_taker::auto::rail::FiatLeg) -> anyhow::Result<PaidFiat> {
        anyhow::bail!("no stored Venmo session")
    }

    async fn attest(
        &self,
        _leg: &zecp2p_taker::auto::rail::FiatLeg,
    ) -> anyhow::Result<zecp2p_escrow::lp_client::WireAttestation> {
        anyhow::bail!("no stored Venmo session")
    }
}

/// A coordinator whose rail cannot pay at all.
pub fn coordinator_that_cannot_pay(
    dir: &std::path::Path,
    scanner: Arc<dyn FundingScanner>,
    node: &FakeNode,
    attestor: &TestAttestor,
) -> Arc<AppState> {
    build(dir, scanner, node, Some(attestor), Some(Arc::new(UnavailableRail)))
}

/// A fiat rail that reports a payment without one having happened.
///
/// Only ever installed by a test. The production binary builds `VenmoRail`,
/// which drives a real browser and a real enclave.
pub struct TestFiat {
    pub paid: Arc<std::sync::Mutex<Vec<u64>>>,
}

impl TestFiat {
    pub fn new() -> Self {
        Self {
            paid: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl FiatRail for TestFiat {
    async fn pay(&self, leg: &zecp2p_taker::auto::rail::FiatLeg) -> anyhow::Result<PaidFiat> {
        let cents = u64::try_from(leg.payment.cents())?;
        self.paid.lock().unwrap().push(cents);
        Ok(PaidFiat {
            cents,
            fiat_left: true,
        })
    }

    async fn attest(
        &self,
        leg: &zecp2p_taker::auto::rail::FiatLeg,
    ) -> anyhow::Result<zecp2p_escrow::lp_client::WireAttestation> {
        // The test attestor does not check the attestation, only the terms, so
        // the shape is what matters here.
        Ok(zecp2p_escrow::lp_client::WireAttestation {
            intent_hash: hex::encode(leg.intent_hash.0),
            release_amount: leg.intent_amount_6dec.to_string(),
            data_hash: hex::encode([0u8; 32]),
            signature: hex::encode([0u8; 65]),
            encoded_payment_details: hex::encode(vec![0u8; 448]),
        })
    }
}

/// A curator stub, so no test reaches the live zk-p2p API.
pub struct FakeCurator {
    pub url: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl FakeCurator {
    pub fn spawn_blocking_new() -> Self {
        let app = axum::Router::new()
            .route("/v2/makers/validate", axum::routing::post(|| async {
                axum::Json(serde_json::json!({ "success": true, "responseObject": true }))
            }))
            .route("/v2/makers/create", axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "success": true,
                    "responseObject": { "hashedOnchainId": format!("0x{}", hex::encode(CURATOR_HASH)) },
                }))
            }));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://127.0.0.1:{}", addr.port()),
            _handle: handle,
        }
    }
}

/// The base configuration every test starts from.
pub fn test_config(dir: &std::path::Path) -> CoordinatorConfig {
    let text = format!(
        r#"
[server]
host = "127.0.0.1"
port = 0
state_dir = "{}"

[zec]
rpc_url = "http://127.0.0.1:1"
network = "test"
refund_hours = 24
block_seconds = 75

[attestor]
url = "http://127.0.0.1:1"
token = "test-token"

[lp]
payout_address = "tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn"
key_env = "ZECP2P_LP_PRIV"

[quote]
rate_usd_per_zec = 40.25
fee_bps = 20
min_zat = 120000
max_zat = 5000000000
max_payment_cents = 2500

[serve]
handles = ["alice"]
live_payments = true

[zkp2p]
api_url = "http://127.0.0.1:1"
"#,
        dir.display()
    );
    toml::from_str(&text).expect("the test configuration parses")
}

/// A coordinator pointed at a fake node and a curator stub.
pub fn coordinator_with_node(
    dir: &std::path::Path,
    scanner: Arc<dyn FundingScanner>,
    node: &FakeNode,
) -> Arc<AppState> {
    build(dir, scanner, node, None, None)
}

/// A coordinator with everything: node, attestor, curator and a fiat rail.
pub fn coordinator_with_everything(
    dir: &std::path::Path,
    scanner: Arc<dyn FundingScanner>,
    node: &FakeNode,
    attestor: &TestAttestor,
) -> Arc<AppState> {
    build(
        dir,
        scanner,
        node,
        Some(attestor),
        Some(Arc::new(TestFiat::new())),
    )
}

fn build(
    dir: &std::path::Path,
    scanner: Arc<dyn FundingScanner>,
    node: &FakeNode,
    attestor: Option<&TestAttestor>,
    fiat: Option<Arc<dyn FiatRail>>,
) -> Arc<AppState> {
    // The LP key is a test key and nothing else ever holds it.
    std::env::set_var("ZECP2P_LP_PRIV", hex::encode([0x22u8; 32]));

    let curator = FakeCurator::spawn_blocking_new();
    let mut config = test_config(dir);
    config.zec.rpc_url = node.url.clone();
    config.zkp2p.api_url = curator.url.clone();
    if let Some(a) = attestor {
        config.attestor.url = a.url.clone();
    }
    // Leaked on purpose: the stub must outlive the test's requests, and a test
    // process exits when the test does.
    std::mem::forget(curator);

    let mut builder = AppStateBuilder::new(config).with_scanner(scanner);
    if let Some(f) = fiat {
        builder = builder.with_fiat(f);
    }
    builder.build().expect("the test coordinator builds")
}
