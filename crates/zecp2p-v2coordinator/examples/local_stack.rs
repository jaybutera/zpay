//! A local stack for driving the real page against the real coordinator.
//!
//! Stands up a Zcash node, an attestor and a zk-p2p curator on loopback, all
//! fake, all speaking the protocols the coordinator actually uses. The escrow
//! is real: the announcement carries a real nonce, the outcome scalar is a real
//! `sign_outcome`, and the release the coordinator broadcasts is a transaction
//! this node parses.
//!
//! The one thing it fakes is money. The chain confirms an output as soon as it
//! is told about one, and the fiat leg reports a payment that never happened.
//! Nothing here should ever be pointed at a real network.
//!
//!     cargo run -p zecp2p-v2coordinator --example local_stack
//!
//! It prints the URLs to put in the coordinator's config, then serves until
//! killed. `POST /fund` on the node tells it an address was paid.

use std::collections::HashMap;
use std::sync::Arc;

use secp256k1_zkp::{Secp256k1, SecretKey};
use tokio::sync::Mutex;

const BRANCH_ID: u32 = 0x37a5_165b;
const CURATOR_HASH: [u8; 32] = [0x5au8; 32];

struct Node {
    height: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), (String, u64, u32)>>,
    /// Outputs by address, for the coordinator's block scan.
    by_address: Mutex<HashMap<String, Vec<(String, u32, u64, String)>>>,
    broadcasts: Mutex<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node = Arc::new(Node {
        height: Mutex::new(3_470_700),
        utxos: Mutex::new(HashMap::new()),
        by_address: Mutex::new(HashMap::new()),
        broadcasts: Mutex::new(Vec::new()),
    });

    let node_app = axum::Router::new()
        .route("/", axum::routing::post(node_rpc))
        .route("/fund", axum::routing::post(fund))
        .route("/state", axum::routing::get(node_state))
        .route("/setheight", axum::routing::post(set_height))
        .with_state(node.clone());
    let node_port: u16 = std::env::var("STACK_NODE_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(18232);
    let node_listener = tokio::net::TcpListener::bind(("127.0.0.1", node_port)).await?;

    let d = SecretKey::from_slice(&[0xd1u8; 32]).unwrap();
    let attestor = Arc::new(Attestor {
        d,
        nonces: Mutex::new(HashMap::new()),
    });
    let attestor_app = axum::Router::new()
        .route("/identity", axum::routing::get(identity))
        .route("/announce", axum::routing::post(announce))
        .route("/attest", axum::routing::post(attest))
        .with_state(attestor.clone());
    let attestor_port: u16 = std::env::var("STACK_ATTESTOR_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(18480);
    let attestor_listener = tokio::net::TcpListener::bind(("127.0.0.1", attestor_port)).await?;

    let curator_app = axum::Router::new()
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
                    "responseObject": { "hashedOnchainId": format!("0x{}", hex::encode(CURATOR_HASH)) },
                }))
            }),
        );
    let curator_port: u16 = std::env::var("STACK_CURATOR_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(18500);
    let curator_listener = tokio::net::TcpListener::bind(("127.0.0.1", curator_port)).await?;

    let secp = Secp256k1::new();
    println!("node      http://127.0.0.1:{node_port}   (POST /fund, GET /state)");
    println!("attestor  http://127.0.0.1:{attestor_port}   key {}", hex::encode(d.public_key(&secp).serialize()));
    println!("curator   http://127.0.0.1:{curator_port}");

    tokio::try_join!(
        async { axum::serve(node_listener, node_app).await.map_err(anyhow::Error::from) },
        async { axum::serve(attestor_listener, attestor_app).await.map_err(anyhow::Error::from) },
        async { axum::serve(curator_listener, curator_app).await.map_err(anyhow::Error::from) },
    )?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct RpcCall {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

async fn node_rpc(
    axum::extract::State(node): axum::extract::State<Arc<Node>>,
    axum::Json(call): axum::Json<RpcCall>,
) -> axum::Json<serde_json::Value> {
    let result = match call.method.as_str() {
        "getblockchaininfo" => serde_json::json!({
            "chain": "test",
            "blocks": *node.height.lock().await,
            "consensus": { "chaintip": format!("{BRANCH_ID:08x}") },
        }),
        "gettxout" => {
            let txid = call.params[0].as_str().unwrap_or_default().to_string();
            let vout = call.params[1].as_u64().unwrap_or(0) as u32;
            match node.utxos.lock().await.get(&(txid, vout)) {
                Some((spk, zat, confs)) => serde_json::json!({
                    "confirmations": confs,
                    "value": *zat as f64 / 1e8,
                    "valueZat": zat,
                    "scriptPubKey": { "hex": spk },
                }),
                None => serde_json::Value::Null,
            }
        }
        "getaddressutxos" => {
            let addresses = call.params[0]["addresses"].as_array().cloned().unwrap_or_default();
            let by_address = node.by_address.lock().await;
            let mut out = Vec::new();
            for a in addresses {
                let Some(addr) = a.as_str() else { continue };
                for (txid, vout, zat, _) in by_address.get(addr).into_iter().flatten() {
                    out.push(serde_json::json!({
                        "txid": txid,
                        "outputIndex": vout,
                        "satoshis": zat,
                        "height": 3_470_700,
                    }));
                }
            }
            serde_json::Value::Array(out)
        }
        "sendrawtransaction" => {
            let raw = call.params[0].as_str().unwrap_or_default().to_string();
            let bytes = hex::decode(&raw).unwrap_or_default();
            let txid = zecp2p_escrow::tx::txid_of_signed(&bytes)
                .map(|t| zecp2p_escrow::rpc::txid_to_display(&t))
                .unwrap_or_default();
            println!("[node] broadcast {txid} ({} bytes)", bytes.len());
            node.broadcasts.lock().await.push(raw);
            *node.height.lock().await += 1;
            serde_json::Value::String(txid)
        }
        other => {
            return axum::Json(serde_json::json!({
                "result": null,
                "error": { "code": -32601, "message": format!("Method not found: {other}") },
            }))
        }
    };
    axum::Json(serde_json::json!({ "result": result, "error": null }))
}

#[derive(serde::Deserialize)]
struct FundRequest {
    address: String,
    script_pubkey: String,
    amount_zat: u64,
    #[serde(default = "default_confs")]
    confirmations: u32,
}

fn default_confs() -> u32 {
    30
}

/// Tells the node an address was paid. This is the wallet, in one call.
async fn fund(
    axum::extract::State(node): axum::extract::State<Arc<Node>>,
    axum::Json(req): axum::Json<FundRequest>,
) -> axum::Json<serde_json::Value> {
    // A txid derived from the address, so a rerun is stable.
    let mut txid = [0u8; 32];
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(req.address.as_bytes()).into();
    txid.copy_from_slice(&digest);
    let display = zecp2p_escrow::rpc::txid_to_display(&txid);

    node.utxos.lock().await.insert(
        (display.clone(), 0),
        (req.script_pubkey.clone(), req.amount_zat, req.confirmations),
    );
    node.by_address
        .lock()
        .await
        .entry(req.address.clone())
        .or_default()
        .push((display.clone(), 0, req.amount_zat, req.script_pubkey));

    println!(
        "[node] funded {} with {} zat, {} confirmations, txid {display}",
        req.address, req.amount_zat, req.confirmations
    );
    axum::Json(serde_json::json!({ "txid": display, "vout": 0 }))
}

#[derive(serde::Deserialize)]
struct SetHeight {
    height: u32,
}

/// Moves the chain tip. Time passing, in one call.
async fn set_height(
    axum::extract::State(node): axum::extract::State<Arc<Node>>,
    axum::Json(req): axum::Json<SetHeight>,
) -> axum::Json<serde_json::Value> {
    *node.height.lock().await = req.height;
    println!("[node] height is now {}", req.height);
    axum::Json(serde_json::json!({ "height": req.height }))
}

async fn node_state(
    axum::extract::State(node): axum::extract::State<Arc<Node>>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "height": *node.height.lock().await,
        "broadcasts": node.broadcasts.lock().await.clone(),
    }))
}

struct Attestor {
    d: SecretKey,
    nonces: Mutex<HashMap<String, SecretKey>>,
}

async fn identity(
    axum::extract::State(a): axum::extract::State<Arc<Attestor>>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    axum::Json(serde_json::json!({
        "p": hex::encode(a.d.public_key(&secp).serialize()),
        "build_id": "local-stack",
    }))
}

#[derive(serde::Deserialize)]
struct AnnounceBody {
    terms: zecp2p_escrow::lp_client::WireTerms,
}

fn terms_from_wire(
    w: &zecp2p_escrow::lp_client::WireTerms,
) -> zecp2p_escrow::terms::CanonicalTerms {
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

async fn announce(
    axum::extract::State(a): axum::extract::State<Arc<Attestor>>,
    axum::Json(body): axum::Json<AnnounceBody>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    let terms = terms_from_wire(&body.terms);
    let event_id = zecp2p_escrow::dlc::event_id(&terms.funding_txid, terms.vout);
    let event_hex = hex::encode(event_id);
    let terms_hash = hex::encode(terms.terms_hash());

    let mut nonces = a.nonces.lock().await;
    // One nonce per event, drawn once. A second R would strand the
    // pre-signature made under the first.
    let k = nonces.entry(event_hex.clone()).or_insert_with(|| {
        let mut raw = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut raw);
        SecretKey::from_slice(&raw).expect("a valid scalar")
    });

    println!("[attestor] announced {event_hex} terms {terms_hash}");
    axum::Json(serde_json::json!({
        "event_id": event_hex,
        "r": hex::encode(k.public_key(&secp).serialize()),
        "p": hex::encode(a.d.public_key(&secp).serialize()),
        "terms_hash": terms_hash,
    }))
}

#[derive(serde::Deserialize)]
struct AttestBody {
    event_id: String,
    terms: zecp2p_escrow::lp_client::WireTerms,
}

async fn attest(
    axum::extract::State(a): axum::extract::State<Arc<Attestor>>,
    axum::Json(body): axum::Json<AttestBody>,
) -> axum::Json<serde_json::Value> {
    let secp = Secp256k1::new();
    let terms = terms_from_wire(&body.terms);
    let nonces = a.nonces.lock().await;
    let Some(k) = nonces.get(&body.event_id) else {
        return axum::Json(serde_json::json!({ "error": "no such event" }));
    };
    let event_id: [u8; 32] = hex::decode(&body.event_id).unwrap().try_into().unwrap();
    let s = zecp2p_escrow::dlc::sign_outcome(&secp, k, &a.d, &event_id, &terms.terms_hash())
        .expect("the outcome signs");
    println!("[attestor] signed the outcome for {}", body.event_id);
    axum::Json(serde_json::json!({ "s": hex::encode(s.secret_bytes()) }))
}
