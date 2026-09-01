//! A stand-in for the zk-p2p curator, built to the live API's actual behaviour.
//!
//! The point of this mock is the thing the taker crate had no test for: the
//! request body. NEW-2 in the 2026-08-31 re-audit was a body the live curator
//! does not accept, and no test existed to catch it, so the failure was waiting
//! for the first live run.
//!
//! So this mock deserializes strictly. It requires a flat `offchainId` and
//! answers the way `api.zkp2p.xyz` answered a probe on 2026-08-31:
//!
//! ```text
//! POST /v2/makers/validate {"processorName":"venmo","offchainId":"test-payee"}
//!   -> {"success":true,"message":"Maker data is valid","responseObject":true}
//! POST /v2/makers/validate {"processorName":"venmo","depositData":{"venmoUsername":"..."}}
//!   -> {"success":true,"message":"Maker data is invalid","responseObject":false}
//! ```
//!
//! Note the second: HTTP 200 with `success: true`. The curator does not reject a
//! wrong body with a status code, it reports the maker as invalid. A mock that
//! answered 400 would let a body bug through a `!status.is_success()` check.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use serde_json::{json, Value};

#[derive(Clone, Default)]
pub struct CuratorLog {
    /// Every raw body the curator was posted, in order, per path.
    pub bodies: Arc<Mutex<Vec<(String, Value)>>>,
}

impl CuratorLog {
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.bodies.lock().unwrap().clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.calls().into_iter().map(|(p, _)| p).collect()
    }
}

pub struct MockCurator {
    port: u16,
    log: CuratorLog,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockCurator {
    pub async fn start() -> Self {
        let log = CuratorLog::default();
        let app = Router::new()
            .route("/v2/makers/validate", post(validate))
            .route("/v2/makers/create", post(create))
            .with_state(log.clone());

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock curator");
        let port = listener.local_addr().expect("local addr").port();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        Self {
            port,
            log,
            shutdown: Some(tx),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn log(&self) -> CuratorLog {
        self.log.clone()
    }

    /// The hash this mock issues for a username, so a test can assert on it.
    pub fn expected_hash(offchain_id: &str) -> alloy::primitives::B256 {
        alloy::primitives::keccak256(format!("mock-zkp2p-payee:{offchain_id}").as_bytes())
    }
}

impl Drop for MockCurator {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Pull a flat `offchainId` out of the body, the way the real curator does.
///
/// Returns `None` for anything else, including the nested `depositData` shape,
/// which is what the live API treats as an invalid maker.
fn offchain_id(body: &Value) -> Option<&str> {
    let processor = body.get("processorName")?.as_str()?;
    if processor != "venmo" {
        return None;
    }
    let id = body.get("offchainId")?.as_str()?;
    if id.is_empty() {
        return None;
    }
    Some(id)
}

/// Usernames this mock's curator has heard of. Anything else validates false,
/// the way the live API rejects a made-up handle.
fn is_registered(offchain_id: &str) -> bool {
    !offchain_id.starts_with("unknown")
}

async fn validate(State(log): State<CuratorLog>, Json(body): Json<Value>) -> Json<Value> {
    log.bodies
        .lock()
        .unwrap()
        .push(("/v2/makers/validate".to_string(), body.clone()));

    match offchain_id(&body).filter(|id| is_registered(id)) {
        Some(_) => Json(json!({
            "success": true,
            "message": "Maker data is valid",
            "responseObject": true,
            "statusCode": 200
        })),
        // 200 with success:true and responseObject:false, as production answers.
        None => Json(json!({
            "success": true,
            "message": "Maker data is invalid",
            "responseObject": false,
            "statusCode": 200
        })),
    }
}

async fn create(State(log): State<CuratorLog>, Json(body): Json<Value>) -> Json<Value> {
    log.bodies
        .lock()
        .unwrap()
        .push(("/v2/makers/create".to_string(), body.clone()));

    match offchain_id(&body) {
        Some(id) => Json(json!({
            "success": true,
            "message": "Maker created successfully",
            "responseObject": {
                "id": 6577,
                "processorName": "venmo",
                "offchainId": id,
                "hashedOnchainId": format!("{:?}", MockCurator::expected_hash(id)),
                "isBusiness": false,
                "revoked": false
            }
        })),
        None => Json(json!({
            "success": false,
            "message": "Maker data is invalid",
            "responseObject": null,
            "statusCode": 400
        })),
    }
}
