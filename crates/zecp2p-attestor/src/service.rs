//! The attestor's HTTP surface, spec section 6.
//!
//! `GET /identity`, `POST /announce`, `POST /attest`. Phase 1 authenticates
//! with a shared bearer token; in Phase 7 the Nitro attestation document on
//! `/identity` is what the user relies on instead.
//!
//! The round-4 review passed the choke-point functions on the understanding
//! that this layer was unwritten, so it is written to that guidance: no handler
//! here accepts a caller-supplied script, amount, confirmation depth, timestamp
//! or nonce. Every one of those comes from the attestor's own node, clock or
//! RNG. What a caller sends is the terms and the attestation, and both are
//! checked against things the attestor already holds.

use std::sync::Arc;

use tokio::sync::Mutex;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use secp256k1_zkp::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use zecp2p_escrow::attestation::PaymentAttestation;
use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::payment_details::RatePolicy;
use zecp2p_escrow::terms::CanonicalTerms;

use crate::db::SqliteEventStore;
use crate::{AttestorError, Clock};

/// Everything the service holds. `d` never leaves it.
pub struct AttestorService<C, K> {
    /// A `tokio::sync::Mutex`, not a `std::sync::Mutex`.
    ///
    /// Round 5 finding R5-4: the std mutex poisons if a handler panics while
    /// holding it, and both handlers took it with `.expect`, so one panic made
    /// every later request panic too. A tokio mutex has no poisoning, and the
    /// blocking work now happens inside `spawn_blocking` where a panic is
    /// returned as a `JoinError` rather than unwinding through the guard.
    db: Mutex<SqliteEventStore>,
    secp: Secp256k1<secp256k1_zkp::All>,
    d: SecretKey,
    chain: C,
    clock: K,
    bearer_token: String,
    build_id: String,
}

impl<C, K> std::fmt::Debug for AttestorService<C, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `d` and the bearer token are both secrets (criterion 14).
        f.debug_struct("AttestorService")
            .field("build_id", &self.build_id)
            .finish_non_exhaustive()
    }
}

impl<C: ChainClient, K: Clock> AttestorService<C, K> {
    pub fn new(
        db: SqliteEventStore,
        d: SecretKey,
        chain: C,
        clock: K,
        bearer_token: String,
        build_id: String,
    ) -> Self {
        Self {
            db: Mutex::new(db),
            secp: Secp256k1::new(),
            d,
            chain,
            clock,
            bearer_token,
            build_id,
        }
    }

    /// The attestor's public key `P`, which the user pins.
    pub fn public_key(&self) -> secp256k1_zkp::PublicKey {
        self.d.public_key(&self.secp)
    }
}

// --- Wire types. Hex in, hex out; nothing here is a chain fact. ---

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    /// 33-byte compressed `P`.
    pub p: String,
    pub build_id: String,
    /// Phase 7 puts the Nitro attestation document here. Until then the user is
    /// trusting the operator, and saying so in the response is more honest than
    /// omitting the field.
    pub attestation_document: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AnnounceRequest {
    pub terms: WireTerms,
}

#[derive(Debug, Serialize)]
pub struct AnnounceResponse {
    pub event_id: String,
    /// 33-byte compressed `R`, drawn by the attestor.
    pub r: String,
    pub p: String,
    pub terms_hash: String,
    pub outcome: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    pub event_id: String,
    pub terms: WireTerms,
    pub attestation: WireAttestation,
}

#[derive(Debug, Serialize)]
pub struct AttestResponse {
    /// The outcome scalar `s`, which is public once the release is broadcast.
    pub s: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireTerms {
    pub funding_txid: String,
    pub vout: u32,
    pub amount_zat: u64,
    pub u_pub: String,
    pub l_pub: String,
    pub refund_height: u64,
    pub usd_amount_6dec: u64,
    pub rate_18dec: String,
    pub payee_hash: String,
    pub lock_confirmed_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireAttestation {
    pub intent_hash: String,
    pub release_amount: String,
    pub data_hash: String,
    pub signature: String,
    pub encoded_payment_details: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    v.try_into().map_err(|_| "expected 32 bytes".to_string())
}

fn hex33(s: &str) -> Result<[u8; 33], String> {
    let v = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    v.try_into().map_err(|_| "expected 33 bytes".to_string())
}

impl WireTerms {
    pub fn decode(&self) -> Result<CanonicalTerms, String> {
        Ok(CanonicalTerms {
            funding_txid: hex32(&self.funding_txid)?,
            vout: self.vout,
            amount_zat: self.amount_zat,
            u_pub: hex33(&self.u_pub)?,
            l_pub: hex33(&self.l_pub)?,
            refund_height: self.refund_height,
            usd_amount_6dec: self.usd_amount_6dec,
            rate_18dec: self.rate_18dec.parse().map_err(|_| "bad rate".to_string())?,
            payee_hash: hex32(&self.payee_hash)?,
            lock_confirmed_ms: self.lock_confirmed_ms,
        })
    }

    pub fn from_terms(t: &CanonicalTerms) -> Self {
        Self {
            funding_txid: hex::encode(t.funding_txid),
            vout: t.vout,
            amount_zat: t.amount_zat,
            u_pub: hex::encode(t.u_pub),
            l_pub: hex::encode(t.l_pub),
            refund_height: t.refund_height,
            usd_amount_6dec: t.usd_amount_6dec,
            rate_18dec: t.rate_18dec.to_string(),
            payee_hash: hex::encode(t.payee_hash),
            lock_confirmed_ms: t.lock_confirmed_ms,
        }
    }
}

impl WireAttestation {
    fn decode(&self) -> Result<(PaymentAttestation, Vec<u8>, Vec<u8>), String> {
        Ok((
            PaymentAttestation {
                intent_hash: hex32(&self.intent_hash)?,
                release_amount: self
                    .release_amount
                    .parse()
                    .map_err(|_| "bad releaseAmount".to_string())?,
                data_hash: hex32(&self.data_hash)?,
            },
            hex::decode(self.signature.trim_start_matches("0x")).map_err(|e| e.to_string())?,
            hex::decode(self.encoded_payment_details.trim_start_matches("0x"))
                .map_err(|e| e.to_string())?,
        ))
    }
}

/// Maps a decision to a status code.
///
/// The split is deliberate: a refusal the caller can act on is a 4xx, and one
/// that means "the attestor could not look" is a 5xx, because the LP retries
/// the second and not the first.
fn status_for(err: &AttestorError) -> StatusCode {
    match err {
        AttestorError::UnknownEvent | AttestorError::EventIdMismatch { .. } => {
            StatusCode::NOT_FOUND
        }
        AttestorError::AlreadySigned
        | AttestorError::DuplicateAnnouncement
        | AttestorError::PaymentAlreadyConsumed => StatusCode::CONFLICT,
        // "The attestor could not look", not "the attestor decided". The LP
        // retries these; it does not retry a 4xx. `EscrowNotFound` and
        // `InsufficientDepth` are here because both mean the attestor's node
        // has not caught up yet, which the LP reaches whenever its own node is
        // ahead (R5-1).
        AttestorError::Chain(_)
        | AttestorError::ZeroClock
        | AttestorError::Unavailable(_)
        | AttestorError::EscrowNotFound
        | AttestorError::InsufficientDepth { .. } => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| {
            // Constant-time-ish: compare full length rather than short-circuit
            // on the first differing byte.
            let (a, b) = (t.as_bytes(), expected.as_bytes());
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        })
}

type Svc<C, K> = Arc<AttestorService<C, K>>;

pub fn router<C, K>(service: Svc<C, K>) -> Router
where
    C: ChainClient + Send + Sync + 'static,
    K: Clock + Send + Sync + 'static,
{
    Router::new()
        .route("/identity", get(identity::<C, K>))
        .route("/announce", post(announce::<C, K>))
        .route("/attest", post(attest::<C, K>))
        .with_state(service)
}

async fn identity<C, K>(State(svc): State<Svc<C, K>>) -> Json<IdentityResponse>
where
    C: ChainClient + Send + Sync + 'static,
    K: Clock + Send + Sync + 'static,
{
    Json(IdentityResponse {
        p: hex::encode(svc.public_key().serialize()),
        build_id: svc.build_id.clone(),
        attestation_document: None,
    })
}

async fn announce<C, K>(
    State(svc): State<Svc<C, K>>,
    headers: HeaderMap,
    Json(req): Json<AnnounceRequest>,
) -> Result<Json<AnnounceResponse>, (StatusCode, Json<ErrorResponse>)>
where
    C: ChainClient + Send + Sync + 'static,
    K: Clock + Send + Sync + 'static,
{
    if !authorized(&headers, &svc.bearer_token) {
        return Err(reject(StatusCode::UNAUTHORIZED, "bad bearer token"));
    }
    let terms = req
        .terms
        .decode()
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;

    // The event id is derived from the outpoint, never taken from the request.
    let event_id = zecp2p_escrow::dlc::event_id(&terms.funding_txid, terms.vout);

    // The nonce is drawn here, from the OS RNG (round 4 finding 1).
    let k = SecretKey::new(&mut secp256k1_zkp::rand::thread_rng());
    let r = k.public_key(&svc.secp);

    let announced_at_ms = svc.clock.now_ms();
    if announced_at_ms == 0 {
        return Err(reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the attestor clock returned zero",
        ));
    }

    // SQLite is blocking. Holding the guard across `spawn_blocking` keeps the
    // announce atomic while keeping the executor free (R5-4).
    let svc2 = svc.clone();
    let terms_hash = terms.terms_hash();
    let funding_txid = terms.funding_txid;
    let k_bytes = k.secret_bytes();
    let r_bytes = r.serialize();
    let result = tokio::task::spawn_blocking(move || {
        let mut db = svc2.db.blocking_lock();
        db.announce(
            event_id,
            terms_hash,
            r_bytes,
            funding_txid,
            k_bytes,
            announced_at_ms,
        )
    })
    .await
    .map_err(|_| {
        reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the attestor could not complete the announcement",
        )
    })?;

    result.map_err(|e| {
        let err = crate::map_store_error(e);
        reject(status_for(&err), &err.to_string())
    })?;

    Ok(Json(AnnounceResponse {
        event_id: hex::encode(event_id),
        r: hex::encode(r.serialize()),
        p: hex::encode(svc.public_key().serialize()),
        terms_hash: hex::encode(terms.terms_hash()),
        outcome: zecp2p_escrow::dlc::OUTCOME_PAID,
    }))
}

async fn attest<C, K>(
    State(svc): State<Svc<C, K>>,
    headers: HeaderMap,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, (StatusCode, Json<ErrorResponse>)>
where
    C: ChainClient + Send + Sync + 'static,
    K: Clock + Send + Sync + 'static,
{
    if !authorized(&headers, &svc.bearer_token) {
        return Err(reject(StatusCode::UNAUTHORIZED, "bad bearer token"));
    }
    let terms = req
        .terms
        .decode()
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
    let (attestation, signature, details) = req
        .attestation
        .decode()
        .map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;

    let requested = hex32(&req.event_id).map_err(|e| reject(StatusCode::BAD_REQUEST, &e))?;
    let derived = zecp2p_escrow::dlc::event_id(&terms.funding_txid, terms.vout);
    if requested != derived {
        return Err(reject(
            StatusCode::NOT_FOUND,
            "the event id is not the one these terms' outpoint produces",
        ));
    }

    // The whole decision is blocking: it reads the escrow over HTTP and then
    // writes SQLite. Running it on a tokio worker is what R5-4 was - reqwest's
    // blocking client cannot drop its runtime inside an async context, and the
    // panic poisoned the store lock for every later request.
    let svc2 = svc.clone();
    let s = tokio::task::spawn_blocking(move || {
        let mut db = svc2.db.blocking_lock();
        crate::attest_over_db(
            &mut db,
            &svc2.chain,
            &svc2.secp,
            &svc2.d,
            &svc2.clock,
            &derived,
            &terms,
            &attestation,
            &signature,
            &details,
            &RatePolicy::production(),
        )
    })
    .await
    .map_err(|_| {
        // A panic in the decision path is an outage, not a verdict. The LP has
        // already paid Venmo by the time it calls this, so it must retry rather
        // than read a crash as "refused".
        reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the attestor could not complete the decision",
        )
    })?
    .map_err(|e| reject(status_for(&e), &e.to_string()))?;

    Ok(Json(AttestResponse {
        s: hex::encode(s.secret_bytes()),
    }))
}

fn reject(code: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        code,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}
