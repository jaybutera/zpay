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
use crate::{AttestorError, ChainObservation, Clock};

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
    /// The enclave key this service trusts.
    ///
    /// Always `ENCLAVE_SIGNER` in a production build - the field only exists
    /// under `test-signer`, and `new` is the only constructor without it. A
    /// regtest run needs it because a real attestation requires a real Venmo
    /// payment through the pinned prover, which is the mainnet leg; running the
    /// plumbing against a test key proves the plumbing and nothing about the
    /// enclave.
    #[cfg(feature = "test-signer")]
    trusted_signer: [u8; 20],
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
            #[cfg(feature = "test-signer")]
            trusted_signer: zecp2p_escrow::attestation::ENCLAVE_SIGNER,
        }
    }

    /// As [`new`], trusting a caller-supplied enclave key. Test builds only.
    #[cfg(feature = "test-signer")]
    #[allow(clippy::too_many_arguments)]
    pub fn with_trusted_signer(
        db: SqliteEventStore,
        d: SecretKey,
        chain: C,
        clock: K,
        bearer_token: String,
        build_id: String,
        trusted_signer: [u8; 20],
    ) -> Self {
        Self {
            trusted_signer,
            ..Self::new(db, d, chain, clock, bearer_token, build_id)
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

    // R6-2: a lost /announce response left the LP with no `R` and no way to ask
    // for it, and with an external wallet the escrow may already be funded - so
    // that escrow waits until `T` for nothing. A repeat carrying the same terms
    // returns the announcement that exists. Different terms for the same escrow
    // stay a 409, which is the rule that matters: one escrow, one nonce.
    if let Err(e) = result {
        let err = crate::map_store_error(e);
        let svc3 = svc.clone();
        let replay = tokio::task::spawn_blocking(move || {
            let db = svc3.db.blocking_lock();
            db.get(&event_id).ok().flatten()
        })
        .await
        .ok()
        .flatten();

        match replay {
            Some(row) if row.terms_hash == terms.terms_hash() => {
                tracing::info!(
                    event_id = %hex::encode(event_id),
                    decision = "replayed",
                    "announce"
                );
                return Ok(Json(AnnounceResponse {
                    event_id: hex::encode(event_id),
                    r: hex::encode(row.r),
                    p: hex::encode(svc.public_key().serialize()),
                    terms_hash: hex::encode(row.terms_hash),
                    outcome: zecp2p_escrow::dlc::OUTCOME_PAID,
                }));
            }
            _ => {
                tracing::warn!(
                    event_id = %hex::encode(event_id),
                    decision = "refused", reason = %err, "announce"
                );
                return Err(reject(status_for(&err), &err.to_string()));
            }
        }
    }

    // Spec section 6: log the event id and the decision. Never `k`, never the
    // terms beyond their hash (criterion 14).
    tracing::info!(
        event_id = %hex::encode(event_id),
        terms_hash = %hex::encode(terms.terms_hash()),
        decision = "announced",
        "announce"
    );

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
    // R6-6: three phases, so the store lock is not held across the chain round
    // trip. One stalled `gettxout` used to block every other announce and attest
    // for as long as the RPC timeout.
    //
    // 1. Under the lock, read the announcement.
    let svc1 = svc.clone();
    let ev1 = derived;
    let event = tokio::task::spawn_blocking(move || {
        let db = svc1.db.blocking_lock();
        crate::attest_prepare(&db, &ev1)
    })
    .await
    .map_err(|_| {
        reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the attestor could not read its store",
        )
    })?
    .map_err(|e| reject(status_for(&e), &e.to_string()))?;

    // 1b. R7-5: an exact replay of an already-signed event is answered before
    //     the node is consulted. `gettxout` returns null for a spent output, so
    //     an LP retrying a lost response after the escrow was released or
    //     refunded used to get a 503 it is told to retry - forever, since the
    //     output never comes back. The scalar already exists and the request
    //     still has to prove it is the same one, which phase 3 checks.
    if event.signed_s.is_some() {
        let svc_r = svc.clone();
        let terms_r = terms.clone();
        let att_r = attestation.clone();
        let sig_r = signature.clone();
        let det_r = details.clone();
        let announced = event.announced_at_ms;
        let replay = tokio::task::spawn_blocking(move || {
            let mut db = svc_r.db.blocking_lock();
            // A signed event's observation cannot change the outcome of a
            // replay: every check a replay must pass is about the request and
            // the row. Feed the recorded escrow facts back in.
            let obs = ChainObservation {
                script_pubkey: zecp2p_escrow::script::p2sh_script_pubkey(
                    &zecp2p_escrow::script::redeem_script(
                        &terms_r.u_pub,
                        &terms_r.l_pub,
                        terms_r.refund_height,
                    )
                    .ok()?,
                ),
                amount_zat: terms_r.amount_zat,
                confirmations: u32::MAX,
                earliest_acceptable_payment_ms: announced,
            };
            #[cfg(feature = "test-signer")]
            let out = crate::attest_decide_and_sign_against_signer(
                &mut db, &svc_r.secp, &svc_r.d, &svc_r.clock, &derived, &terms_r, &att_r,
                &sig_r, &det_r, &obs, &RatePolicy::production(), &svc_r.trusted_signer,
            );
            #[cfg(not(feature = "test-signer"))]
            let out = crate::attest_decide_and_sign(
                &mut db, &svc_r.secp, &svc_r.d, &svc_r.clock, &derived, &terms_r, &att_r,
                &sig_r, &det_r, &obs, &RatePolicy::production(),
            );
            Some(out)
        })
        .await
        .ok()
        .flatten();

        if let Some(result) = replay {
            return match result {
                Ok(s) => {
                    tracing::info!(
                        event_id = %hex::encode(derived), decision = "replayed", "attest"
                    );
                    Ok(Json(AttestResponse {
                        s: hex::encode(s.secret_bytes()),
                    }))
                }
                Err(e) => {
                    tracing::warn!(
                        event_id = %hex::encode(derived), decision = "refused",
                        phase = "replay", reason = %e, "attest"
                    );
                    Err(reject(status_for(&e), &e.to_string()))
                }
            };
        }
    }

    // 2. Without the lock, ask the node about the escrow.
    let svc2 = svc.clone();
    let terms2 = terms.clone();
    let announced_at = event.announced_at_ms;
    let observation = tokio::task::spawn_blocking(move || {
        crate::observe_escrow(&svc2.chain, &terms2, announced_at)
    })
    .await
    .map_err(|_| {
        tracing::warn!(
            event_id = %hex::encode(derived), decision = "refused",
            phase = "chain", "attest"
        );
        reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "the attestor could not reach its node",
        )
    })?
    .map_err(|e| {
        tracing::warn!(
            event_id = %hex::encode(derived), decision = "refused",
            phase = "chain", reason = %e, "attest"
        );
        reject(status_for(&e), &e.to_string())
    })?;

    // 3. Under the lock again, decide and sign. A request that raced us between
    //    phases loses at the commit, not here: the signing transaction's
    //    `UPDATE ... WHERE s IS NULL` and the UNIQUE payment nullifier are what
    //    make check-then-sign atomic.
    let svc3 = svc.clone();
    let s = tokio::task::spawn_blocking(move || {
        let mut db = svc3.db.blocking_lock();
        #[cfg(feature = "test-signer")]
        let out = crate::attest_decide_and_sign_against_signer(
            &mut db, &svc3.secp, &svc3.d, &svc3.clock, &derived, &terms, &attestation,
            &signature, &details, &observation, &RatePolicy::production(),
            &svc3.trusted_signer,
        );
        #[cfg(not(feature = "test-signer"))]
        let out = crate::attest_decide_and_sign(
            &mut db, &svc3.secp, &svc3.d, &svc3.clock, &derived, &terms, &attestation,
            &signature, &details, &observation, &RatePolicy::production(),
        );
        out
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
    .map_err(|e| {
        tracing::warn!(
            event_id = %hex::encode(derived),
            decision = "refused",
            reason = %e,
            "attest"
        );
        reject(status_for(&e), &e.to_string())
    })?;

    // Spec section 6: the event id, the decision, and the enclave signature -
    // and of the attestation payload only the intent hash, the release amount
    // and the signer.
    tracing::info!(
        event_id = %hex::encode(derived),
        decision = "signed",
        intent_hash = %req.attestation.intent_hash,
        release_amount = %req.attestation.release_amount,
        enclave_signature = %req.attestation.signature,
        "attest"
    );

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
