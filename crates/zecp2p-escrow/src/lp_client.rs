//! The LP's client for the attestor, spec 5.1 and 5.5.
//!
//! Round 7's blocker: nothing outside the attestor crate ever spoke to
//! `/announce` or `/attest`, so the attestor could not be part of any run. This
//! is that client, and it is deliberately small - the LP's judgement lives in
//! `lp.rs`, and this only carries bytes.
//!
//! # Byte order on the wire
//!
//! `funding_txid` in [`WireTerms`] is the **internal** order: the bytes as they
//! appear inside a transaction, which is the reverse of what every Zcash RPC
//! and every block explorer prints. Sent the other way the attestor asks its
//! node about an outpoint that does not exist and answers a 503 the LP is told
//! to retry, forever (round 7, item 7). [`WireTerms::from_terms`] does the right
//! thing; if you are building one by hand from an explorer, reverse it first.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::attestation::PaymentAttestation;
use crate::terms::CanonicalTerms;

/// The largest answer this client will read.
///
/// R8-6: every response the attestor sends is a few hundred bytes of hex. 64 KiB
/// is generous by two orders of magnitude and bounds what a misbehaving peer can
/// make the LP allocate.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// How long to wait for an attestor answer.
///
/// It must exceed the attestor's own rate-limit waiting, which is up to three
/// 60 s windows, plus its chain reads. Staged in review: the cold-attestor
/// `attest` that failed at 60 s completed in one run of 120 s with this.
pub const ATTESTOR_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum LpClientError {
    #[error("the attestor is unreachable: {0}")]
    Unreachable(String),
    /// The attestor did not answer inside the client's budget.
    ///
    /// R13-1: this is not a refusal, and must never be reported as one. The
    /// attestor reads the chain through the same rate-limited endpoint the
    /// runner does, so at `attest` its first `gettxout` can be the sixth call
    /// in the provider's minute and it sleeps inside the request. A timeout
    /// here means the work may still be in flight, or was cancelled when this
    /// client dropped the connection; either way the answer is to wait and run
    /// the same command again, not to re-run the prover.
    #[error("the attestor did not answer in time: {0}")]
    TimedOut(String),
    #[error("the attestor refused with {status}: {message}")]
    Refused { status: u16, message: String },
    #[error("the attestor's answer did not parse: {0}")]
    BadAnswer(String),
}

impl LpClientError {
    /// Whether the LP should try again.
    ///
    /// The split is the one `status_for` documents on the attestor side: 5xx
    /// means the attestor could not look, and 4xx means it looked and refused.
    /// An LP that retries a 4xx loops; an LP that gives up on a 5xx abandons an
    /// escrow it has already paid for.
    pub fn is_retryable(&self) -> bool {
        match self {
            LpClientError::Unreachable(_) | LpClientError::TimedOut(_) => true,
            LpClientError::Refused { status, .. } => *status >= 500,
            LpClientError::BadAnswer(_) => false,
        }
    }
}

/// The terms as they cross the wire. See the module note on byte order.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireTerms {
    /// Internal byte order, not the RPC's display order.
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

impl WireTerms {
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

#[derive(Debug, Serialize)]
struct AnnounceRequest {
    terms: WireTerms,
}

/// What `/announce` returns: the attestor's key, its nonce point, and the terms
/// hash it pinned.
#[derive(Debug, Deserialize, Clone)]
pub struct Announcement {
    pub event_id: String,
    pub r: String,
    pub p: String,
    pub terms_hash: String,
}

#[derive(Debug, Serialize)]
struct AttestRequest {
    event_id: String,
    terms: WireTerms,
    attestation: WireAttestation,
}

#[derive(Debug, Serialize, Clone)]
pub struct WireAttestation {
    pub intent_hash: String,
    pub release_amount: String,
    pub data_hash: String,
    pub signature: String,
    pub encoded_payment_details: String,
}

impl WireAttestation {
    pub fn from_parts(
        a: &PaymentAttestation,
        signature: &[u8],
        encoded_payment_details: &[u8],
    ) -> Self {
        Self {
            intent_hash: hex::encode(a.intent_hash),
            release_amount: a.release_amount.to_string(),
            data_hash: hex::encode(a.data_hash),
            signature: hex::encode(signature),
            encoded_payment_details: hex::encode(encoded_payment_details),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AttestResponse {
    s: String,
}

#[derive(Debug, Deserialize)]
struct IdentityResponse {
    p: String,
    build_id: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
}

/// The LP's connection to one attestor.
pub struct AttestorClient {
    base_url: String,
    token: String,
    http: reqwest::blocking::Client,
}

impl std::fmt::Debug for AttestorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bearer token is a secret.
        f.debug_struct("AttestorClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl AttestorClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, LpClientError> {
        let http = reqwest::blocking::Client::builder()
            // R13-1: the attestor reads the chain through the same
            // rate-limited endpoint the runner does, and waits out a 429
            // *inside* the request. At `attest` on a cold attestor its first
            // `gettxout` is reliably the sixth call in the provider's minute,
            // so a 60 s budget here expired at the same moment the attestor
            // was sleeping and the run died calling it a refusal. The attestor
            // may wait up to three windows; this must outlast that.
            .timeout(ATTESTOR_TIMEOUT)
            .build()
            .map_err(|e| LpClientError::Unreachable(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into(),
            token: token.into(),
            http,
        })
    }

    /// `GET /identity`: the attestor's public key, which the user pins.
    pub fn identity(&self) -> Result<(String, String), LpClientError> {
        let r: IdentityResponse = self.get("/identity")?;
        Ok((r.p, r.build_id))
    }

    /// `POST /announce`, spec 5.1.
    ///
    /// A repeat with the same terms returns the announcement that exists, so
    /// this is safe to retry after a lost response (spec 19.1).
    pub fn announce(&self, terms: &CanonicalTerms) -> Result<Announcement, LpClientError> {
        self.post(
            "/announce",
            &AnnounceRequest {
                terms: WireTerms::from_terms(terms),
            },
        )
    }

    /// `POST /attest`, spec 5.5. Returns the outcome scalar `s`.
    ///
    /// A repeat of the identical request returns the same scalar, which is what
    /// makes a lost response recoverable.
    pub fn attest(
        &self,
        event_id: &str,
        terms: &CanonicalTerms,
        attestation: WireAttestation,
    ) -> Result<[u8; 32], LpClientError> {
        let r: AttestResponse = self.post(
            "/attest",
            &AttestRequest {
                event_id: event_id.to_string(),
                terms: WireTerms::from_terms(terms),
                attestation,
            },
        )?;
        let bytes = hex::decode(&r.s).map_err(|e| LpClientError::BadAnswer(e.to_string()))?;
        bytes
            .try_into()
            .map_err(|_| LpClientError::BadAnswer("s is not 32 bytes".into()))
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, LpClientError> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .send()
            .map_err(Self::send_error)?;
        Self::parse(resp)
    }

    fn post<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, LpClientError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(Self::send_error)?;
        Self::parse(resp)
    }

    /// Separates "did not answer in time" from "could not be reached at all".
    fn send_error(e: reqwest::Error) -> LpClientError {
        if e.is_timeout() {
            LpClientError::TimedOut(e.to_string())
        } else {
            LpClientError::Unreachable(e.to_string())
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(
        resp: reqwest::blocking::Response,
    ) -> Result<T, LpClientError> {
        use std::io::Read;

        let status = resp.status();
        // R8-6: `text()` reads whatever the peer sends. An attestor cannot steal
        // by being large, but it can make the LP allocate, and every answer this
        // client expects is a few hundred bytes.
        let mut buf = Vec::new();
        resp.take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut buf)
            .map_err(|e| LpClientError::Unreachable(e.to_string()))?;
        if buf.len() as u64 == MAX_RESPONSE_BYTES {
            return Err(LpClientError::BadAnswer(format!(
                "the attestor's answer exceeded {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        if !status.is_success() {
            let message = serde_json::from_str::<ErrorBody>(&text)
                .map(|b| b.error)
                .unwrap_or_else(|_| text.chars().take(200).collect());
            return Err(LpClientError::Refused {
                status: status.as_u16(),
                message,
            });
        }
        serde_json::from_str(&text).map_err(|e| LpClientError::BadAnswer(e.to_string()))
    }
}
