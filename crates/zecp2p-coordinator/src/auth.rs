//! Who is allowed to do what.
//!
//! Two separate questions, answered two different ways.
//!
//! **Ownership** of a session is proven by a signature from the address the
//! session names. `POST /offramp` carries a caller-supplied `user_address`, and
//! rescue and withdraw move that user's money, so the caller has to show it
//! holds the key for that address rather than merely naming it. The proof is an
//! EIP-191 personal_sign over a fixed-format message that names the action, the
//! address and the session, so a signature captured from one request cannot be
//! replayed against another.
//!
//! **Access** to the taker-facing listing is a shared bearer token. There is no
//! per-taker identity to bind to, and the point is only to stop the endpoint
//! being a public directory of Venmo handles.
//!
//! Both are enforced, not advisory: an unauthenticated coordinator reachable off
//! loopback is refused at startup in `main.rs`.

use alloy::primitives::Address;
use alloy::signers::Signature;
use axum::http::HeaderMap;
use std::str::FromStr;

use crate::error::AppError;

/// Header carrying the hex EIP-191 signature over [`ownership_message`].
pub const SIGNATURE_HEADER: &str = "x-zecp2p-signature";

/// Header carrying the bearer token for taker-facing endpoints.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The exact bytes a user signs to prove they control `user_address`.
///
/// Every field that decides what the request does is in here. `action` stops a
/// signature for one endpoint being replayed against another, and `scope` binds
/// it to the one session (or, at creation time, to the request's own
/// parameters) so it cannot be reused against a different one.
pub fn ownership_message(action: &str, user_address: Address, scope: &str) -> String {
    format!("zecp2p:{action}:{user_address:?}:{scope}")
}

/// Recover the signer of `message` from an EIP-191 signature.
fn recover(message: &str, signature_hex: &str) -> Result<Address, AppError> {
    let signature = Signature::from_str(signature_hex.trim())
        .map_err(|_| AppError::Unauthorized("signature is not valid hex".to_string()))?;

    signature
        .recover_address_from_msg(message.as_bytes())
        .map_err(|_| AppError::Unauthorized("signature does not recover".to_string()))
}

/// Require that `headers` carry a signature over `ownership_message(...)` made
/// by `user_address` itself.
pub fn require_owner(
    headers: &HeaderMap,
    action: &str,
    user_address: Address,
    scope: &str,
) -> Result<(), AppError> {
    let provided = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Unauthorized(format!(
                "missing {SIGNATURE_HEADER}; sign \"{}\" with the session's key",
                ownership_message(action, user_address, scope)
            ))
        })?;

    let message = ownership_message(action, user_address, scope);
    let recovered = recover(&message, provided)?;

    if recovered != user_address {
        return Err(AppError::Unauthorized(
            "signature is from a different address than the session's user".to_string(),
        ));
    }

    Ok(())
}

/// Require the taker bearer token, when one is configured.
///
/// `expected` is `None` only for a loopback-bound development coordinator;
/// `main.rs` refuses to start without a token on any other bind address, so a
/// reachable deployment always has one.
pub fn require_taker_token(headers: &HeaderMap, expected: Option<&str>) -> Result<(), AppError> {
    let Some(expected) = expected else {
        return Ok(());
    };

    let provided = headers
        .get(AUTHORIZATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            AppError::Unauthorized("missing bearer token for the deposit listing".to_string())
        })?;

    // Length-independent comparison; the token is a shared secret.
    if !constant_time_eq(provided.trim().as_bytes(), expected.as_bytes()) {
        return Err(AppError::Unauthorized("bearer token is not valid".to_string()));
    }

    Ok(())
}

/// Compare without leaking where the first difference is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use axum::http::HeaderValue;

    fn signed_headers(signer: &PrivateKeySigner, message: &str) -> HeaderMap {
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            SIGNATURE_HEADER,
            HeaderValue::from_str(&sig.to_string()).unwrap(),
        );
        headers
    }

    #[test]
    fn the_session_owner_is_accepted() {
        let signer = PrivateKeySigner::random();
        let user = signer.address();
        let message = ownership_message("rescue", user, "session-1");

        assert!(require_owner(&signed_headers(&signer, &message), "rescue", user, "session-1").is_ok());
    }

    #[test]
    fn a_stranger_signing_for_someone_elses_address_is_refused() {
        let attacker = PrivateKeySigner::random();
        let victim = PrivateKeySigner::random().address();

        // The attacker signs the victim's message with their own key.
        let message = ownership_message("rescue", victim, "session-1");
        let headers = signed_headers(&attacker, &message);

        assert!(require_owner(&headers, "rescue", victim, "session-1").is_err());
    }

    #[test]
    fn a_missing_signature_is_refused() {
        let user = PrivateKeySigner::random().address();
        assert!(require_owner(&HeaderMap::new(), "rescue", user, "session-1").is_err());
    }

    #[test]
    fn a_signature_for_one_session_does_not_work_on_another() {
        let signer = PrivateKeySigner::random();
        let user = signer.address();
        let headers = signed_headers(&signer, &ownership_message("rescue", user, "session-1"));

        assert!(require_owner(&headers, "rescue", user, "session-2").is_err());
    }

    #[test]
    fn a_signature_for_one_action_does_not_work_on_another() {
        let signer = PrivateKeySigner::random();
        let user = signer.address();
        let headers = signed_headers(&signer, &ownership_message("rescue", user, "session-1"));

        assert!(require_owner(&headers, "withdraw", user, "session-1").is_err());
    }

    #[test]
    fn the_taker_token_has_to_match() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION_HEADER, HeaderValue::from_static("Bearer right"));

        assert!(require_taker_token(&headers, Some("right")).is_ok());
        assert!(require_taker_token(&headers, Some("wrong")).is_err());
        assert!(require_taker_token(&HeaderMap::new(), Some("right")).is_err());
        // Unset means loopback development, which main.rs gates separately.
        assert!(require_taker_token(&HeaderMap::new(), None).is_ok());
    }
}
