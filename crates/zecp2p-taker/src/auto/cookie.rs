//! The Venmo session cookie: why it can be stored, and when to stop using it.
//!
//! The enclave replays a logged-in Venmo request from inside AWS Nitro and
//! signs the result. What it replays is a session cookie, which is a live bearer
//! credential. That is the whole browser dependency, and the useful finding is
//! how little of it is per-fill.
//!
//! zk-p2p's own attestation client documents that the service enforces **no
//! capture-age limit and no one-use replay limit**, and that verification
//! depends only on the upstream session still being active. So one capture from
//! a real logged-in browser serves many fills for the life of that Venmo
//! session. The daemon does not need a browser per attestation, and the
//! browser-driven step belongs in a `refresh-cookie` subcommand rather
//! than in the fill path.
//!
//! The same document says the flip side plainly: a leaked encrypted JWE is
//! valid for the upstream session lifetime and should be treated as equivalent
//! to leaking the cookie itself. This store is therefore as sensitive as a
//! password file.
//!
//! # What this module deliberately does not do
//!
//! It does not encrypt at rest. Doing that properly needs a key the operator
//! supplies at start and a decision about where that key lives, and a
//! half-implemented version reads as protection while providing none. The file
//! is created 0600 and the value is never logged; the gap is named in
//! `docs/status/auto-taker-daemon-design.md` rather than papered over.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Session material for the enclave, plus when it was captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMaterial {
    /// The `account.venmo.com` Cookie header.
    pub cookie: String,
    /// The numeric Venmo sender id whose feed the enclave reads.
    pub sender_id: String,
    /// The User-Agent the cookie was captured under. Venmo ties sessions to it
    /// closely enough that a mismatched agent can fail the replay.
    #[serde(default)]
    pub user_agent: Option<String>,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

impl SessionMaterial {
    pub fn age(&self) -> chrono::Duration {
        chrono::Utc::now() - self.captured_at
    }
}

/// Never let the cookie reach a log line through a derived Debug.
impl std::fmt::Display for SessionMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session for sender {} captured {} ({} bytes of cookie, not shown)",
            self.sender_id,
            self.captured_at.to_rfc3339(),
            self.cookie.len()
        )
    }
}

/// Why the daemon will not start a fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieHealth {
    /// Usable as far as anything local can tell. The enclave is the only real
    /// authority, and it is not consulted here.
    Usable,
    /// No stored session at all.
    Missing,
    /// Present but structurally wrong.
    Malformed(String),
    /// Older than the operator's configured limit.
    Stale { age_hours: i64, limit_hours: i64 },
}

impl CookieHealth {
    pub fn is_usable(&self) -> bool {
        matches!(self, CookieHealth::Usable)
    }

    /// The message an operator sees when a fill is refused.
    pub fn explain(&self) -> String {
        match self {
            CookieHealth::Usable => "session material looks usable".into(),
            CookieHealth::Missing => {
                "no stored Venmo session. Run `zecp2p-taker refresh-cookie` before \
                 the daemon can fill anything."
                    .into()
            }
            CookieHealth::Malformed(why) => {
                format!("the stored Venmo session is unusable: {why}. Re-capture it.")
            }
            CookieHealth::Stale {
                age_hours,
                limit_hours,
            } => format!(
                "the stored Venmo session was captured {age_hours}h ago, past the \
                 {limit_hours}h limit. Venmo may have expired it. Re-capture before \
                 signalling: failing this check costs nothing, failing after the \
                 payment costs the payment."
            ),
        }
    }
}

pub struct CookieStore {
    path: PathBuf,
    max_age_hours: i64,
}

impl CookieStore {
    pub fn new(path: impl AsRef<Path>, max_age_hours: i64) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            max_age_hours,
        }
    }

    pub fn load(&self) -> Result<Option<SessionMaterial>> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => {
                let material: SessionMaterial = serde_json::from_str(&contents).with_context(
                    || format!("{} is not a session-material file", self.path.display()),
                )?;
                Ok(Some(material))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("could not read {}", self.path.display())),
        }
    }

    /// Write session material, owner-readable only.
    pub fn store(&self, material: &SessionMaterial) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(material)?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("could not write {}", self.path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("could not restrict {}", self.path.display()))?;
        }
        Ok(())
    }

    /// Everything checkable without asking the enclave.
    ///
    /// Called **before** `signalIntent`, never after the payment. The whole
    /// point is to fail while failing is free.
    pub fn health(&self) -> Result<CookieHealth> {
        let Some(material) = self.load()? else {
            return Ok(CookieHealth::Missing);
        };
        Ok(check(&material, self.max_age_hours))
    }
}

/// The health rules, separated from the filesystem so they are testable.
pub fn check(material: &SessionMaterial, max_age_hours: i64) -> CookieHealth {
    if material.cookie.trim().is_empty() {
        return CookieHealth::Malformed("the cookie is empty".into());
    }
    // A Venmo session cookie is a name=value list. Anything without an '=' is
    // not one, and is most likely a path or a placeholder that got pasted in.
    if !material.cookie.contains('=') {
        return CookieHealth::Malformed(
            "the cookie carries no name=value pair; it does not look like a Cookie header".into(),
        );
    }
    if material.sender_id.trim().is_empty() {
        return CookieHealth::Malformed("no Venmo sender id".into());
    }
    if !material.sender_id.chars().all(|c| c.is_ascii_digit()) {
        return CookieHealth::Malformed(format!(
            "the sender id {:?} is not numeric; the enclave wants the numeric id, \
             not the handle",
            material.sender_id
        ));
    }

    let age_hours = material.age().num_hours();
    if age_hours > max_age_hours {
        return CookieHealth::Stale {
            age_hours,
            limit_hours: max_age_hours,
        };
    }

    CookieHealth::Usable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(age_hours: i64) -> SessionMaterial {
        SessionMaterial {
            cookie: "api_access_token=abc; _csrf=def".into(),
            sender_id: "1234567890".into(),
            user_agent: Some("Mozilla/5.0".into()),
            captured_at: chrono::Utc::now() - chrono::Duration::hours(age_hours),
        }
    }

    #[test]
    fn a_fresh_capture_is_usable() {
        assert_eq!(check(&material(1), 24), CookieHealth::Usable);
    }

    /// The finding that makes the daemon practical: a cookie captured hours ago
    /// is still fine, because the service enforces no capture-age limit of its
    /// own. The limit here is the operator's caution, not the protocol's.
    #[test]
    fn a_cookie_hours_old_is_still_usable() {
        assert_eq!(check(&material(20), 24), CookieHealth::Usable);
    }

    #[test]
    fn a_stale_capture_refuses_before_anything_is_spent() {
        let health = check(&material(48), 24);
        assert!(matches!(health, CookieHealth::Stale { .. }));
        assert!(!health.is_usable());
        assert!(health.explain().contains("costs the payment"));
    }

    #[test]
    fn a_pasted_placeholder_is_caught() {
        let mut m = material(1);
        m.cookie = "/path/to/cookie.txt".into();
        assert!(matches!(check(&m, 24), CookieHealth::Malformed(_)));
    }

    /// The handle is not the sender id, and the enclave will not say so kindly.
    #[test]
    fn a_handle_in_the_sender_id_field_is_caught() {
        let mut m = material(1);
        m.sender_id = "test-payee".into();
        match check(&m, 24) {
            CookieHealth::Malformed(why) => assert!(why.contains("numeric"), "{why}"),
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_store_reports_missing_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let store = CookieStore::new(dir.path().join("none.json"), 24);
        assert_eq!(store.health().unwrap(), CookieHealth::Missing);
        assert!(store.health().unwrap().explain().contains("refresh-cookie"));
    }

    #[test]
    fn a_stored_session_round_trips_and_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let store = CookieStore::new(&path, 24);
        store.store(&material(0)).unwrap();

        assert!(store.health().unwrap().is_usable());
        assert_eq!(store.load().unwrap().unwrap().sender_id, "1234567890");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "session material must not be world-readable");
        }
    }

    /// The Display impl is what goes in logs, and it must not carry the cookie.
    #[test]
    fn the_rendered_form_does_not_leak_the_cookie() {
        let m = material(1);
        let shown = m.to_string();
        assert!(!shown.contains("api_access_token"));
        assert!(!shown.contains("abc"));
        assert!(shown.contains("1234567890"));
    }
}
