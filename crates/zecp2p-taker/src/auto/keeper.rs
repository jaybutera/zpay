//! Keeping the Venmo session alive, and re-capturing it before the age limit.
//!
//! [`crate::auto::health`] answers "is the session dead yet". This module
//! answers the two questions that come before it: "is it about to die" and "is
//! the stored copy about to be refused". Those are different clocks, and the
//! daemon needs both.
//!
//! # The two clocks
//!
//! **Venmo's clock** decides when the browser stops being signed in. **The
//! coordinator's clock** (`session_max_age_hours`, 24h) decides when the stored
//! `venmo-session.json` is refused for being old. A capture is only possible
//! while the first clock is still running, and it is only *needed* because of
//! the second. Re-capturing at 18h of file age turns the daily manual step into
//! nothing, but only if the browser is still signed in at 18h.
//!
//! # What the 2026-09-05 measurement showed
//!
//! The premise this module was first sketched against was that the hub's
//! browser stays signed in far longer than 24h, so a periodic re-capture would
//! be enough on its own. That was measured against the live hub and it is not
//! true.
//!
//! The session captured at 01:14Z was gone from the browser by 04:19Z, about
//! three hours later, with the browser process untouched the whole time
//! (`chrome-venmo.service` had been up since the previous 17:48Z). The
//! session-scoped cookies -- `api_access_token`, `lls_session`, `pwv_id_token`,
//! `w_fc` -- had all been dropped. Venmo had expired the session server-side
//! while the tab sat idle on it.
//!
//! Two consequences shape everything below:
//!
//! 1. **A re-capture timer alone does not help.** Waking at 18h to capture from
//!    a browser that was logged out at 3h captures nothing. Something has to
//!    keep the session from expiring in the first place, which is
//!    [`KeepAlive`]: periodic authenticated traffic, so the session is in use
//!    rather than idle.
//!
//! 2. **There is no captcha-free re-login.** Navigating the logged-out browser
//!    to `account.venmo.com` did not silently reissue a token; it redirected to
//!    `id.venmo.com/signin`, and that page carries hCaptcha and reCAPTCHA
//!    markers. The captcha precedes the 2FA step, so a stored TOTP seed does
//!    not reach it. Once the session is actually gone, a human signs in. This
//!    module does not pretend otherwise, and deliberately contains no code that
//!    tries.
//!
//! So: hold the session open for as long as Venmo will allow, capture from it
//! on a schedule that keeps the stored file young, and when it is nonetheless
//! gone, say so loudly and exactly once per logout.
//!
//! # Why the liveness check is not the tab URL
//!
//! [`crate::venmo::VenmoBrowser::probe_session`] decides live-versus-signed-out
//! from the tab's URL. At 04:19Z on 2026-09-05 that URL was
//! `https://account.venmo.com/` with the title "Venmo | Welcome Jay", and the
//! session behind it was dead: the page was a render left over from when the
//! session still worked, and nothing had navigated since. A URL check calls
//! that healthy.
//!
//! [`SessionProof::from_cookies`] therefore judges on the session cookies the
//! browser actually holds. A signed-in browser has `api_access_token`; a
//! logged-out one does not, whatever its address bar says. That is the same
//! marker `scripts/capture-venmo-session.sh` refuses on, so the keeper and the
//! capture cannot disagree about what signed in means.

use std::time::Duration;

/// The cookie that is the Venmo session bearer.
///
/// Its presence is the difference between a browser that can pay and a browser
/// showing a stale page. `capture-venmo-session.sh` refuses to write a file
/// without it, for the same reason.
pub const SESSION_COOKIE: &str = "api_access_token";

/// Cookies that a signed-in `account.venmo.com` browser carries and a
/// logged-out one does not.
///
/// Only [`SESSION_COOKIE`] is load-bearing; the rest are reported alongside it
/// so a partial expiry is legible in the log rather than looking like a clean
/// logout. All four were present in the 01:14Z capture and absent at 04:19Z.
pub const SESSION_COOKIES: [&str; 4] = [
    SESSION_COOKIE,
    "lls_session",
    "pwv_id_token",
    "w_fc",
];

/// Whether the browser is really signed in, judged by its cookies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionProof {
    /// The session bearer is present. A capture taken now is usable.
    SignedIn {
        /// The session cookies actually held, for the log.
        present: Vec<String>,
    },
    /// The session bearer is gone. Only a human can fix this.
    SignedOut {
        /// Which of [`SESSION_COOKIES`] were missing.
        missing: Vec<String>,
    },
}

impl SessionProof {
    /// Judge a browser's venmo.com cookie names.
    ///
    /// Takes names rather than values: nothing here needs the secret, and a
    /// function that never receives it cannot log it.
    pub fn from_cookies<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let held: Vec<String> = names.into_iter().map(|n| n.as_ref().to_string()).collect();
        let present: Vec<String> = SESSION_COOKIES
            .iter()
            .filter(|w| held.iter().any(|h| h == *w))
            .map(|w| w.to_string())
            .collect();

        if present.iter().any(|p| p == SESSION_COOKIE) {
            SessionProof::SignedIn { present }
        } else {
            SessionProof::SignedOut {
                missing: SESSION_COOKIES
                    .iter()
                    .filter(|w| !held.iter().any(|h| h == *w))
                    .map(|w| w.to_string())
                    .collect(),
            }
        }
    }

    pub fn is_signed_in(&self) -> bool {
        matches!(self, SessionProof::SignedIn { .. })
    }
}

/// How often to touch the session, and how old the stored file may get.
#[derive(Debug, Clone, PartialEq)]
pub struct KeeperConfig {
    /// How often to make an authenticated request so the session is not idle.
    ///
    /// The measured expiry was about three hours of idleness, so the default is
    /// well inside it. This costs one request; being wrong the other way costs
    /// a manual captcha sign-in.
    pub keepalive_seconds: u64,
    /// Re-capture once the stored file is older than this.
    ///
    /// Below the coordinator's `session_max_age_hours` by enough that a few
    /// consecutive failures still land before the cutoff.
    pub recapture_after_hours: i64,
    /// The coordinator's own cutoff, for the alert text.
    pub max_age_hours: i64,
}

impl Default for KeeperConfig {
    fn default() -> Self {
        Self {
            keepalive_seconds: 20 * 60,
            recapture_after_hours: 18,
            max_age_hours: 24,
        }
    }
}

impl KeeperConfig {
    pub fn keepalive_interval(&self) -> Duration {
        // A keepalive slower than the measured ~3h idle expiry is not a
        // keepalive. Clamped rather than trusted so a mistyped config cannot
        // silently switch the feature off.
        Duration::from_secs(self.keepalive_seconds.clamp(60, 2 * 3600))
    }

    /// Whether a stored file of this age should be re-captured now.
    pub fn should_recapture(&self, age_hours: i64) -> bool {
        age_hours >= self.recapture_after_hours
    }

    /// Whether the configuration leaves a usable margin before the cutoff.
    ///
    /// A re-capture threshold at or past the cutoff means the first attempt
    /// happens after the coordinator has already started refusing, which is the
    /// problem this module exists to remove.
    pub fn margin_is_sane(&self) -> bool {
        self.recapture_after_hours > 0 && self.recapture_after_hours < self.max_age_hours
    }
}

/// What one keeper tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeeperTick {
    /// Session touched, still signed in, stored file still young enough.
    Held { age_hours: i64 },
    /// Session touched and the stored file re-captured from it.
    Recaptured { was_age_hours: i64 },
    /// The session is signed in but the re-capture failed.
    ///
    /// Distinct from [`Self::LoggedOut`]: the session is fine and the next tick
    /// can retry, so this must not raise the human alarm.
    RecaptureFailed { why: String, age_hours: i64 },
    /// The browser is signed out. Only a captcha sign-in fixes this.
    LoggedOut { detail: String },
    /// The browser could not be reached at all.
    NoBrowser { why: String },
}

impl KeeperTick {
    /// Whether this tick means a person has to do something.
    ///
    /// A failed re-capture on a live session is not in here: it retries, and
    /// paging a human for something that fixes itself in twenty minutes is how
    /// the alert stops being read.
    pub fn needs_human(&self) -> bool {
        matches!(self, KeeperTick::LoggedOut { .. })
    }
}

/// The message sent when the session is genuinely gone.
///
/// Carries the command, because an alert that says "sign in" without saying how
/// is an alert that gets deferred. Both scripts are named in order: the sign-in
/// is what needs the human and the captcha, the capture is what the coordinator
/// actually reads, and skipping the second leaves a signed-in browser that
/// still cannot pay.
pub fn logout_alert(detail: &str, cfg: &KeeperConfig) -> String {
    format!(
        "VENMO SESSION LOST -- the hub cannot pay until someone signs in.\n\
         \n\
         {detail}\n\
         \n\
         This needs a human: Venmo's sign-in page carries hCaptcha and \
         reCAPTCHA, and the captcha comes before the 2FA step, so the stored \
         TOTP seed cannot reach it. Nothing automated can get past this.\n\
         \n\
         From the laptop, in ~/src/zecp2p:\n\
         \n\
             ./scripts/venmo-signin.sh            # solve the captcha, type the code\n\
             ./scripts/capture-venmo-session.sh   # always, or the hub still cannot pay\n\
         \n\
         Until both run, the coordinator refuses to fill: session material older \
         than {}h is rejected before any money moves.",
        cfg.max_age_hours
    )
}

/// Decide what a tick should do, given what the browser and the file say.
///
/// Split from any I/O so the decision is testable without a browser: this is
/// the part that has to be right, and a test for it should not need Chrome.
pub fn decide(
    proof: &SessionProof,
    stored_age_hours: Option<i64>,
    cfg: &KeeperConfig,
) -> KeeperDecision {
    match proof {
        SessionProof::SignedOut { missing } => KeeperDecision::Alert {
            detail: format!(
                "the hub's browser is no longer signed in: {} missing from its \
                 venmo.com cookies. Note that the tab's address bar can still \
                 read account.venmo.com while this is true -- the page is a \
                 stale render, not a live session.",
                missing.join(", ")
            ),
        },
        SessionProof::SignedIn { .. } => match stored_age_hours {
            // No stored file at all: capture, whatever the clock says. This is
            // the state after a fresh sign-in, and waiting 18h to write the
            // file the coordinator needs would be absurd.
            None => KeeperDecision::Recapture { age_hours: 0 },
            Some(age) if cfg.should_recapture(age) => KeeperDecision::Recapture { age_hours: age },
            Some(age) => KeeperDecision::Hold { age_hours: age },
        },
    }
}

/// The action a tick decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeeperDecision {
    /// Do nothing beyond having touched the session.
    Hold { age_hours: i64 },
    /// Write a fresh `venmo-session.json` from the live browser.
    Recapture { age_hours: i64 },
    /// Tell a human, because nothing here can fix it.
    Alert { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact cookie set the hub held at 01:14Z on 2026-09-05, when the
    /// stored capture was good.
    fn signed_in_cookies() -> Vec<&'static str> {
        vec![
            "ts", "ts_c", "v_id", "ddvm", "_csrf", "d_id", "LANG", "nsid",
            "s_id", "lls_session", "api_access_token", "pwv_id_token", "w_fc",
            "__cf_bm", "cookie_prefs",
        ]
    }

    /// The set the same browser held at 04:19Z, three hours later, having been
    /// expired server-side while idle. Note `s_id` survives and the page still
    /// rendered as signed in.
    fn signed_out_cookies() -> Vec<&'static str> {
        vec![
            "ts", "ts_c", "v_id", "ddvm", "_csrf", "d_id", "LANG", "nsid",
            "s_id", "cookie_prefs", "tsrce", "x-last-url",
        ]
    }

    #[test]
    fn the_bearer_cookie_decides_signed_in() {
        let proof = SessionProof::from_cookies(signed_in_cookies());
        assert!(proof.is_signed_in());
        match proof {
            SessionProof::SignedIn { present } => {
                assert!(present.iter().any(|p| p == SESSION_COOKIE));
                assert!(present.iter().any(|p| p == "lls_session"));
            }
            other => panic!("expected signed in, got {other:?}"),
        }
    }

    /// The measured logout: cookies remain, the bearer does not.
    #[test]
    fn a_browser_without_the_bearer_is_signed_out_however_many_cookies_remain() {
        let proof = SessionProof::from_cookies(signed_out_cookies());
        assert!(!proof.is_signed_in());
        match proof {
            SessionProof::SignedOut { missing } => {
                assert!(missing.iter().any(|m| m == SESSION_COOKIE));
                assert!(missing.iter().any(|m| m == "lls_session"));
            }
            other => panic!("expected signed out, got {other:?}"),
        }
    }

    /// The regression that made this module necessary: the tab URL said
    /// `account.venmo.com` and the title said "Welcome Jay" while the session
    /// was dead. Nothing in the judgement may consult a URL.
    #[test]
    fn a_stale_signed_in_page_does_not_make_a_dead_session_look_live() {
        let proof = SessionProof::from_cookies(signed_out_cookies());
        assert!(
            !proof.is_signed_in(),
            "a stale account.venmo.com render must not read as a live session"
        );
        let decision = decide(&proof, Some(1), &KeeperConfig::default());
        assert!(matches!(decision, KeeperDecision::Alert { .. }));
    }

    #[test]
    fn a_young_file_on_a_live_session_is_left_alone() {
        let proof = SessionProof::from_cookies(signed_in_cookies());
        assert_eq!(
            decide(&proof, Some(3), &KeeperConfig::default()),
            KeeperDecision::Hold { age_hours: 3 }
        );
    }

    /// The whole point: the file is re-captured before the coordinator's cutoff,
    /// not after it starts refusing.
    #[test]
    fn a_file_past_the_threshold_is_recaptured_before_the_cutoff() {
        let cfg = KeeperConfig::default();
        let proof = SessionProof::from_cookies(signed_in_cookies());
        assert_eq!(
            decide(&proof, Some(18), &cfg),
            KeeperDecision::Recapture { age_hours: 18 }
        );
        assert!(
            cfg.recapture_after_hours < cfg.max_age_hours,
            "re-capture must happen before the coordinator refuses"
        );
    }

    /// After a fresh sign-in there is no file yet, and waiting for the age
    /// threshold would leave the hub unable to pay for 18h.
    #[test]
    fn a_missing_file_is_captured_immediately_rather_than_on_the_clock() {
        let proof = SessionProof::from_cookies(signed_in_cookies());
        assert_eq!(
            decide(&proof, None, &KeeperConfig::default()),
            KeeperDecision::Recapture { age_hours: 0 }
        );
    }

    /// A logged-out browser is never asked to re-capture: the capture would
    /// write a file authenticating nobody, which is the failure the script
    /// already refuses at.
    #[test]
    fn a_signed_out_browser_is_never_recaptured_however_stale_the_file() {
        let proof = SessionProof::from_cookies(signed_out_cookies());
        for age in [0, 12, 18, 48, 1000] {
            assert!(
                matches!(decide(&proof, Some(age), &KeeperConfig::default()),
                         KeeperDecision::Alert { .. }),
                "age {age} must alert, never capture"
            );
        }
    }

    /// The keepalive has to be faster than the measured idle expiry, and a
    /// config that says otherwise is clamped rather than obeyed.
    #[test]
    fn the_keepalive_stays_inside_the_measured_idle_expiry() {
        let measured_expiry = Duration::from_secs(3 * 3600);
        assert!(KeeperConfig::default().keepalive_interval() < measured_expiry);

        let silly = KeeperConfig {
            keepalive_seconds: 86_400,
            ..KeeperConfig::default()
        };
        assert!(
            silly.keepalive_interval() < measured_expiry,
            "a mistyped interval must not switch the keepalive off"
        );

        let too_fast = KeeperConfig {
            keepalive_seconds: 1,
            ..KeeperConfig::default()
        };
        assert!(too_fast.keepalive_interval() >= Duration::from_secs(60));
    }

    #[test]
    fn a_threshold_past_the_cutoff_is_caught_as_insane() {
        assert!(KeeperConfig::default().margin_is_sane());
        assert!(!KeeperConfig { recapture_after_hours: 24, ..Default::default() }.margin_is_sane());
        assert!(!KeeperConfig { recapture_after_hours: 30, ..Default::default() }.margin_is_sane());
    }

    /// A failed capture on a live session retries; it must not page anyone.
    #[test]
    fn only_a_real_logout_wakes_a_human() {
        assert!(KeeperTick::LoggedOut { detail: "gone".into() }.needs_human());
        assert!(!KeeperTick::Held { age_hours: 2 }.needs_human());
        assert!(!KeeperTick::Recaptured { was_age_hours: 18 }.needs_human());
        assert!(!KeeperTick::RecaptureFailed {
            why: "ssh timed out".into(),
            age_hours: 19
        }
        .needs_human());
    }

    /// The alert has to carry both commands and the reason a human is needed.
    #[test]
    fn the_alert_says_what_to_run_and_why_it_cannot_be_automated() {
        let msg = logout_alert("the bearer cookie is gone", &KeeperConfig::default());
        assert!(msg.contains("venmo-signin.sh"));
        assert!(msg.contains("capture-venmo-session.sh"));
        assert!(msg.contains("captcha"));
        assert!(msg.contains("24h"));
        assert!(msg.contains("the bearer cookie is gone"));
    }

    /// Nothing in this module may carry a cookie value into a message.
    #[test]
    fn no_cookie_value_reaches_the_alert() {
        let proof = SessionProof::from_cookies(signed_out_cookies());
        let detail = match decide(&proof, Some(30), &KeeperConfig::default()) {
            KeeperDecision::Alert { detail } => detail,
            other => panic!("expected alert, got {other:?}"),
        };
        let msg = logout_alert(&detail, &KeeperConfig::default());
        // Names are fine and useful; a value would be a leak. The judgement
        // function never receives one, so this asserts the shape stays that way.
        assert!(msg.contains("api_access_token"));
        assert!(!msg.contains("="), "a name=value pair means a value leaked in");
    }
}
