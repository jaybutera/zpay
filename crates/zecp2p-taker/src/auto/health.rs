//! Noticing a dead Venmo session before a payment does, and fixing it.
//!
//! The taker had two ways to learn its session had expired, and both were late.
//! [`crate::venmo::VenmoBrowser::pay`] checks the tab URL at the top of a
//! payment, and [`crate::auto::cookie::CookieStore::health`] checks the stored
//! cookie's age before signalling. Both run inside a fill, which means the
//! earliest anything noticed was the moment a trade had already arrived. The
//! 2026-09-02 dual-rail run hit that twice.
//!
//! This module moves the discovery off the fill path entirely: a timer checks
//! the live session on its own schedule, and a fill that starts finds a session
//! already known to be good. The check is cheap enough to run often, because it
//! is one CDP round trip against a tab that is already open.
//!
//! # Why the recheck after a re-login is not optional
//!
//! [`Supervisor::check_once`] re-reads the session after a re-login rather than
//! trusting the outcome the login flow returned. Those are different claims: the
//! login flow says the form was driven and the page stopped looking signed out,
//! and the recheck says the session is live now. Venmo can accept a sign-in and
//! then challenge the device, which leaves a page that satisfies the first and
//! not the second. Reporting the first as a healthy session is how a daemon
//! goes back to sleep in front of a login wall.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

use crate::auto::login::{
    self, Credentials, LoginOutcome, LoginStep, TwoFactorMethod,
};

/// What the session looks like right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// A Venmo tab is open and signed in.
    Live { url: String },
    /// A Venmo tab is open and showing a sign-in page.
    SignedOut { url: String },
    /// The browser answered but has no Venmo tab.
    ///
    /// Distinct from [`Self::SignedOut`] because the fix differs: a signed-out
    /// tab is navigated to the login form, and a missing tab has to be opened
    /// first. Before this, a browser restart looked exactly like an expiry and
    /// the daemon sat waiting for a tab nobody was going to open.
    NoTab,
    /// No browser is answering on the CDP port at all.
    ///
    /// Nothing this process can fix: Chrome is not running, or is running
    /// without `--remote-debugging-port`. Re-login is not attempted, because
    /// there is nothing to drive.
    NoBrowser { why: String },
}

impl SessionState {
    pub fn is_live(&self) -> bool {
        matches!(self, SessionState::Live { .. })
    }

    /// Whether driving the login form could plausibly fix this.
    pub fn login_could_fix(&self) -> bool {
        matches!(self, SessionState::SignedOut { .. } | SessionState::NoTab)
    }

    /// One line for the log.
    pub fn summary(&self) -> String {
        match self {
            SessionState::Live { url } => format!("signed in at {url}"),
            SessionState::SignedOut { url } => format!("signed out: the tab is on {url}"),
            SessionState::NoTab => "the browser is up but has no Venmo tab".into(),
            SessionState::NoBrowser { why } => format!("no browser answering CDP: {why}"),
        }
    }
}

/// What one health tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// The session was already fine.
    Healthy,
    /// The session was dead and a re-login brought it back.
    Recovered,
    /// The session is dead and re-login is switched off.
    NeedsOperator { state: SessionState, why: String },
    /// The session is dead, a re-login was tried, and it did not finish.
    ReloginFailed { why: String, attempt: u32 },
    /// The session is dead and a human has to type a code.
    ///
    /// Separate from [`Self::ReloginFailed`] because this one does not retry:
    /// no number of attempts produces an SMS code this process can read.
    AwaitingHumanCode { method: TwoFactorMethod, what_to_do: String },
    /// Enough attempts have failed that the loop has stopped trying.
    GaveUp { attempts: u32 },
}

impl Tick {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Tick::Healthy | Tick::Recovered)
    }

    /// Whether a human needs to look at this.
    pub fn needs_operator(&self) -> bool {
        matches!(
            self,
            Tick::NeedsOperator { .. } | Tick::AwaitingHumanCode { .. } | Tick::GaveUp { .. }
        )
    }
}

/// What the supervisor needs from a browser, so tests do not need one.
///
/// The real implementation is [`crate::venmo::VenmoBrowser`]. This trait exists
/// because the interesting logic here is the state machine around the browser,
/// and a test that has to start Chrome to exercise a backoff counter is a test
/// nobody runs.
#[allow(async_fn_in_trait)]
pub trait SessionDriver: Send + Sync {
    /// Look at the browser and say what the session is.
    async fn probe(&self) -> SessionState;

    /// Run one login step, returning the JSON value it produced.
    async fn run_step(&self, step: &LoginStep) -> Result<serde_json::Value>;

    /// Poll a step that answers true when the page is ready.
    async fn await_step(&self, step: &LoginStep, what: &str) -> Result<()>;

    /// Make sure there is a Venmo tab to drive, opening one if there is not.
    async fn ensure_tab(&self) -> Result<()>;
}

/// The health check, its schedule, and the re-login it triggers.
pub struct Supervisor<D: SessionDriver> {
    driver: Arc<D>,
    credentials: Option<Credentials>,
    /// Consecutive failed attempts. Reset on any healthy tick.
    failures: u32,
}

impl<D: SessionDriver> Supervisor<D> {
    /// A supervisor with credentials, able to re-login when configured to.
    pub fn new(driver: Arc<D>, credentials: Option<Credentials>) -> Self {
        Self {
            driver,
            credentials,
            failures: 0,
        }
    }

    /// How often the check runs.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(
            self.credentials
                .as_ref()
                .map(|c| c.check_interval_seconds)
                .unwrap_or(900)
                .max(30),
        )
    }

    /// Whether this supervisor can actually fix a dead session by itself.
    pub fn can_recover(&self) -> bool {
        self.credentials
            .as_ref()
            .is_some_and(|c| c.can_run_unattended())
    }

    /// What the operator is told at startup about how unattended this really is.
    ///
    /// Printed once, at start, rather than discovered at the first expiry. An
    /// operator who believes the daemon is self-healing when it is not will not
    /// be watching it at the moment it stops.
    pub fn readiness(&self) -> String {
        match &self.credentials {
            None => "no Venmo credentials configured: an expiry stops the daemon until \
                     someone signs in by hand. Fill in config/venmo.local.toml to \
                     change that."
                .into(),
            Some(c) if !c.auto_relogin => {
                "Venmo credentials are loaded but auto_relogin is false: the health \
                 check will report an expiry and not act on it. Set auto_relogin = \
                 true to let it sign back in."
                    .into()
            }
            Some(c) if !c.method.is_automatable() => format!(
                "auto_relogin is on, but the account's second factor is {:?}, which \
                 this process cannot answer. A re-login will drive the form and stop \
                 at the code box. To run unattended: {}",
                c.method,
                c.method.manual_step()
            ),
            Some(c) => format!(
                "ready to run unattended: the session is checked every {}s and a dead \
                 one is signed back in automatically, up to {} consecutive failures.",
                c.check_interval_seconds, c.max_attempts
            ),
        }
    }

    /// Run one health check, and act on it.
    pub async fn check_once(&mut self) -> Tick {
        let state = self.driver.probe().await;

        if state.is_live() {
            // Any healthy tick clears the counter: the failures that matter are
            // consecutive ones. A daemon that accumulated a single failure a
            // week for three weeks and then refused to try is counting the
            // wrong thing.
            if self.failures > 0 {
                tracing::info!(
                    cleared = self.failures,
                    "the Venmo session is healthy again"
                );
                self.failures = 0;
            }
            return Tick::Healthy;
        }

        tracing::warn!(state = %state.summary(), "the Venmo session is not usable");

        if !state.login_could_fix() {
            return Tick::NeedsOperator {
                why: state.summary(),
                state,
            };
        }

        let Some(credentials) = self.credentials.clone() else {
            return Tick::NeedsOperator {
                why: "no Venmo credentials are configured, so the daemon cannot sign \
                      back in. Fill in config/venmo.local.toml."
                    .into(),
                state,
            };
        };

        if !credentials.auto_relogin {
            return Tick::NeedsOperator {
                why: "auto_relogin is false, so the session was not repaired. Sign in \
                      by hand, or set auto_relogin = true."
                    .into(),
                state,
            };
        }

        if self.failures >= credentials.max_attempts {
            return Tick::GaveUp {
                attempts: self.failures,
            };
        }

        match self.relogin(&credentials).await {
            LoginOutcome::SignedIn => {
                // Not trusted: re-read the session. The login flow saw a page
                // stop looking signed out, which is a weaker claim than the
                // session being live, and Venmo can challenge a device after
                // accepting the password.
                let after = self.driver.probe().await;
                if after.is_live() {
                    self.failures = 0;
                    tracing::info!("signed back into Venmo; the session is live");
                    Tick::Recovered
                } else {
                    self.failures += 1;
                    Tick::ReloginFailed {
                        why: format!(
                            "the sign-in reported success but the session is still {}",
                            after.summary()
                        ),
                        attempt: self.failures,
                    }
                }
            }
            LoginOutcome::NeedsHumanCode { method, what_to_do } => {
                // Deliberately does not touch `failures`. This is not a failed
                // attempt, it is a finished one that needs a person, and
                // counting it would eventually trip `GaveUp` and stop the
                // checks that are the only thing still reporting.
                Tick::AwaitingHumanCode { method, what_to_do }
            }
            LoginOutcome::Failed { why } => {
                self.failures += 1;
                Tick::ReloginFailed {
                    why,
                    attempt: self.failures,
                }
            }
        }
    }

    /// Drive the login form once.
    async fn relogin(&self, credentials: &Credentials) -> LoginOutcome {
        if let Err(e) = self.driver.ensure_tab().await {
            return LoginOutcome::Failed {
                why: format!("could not get a Venmo tab to sign in on: {e:#}"),
            };
        }

        for step in login::signin_steps(credentials) {
            tracing::debug!(step = %step.describe(), "login");
            let result = match &step {
                LoginStep::WaitFor { .. } => self.driver.await_step(&step, "the login form").await,
                _ => self.driver.run_step(&step).await.map(|_| ()),
            };
            if let Err(e) = result {
                return LoginOutcome::Failed {
                    why: format!("{}: {e:#}", step.describe()),
                };
            }
        }

        // The form is submitted. What happens next is the 2FA split.
        match credentials.method {
            TwoFactorMethod::Totp => {
                let code = match credentials.current_code() {
                    Ok(Some(code)) => code,
                    Ok(None) | Err(_) => {
                        return LoginOutcome::Failed {
                            why: "method is totp but no code could be computed; check \
                                  totp_secret"
                                .into(),
                        }
                    }
                };
                for step in login::totp_steps(&code) {
                    let result = match &step {
                        LoginStep::AwaitCodePrompt => {
                            self.driver.await_step(&step, "the 2FA code box").await
                        }
                        LoginStep::AwaitSignedIn => {
                            self.driver.await_step(&step, "a signed-in session").await
                        }
                        _ => self.driver.run_step(&step).await.map(|_| ()),
                    };
                    if let Err(e) = result {
                        return LoginOutcome::Failed {
                            why: format!("{}: {e:#}", step.describe()),
                        };
                    }
                }
                LoginOutcome::SignedIn
            }

            TwoFactorMethod::None => {
                match self
                    .driver
                    .await_step(&LoginStep::AwaitSignedIn, "a signed-in session")
                    .await
                {
                    Ok(()) => LoginOutcome::SignedIn,
                    Err(e) => LoginOutcome::Failed {
                        why: format!("the sign-in did not complete: {e:#}"),
                    },
                }
            }

            method @ (TwoFactorMethod::Sms | TwoFactorMethod::Email) => {
                // The form is filled and submitted, so the code has been sent
                // and the box is open. That is genuinely the whole of what this
                // process can do, and leaving the page there means the human
                // types six digits rather than a password.
                LoginOutcome::NeedsHumanCode {
                    method,
                    what_to_do: format!(
                        "Venmo has sent a {} code and the tab is waiting at the code \
                         box. {}",
                        match method {
                            TwoFactorMethod::Sms => "text",
                            _ => "email",
                        },
                        method.manual_step()
                    ),
                }
            }
        }
    }

    /// Check on a timer, forever, reporting each tick.
    ///
    /// The daemon runs this alongside the fill loop rather than inside it. That
    /// is the point of the whole module: the check happens on its own schedule,
    /// so a fill starts against a session whose health is already known instead
    /// of discovering the answer with a trade in hand.
    pub async fn run(mut self, mut on_tick: impl FnMut(&Tick)) -> ! {
        tracing::info!("{}", self.readiness());
        loop {
            let tick = self.check_once().await;
            match &tick {
                Tick::Healthy => tracing::debug!("Venmo session healthy"),
                Tick::Recovered => tracing::info!("Venmo session recovered by re-login"),
                Tick::NeedsOperator { why, .. } => tracing::error!("{why}"),
                Tick::AwaitingHumanCode { what_to_do, .. } => tracing::error!("{what_to_do}"),
                Tick::ReloginFailed { why, attempt } => {
                    tracing::error!(attempt, "re-login failed: {why}")
                }
                Tick::GaveUp { attempts } => tracing::error!(
                    attempts,
                    "not trying to sign in again: Venmo locks an account after \
                     repeated failures, and a locked account is worse than a dead \
                     session. A human has to sign in."
                ),
            }
            on_tick(&tick);

            // A failed attempt waits longer than the normal interval, so a
            // wrong password is not retried on a fast timer.
            let wait = match (&tick, &self.credentials) {
                (Tick::ReloginFailed { attempt, .. }, Some(c)) => {
                    self.interval().max(c.backoff(*attempt))
                }
                _ => self.interval(),
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A scripted browser: it answers probes from a queue and records steps.
    struct MockDriver {
        probes: Mutex<Vec<SessionState>>,
        /// Steps that must fail, by the text of their description.
        fail_on: Option<String>,
        pub ran: Mutex<Vec<String>>,
        /// Every value typed, so a test can assert the password reached the page.
        pub typed: Mutex<Vec<String>>,
        pub tabs_opened: Mutex<u32>,
    }

    impl MockDriver {
        fn new(probes: Vec<SessionState>) -> Arc<Self> {
            Arc::new(Self {
                // Reversed so `pop` walks them in order.
                probes: Mutex::new(probes.into_iter().rev().collect()),
                fail_on: None,
                ran: Mutex::new(Vec::new()),
                typed: Mutex::new(Vec::new()),
                tabs_opened: Mutex::new(0),
            })
        }

        fn failing(probes: Vec<SessionState>, on: &str) -> Arc<Self> {
            let mut driver = Self::new(probes);
            Arc::get_mut(&mut driver).unwrap().fail_on = Some(on.to_string());
            driver
        }
    }

    impl SessionDriver for MockDriver {
        async fn probe(&self) -> SessionState {
            // The last scripted answer repeats, so a test only scripts the
            // transitions it cares about.
            let mut probes = self.probes.lock().unwrap();
            if probes.len() > 1 {
                probes.pop().unwrap()
            } else {
                probes.last().cloned().unwrap_or(SessionState::NoTab)
            }
        }

        async fn run_step(&self, step: &LoginStep) -> Result<serde_json::Value> {
            self.ran.lock().unwrap().push(step.describe());
            if let LoginStep::FillSecret { value, .. } = step {
                self.typed.lock().unwrap().push(value.clone());
            }
            if let Some(fail) = &self.fail_on {
                if step.describe().contains(fail) {
                    anyhow::bail!("scripted failure on {}", step.describe());
                }
            }
            Ok(serde_json::Value::Bool(true))
        }

        async fn await_step(&self, step: &LoginStep, _what: &str) -> Result<()> {
            self.ran.lock().unwrap().push(step.describe());
            if let Some(fail) = &self.fail_on {
                if step.describe().contains(fail) {
                    anyhow::bail!("scripted failure on {}", step.describe());
                }
            }
            Ok(())
        }

        async fn ensure_tab(&self) -> Result<()> {
            *self.tabs_opened.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn creds(method: TwoFactorMethod, auto: bool) -> Credentials {
        Credentials {
            username: "operator@example.com".into(),
            password: "a-real-password".into(),
            method,
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            check_interval_seconds: 900,
            auto_relogin: auto,
            max_attempts: 3,
            retry_backoff_seconds: 300,
        }
    }

    fn live() -> SessionState {
        SessionState::Live {
            url: "https://account.venmo.com/".into(),
        }
    }

    fn out() -> SessionState {
        SessionState::SignedOut {
            url: "https://id.venmo.com/signin".into(),
        }
    }

    // ------------------------------------------------------------------
    // The healthy path
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn a_live_session_is_left_alone() {
        let driver = MockDriver::new(vec![live()]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)));
        assert_eq!(sup.check_once().await, Tick::Healthy);
        // Nothing was driven: a healthy session must not be touched, and
        // certainly must not have a password typed at it.
        assert!(driver.ran.lock().unwrap().is_empty());
        assert!(driver.typed.lock().unwrap().is_empty());
    }

    /// The whole point of the module: the expiry is found by the timer rather
    /// than by a payment, and the session is live again before any fill starts.
    #[tokio::test]
    async fn an_expired_session_is_signed_back_in_before_any_fill() {
        let driver = MockDriver::new(vec![out(), live()]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)));

        assert_eq!(sup.check_once().await, Tick::Recovered);

        let ran = driver.ran.lock().unwrap().clone();
        assert!(ran.iter().any(|s| s.contains("username")), "{ran:?}");
        assert!(ran.iter().any(|s| s.contains("password")), "{ran:?}");
        assert!(ran.iter().any(|s| s.contains("authenticator code")), "{ran:?}");
        assert!(ran.iter().any(|s| s.contains("sign-in")), "{ran:?}");

        // The code that was typed is a real six-digit TOTP, not a placeholder.
        let typed = driver.typed.lock().unwrap().clone();
        let code = typed.last().expect("a code was typed");
        assert_eq!(code.len(), 6, "{code}");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");
    }

    /// A browser that came back without a Venmo tab is not the same as an
    /// expiry, and it must be fixed by opening one rather than waiting.
    #[tokio::test]
    async fn a_missing_tab_is_opened_rather_than_waited_on() {
        let driver = MockDriver::new(vec![SessionState::NoTab, live()]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)));
        assert_eq!(sup.check_once().await, Tick::Recovered);
        assert_eq!(*driver.tabs_opened.lock().unwrap(), 1);
    }

    // ------------------------------------------------------------------
    // The recheck
    // ------------------------------------------------------------------

    /// Venmo can accept a password and then challenge the device. The login
    /// flow sees a page that stopped looking signed out; the session is still
    /// dead. Trusting the first is how a daemon sleeps in front of a login wall.
    #[tokio::test]
    async fn a_login_that_reports_success_is_rechecked_and_not_believed() {
        // Signed out, then still signed out after the whole login ran.
        let driver = MockDriver::new(vec![out(), out()]);
        let mut sup = Supervisor::new(driver, Some(creds(TwoFactorMethod::Totp, true)));

        match sup.check_once().await {
            Tick::ReloginFailed { why, attempt } => {
                assert!(why.contains("still"), "{why}");
                assert_eq!(attempt, 1);
            }
            other => panic!("expected a failed re-login, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // The gates
    // ------------------------------------------------------------------

    /// Off by default: the health check reports and does not type a password.
    #[tokio::test]
    async fn auto_relogin_off_reports_without_acting() {
        let driver = MockDriver::new(vec![out()]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, false)));

        match sup.check_once().await {
            Tick::NeedsOperator { why, .. } => assert!(why.contains("auto_relogin"), "{why}"),
            other => panic!("expected NeedsOperator, got {other:?}"),
        }
        assert!(driver.typed.lock().unwrap().is_empty(), "no password was typed");
    }

    #[tokio::test]
    async fn no_credentials_means_no_login_attempt() {
        let driver = MockDriver::new(vec![out()]);
        let mut sup = Supervisor::new(driver.clone(), None);
        assert!(matches!(sup.check_once().await, Tick::NeedsOperator { .. }));
        assert!(driver.ran.lock().unwrap().is_empty());
    }

    /// A dead CDP port is not something a login fixes, so it is not attempted.
    #[tokio::test]
    async fn a_dead_browser_is_not_something_a_login_can_fix() {
        let driver = MockDriver::new(vec![SessionState::NoBrowser {
            why: "connection refused".into(),
        }]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)));
        assert!(matches!(sup.check_once().await, Tick::NeedsOperator { .. }));
        assert!(driver.ran.lock().unwrap().is_empty(), "nothing to drive");
    }

    // ------------------------------------------------------------------
    // SMS: driven as far as possible, then stopped
    // ------------------------------------------------------------------

    /// The SMS path fills the form so the code is sent and the box is open,
    /// then stops. The human types six digits rather than a password.
    #[tokio::test]
    async fn an_sms_account_is_driven_to_the_code_box_and_then_stops() {
        let driver = MockDriver::new(vec![out()]);
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Sms, true)));

        match sup.check_once().await {
            Tick::AwaitingHumanCode { method, what_to_do } => {
                assert_eq!(method, TwoFactorMethod::Sms);
                assert!(what_to_do.contains("code box"), "{what_to_do}");
                assert!(what_to_do.contains("totp"), "{what_to_do} must name the way out");
            }
            other => panic!("expected AwaitingHumanCode, got {other:?}"),
        }

        // The form really was driven: the password went in, so Venmo sent a code.
        let ran = driver.ran.lock().unwrap().clone();
        assert!(ran.iter().any(|s| s.contains("password")), "{ran:?}");
        assert!(ran.iter().any(|s| s.contains("sign-in")), "{ran:?}");
        // And no code was invented and typed at an account with a lockout.
        assert!(!ran.iter().any(|s| s.contains("authenticator code")), "{ran:?}");
    }

    /// Waiting for a human is not a failed attempt. Counting it would trip
    /// `GaveUp` and stop the checks that are the only thing still reporting.
    #[tokio::test]
    async fn waiting_for_a_human_never_exhausts_the_attempts() {
        let driver = MockDriver::new(vec![out()]);
        let mut sup = Supervisor::new(driver, Some(creds(TwoFactorMethod::Sms, true)));
        for _ in 0..10 {
            assert!(matches!(
                sup.check_once().await,
                Tick::AwaitingHumanCode { .. }
            ));
        }
        assert_eq!(sup.failures, 0, "a human gate is not a failure");
    }

    // ------------------------------------------------------------------
    // Lockout protection
    // ------------------------------------------------------------------

    /// Venmo locks an account after repeated failures, so the loop stops trying
    /// and keeps reporting. A locked account is worse than a dead session: one
    /// needs a sign-in, the other needs an appeal.
    #[tokio::test]
    async fn repeated_failures_stop_before_the_account_locks() {
        let driver = MockDriver::failing(vec![out()], "password");
        let mut sup = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)));

        for attempt in 1..=3 {
            match sup.check_once().await {
                Tick::ReloginFailed { attempt: n, .. } => assert_eq!(n, attempt),
                other => panic!("attempt {attempt}: {other:?}"),
            }
        }
        assert_eq!(sup.check_once().await, Tick::GaveUp { attempts: 3 });

        // And having given up, it stops driving the form entirely.
        let before = driver.ran.lock().unwrap().len();
        let _ = sup.check_once().await;
        assert_eq!(driver.ran.lock().unwrap().len(), before, "no further attempts");
    }

    /// The counter is consecutive failures, not lifetime ones. A daemon that
    /// failed once a week for three weeks and then refused to try is counting
    /// the wrong thing.
    #[tokio::test]
    async fn one_healthy_tick_clears_the_failure_count() {
        let driver = MockDriver::failing(vec![out(), out()], "password");
        let mut sup = Supervisor::new(driver, Some(creds(TwoFactorMethod::Totp, true)));
        assert!(matches!(sup.check_once().await, Tick::ReloginFailed { .. }));
        assert_eq!(sup.failures, 1);

        let healthy = MockDriver::new(vec![live()]);
        sup = Supervisor::new(healthy, Some(creds(TwoFactorMethod::Totp, true)));
        sup.failures = 2;
        assert_eq!(sup.check_once().await, Tick::Healthy);
        assert_eq!(sup.failures, 0);
    }

    // ------------------------------------------------------------------
    // Reporting
    // ------------------------------------------------------------------

    /// An operator is told at startup how unattended this actually is, because
    /// one who believes it self-heals will not be watching when it stops.
    #[test]
    fn readiness_states_plainly_whether_it_can_run_unattended() {
        let driver = MockDriver::new(vec![live()]);

        let none = Supervisor::new(driver.clone(), None).readiness();
        assert!(none.contains("venmo.local.toml"), "{none}");

        let off = Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, false)))
            .readiness();
        assert!(off.contains("auto_relogin"), "{off}");

        let sms =
            Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Sms, true))).readiness();
        assert!(sms.contains("code box"), "{sms}");

        let ready =
            Supervisor::new(driver, Some(creds(TwoFactorMethod::Totp, true))).readiness();
        assert!(ready.contains("unattended"), "{ready}");
    }

    #[test]
    fn only_a_totp_supervisor_claims_it_can_recover() {
        let driver = MockDriver::new(vec![live()]);
        assert!(Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, true)))
            .can_recover());
        assert!(!Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Sms, true)))
            .can_recover());
        assert!(!Supervisor::new(driver.clone(), Some(creds(TwoFactorMethod::Totp, false)))
            .can_recover());
        assert!(!Supervisor::new(driver, None).can_recover());
    }

    /// A check interval nobody set, or one set to something that would hammer
    /// the browser, is floored rather than obeyed.
    #[test]
    fn the_interval_has_a_floor() {
        let driver = MockDriver::new(vec![live()]);
        let mut c = creds(TwoFactorMethod::Totp, true);
        c.check_interval_seconds = 1;
        assert_eq!(
            Supervisor::new(driver.clone(), Some(c)).interval(),
            Duration::from_secs(30)
        );

        let mut c = creds(TwoFactorMethod::Totp, true);
        c.check_interval_seconds = 900;
        assert_eq!(
            Supervisor::new(driver, Some(c)).interval(),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn a_tick_says_whether_a_human_is_needed() {
        assert!(!Tick::Healthy.needs_operator());
        assert!(!Tick::Recovered.needs_operator());
        assert!(Tick::GaveUp { attempts: 3 }.needs_operator());
        assert!(Tick::AwaitingHumanCode {
            method: TwoFactorMethod::Sms,
            what_to_do: String::new(),
        }
        .needs_operator());
        // A single failed attempt is not yet an operator problem: the loop is
        // still retrying and may well recover on its own.
        assert!(!Tick::ReloginFailed {
            why: String::new(),
            attempt: 1
        }
        .needs_operator());
    }

    #[test]
    fn a_state_says_whether_a_login_could_fix_it() {
        assert!(out().login_could_fix());
        assert!(SessionState::NoTab.login_could_fix());
        assert!(!live().login_could_fix());
        assert!(!SessionState::NoBrowser { why: String::new() }.login_could_fix());
    }
}
