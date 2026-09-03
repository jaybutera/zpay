//! Signing back into Venmo when the session has gone, without a human present.
//!
//! Until now the driver attached to a tab the operator had signed into by hand
//! and refused to do anything else: `venmo.rs` says so in its own module note,
//! and the 2026-09-02 dual-rail run recorded the consequence, which is that the
//! Venmo session expired twice mid-run and each expiry stopped the daemon until
//! somebody noticed. A 24/7 taker cannot be one keystroke from stopped.
//!
//! # What this does and does not touch
//!
//! It drives the login form and nothing else. Every guard in [`crate::venmo`]
//! stays exactly where it is: this module never fills an amount, never clicks a
//! send button, and never runs as part of a payment. The health loop calls it
//! between fills, and a fill that finds a dead session still fails the way it
//! failed before rather than logging in underneath itself. That separation is
//! deliberate. Interleaving a credential flow with the money flow would put a
//! page transition inside the window between the amount readback and the click,
//! and that window is the one thing this repository has paid to keep narrow.
//!
//! # The 2FA split, which decides whether 24/7 is possible at all
//!
//! Venmo challenges a fresh sign-in with a second factor, and only one of the
//! three kinds can be answered by software:
//!
//! - [`TwoFactorMethod::Totp`]: an authenticator seed. [`totp_now`] computes the
//!   six digits from the shared secret, so the whole re-login completes with
//!   nobody watching. This is the only configuration in which the daemon
//!   genuinely runs unattended.
//! - [`TwoFactorMethod::Sms`] and [`TwoFactorMethod::Email`]: a code delivered
//!   to a device this process cannot read. The flow is driven as far as the code
//!   box and then stops with [`LoginOutcome::NeedsHumanCode`], naming what is
//!   needed. Pretending otherwise would mean a daemon that reports success while
//!   sitting on a half-finished login.
//!
//! There is no third option worth building. Reading the code out of an SMS
//! gateway or a mailbox means giving this process a second set of credentials to
//! a second account, which moves the problem rather than solving it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

/// Venmo's sign-in URL.
///
/// `id.venmo.com` rather than `account.venmo.com`: signing out redirects to the
/// former, and [`crate::venmo::VenmoBrowser::session_looks_live`] already keys
/// on that hostname's paths.
pub const SIGNIN_URL: &str = "https://id.venmo.com/signin";

/// The username field on the sign-in form.
///
/// Matched on several handles rather than one. Venmo has shipped this field as
/// `input[name='username']` and as a bare `input[type='email']`, and a login
/// page is not something this repository can re-read on demand the way the
/// payment page was read on 2026-09-02. A selector list degrades to "one of
/// these matched"; a single selector degrades to a hang.
const USERNAME_SELECTOR: &str =
    "input[name='username'], input[name='email'], input[type='email'], input[aria-label='Email or phone']";

/// The password field. `type='password'` is the one handle that cannot drift:
/// the field is defined by it.
const PASSWORD_SELECTOR: &str = "input[type='password'], input[name='password']";

/// The 2FA code box.
const CODE_SELECTOR: &str =
    "input[name='code'], input[autocomplete='one-time-code'], input[name='otp'], input[aria-label='Code']";

/// What the sign-in button says.
///
/// Matched by text for the same reason the payment page's buttons are: the live
/// page carries no id, test id or aria-label on it, and `button[type='submit']`
/// on a Venmo page is a selector this codebase has already been burned by. See
/// the note on `SEND_SELECTOR` in [`crate::venmo`].
const SIGNIN_LABELS: [&str; 3] = ["Sign In", "Sign in", "Log In"];

/// The button that submits the 2FA code.
const CODE_SUBMIT_LABELS: [&str; 4] = ["Submit", "Verify", "Continue", "Next"];

/// Which second factor the account is enrolled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TwoFactorMethod {
    /// An authenticator app. The only one this process can answer by itself.
    Totp,
    /// A texted code. Needs a human.
    Sms,
    /// A mailed code. Needs a human.
    Email,
    /// The account is not enrolled and the form goes straight through.
    ///
    /// Kept as an explicit setting rather than inferred from a missing method,
    /// because "no second factor" and "we forgot to configure one" want
    /// different behaviour and look identical in a config file.
    None,
}

impl TwoFactorMethod {
    /// Whether a re-login under this method can finish with nobody watching.
    ///
    /// This is the single question that decides whether the daemon is a 24/7
    /// process or a supervised one, so it is one function and every caller
    /// reads it rather than re-deriving the answer.
    pub fn is_automatable(self) -> bool {
        matches!(self, TwoFactorMethod::Totp | TwoFactorMethod::None)
    }

    /// What a human has to do, when they have to do it.
    pub fn manual_step(self) -> &'static str {
        match self {
            TwoFactorMethod::Totp => {
                "nothing: the taker computes the authenticator code from the seed"
            }
            TwoFactorMethod::None => "nothing: the account has no second factor",
            TwoFactorMethod::Sms => {
                "read the code Venmo texted and type it into the open tab, or switch \
                 the account to an authenticator app and set method = \"totp\""
            }
            TwoFactorMethod::Email => {
                "read the code Venmo emailed and type it into the open tab, or switch \
                 the account to an authenticator app and set method = \"totp\""
            }
        }
    }
}

/// The placeholder strings the shipped template carries.
///
/// A config still holding one of these is not a configured config, and the
/// difference matters at startup rather than at 3am: an unattended daemon that
/// accepted the placeholder would try to sign in as the literal user
/// `PUT-YOUR-VENMO-EMAIL-HERE` and, after enough tries, get the real account
/// rate-limited for it.
const PLACEHOLDERS: [&str; 3] = [
    "PUT-YOUR-VENMO-EMAIL-HERE",
    "PUT-YOUR-VENMO-PASSWORD-HERE",
    "PUT-YOUR-BASE32-TOTP-SEED-HERE",
];

/// Whether a config value is still the shipped placeholder.
pub fn is_placeholder(value: &str) -> bool {
    let value = value.trim();
    PLACEHOLDERS.iter().any(|p| p.eq_ignore_ascii_case(value))
}

/// The credentials file, as parsed.
#[derive(Clone, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    #[serde(default = "default_method")]
    pub method: TwoFactorMethod,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default = "default_check_interval")]
    pub check_interval_seconds: u64,
    /// Whether the health loop may drive the login form by itself.
    #[serde(default)]
    pub auto_relogin: bool,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_backoff")]
    pub retry_backoff_seconds: u64,
}

/// `sms` rather than `totp`: the method most accounts are on, and the one whose
/// wrong guess fails safely. Defaulting to `totp` would have the daemon report
/// itself unattended-capable on an account that will ask for a text.
fn default_method() -> TwoFactorMethod {
    TwoFactorMethod::Sms
}

fn default_check_interval() -> u64 {
    900
}

fn default_max_attempts() -> u32 {
    3
}

fn default_backoff() -> u64 {
    300
}

/// The password must not reach a log line through a derived Debug.
///
/// The same reasoning as [`crate::auto::cookie::SessionMaterial`]'s Display: a
/// struct holding a live credential gets a hand-written Debug or it eventually
/// gets printed by a `{:?}` somebody added in a hurry.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &format_args!("<{} bytes, not shown>", self.password.len()))
            .field("method", &self.method)
            .field(
                "totp_secret",
                &format_args!(
                    "{}",
                    if self.totp_secret.is_some() {
                        "<set, not shown>"
                    } else {
                        "<unset>"
                    }
                ),
            )
            .field("auto_relogin", &self.auto_relogin)
            .finish()
    }
}

/// The file's outer shape: `[venmo_login]` and nothing else required.
#[derive(Debug, Clone, Deserialize)]
struct CredentialsFile {
    venmo_login: Credentials,
}

impl Credentials {
    /// Read the credentials file, refusing the ways it is usually wrong.
    ///
    /// The three refusals are all about failing at startup instead of at the
    /// first expiry. A daemon meant to run for weeks unattended gets exactly one
    /// cheap moment to notice its credentials are unusable, and this is it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!(
                "could not read the Venmo credentials at {}. Copy \
                 config/venmo.example.toml to it and fill in the placeholders.",
                path.display()
            )
        })?;

        Self::require_private(path)?;

        let file: CredentialsFile = toml::from_str(&contents).with_context(|| {
            format!("{} is not a [venmo_login] credentials file", path.display())
        })?;
        let credentials = file.venmo_login;
        credentials.validate(path)?;
        Ok(credentials)
    }

    /// Refuse a credentials file anyone else on the box can read.
    ///
    /// The cookie store writes 0600 and this file is strictly more sensitive
    /// than the cookie store: a cookie expires, a password does not. Checking
    /// the mode is worth more here than there, because this file is one the
    /// operator creates by hand and `cp` gives it the umask.
    #[cfg(unix)]
    fn require_private(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("could not stat {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} is mode {:o}: readable by someone other than its owner. It holds \
                 a Venmo password. Run `chmod 600 {}` and start again.",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn require_private(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Everything checkable without a browser.
    pub fn validate(&self, path: &Path) -> Result<()> {
        if self.username.trim().is_empty() || is_placeholder(&self.username) {
            anyhow::bail!(
                "the Venmo username in {} is still the placeholder. Put the real \
                 sign-in email or phone number there.",
                path.display()
            );
        }
        if self.password.is_empty() || is_placeholder(&self.password) {
            anyhow::bail!(
                "the Venmo password in {} is still the placeholder. Put the real \
                 password there; nothing else reads it and it is never logged.",
                path.display()
            );
        }
        if self.method == TwoFactorMethod::Totp {
            let secret = self.totp_secret.as_deref().unwrap_or("");
            if secret.trim().is_empty() || is_placeholder(secret) {
                anyhow::bail!(
                    "{} sets method = \"totp\" but carries no usable totp_secret. \
                     Without the seed the re-login drives the form and then stops at \
                     the code box, which is a worse place to learn this than startup.",
                    path.display()
                );
            }
            // Parse it now rather than at the code box, for the same reason.
            decode_base32(secret).with_context(|| {
                format!("the totp_secret in {} is not valid base32", path.display())
            })?;
        }
        if self.max_attempts == 0 {
            anyhow::bail!(
                "{} sets max_attempts = 0, which disables re-login entirely. Set \
                 auto_relogin = false if that is what you meant.",
                path.display()
            );
        }
        Ok(())
    }

    /// The current authenticator code, when there is a seed to compute it from.
    pub fn current_code(&self) -> Result<Option<String>> {
        match self.method {
            TwoFactorMethod::Totp => {
                let secret = self
                    .totp_secret
                    .as_deref()
                    .context("method is totp but no totp_secret is set")?;
                Ok(Some(totp_now(secret)?))
            }
            _ => Ok(None),
        }
    }

    /// Whether an unattended re-login is possible with this configuration.
    pub fn can_run_unattended(&self) -> bool {
        self.auto_relogin && self.method.is_automatable()
    }

    /// How long to wait before attempt `attempt` (1-based), capped at an hour.
    ///
    /// Doubling matters more than the exact numbers: Venmo locks an account
    /// after repeated failures, and a fixed short retry against a password that
    /// has actually changed is how a recoverable expiry becomes a lockout.
    pub fn backoff(&self, attempt: u32) -> std::time::Duration {
        let shift = attempt.saturating_sub(1).min(16);
        let seconds = self
            .retry_backoff_seconds
            .saturating_mul(1u64 << shift)
            .min(3_600);
        std::time::Duration::from_secs(seconds)
    }
}

/// One action on the login page.
///
/// Data rather than calls, exactly as [`crate::venmo::PaymentStep`] is, and for
/// the same two reasons: the sequence can be printed without running it, and it
/// can be tested against a mocked page without a browser at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStep {
    Navigate {
        url: String,
    },
    WaitFor {
        selector: String,
    },
    /// Type into a field. The value is never rendered by [`Self::describe`].
    FillSecret {
        selector: String,
        value: String,
        /// What to call this field in a log line.
        field: &'static str,
    },
    /// Click the first button whose text is one of these.
    ClickOneOf {
        labels: Vec<String>,
        what: &'static str,
    },
    /// Answer true once the page is signed in.
    AwaitSignedIn,
    /// Answer true once a 2FA code box is on screen.
    AwaitCodePrompt,
}

impl LoginStep {
    /// Whether the step carries a credential, and so must never be printed.
    pub fn is_secret(&self) -> bool {
        matches!(self, LoginStep::FillSecret { .. })
    }

    /// One line for a log or a dry run, with no credential in it.
    pub fn describe(&self) -> String {
        match self {
            LoginStep::Navigate { url } => format!("open {url}"),
            LoginStep::WaitFor { selector } => format!("wait for {selector}"),
            LoginStep::FillSecret { field, .. } => format!("type the {field} (not shown)"),
            LoginStep::ClickOneOf { what, .. } => format!("click the {what} button"),
            LoginStep::AwaitSignedIn => "wait for the session to be signed in".into(),
            LoginStep::AwaitCodePrompt => "wait for the 2FA code box".into(),
        }
    }

    /// The JavaScript this step runs in the tab.
    pub fn to_expression(&self) -> String {
        match self {
            LoginStep::Navigate { url } => format!("location.href = {}", json!(url)),

            LoginStep::WaitFor { selector } => {
                format!("document.querySelector({}) !== null", json!(selector))
            }

            // Set through React's own value tracker, not by assigning `el.value`.
            // The identical mistake on the payment page silently discarded the
            // amount, and a login form is React too: a password that does not
            // take reads as a wrong password, and enough of those lock the
            // account.
            LoginStep::FillSecret { selector, value, .. } => format!(
                "(() => {{ \
                   const el = document.querySelector({sel}); \
                   if (!el) throw new Error('missing login field'); \
                   const setter = Object.getOwnPropertyDescriptor( \
                     HTMLInputElement.prototype, 'value').set; \
                   el.focus(); \
                   if (el._valueTracker) {{ el._valueTracker.setValue(''); }} \
                   setter.call(el, {val}); \
                   el.dispatchEvent(new Event('input', {{bubbles:true}})); \
                   el.dispatchEvent(new Event('change', {{bubbles:true}})); \
                   return true; \
                 }})()",
                sel = json!(selector),
                val = json!(value)
            ),

            LoginStep::ClickOneOf { labels, .. } => format!(
                "(() => {{ \
                   const want = {labels}; \
                   const el = [...document.querySelectorAll('button, input[type=\"submit\"]')] \
                     .find(b => want.includes(((b.innerText || b.value) || '').trim())); \
                   if (!el) throw new Error('no button labelled ' + want.join('/')); \
                   if (el.disabled) throw new Error('the button is disabled'); \
                   el.click(); \
                   return true; \
                 }})()",
                labels = json!(labels)
            ),

            // Signed in is a positive statement about the page, not the absence
            // of a login form. A form that has been submitted but not answered
            // has no password box on it either, and treating that as success
            // would have the health check declare a dead session healthy.
            LoginStep::AwaitSignedIn => format!(
                "(() => {{ \
                   const u = location.href.toLowerCase(); \
                   if ({signin}.some(p => u.includes(p))) return false; \
                   if (document.querySelector({pw}) !== null) return false; \
                   return u.includes('venmo.com'); \
                 }})()",
                signin = json!(SIGNED_OUT_MARKERS),
                pw = json!(PASSWORD_SELECTOR)
            ),

            LoginStep::AwaitCodePrompt => {
                format!("document.querySelector({}) !== null", json!(CODE_SELECTOR))
            }
        }
    }
}

/// URL fragments that mean the browser is not on a signed-in page.
///
/// Shared by the step above and by [`crate::venmo::VenmoBrowser::session_looks_live`]'s
/// successor so the two cannot disagree about what signed out looks like.
pub const SIGNED_OUT_MARKERS: [&str; 5] = [
    "/signin",
    "/login",
    "account/sign-in",
    "id.venmo.com",
    "/signup",
];

/// Whether a URL is one of Venmo's signed-out pages.
pub fn url_is_signed_out(url: &str) -> bool {
    let url = url.to_ascii_lowercase();
    SIGNED_OUT_MARKERS.iter().any(|m| url.contains(m))
}

/// The steps that sign in, up to but not including the second factor.
///
/// Split from the 2FA steps because the split is where an un-automatable method
/// has to stop, and a single flat sequence would have no place to stop at.
pub fn signin_steps(credentials: &Credentials) -> Vec<LoginStep> {
    vec![
        LoginStep::Navigate {
            url: SIGNIN_URL.to_string(),
        },
        LoginStep::WaitFor {
            selector: USERNAME_SELECTOR.to_string(),
        },
        LoginStep::FillSecret {
            selector: USERNAME_SELECTOR.to_string(),
            value: credentials.username.clone(),
            field: "username",
        },
        LoginStep::FillSecret {
            selector: PASSWORD_SELECTOR.to_string(),
            value: credentials.password.clone(),
            field: "password",
        },
        LoginStep::ClickOneOf {
            labels: SIGNIN_LABELS.iter().map(|s| s.to_string()).collect(),
            what: "sign-in",
        },
    ]
}

/// The steps that answer an authenticator challenge.
///
/// Only ever built for [`TwoFactorMethod::Totp`]: there is nothing to type for
/// the other methods, and a caller reaching here with an SMS code it invented
/// would be typing a wrong code at an account that locks.
pub fn totp_steps(code: &str) -> Vec<LoginStep> {
    vec![
        LoginStep::AwaitCodePrompt,
        LoginStep::FillSecret {
            selector: CODE_SELECTOR.to_string(),
            value: code.to_string(),
            field: "authenticator code",
        },
        LoginStep::ClickOneOf {
            labels: CODE_SUBMIT_LABELS.iter().map(|s| s.to_string()).collect(),
            what: "code submit",
        },
        LoginStep::AwaitSignedIn,
    ]
}

/// How a re-login ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The session is live again and the daemon can carry on.
    SignedIn,
    /// The form was driven as far as it can be and a human has to finish.
    ///
    /// Not an error: everything this process could do, it did. The distinction
    /// matters because an error retries and this must not.
    NeedsHumanCode {
        method: TwoFactorMethod,
        what_to_do: String,
    },
    /// Venmo rejected the credentials, or the page did something unexpected.
    Failed { why: String },
}

impl LoginOutcome {
    pub fn is_signed_in(&self) -> bool {
        matches!(self, LoginOutcome::SignedIn)
    }

    /// Whether trying again could plausibly help.
    ///
    /// A missing code cannot be retried into existence, and retrying a rejected
    /// password is how the account gets locked. Only the first is worth a
    /// second attempt, and even that is bounded by `max_attempts`.
    pub fn worth_retrying(&self) -> bool {
        matches!(self, LoginOutcome::Failed { .. })
    }
}

// ===========================================================================
// TOTP (RFC 6238)
// ===========================================================================
//
// Implemented here rather than pulled in, because it is thirty lines over
// `hmac` and `sha1`, which the tree already builds, and because the RFC ships
// test vectors that pin it exactly. The vectors are in the tests below.

/// Decode an RFC 4648 base32 secret, tolerating what authenticator apps print.
///
/// Enrolment secrets are shown in groups of four with spaces, sometimes
/// lowercase, sometimes without padding. Refusing any of those would mean the
/// operator has to reformat a credential by hand, which is the same reasoning
/// [`crate::auto::cookie`] gives for accepting a bare Cookie header.
pub fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();

    if cleaned.is_empty() {
        anyhow::bail!("the TOTP secret is empty");
    }

    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::new();
    for ch in cleaned.bytes() {
        let value = ALPHABET
            .iter()
            .position(|c| *c == ch)
            .ok_or_else(|| anyhow::anyhow!("{:?} is not a base32 character", ch as char))?
            as u32;
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }

    if out.is_empty() {
        anyhow::bail!("the TOTP secret decodes to no bytes");
    }
    Ok(out)
}

/// The six-digit code for a given Unix time, 30-second steps.
pub fn totp_at(secret: &str, unix_seconds: u64) -> Result<String> {
    let key = decode_base32(secret)?;
    Ok(hotp(&key, unix_seconds / 30))
}

/// The six-digit code for right now.
pub fn totp_now(secret: &str) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs();
    totp_at(secret, now)
}

/// RFC 4226 HOTP over HMAC-SHA1, truncated to six digits.
fn hotp(key: &[u8], counter: u64) -> String {
    use hmac::{Hmac, Mac};

    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation, RFC 4226 section 5.3.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    format!("{:06}", binary % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            username: "operator@example.com".into(),
            password: "hunter2-but-longer".into(),
            method: TwoFactorMethod::Totp,
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            check_interval_seconds: 900,
            auto_relogin: true,
            max_attempts: 3,
            retry_backoff_seconds: 300,
        }
    }

    // ------------------------------------------------------------------
    // The credential never reaches a log line
    // ------------------------------------------------------------------

    /// The failure this is built to prevent: a `{:?}` on the config struct
    /// putting the Venmo password into a log file that gets pasted into a bug
    /// report. The Debug is hand-written; this is what holds it that way.
    #[test]
    fn debug_never_prints_the_password_or_the_seed() {
        let rendered = format!("{:?}", creds());
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("JBSWY3DP"), "{rendered}");
        // The username is not a secret and is what makes a log line useful.
        assert!(rendered.contains("operator@example.com"), "{rendered}");
    }

    /// A step that types a credential must not render it either. The dry-run
    /// printer walks every step and prints `describe()`.
    #[test]
    fn no_step_describes_itself_with_the_credential_in_it() {
        let mut steps = signin_steps(&creds());
        steps.extend(totp_steps("123456"));
        for step in &steps {
            let line = step.describe();
            assert!(!line.contains("hunter2-but-longer"), "{line}");
            assert!(!line.contains("123456"), "{line}");
            assert!(!line.is_empty());
        }
        // And the two fills are marked, so a future printer cannot forget.
        assert_eq!(steps.iter().filter(|s| s.is_secret()).count(), 3);
    }

    // ------------------------------------------------------------------
    // Startup refusals
    // ------------------------------------------------------------------

    /// The shipped template must not be usable as-is. An unattended daemon that
    /// accepted it would sign in as the literal placeholder repeatedly and get
    /// the real account rate-limited.
    #[test]
    fn the_shipped_placeholders_are_refused() {
        let path = Path::new("config/venmo.local.toml");
        let mut c = creds();
        c.username = "PUT-YOUR-VENMO-EMAIL-HERE".into();
        assert!(c.validate(path).is_err(), "placeholder username");

        let mut c = creds();
        c.password = "PUT-YOUR-VENMO-PASSWORD-HERE".into();
        assert!(c.validate(path).is_err(), "placeholder password");

        let mut c = creds();
        c.totp_secret = Some("PUT-YOUR-BASE32-TOTP-SEED-HERE".into());
        assert!(c.validate(path).is_err(), "placeholder seed");
    }

    /// `method = "totp"` with no seed is the configuration that fails at the
    /// code box at 3am instead of at startup, so it is refused at startup.
    #[test]
    fn totp_without_a_seed_is_refused_at_load_not_at_the_code_box() {
        let mut c = creds();
        c.totp_secret = None;
        let err = c.validate(Path::new("x.toml")).unwrap_err().to_string();
        assert!(err.contains("totp_secret"), "{err}");
        assert!(err.contains("startup"), "{err}");
    }

    /// A seed that is not base32 is caught at load too, for the same reason.
    #[test]
    fn a_malformed_seed_is_caught_at_load() {
        let mut c = creds();
        c.totp_secret = Some("not!valid!base32".into());
        assert!(c.validate(Path::new("x.toml")).is_err());
    }

    /// A file readable by other users on the box holds a password in the clear.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_credentials_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("venmo.local.toml");
        std::fs::write(
            &path,
            "[venmo_login]\nusername = \"a@b.c\"\npassword = \"x\"\nmethod = \"sms\"\n",
        )
        .unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Credentials::load(&path).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Credentials::load(&path).is_ok(), "0600 must be accepted");
    }

    /// The example template the repo ships has to parse, or the first thing an
    /// operator does with it fails.
    #[test]
    fn the_shipped_example_template_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/venmo.example.toml");
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must ship: {e}", path.display()));
        let file: CredentialsFile =
            toml::from_str(&contents).expect("the shipped template must parse");
        // And it must still be placeholders, not somebody's real account.
        assert!(is_placeholder(&file.venmo_login.username), "template has a real username");
        assert!(is_placeholder(&file.venmo_login.password), "template has a real password");
        // Shipped with re-login off: turning it on is a deliberate act.
        assert!(!file.venmo_login.auto_relogin);
    }

    // ------------------------------------------------------------------
    // The 2FA split
    // ------------------------------------------------------------------

    /// The question the whole feature turns on. SMS and email cannot be
    /// answered by this process, and saying otherwise would produce a daemon
    /// that reports success while sitting on a half-finished login.
    #[test]
    fn only_totp_and_no_2fa_can_run_unattended() {
        assert!(TwoFactorMethod::Totp.is_automatable());
        assert!(TwoFactorMethod::None.is_automatable());
        assert!(!TwoFactorMethod::Sms.is_automatable());
        assert!(!TwoFactorMethod::Email.is_automatable());
    }

    /// And each un-automatable method says what the human has to do, naming the
    /// way out rather than only the problem.
    #[test]
    fn a_manual_method_names_the_step_and_the_fix() {
        for method in [TwoFactorMethod::Sms, TwoFactorMethod::Email] {
            let step = method.manual_step();
            assert!(step.contains("code"), "{step}");
            assert!(step.contains("totp"), "{step} must name the way out");
        }
    }

    /// Auto-relogin is off unless both switches agree: the operator turned it
    /// on, and the method can actually finish.
    #[test]
    fn unattended_needs_both_the_flag_and_an_automatable_method() {
        let mut c = creds();
        assert!(c.can_run_unattended());

        c.auto_relogin = false;
        assert!(!c.can_run_unattended(), "off by config");

        c.auto_relogin = true;
        c.method = TwoFactorMethod::Sms;
        assert!(!c.can_run_unattended(), "SMS cannot finish alone");
    }

    /// A missing SMS code is not a failure to retry. Retrying a rejected
    /// password is how an account gets locked.
    #[test]
    fn only_an_outright_failure_is_retried() {
        assert!(LoginOutcome::Failed { why: "bad password".into() }.worth_retrying());
        assert!(!LoginOutcome::SignedIn.worth_retrying());
        assert!(!LoginOutcome::NeedsHumanCode {
            method: TwoFactorMethod::Sms,
            what_to_do: "type it".into(),
        }
        .worth_retrying());
    }

    /// Backoff doubles and then stops doubling, so a wrong password cannot be
    /// hammered but the wait never grows past an hour either.
    #[test]
    fn backoff_doubles_and_caps_at_an_hour() {
        let c = creds();
        assert_eq!(c.backoff(1).as_secs(), 300);
        assert_eq!(c.backoff(2).as_secs(), 600);
        assert_eq!(c.backoff(3).as_secs(), 1_200);
        assert_eq!(c.backoff(30).as_secs(), 3_600, "capped, and no overflow");
    }

    // ------------------------------------------------------------------
    // The steps themselves
    // ------------------------------------------------------------------

    /// The fill goes through React's native setter, exactly as the payment
    /// page's does. A password that silently does not take reads to Venmo as a
    /// wrong password, and enough of those lock the account.
    #[test]
    fn the_login_fill_sets_the_value_the_way_react_accepts() {
        let js = LoginStep::FillSecret {
            selector: PASSWORD_SELECTOR.into(),
            value: "x".into(),
            field: "password",
        }
        .to_expression();
        assert!(js.contains("_valueTracker"), "{js}");
        assert!(js.contains("getOwnPropertyDescriptor"), "{js}");
        assert!(js.contains("new Event('input'"), "{js}");
    }

    /// Buttons are matched by text, never by `button[type='submit']`. That
    /// selector on a Venmo page is one this repository has already been burned
    /// by: on the payment page it also matched two avatars and a cookie banner.
    #[test]
    fn buttons_are_matched_by_text_not_by_submit_type() {
        let js = LoginStep::ClickOneOf {
            labels: SIGNIN_LABELS.iter().map(|s| s.to_string()).collect(),
            what: "sign-in",
        }
        .to_expression();
        assert!(js.contains("innerText"), "{js}");
        assert!(js.contains("Sign In"), "{js}");
        assert!(js.contains("disabled"), "{js} must refuse a disabled button");
        assert!(!js.contains("button[type='submit']"), "{js}");
    }

    /// Every step that reaches through a lookup guards the null first. The same
    /// property `venmo.rs` holds; a TypeError here reads as a page error rather
    /// than as "the field is not there".
    #[test]
    fn no_login_step_dereferences_a_missing_element() {
        let mut steps = signin_steps(&creds());
        steps.extend(totp_steps("000000"));
        for step in steps {
            let js = step.to_expression();
            if !js.contains("querySelector") {
                continue;
            }
            assert!(
                js.contains("if (!el)") || js.contains("!== null") || js.contains("if (!el)"),
                "{js}"
            );
        }
    }

    /// Signed-in is a positive test, not the absence of a login form. A
    /// submitted-but-unanswered form has no password box either, and calling
    /// that signed in would have the health check declare a dead session live.
    #[test]
    fn signed_in_is_asserted_positively_rather_than_by_absence() {
        let js = LoginStep::AwaitSignedIn.to_expression();
        assert!(js.contains("venmo.com"), "{js}");
        assert!(js.contains("/signin"), "{js}");
        assert!(js.contains("return false"), "{js}");
    }

    /// The sign-in sequence puts the username in before the password and clicks
    /// only after both. A click with an empty password is a failed attempt
    /// against an account with a lockout counter.
    #[test]
    fn the_form_is_filled_before_it_is_submitted() {
        let steps = signin_steps(&creds());
        let click = steps
            .iter()
            .position(|s| matches!(s, LoginStep::ClickOneOf { .. }))
            .expect("a submit");
        let fills: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_secret())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(fills.len(), 2, "username and password");
        assert!(fills.iter().all(|i| *i < click), "both fills precede the click");
    }

    /// The code box is waited for before anything is typed into it. Typing into
    /// a page that has not rendered the box yet throws, and the retry that
    /// follows spends another attempt against the lockout counter.
    #[test]
    fn the_code_box_is_waited_for_before_the_code_is_typed() {
        let steps = totp_steps("123456");
        assert_eq!(steps[0], LoginStep::AwaitCodePrompt);
        assert!(steps[1].is_secret());
        assert_eq!(*steps.last().unwrap(), LoginStep::AwaitSignedIn);
    }

    /// Nothing in the login flow can move money. This is the property that
    /// keeps the credential path and the payment path apart, and it is asserted
    /// rather than assumed because the two modules render JavaScript the same
    /// way and could grow into each other.
    #[test]
    fn no_login_step_touches_the_payment_page() {
        let mut steps = signin_steps(&creds());
        steps.extend(totp_steps("000000"));
        for step in steps {
            let js = step.to_expression();
            assert!(!js.contains("aria-label='Amount'"), "{js}");
            assert!(!js.contains("payment-note"), "{js}");
            assert!(!js.to_lowercase().contains("/pay?"), "{js}");
        }
    }

    // ------------------------------------------------------------------
    // Signed-out detection
    // ------------------------------------------------------------------

    #[test]
    fn venmos_signed_out_urls_are_recognised() {
        assert!(url_is_signed_out("https://id.venmo.com/signin"));
        assert!(url_is_signed_out("https://account.venmo.com/login"));
        assert!(url_is_signed_out("https://venmo.com/account/sign-in"));
        assert!(url_is_signed_out("https://ID.VENMO.COM/SIGNIN"), "case");
        assert!(!url_is_signed_out("https://account.venmo.com/"));
        assert!(!url_is_signed_out("https://account.venmo.com/pay?recipients=x"));
    }

    // ------------------------------------------------------------------
    // TOTP, against the RFC's own vectors
    // ------------------------------------------------------------------

    /// RFC 6238 appendix B, the SHA-1 rows. The secret is the ASCII string
    /// "12345678901234567890", which is base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
    #[test]
    fn rfc6238_test_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for (time, expected) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(totp_at(secret, time).unwrap(), expected, "at t={time}");
        }
    }

    /// A code is always six digits, including when the truncation lands on a
    /// small number. `format!("{}", n % 1_000_000)` would print "5924" and
    /// Venmo would reject it.
    #[test]
    fn a_code_is_always_six_digits() {
        assert_eq!(totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1_234_567_890).unwrap(), "005924");
        for t in [0u64, 1, 59, 12_345, 999_999_999] {
            let code = totp_at("JBSWY3DPEHPK3PXP", t).unwrap();
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");
        }
    }

    /// The code changes on a 30-second step and holds still inside one.
    #[test]
    fn the_code_steps_every_thirty_seconds() {
        let s = "JBSWY3DPEHPK3PXP";
        assert_eq!(totp_at(s, 0).unwrap(), totp_at(s, 29).unwrap());
        assert_ne!(totp_at(s, 29).unwrap(), totp_at(s, 30).unwrap());
        assert_eq!(totp_at(s, 30).unwrap(), totp_at(s, 59).unwrap());
    }

    /// Authenticator apps print the seed in spaced groups, lowercase, and
    /// sometimes unpadded. Making the operator reformat a credential by hand is
    /// how it ends up pasted somewhere it should not be.
    #[test]
    fn a_seed_is_accepted_the_way_an_authenticator_app_prints_it() {
        let canonical = decode_base32("JBSWY3DPEHPK3PXP").unwrap();
        for variant in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSWY3DPEHPK3PXP======",
            "JBSW-Y3DP-EHPK-3PXP",
            " JBSWY3DPEHPK3PXP ",
        ] {
            assert_eq!(decode_base32(variant).unwrap(), canonical, "{variant}");
        }
    }

    /// And the known-answer test for the decoder itself: this seed is the
    /// ASCII string "Hello!\xDE\xAD\xBE\xEF".
    #[test]
    fn base32_decodes_to_the_right_bytes() {
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xDE\xAD\xBE\xEF"
        );
    }

    #[test]
    fn a_seed_that_is_not_base32_is_rejected() {
        assert!(decode_base32("").is_err());
        assert!(decode_base32("!!!!").is_err());
        assert!(decode_base32("18").is_err(), "1 and 8 are not in the alphabet");
    }

    /// The code is computed from the seed rather than read from anywhere, which
    /// is the whole reason TOTP is the only automatable method.
    #[test]
    fn a_totp_config_produces_a_code_and_the_others_do_not() {
        assert!(creds().current_code().unwrap().is_some());
        for method in [TwoFactorMethod::Sms, TwoFactorMethod::Email, TwoFactorMethod::None] {
            let mut c = creds();
            c.method = method;
            assert!(c.current_code().unwrap().is_none(), "{method:?}");
        }
    }
}
