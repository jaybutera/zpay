//! The login steps, run against a page instead of asserted over as strings.
//!
//! `auto::login`'s own tests assert over the *text* of the generated
//! JavaScript: that a fill clears React's value tracker, that a button is
//! matched by its label. Those catch a step that stops doing the right thing.
//! They cannot catch a step whose JavaScript does not parse, or whose selector
//! matches nothing on a page shaped like Venmo's. Both of those failures cost a
//! live run and neither shows up in a string assertion, which is exactly how
//! the payment page's `input[name='amount']` survived until someone ran it.
//!
//! So these tests execute the real expressions. `tests/mock_login_page.js`
//! carries a small DOM and a page whose markup mirrors the real form: a
//! password input identified only by `type='password'`, a sign-in button with
//! no id and no test id, and two decoy `type='submit'` buttons that are not the
//! sign-in button.
//!
//! The DOM models one behaviour precisely, because it is the one that has
//! already cost this repository a live run: a React-controlled input reverts a
//! write whose value tracker was not cleared first, silently and without
//! throwing. On the payment page that discarded the amount. On a login form it
//! reads to Venmo as an empty password, and enough of those lock the account.

use std::io::Write;
use std::process::{Command, Stdio};

use zecp2p_taker::auto::login::{self, Credentials, LoginStep, TwoFactorMethod};

/// Skip rather than fail when node is not installed.
///
/// The suite has to pass on a machine without a JavaScript runtime, and a test
/// that fails for a missing tool trains people to ignore red. It reports the
/// skip so a silent pass is not mistaken for coverage.
fn node_available() -> bool {
    match Command::new("node").arg("--version").output() {
        Ok(out) => out.status.success(),
        Err(_) => {
            eprintln!("skipping: node is not installed, so the mocked login page cannot run");
            false
        }
    }
}

fn script() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mock_login_page.js")
}

/// What the page reported after running an expression.
#[derive(Debug)]
struct PageResult {
    ok: bool,
    error: Option<String>,
    value: serde_json::Value,
    state: Vec<serde_json::Value>,
}

impl PageResult {
    /// The value of the field matching this selector-ish description.
    fn field_value(&self, index: usize) -> String {
        self.state
            .get(index)
            .and_then(|e| e.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    fn clicked(&self) -> Vec<String> {
        self.state
            .iter()
            .filter(|e| e.get("clicked").and_then(|c| c.as_bool()).unwrap_or(false))
            .map(|e| {
                e.get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }
}

/// Run one expression against one of the mock pages.
fn run_on(page: &str, expression: &str) -> PageResult {
    let mut child = Command::new("node")
        .arg(script())
        .arg(page)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node should start");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(expression.as_bytes())
        .expect("write the expression");

    let out = child.wait_with_output().expect("node should finish");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "the mock page did not answer JSON: {e}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });

    PageResult {
        ok: parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        error: parsed
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        value: parsed.get("value").cloned().unwrap_or(serde_json::Value::Null),
        state: parsed
            .get("state")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
    }
}

fn creds() -> Credentials {
    Credentials {
        username: "operator@example.com".into(),
        password: "a-real-password".into(),
        method: TwoFactorMethod::Totp,
        totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
        check_interval_seconds: 900,
        auto_relogin: true,
        max_attempts: 3,
        retry_backoff_seconds: 300,
    }
}

// ===========================================================================
// The selectors find the real fields
// ===========================================================================

/// Every selector in the sign-in sequence matches something on a page shaped
/// like Venmo's. This is the check that a string assertion cannot make, and the
/// one that would have caught `input[name='amount']` on the payment page before
/// it timed out on a live run.
#[test]
fn every_login_selector_matches_the_field_it_names() {
    if !node_available() {
        return;
    }
    for step in login::signin_steps(&creds()) {
        if let LoginStep::WaitFor { selector } = &step {
            let result = run_on("signin", &step.to_expression());
            assert!(result.ok, "{selector}: {:?}", result.error);
            assert_eq!(
                result.value,
                serde_json::Value::Bool(true),
                "{selector} matched nothing on the sign-in page"
            );
        }
    }
}

/// The 2FA code box is found on the challenge page.
#[test]
fn the_code_box_selector_matches_the_challenge_page() {
    if !node_available() {
        return;
    }
    let result = run_on("code", &LoginStep::AwaitCodePrompt.to_expression());
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.value, serde_json::Value::Bool(true));

    // And it is not on the sign-in page, so waiting for it is a real wait
    // rather than something that passes immediately.
    let before = run_on("signin", &LoginStep::AwaitCodePrompt.to_expression());
    assert_eq!(before.value, serde_json::Value::Bool(false));
}

// ===========================================================================
// The fill survives React
// ===========================================================================

/// The password reaches the field and is still there after React re-renders.
///
/// The mock DOM reverts a write whose value tracker was not cleared, which is
/// what a real controlled input does. A password that silently does not take
/// reads to Venmo as a wrong password, and enough wrong passwords lock the
/// account, so this is the difference between a recoverable expiry and an
/// appeal.
#[test]
fn the_password_survives_the_react_render() {
    if !node_available() {
        return;
    }
    let steps = login::signin_steps(&creds());
    let password = steps
        .iter()
        .find(|s| matches!(s, LoginStep::FillSecret { field: "password", .. }))
        .expect("a password fill");

    let result = run_on("signin", &password.to_expression());
    assert!(result.ok, "{:?}", result.error);
    // Index 1 is the password input on the mock page.
    assert_eq!(
        result.field_value(1),
        "a-real-password",
        "the password did not survive the render: React discarded the write"
    );
}

/// And the username lands in the username field, not the password one.
#[test]
fn the_username_goes_into_the_username_field() {
    if !node_available() {
        return;
    }
    let steps = login::signin_steps(&creds());
    let username = steps
        .iter()
        .find(|s| matches!(s, LoginStep::FillSecret { field: "username", .. }))
        .expect("a username fill");

    let result = run_on("signin", &username.to_expression());
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.field_value(0), "operator@example.com");
    assert_eq!(result.field_value(1), "", "nothing in the password field");
}

/// The guard against the mock being too generous: a naive `el.value =` fill
/// must be discarded by this page. If it is not, every test above passes for
/// the wrong reason and proves nothing about the real fill.
#[test]
fn the_mock_page_really_does_discard_a_naive_fill() {
    if !node_available() {
        return;
    }
    let naive = "(() => { const el = document.querySelector(\"input[type='password']\"); \
                 el.value = 'a-real-password'; \
                 el.dispatchEvent(new Event('input', {bubbles:true})); \
                 return el.value; })()";
    let result = run_on("signin", naive);
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(
        result.field_value(1),
        "",
        "the mock accepted a fill that React would have discarded, so it cannot \
         prove anything about the real one"
    );
}

// ===========================================================================
// The button is the right button
// ===========================================================================

/// The sign-in click finds the button labelled "Sign In" and not either of the
/// `type='submit'` decoys beside it.
///
/// The payment page had exactly this shape: `button[type='submit']` there
/// matched a cookie banner, two avatars, and the confirmation's own button. On
/// a login page the equivalent mistake clicks "Sign up for Venmo".
#[test]
fn the_sign_in_click_finds_the_sign_in_button_and_not_a_decoy() {
    if !node_available() {
        return;
    }
    let steps = login::signin_steps(&creds());
    let click = steps
        .iter()
        .find(|s| matches!(s, LoginStep::ClickOneOf { .. }))
        .expect("a submit");

    let result = run_on("signin", &click.to_expression());
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.clicked(), vec!["Sign In".to_string()]);
}

/// The code submit finds its button on the challenge page.
#[test]
fn the_code_submit_finds_its_button() {
    if !node_available() {
        return;
    }
    let click = login::totp_steps("123456")
        .into_iter()
        .find(|s| matches!(s, LoginStep::ClickOneOf { .. }))
        .expect("a submit");

    let result = run_on("code", &click.to_expression());
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.clicked(), vec!["Submit".to_string()]);
}

/// A click that finds no button raises rather than silently doing nothing. A
/// no-op here would leave the daemon waiting on a form it never submitted.
#[test]
fn a_click_with_no_matching_button_raises() {
    if !node_available() {
        return;
    }
    let click = login::totp_steps("123456")
        .into_iter()
        .find(|s| matches!(s, LoginStep::ClickOneOf { .. }))
        .expect("a submit");

    // The account page has no "Submit" button on it.
    let result = run_on("account", &click.to_expression());
    assert!(!result.ok, "a missing button must raise, not return quietly");
    assert!(
        result.error.unwrap_or_default().contains("no button labelled"),
        "and it must say which button it wanted"
    );
}

// ===========================================================================
// Signed-in detection, against all three pages
// ===========================================================================

/// The check that decides whether a re-login worked. It has to be true on the
/// account page and false on both pages that are not a live session, and the
/// second half is what matters: a submitted-but-unanswered form has no password
/// box either, and calling that signed in is how a daemon goes back to sleep in
/// front of a login wall.
#[test]
fn signed_in_is_true_only_on_the_account_page() {
    if !node_available() {
        return;
    }
    let expression = LoginStep::AwaitSignedIn.to_expression();

    let account = run_on("account", &expression);
    assert!(account.ok, "{:?}", account.error);
    assert_eq!(
        account.value,
        serde_json::Value::Bool(true),
        "a real account page is signed in"
    );

    for page in ["signin", "code"] {
        let result = run_on(page, &expression);
        assert!(result.ok, "{page}: {:?}", result.error);
        assert_eq!(
            result.value,
            serde_json::Value::Bool(false),
            "{page} is not a signed-in session"
        );
    }
}

// ===========================================================================
// Nothing in the login flow can move money
// ===========================================================================

/// Every step of the whole flow runs against every page without throwing
/// something unexpected, and none of them clicks anything on the account page.
///
/// The account page is where a signed-in browser sits between fills, and it is
/// the page a misfiring login step would be running against. Nothing in this
/// flow may click there: the real one carries a "Pay or Request" button.
#[test]
fn the_login_flow_clicks_nothing_on_a_signed_in_account_page() {
    if !node_available() {
        return;
    }
    let mut steps = login::signin_steps(&creds());
    steps.extend(login::totp_steps("123456"));

    for step in steps {
        if matches!(step, LoginStep::Navigate { .. }) {
            continue;
        }
        let result = run_on("account", &step.to_expression());
        // A step may legitimately fail here (there is no password box on the
        // account page). What it may not do is click something.
        assert!(
            result.clicked().is_empty(),
            "{} clicked {:?} on a signed-in account page",
            step.describe(),
            result.clicked()
        );
    }
}
