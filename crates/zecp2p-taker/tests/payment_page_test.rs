//! The payment steps, run against a page rather than asserted over as strings.
//!
//! `venmo`'s own tests assert over the shape of the step list and the text of
//! the generated JavaScript. Those are worth having and they did not catch the
//! failure that mattered: on 2026-09-05 order `esc_2c0cef0587c47bafd201e104`
//! ran the whole sequence without error, in about three seconds, and `pay`
//! returned success for $2.01 that never left the account. Every step passed
//! because every step was asking about the payment *form*, and the form was
//! right; nothing asked whether Venmo had done anything.
//!
//! These tests execute the real expressions against a page that models that
//! exact state -- filled amount, correct recipient, a live confirmation button,
//! and buttons whose clicks do nothing. A driver that reports success against
//! that page is the bug, so the test asserts it does not.

use std::io::Write;
use std::process::{Command, Stdio};

use zecp2p_taker::venmo::{PaymentRequest, PaymentStep, VenmoBrowser};

/// Skip rather than fail when node is not installed, as the login page test
/// does: a suite that goes red for a missing tool trains people to ignore red.
fn node_available() -> bool {
    match Command::new("node").arg("--version").output() {
        Ok(out) => out.status.success(),
        Err(_) => {
            eprintln!("skipping: node is not installed, so the mocked payment page cannot run");
            false
        }
    }
}

fn script() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mock_login_page.js")
}

/// One step's answer from the page.
#[derive(Debug)]
struct StepResult {
    ok: bool,
    error: Option<String>,
    value: serde_json::Value,
}

/// Run a whole sequence against one page that persists between the steps.
///
/// Per-expression processes cannot express this flow: the entire question is
/// what the page looks like after a click.
fn run_sequence(page: &str, expressions: &[String]) -> Vec<StepResult> {
    let mut input = String::from("@@sequence\n");
    for (i, e) in expressions.iter().enumerate() {
        if i > 0 {
            input.push_str("\n@@\n");
        }
        input.push_str(e);
    }

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
        .write_all(input.as_bytes())
        .expect("write the sequence");

    let out = child.wait_with_output().expect("node should finish");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "the mock page did not answer JSON: {e}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });

    parsed
        .get("steps")
        .and_then(|s| s.as_array())
        .expect("a steps array")
        .iter()
        .map(|s| StepResult {
            ok: s.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
            error: s
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            value: s.get("value").cloned().unwrap_or(serde_json::Value::Null),
        })
        .collect()
}

/// The steps of the payment that was falsely reported sent.
fn the_incident_payment() -> Vec<PaymentStep> {
    VenmoBrowser::new("http://127.0.0.1:9222", 60).payment_steps(&PaymentRequest {
        recipient: "jay-butera".to_string(),
        amount: "2.01".to_string(),
        note: "thanks 5df45b72".to_string(),
    })
}

/// The expressions for every step that is not a poll.
///
/// `WaitFor`, `WaitForConfirm` and `RequireSendConfirmed` are polled by the
/// driver rather than run once; their expressions are predicates, and running
/// one is the same question the poll asks on each pass.
fn expressions(steps: &[PaymentStep]) -> Vec<String> {
    steps.iter().map(|s| s.expression_for_test()).collect()
}

/// The reproduction.
///
/// Every step up to and including the two clicks passes against the stale page,
/// which is what made this so expensive: there was no error to see. The
/// confirmation is the one predicate that answers "no", and before it existed
/// there was nothing after the click to answer at all.
#[test]
fn the_stale_page_that_caused_the_false_success_is_now_caught() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("stalepay", &expressions(&steps));
    assert_eq!(results.len(), steps.len(), "every step should have run");

    // The bug, stated: nothing before the confirmation objects to this page.
    let last_click = steps
        .iter()
        .rposition(|s| s.is_irreversible())
        .expect("a send step");
    for (i, (step, result)) in steps.iter().zip(&results).enumerate().take(last_click + 1) {
        assert!(
            result.ok,
            "step {i} ({}) failed on the stale page: {:?}. \
             The incident's whole difficulty was that none of these failed.",
            step.describe(),
            result.error
        );
    }

    // And the confirmation is what catches it: the button naming $2.01 is
    // still on the page after both clicks, so the predicate is false and the
    // driver's poll runs out and errors instead of returning success.
    let confirmation = results.last().expect("the confirmation step");
    assert!(confirmation.ok, "the predicate itself must not throw");
    assert_eq!(
        confirmation.value,
        serde_json::json!(false),
        "the $2.01 confirmation is still on the stale page, so the send did not post"
    );
}

/// The other half: a page where the click actually posts must still pass.
///
/// A check that says "unconfirmed" on a working payment is worse than no check,
/// because the operator learns to override it.
#[test]
fn a_payment_that_actually_posts_is_confirmed() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("livepay", &expressions(&steps));

    for (i, (step, result)) in steps.iter().zip(&results).enumerate() {
        assert!(
            result.ok,
            "step {i} ({}) failed on a working page: {:?}",
            step.describe(),
            result.error
        );
    }
    assert_eq!(
        results.last().expect("the confirmation").value,
        serde_json::json!(true),
        "the confirmation cleared, so the payment posted"
    );
}

/// The confirmation predicate reads the page and changes nothing.
///
/// It runs after money has moved, so a step that could click or type there is a
/// second payment waiting to happen.
#[test]
fn the_confirmation_does_not_touch_the_page() {
    if !node_available() {
        return;
    }
    let confirm = PaymentStep::RequireSendConfirmed {
        amount: "2.01".to_string(),
    };
    // Run it twice against the stale page: a predicate with a side effect would
    // answer differently the second time.
    let results = run_sequence(
        "stalepay",
        &[confirm.expression_for_test(), confirm.expression_for_test()],
    );
    assert_eq!(results[0].value, serde_json::json!(false));
    assert_eq!(
        results[1].value, results[0].value,
        "the confirmation must be a pure read"
    );
}
