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

/// Whether the confirmation report says the payment posted.
///
/// The predicate answers an object rather than a bool: `ok` is the verdict and
/// the other fields say what was seen, so a failure can name the page instead
/// of asserting a reason nobody observed.
fn confirmed(result: &StepResult) -> bool {
    result
        .value
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| {
            panic!(
                "the confirmation must answer a report, got {:?}",
                result.value
            )
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

/// The reproduction, now caught before the first click rather than after it.
///
/// The incident's tab had a confirmation sheet open when the drive started, so
/// the temporal rule refuses it at `RequireNoOpenSheet` and no money button is
/// ever pressed. That is strictly better than what round 1 achieved -- the
/// clicks used to happen and only the post-click check objected -- and it is
/// the same page that produced the false success.
#[test]
fn the_stale_page_that_caused_the_false_success_is_now_caught() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("stalepay", &expressions(&steps));

    // The open-sheet check answers a report and the driver judges it in Rust,
    // so the refusal shows up as `ok: false` in its value rather than as a
    // thrown error.
    let at = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::RequireNoOpenSheet))
        .expect("the sequence must carry the open-sheet check");
    let report = &results[at].value;
    assert_eq!(
        report.get("ok"),
        Some(&serde_json::json!(false)),
        "the incident's page had a sheet open, so this must refuse: {report:?}"
    );
    // And it names what to close.
    let sheets = report
        .get("sheets")
        .and_then(|v| v.as_array())
        .expect("the report lists the sheets it found");
    assert_eq!(sheets, &vec![serde_json::json!("Pay Jay Butera $2.01")]);

    // The check sits before every money step, so the refusal costs nothing.
    assert!(
        steps[..at].iter().all(|s| !s.is_irreversible()),
        "the open-sheet check must come before any money button"
    );
}

/// The post-click confirmation still catches a click that does nothing.
///
/// `RequireNoOpenSheet` removes the incident's *entry* condition, so without
/// this the post-click check would no longer have a test that reaches it on a
/// page where the click is inert. Here the form starts clean, our own click
/// opens the sheet, and the confirm click does nothing -- which is the state
/// round 1 was built for.
#[test]
fn a_click_that_does_nothing_is_still_caught_after_the_sheet_opens() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("inertclickpay", &expressions(&steps));
    assert_eq!(results.len(), steps.len(), "every step should have run");

    // The point that made the incident expensive: nothing before the
    // confirmation objects, because everything before it asks about the form.
    let last_click = steps
        .iter()
        .rposition(|s| s.is_irreversible())
        .expect("a send step");
    for (i, (step, result)) in steps.iter().zip(&results).enumerate().take(last_click + 1) {
        assert!(
            result.ok,
            "step {i} ({}) failed before the confirmation: {:?}",
            step.describe(),
            result.error
        );
    }

    let confirmation = results.last().expect("the confirmation step");
    assert!(
        !confirmed(confirmation),
        "the sheet is still up after the confirm click, so nothing was sent: {:?}",
        confirmation.value
    );
    assert_eq!(
        confirmation.value.get("sheet"),
        Some(&serde_json::json!(true)),
        "the report must name the sheet it saw: {:?}",
        confirmation.value
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
    assert!(
        confirmed(results.last().expect("the confirmation")),
        "the whole form cleared, so the payment posted: {:?}",
        results.last().unwrap().value
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
    assert!(!confirmed(&results[0]));
    assert_eq!(
        results[1].value, results[0].value,
        "the confirmation must be a pure read"
    );
}

/// Finding 1: a dismissed confirmation sheet is not a payment.
///
/// Venmo rejecting a stale confirmation closes the sheet and drops back to the
/// plain pay form, whose button reads "Pay" rather than "Pay Jay Butera $2.01".
/// The first version of this check asked only whether the amount-naming button
/// was gone, and it was -- so it reported the payment sent while the money sat
/// in the account. That is the incident again with a different page shape.
#[test]
fn a_confirmation_that_dismisses_without_sending_is_not_confirmed() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("dismissingpay", &expressions(&steps));
    let confirmation = results.last().expect("the confirmation step");

    assert!(
        !confirmed(confirmation),
        "the sheet closed but the pay form is still up, so nothing was sent: {:?}",
        confirmation.value
    );
    // The bare "Pay" button is the tell, and the report names it rather than
    // claiming the sheet is still open.
    assert_eq!(
        confirmation.value.get("payBtn"),
        Some(&serde_json::json!(true)),
        "the report must name the form it saw: {:?}",
        confirmation.value
    );
}

/// Finding 1: a session that expires at the click is not a payment.
///
/// The redirect to sign-in takes the form and the confirmation with it, so
/// every "is the button gone" question answers yes on a page where no payment
/// could possibly have posted.
#[test]
fn a_session_that_expires_at_the_click_is_not_confirmed() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("expiringpay", &expressions(&steps));
    let confirmation = results.last().expect("the confirmation step");

    assert!(
        !confirmed(confirmation),
        "a sign-in page is not a completed payment: {:?}",
        confirmation.value
    );
    assert_eq!(
        confirmation.value.get("signedOut"),
        Some(&serde_json::json!(true)),
        "the report must say the tab went to a signed-out page: {:?}",
        confirmation.value
    );
}

/// A same-order retry does not click its own stale sheet.
///
/// The reviewer's ruling in round 2: even when the amount and note match --
/// which for a retry of the same order they always do -- a pre-existing sheet
/// is a refusal. Its terms were fixed when it opened, before this drive ran a
/// single readback, so clicking it would send something none of this run's own
/// checks looked at. The note binding permitted exactly this; the temporal
/// rule does not.
///
/// There is no automatic retry in the coordinator -- every `fiat.pay` failure
/// writes `NeedsOperator` and fails the order -- so this is only reached after
/// a human has looked at the tab, and the right instruction is to close the
/// sheet and start clean.
#[test]
fn a_retry_of_the_same_order_refuses_its_own_stale_sheet() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    // `stalepay` is this order's own earlier attempt: same payee, same amount,
    // same note. Nothing textual can tell it from a fresh one.
    let results = run_sequence("stalepay", &expressions(&steps));

    let at = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::RequireNoOpenSheet))
        .expect("the open-sheet check");
    assert_eq!(
        results[at].value.get("ok"),
        Some(&serde_json::json!(false)),
        "a retry must refuse the sheet its own earlier attempt left open: {:?}",
        results[at].value
    );

    // And it is refused for being open, not for what it says: the label names
    // this very payment.
    let sheets = results[at]
        .value
        .get("sheets")
        .and_then(|v| v.as_array())
        .expect("the sheets it found");
    assert!(
        sheets
            .iter()
            .any(|s| s.as_str().unwrap_or_default().contains("2.01")),
        "the stale sheet names this order's own amount: {sheets:?}"
    );
}

/// Item 4: a stale sheet for another payee is not clicked.
///
/// The label matches on prefix and amount, and a sheet an earlier drive left
/// open for a different payee at the same amount matches both. If that sheet
/// posts on click it pays the previous drive's recipient. The note is what
/// tells them apart: it is per-payment and this run typed its own two steps
/// earlier.
#[test]
fn a_stale_sheet_for_another_payee_is_refused_before_the_click() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let click = steps
        .iter()
        .rposition(|s| s.is_irreversible())
        .expect("a send step");

    let results = run_sequence("otherpayeesheet", &expressions(&steps));

    // The run must stop at or before the click. Where it stops is the
    // interesting part: the fills rewrite the amount and the note, so by the
    // time the click is reached this page no longer looks stale -- which is
    // why the *first* refusal matters more than the last.
    let stopped = results
        .iter()
        .position(|r| !r.ok)
        .expect("some step must refuse this page");
    assert!(
        stopped <= click,
        "the refusal must come no later than the click: stopped at {stopped}, click at {click}"
    );

    // No money moved. The bare "Pay" click does run here, and that is fine:
    // on a form it only opens a confirmation, and this page's confirmation was
    // already open. What must not run is the click that names an amount, which
    // is the one that sends -- and it refuses inside its own JavaScript,
    // before `el.click()`.
    let sent = steps
        .iter()
        .take(stopped)
        .any(|s| matches!(s, PaymentStep::ConfirmNamedAmount { .. }));
    assert!(
        !sent,
        "the amount-naming confirmation was clicked before the page was refused"
    );

    // And it refuses for the right reason: the sheet is not this drive's.
    let why = results[stopped].error.clone().unwrap_or_default();
    assert!(
        why.contains("note"),
        "the refusal at step {stopped} ({}) should name the note, got {why:?}",
        steps[stopped].describe()
    );
}

/// Item 4: the recipient check reads the page, not the URL we just wrote.
///
/// `RequireRecipient` used to fold `location.href` into its haystack, so it
/// confirmed the address `Navigate` had assigned one step earlier rather than
/// anything the document rendered. A pay form left open for someone else, at a
/// URL naming our payee, passed it.
#[test]
fn the_recipient_check_does_not_read_the_url_we_navigated_to() {
    if !node_available() {
        return;
    }
    let step = PaymentStep::RequireRecipient {
        recipient: "jay-butera".to_string(),
    };
    let results = run_sequence("wrongpayeeform", &[step.expression_for_test()]);
    let ok = results[0]
        .value
        .get("ok")
        .and_then(|v| v.as_bool())
        .expect("the recipient check answers a report");
    assert!(
        !ok,
        "the page names someone-else and only the URL names jay-butera, so this          must not pass: {:?}",
        results[0].value
    );
}

/// A payment never blocks on the audience control.
///
/// Decided on 2026-09-05: the account default is Private, so the driver
/// inherits it and does not touch the control per payment. The point of
/// pinning it here is the *refusal* rather than the setting -- a readback step
/// stalls a locked escrow and a held in-flight slot over a menu, and the
/// account default already covers what it was protecting.
///
/// The note and its tag are unaffected and still identify the fill; they are
/// simply not published by a payment the account already keeps private.
#[test]
fn no_step_touches_or_refuses_over_the_audience() {
    let steps = the_incident_payment();
    for step in &steps {
        let described = step.describe();
        assert!(
            !described.contains("audience"),
            "a payment must not drive or check the audience, found: {described}"
        );
        let js = step.expression_for_test();
        assert!(
            !js.contains("Public") && !js.contains("Friends"),
            "no step may read Venmo's audience words: {js}"
        );
    }
    // The note is still filled, because the tag is what identifies the fill.
    assert!(
        steps.iter().any(|s| matches!(
            s,
            PaymentStep::Fill { value, .. } if value.contains("5df45b72")
        )),
        "the tagged note must still be typed"
    );
}
