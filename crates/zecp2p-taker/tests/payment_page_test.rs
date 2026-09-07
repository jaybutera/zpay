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

use zecp2p_taker::venmo::{PaymentRequest, PaymentStep, ResolvedPayee, VenmoBrowser};

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
    VenmoBrowser::new("http://127.0.0.1:9222", 60).payment_steps(
        &PaymentRequest {
            recipient: "jay-butera".to_string(),
            amount: "2.01".to_string(),
            note: "thanks 5df45b72".to_string(),
        },
        &the_resolved_payee(),
    )
}

/// What `resolve_payee` answered for `jay-butera` against the live session on
/// 2026-09-06. Real values: the id is the one Venmo returned.
fn the_resolved_payee() -> ResolvedPayee {
    ResolvedPayee {
        handle: "Jay-Butera".to_string(),
        id: JAY_BUTERA_ID.to_string(),
        display_name: "Jay Butera".to_string(),
    }
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

/// Whether the driver would have stopped the run at this step.
///
/// `run_sequence` keeps going after every step, because a step that answers a
/// report rather than throwing does not stop the node runner. The real driver
/// does stop: `VenmoBrowser::pay` calls `execute`, `execute` judges the report
/// in Rust and returns `Err`, and the `for` loop over the steps returns. Until
/// this existed the tests only ever noticed a refusal that threw *inside* the
/// JavaScript, so `RequireNoOpenSheet` refusing a page proved nothing about
/// whether a money button afterwards was pressed -- and in the sequence it
/// was. A test that wants to claim no money moved has to ask this question.
fn refused(step: &PaymentStep, result: &StepResult) -> bool {
    if !result.ok {
        return true;
    }
    match step {
        // Judged in Rust off a report: `ok: false` is a refusal.
        PaymentStep::RequireNoOpenSheet
        | PaymentStep::RequireSendConfirmed { .. }
        | PaymentStep::WaitForConfirm { .. } => {
            result.value.get("ok") == Some(&serde_json::json!(false))
        }
        // The recipient check answers the payees and `page_pays_only` judges
        // them. Anything but exactly our payee stops the run.
        PaymentStep::RequireRecipient { payee_id, .. } => {
            let payees = result.value.get("payees").and_then(|v| v.as_array());
            match payees {
                Some(list) => {
                    list.len() != 1
                        || list[0].get("id").and_then(|v| v.as_str()) != Some(payee_id.as_str())
                }
                None => true,
            }
        }
        // The amount is compared in Rust against what the field answered.
        PaymentStep::RequireAmount { expected, .. } => {
            result.value.as_str().map(|v| v != expected).unwrap_or(true)
        }
        _ => false,
    }
}

/// The first step the driver would have stopped at, if any.
fn first_refusal(steps: &[PaymentStep], results: &[StepResult]) -> Option<usize> {
    steps.iter().zip(results).position(|(s, r)| refused(s, r))
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
/// posts on click it pays the previous drive's recipient.
///
/// The note used to be what told them apart, and that binding is gone: since
/// `carriesNote` reads the note field, and this run's own fill put the note
/// there, the note no longer discriminates. What refuses this page is
/// `RequireNoOpenSheet`, which is temporal and does not care what the sheet
/// says: the sheet existed before our click, so it is not ours. That is the
/// stronger guard and it sits before every money button.
///
/// This test was passing for the wrong reason until 2026-09-07. It asked for
/// the first result with `ok == false`, which only sees a refusal thrown from
/// inside the JavaScript, and `RequireNoOpenSheet` answers a report instead.
/// So the refusal it was reading was the note check inside `ConfirmNamedAmount`
/// -- two steps and one money click later. In the sequence the bare "Pay"
/// click had already run. `first_refusal` asks the question the driver asks.
#[test]
fn a_stale_sheet_for_another_payee_is_refused_before_the_click() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("otherpayeesheet", &expressions(&steps));

    let stopped = first_refusal(&steps, &results).expect("some step must refuse this page");

    // No money button runs. Not "the amount-naming one does not" -- none of
    // them, including the bare "Pay" that opens a sheet, because on this page
    // a sheet is already open and opening another is not what we want either.
    assert!(
        steps[..stopped].iter().all(|s| !s.is_irreversible()),
        "step {stopped} ({}) refused, but a money step ran before it",
        steps[stopped].describe()
    );

    // And it refuses for the right reason: a sheet this drive did not open.
    assert!(
        matches!(steps[stopped], PaymentStep::RequireNoOpenSheet),
        "the refusal should be the open-sheet check, got step {stopped} ({})",
        steps[stopped].describe()
    );
    let sheets = results[stopped]
        .value
        .get("sheets")
        .and_then(|v| v.as_array())
        .expect("the report names the sheets it found");
    assert_eq!(
        sheets,
        &vec![serde_json::json!("Pay Someone Else $2.01")],
        "the refusal must name the other payee's sheet"
    );
}

/// The 2026-09-07 failure: a correctly filled form the driver refused to pay.
///
/// Order `esc_5276115f1f0173f248dfacc2`, $1.50, mainnet. The escrow funded
/// 142,565 zat and reached 10 confirmations, the coordinator entered `paying`,
/// and the fiat leg then sat for 120s and gave up with "waited 120s for a
/// confirmation button naming $1.50 and it never appeared". The tab, read over
/// CDP while it was stuck, had the amount field on "1.50", the note textarea on
/// "thanks c67ce0b7", the payee resolved to Jay-Butera, and an enabled button
/// reading exactly "Pay Jay Butera $1.50". Nothing was missing. No dollars left
/// the account.
///
/// `carriesNote` tested `document.body.innerText` for the note, and a
/// `<textarea>`'s value is not in `innerText`. The note half of the predicate
/// could not pass on any correctly filled form, so the click never happened.
/// Five consecutive live runs failed on this leg with the suite green, because
/// every fixture rendered the note as a `<div>` beside the field and no test
/// drove a page shaped like the real one.
///
/// This is that page: the note is in the textarea and nowhere else. The drive
/// must click, and it must report the payment posted.
#[test]
fn a_note_that_lives_only_in_the_field_is_still_paid() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("noteonlyinfield", &expressions(&steps));

    // A thrown refusal stops the node runner, so a short result list is itself
    // the failure: name the step that threw rather than comparing lengths.
    if results.len() != steps.len() {
        let at = results.len() - 1;
        panic!(
            "the drive stopped at step {at} ({}) on a correctly filled form: {}. \
             The form was right -- amount typed, note typed, payee resolved -- so \
             every step had to pass and one refused.",
            steps[at].describe(),
            results[at].error.clone().unwrap_or_default()
        );
    }
    if let Some(stopped) = first_refusal(&steps, &results) {
        panic!(
            "step {stopped} ({}) refused a correctly filled form: {:?} {}",
            steps[stopped].describe(),
            results[stopped].error,
            results[stopped].value
        );
    }

    // The confirmation wait is the step that failed live. It has to pass here,
    // and its report has to say the note was found rather than passing for
    // some other reason.
    let waited = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::WaitForConfirm { .. }))
        .expect("the sequence must wait for the confirmation");
    assert_eq!(
        results[waited].value.get("note"),
        Some(&serde_json::json!(true)),
        "the note is in the textarea, so the note half must be satisfied: {}",
        results[waited].value
    );

    // The money button was actually pressed, and it was the right one.
    let clicked = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::ConfirmNamedAmount { .. }))
        .expect("the sequence must carry the amount-naming click");
    assert_eq!(
        results[clicked].value,
        serde_json::json!("Pay Jay Butera $2.01"),
        "the drive must click the confirmation naming this payment"
    );

    assert!(
        confirmed(results.last().expect("the confirmation")),
        "the form went away, so the payment posted: {}",
        results.last().unwrap().value
    );
}

/// The note predicate is satisfiable on a page that renders no note at all.
///
/// Stated as its own test rather than left implicit in the payment above,
/// because this is the property whose absence cost five live runs: a predicate
/// that guards a money click has to be able to answer yes. A guard that cannot
/// pass is not a strict guard, it is an outage.
#[test]
fn the_note_check_can_pass_when_the_note_is_only_in_the_textarea() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("noteonlyinfield", &expressions(&steps));
    let waited = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::WaitForConfirm { .. }))
        .expect("a confirmation wait");
    let report = &results[waited].value;

    // Every half, named. A bare `ok` would not distinguish this from a page
    // where the note happened to be rendered somewhere.
    for half in ["ok", "note", "named", "enabled"] {
        assert_eq!(
            report.get(half),
            Some(&serde_json::json!(true)),
            "the {half} half of the confirmation wait must be satisfied: {report}"
        );
    }
}

/// No money-gating predicate reads a form control's value out of rendered text.
///
/// The class of bug, stated once so a new step inherits the rule rather than
/// rediscovering it. A predicate that searches `document.body.innerText` for a
/// string that only ever lives in an `<input>` or `<textarea>` value cannot pass
/// on a correct page: `innerText` is rendered content and a form control's value
/// is not content. That is unsatisfiable, and an unsatisfiable guard in front of
/// a money click is an outage, not caution.
///
/// The two things the payment steps look for are the amount and the note. Both
/// live in fields. So: whatever reads the amount must read a field, and whatever
/// reads the note must at least be able to read a field.
#[test]
fn every_field_backed_check_reads_a_field() {
    let steps = the_incident_payment();

    for step in &steps {
        let js = step.expression_for_test();
        match step {
            // The amount readback exists precisely because a React input can
            // hold a value the script never set. It has to read `.value`.
            PaymentStep::RequireAmount { .. } => {
                assert!(
                    js.contains(".value"),
                    "the amount readback must read the field's value, got {js}"
                );
                assert!(
                    !js.contains("innerText"),
                    "the amount is not rendered text; reading it there is the \
                     unsatisfiable-predicate bug, got {js}"
                );
            }
            // The note check may prefer rendered text, and must not stop there:
            // on the live page the note is in the textarea and nowhere else.
            PaymentStep::WaitForConfirm { .. } | PaymentStep::ConfirmNamedAmount { .. } => {
                assert!(
                    js.contains("carriesNote"),
                    "the confirmation steps gate on the note, got {js}"
                );
                assert!(
                    js.contains("f.value") || js.contains(".value"),
                    "the note check must be able to read the field, or it cannot \
                     pass on a correctly filled form: {js}"
                );
            }
            _ => {}
        }
    }
}

/// An unhandled confirmation input on the page is reported, not ignored.
///
/// The 2026-09-07 CDP read of the stuck tab found an empty
/// `<input name="pwu-confirm-last-four" type="number">` next to the form.
/// Nothing in any crate touches it: no step fills it, no check reads it, and no
/// earlier inspection of the live page recorded it existing.
///
/// **Whether it gates the confirm click is unknown and this test does not
/// claim otherwise.** On that run the click never happened, because the note
/// predicate refused first, so Venmo was never asked what it would do with an
/// empty field. Only a live run that reaches the click can settle it.
///
/// What can be settled from code is that the driver stops being silent about
/// it. If a future confirmation wait does time out, the operator is told the
/// page carries an input this driver never fills in, instead of being sent to
/// look for a button that is on screen.
#[test]
fn an_unhandled_confirmation_input_is_named_in_the_report() {
    if !node_available() {
        return;
    }
    let steps = the_incident_payment();
    let results = run_sequence("stepupconfirm", &expressions(&steps));
    let waited = steps
        .iter()
        .position(|s| matches!(s, PaymentStep::WaitForConfirm { .. }))
        .expect("a confirmation wait");
    let report = &results[waited].value;

    assert_eq!(
        report.get("stepUp"),
        Some(&serde_json::json!(["pwu-confirm-last-four"])),
        "the report must name the input no step in this driver fills in: {report}"
    );

    // And noticing it does not become a refusal. The driver has no evidence
    // the field is required, and refusing on a page that would have paid is
    // the failure this whole change is about.
    assert_eq!(
        report.get("ok"),
        Some(&serde_json::json!(true)),
        "an input of unknown purpose must not block a payment: {report}"
    );
    assert!(
        confirmed(results.last().expect("the confirmation")),
        "this page still sends on confirm: {}",
        results.last().unwrap().value
    );
}

/// A fixture cannot give a form control rendered text.
///
/// The mock's `document.body.innerText` used to be a plain join of every
/// element's `innerText`, and the fixtures happened to agree with a browser
/// only because `Fill` writes `.value` and never `.innerText`. That accident is
/// what let every fixture render the note beside the field while the live page
/// kept it in the field alone, and it is why five live runs failed green.
///
/// The getter now refuses a form control carrying text, so the agreement is a
/// rule rather than a coincidence. This test is what proves the rule is armed:
/// without it, a later fixture could quietly restore the unfaithful model.
#[test]
fn the_mock_refuses_to_render_text_inside_a_form_control() {
    if !node_available() {
        return;
    }
    // `unfaithfulnote` puts the note on the textarea's `innerText`, which no
    // browser does. Reading `document.body.innerText` must throw.
    let results = run_sequence("unfaithfulnote", &["document.body.innerText".to_string()]);
    assert!(
        !results[0].ok,
        "a textarea with innerText models a page that cannot exist, so reading \
         the body must refuse: {:?}",
        results[0].value
    );
    let why = results[0].error.clone().unwrap_or_default();
    assert!(
        why.contains("TEXTAREA") && why.contains("form control"),
        "the refusal must say what is wrong with the fixture, got {why:?}"
    );
}

/// The confirmation wait says which half refused, not just that it refused.
///
/// The live message was "waited 120s for a confirmation button naming $1.50 and
/// it never appeared". The button was there and enabled for the whole 120s.
/// The operator read the message and looked for a missing button, which is the
/// diagnostic cost of a three-part predicate that answers one bool.
///
/// `stalepay` reproduces the live shape exactly: an enabled "Pay Jay Butera
/// $2.01" button on the page, and a note this drive never typed. The report has
/// to say the button is there and the note is not.
#[test]
fn the_confirmation_wait_names_the_half_that_refused() {
    if !node_available() {
        return;
    }
    let wait = PaymentStep::WaitForConfirm {
        amount: "2.01".to_string(),
        note: "a note this page has never held".to_string(),
    };
    let results = run_sequence("stalepay", &[wait.expression_for_test()]);
    let report = &results[0].value;

    assert_eq!(
        report.get("ok"),
        Some(&serde_json::json!(false)),
        "a note the page does not carry must refuse: {report}"
    );
    assert_eq!(
        report.get("note"),
        Some(&serde_json::json!(false)),
        "the note is the half that failed: {report}"
    );
    // The half the old message blamed. The button is on the page and enabled,
    // so a timeout here must not say it never appeared.
    assert_eq!(
        report.get("named"),
        Some(&serde_json::json!(true)),
        "the button naming the amount is on this page: {report}"
    );
    assert_eq!(
        report.get("enabled"),
        Some(&serde_json::json!(true)),
        "and it is enabled, which is what made the live message wrong: {report}"
    );
}

// ===========================================================================
// The recipient check, rebuilt 2026-09-06.
//
// The old check scraped every `@handle` out of `document.body.innerText` and
// required one to equal the payee. The live pay page renders the recipient
// only as a display name under "To", and the sole `@handle` on it is the
// logged-in account's own, from the chrome at the top of every page. So the
// set it searched never held the recipient and always held the sender: every
// legitimate payment failed closed, and a payment to the LP's own account was
// the one case that would have passed.
//
// It now reads `__NEXT_DATA__.props.pageProps.txnUserDetails`, the page's own
// state for the form, and requires exactly one payee carrying the numeric id
// `VenmoBrowser::resolve_payee` got from `GET /api/user/<handle>`. The
// fixtures below are the page states that endpoint and the live pay page
// actually produced on 2026-09-06; the ids are Venmo's real ones.
// ===========================================================================

/// Venmo's id for `jay-butera`, from the live per-user read.
const JAY_BUTERA_ID: &str = "2041148646359040020";

/// Whether the driver would accept this page as a payment to this account.
///
/// Runs the real expression against the page and hands the answer to the real
/// comparison, `venmo::page_pays_only`. Nothing here re-implements the check:
/// the 2026-09-05 false success was a sequence whose every expression was
/// correct and whose result was still wrong, and a test that mirrors the logic
/// instead of calling it cannot catch that.
fn page_pays(page: &str, payee_id: &str) -> Result<(), String> {
    let step = PaymentStep::RequireRecipient {
        recipient: "jay-butera".to_string(),
        payee_id: payee_id.to_string(),
    };
    let results = run_sequence(page, &[step.expression_for_test()]);
    assert!(
        results[0].ok,
        "the recipient check must answer rather than throw, got {:?}",
        results[0].error
    );
    zecp2p_taker::venmo::page_pays_only(&results[0].value, payee_id)
}

/// The ordinary case still passes.
///
/// This is the payment that was blocked on 2026-09-06 with the escrow funded:
/// a correct form for the right payee that the old check could not read.
#[test]
fn the_payee_the_page_is_addressed_to_is_accepted() {
    if !node_available() {
        return;
    }
    assert_eq!(
        page_pays("cleanpay", JAY_BUTERA_ID),
        Ok(()),
        "the live pay form for @jay-butera must pass"
    );
}

/// Item 4: the recipient check reads the page, not the URL we just wrote.
///
/// `RequireRecipient` used to fold `location.href` into its haystack, so it
/// confirmed the address `Navigate` had assigned one step earlier rather than
/// anything the document carried.
///
/// Measured again on the live page 2026-09-06 and the reason is sharper than
/// it was: a `pushState` to a different handle moved the URL while the page
/// state and the rendered "To" field both stayed on the original payee. The
/// URL is the half that can lie about who a loaded form pays.
#[test]
fn the_recipient_check_does_not_read_the_url_we_navigated_to() {
    if !node_available() {
        return;
    }
    let refusal = page_pays("wrongpayeeform", JAY_BUTERA_ID)
        .expect_err("a form for Jordan Bryant at our payee's URL must be refused");
    assert!(
        refusal.contains("2261773692436480899"),
        "the refusal must name who the page would have paid, got {refusal:?}"
    );
}

/// The self-payment hole, closed.
///
/// The old check's only passing case. `@Jay-Butera-2` is the logged-in
/// account, its handle is on every page, so "does the page name our payee"
/// reduced to "am I paying myself?" and answered yes for exactly the recipient
/// it should refuse.
///
/// Venmo's own answer helps: it will not let an account pay itself, so the
/// form comes back with no payee. Either way this refuses, and it must refuse
/// whichever id it is asked about.
#[test]
fn a_form_for_our_own_account_is_refused() {
    if !node_available() {
        return;
    }
    assert!(
        page_pays("selfpayment", JAY_BUTERA_ID).is_err(),
        "a form that pays nobody is not a form that pays our payee"
    );
    // And asked about the LP's own id, which is the id the old check was in
    // effect matching on, it still refuses.
    assert!(
        page_pays("selfpayment", "4676038579717835818").is_err(),
        "the sender's own handle being on the page is not a payee"
    );
}

/// A handle Venmo cannot resolve gets a pay form and no payee.
///
/// The form renders, so `WaitFor` on the amount field passes and the run
/// carries on to this step. There is nothing to match, and a check with no
/// input must refuse rather than shrug.
#[test]
fn a_form_for_an_unresolvable_handle_is_refused() {
    if !node_available() {
        return;
    }
    let refusal = page_pays("unresolvedpayee", JAY_BUTERA_ID)
        .expect_err("a form naming no payee must be refused");
    assert!(
        refusal.contains("no payee"),
        "the refusal must say the page named nobody, got {refusal:?}"
    );
}

/// One hyphen away is a different person.
///
/// `jaybutera` resolves to `JayButera` -- Joseph Butera, id
/// 3457650285086115910 -- on the live session. The pay page for him is
/// well-formed and renders "Joseph Butera" under "To". Nothing about the page
/// distinguishes it from the right one except the id.
#[test]
fn a_near_miss_handle_is_a_different_account() {
    if !node_available() {
        return;
    }
    let refusal =
        page_pays("nearmisspayee", JAY_BUTERA_ID).expect_err("@JayButera is not @Jay-Butera");
    assert!(
        refusal.contains("3457650285086115910"),
        "the refusal must name the id the page carries, got {refusal:?}"
    );
}

/// Our payee plus a stranger is not our payee.
///
/// Venmo's pay form takes several recipients and splits the amount among them.
/// A check asking "is ours on the page" answers yes here and sends half the
/// money to an account the order never named.
#[test]
fn a_form_that_also_pays_someone_else_is_refused() {
    if !node_available() {
        return;
    }
    let refusal = page_pays("splitpayee", JAY_BUTERA_ID)
        .expect_err("a split payment is not the payment this order authorised");
    assert!(
        refusal.contains("2261773692436480899"),
        "the refusal must name the extra payee, got {refusal:?}"
    );
}

/// The state this reads is not a documented API, so its absence is a refusal.
///
/// `__NEXT_DATA__` is Venmo's build detail and it can disappear. When it does,
/// there is no weaker reading of the page to fall back to: the display name
/// under "To" is not a resolution and the only handle rendered is the
/// sender's. Falling back to either is how the guard got into this state.
#[test]
fn a_page_that_cannot_say_who_it_pays_is_refused() {
    if !node_available() {
        return;
    }
    for page in ["nopagestate", "brokenpagestate", "nopayeekey"] {
        let refusal = page_pays(page, JAY_BUTERA_ID)
            .expect_err(&format!("{page} must be refused, not accepted"));
        assert!(
            refusal.contains("cannot say who it pays"),
            "{page} must refuse for the reason it actually has, got {refusal:?}"
        );
    }
}

/// Case is presentation, not identity.
///
/// Venmo echoes a handle in whatever case its owner set; the string we pay
/// comes from the curator. A payment must not turn on that difference, or the
/// rail fails closed on every order for a payee who capitalised their name.
/// The id is what is compared, so the case never enters into it.
#[test]
fn a_handle_in_another_case_is_still_ours() {
    if !node_available() {
        return;
    }
    assert_eq!(
        page_pays("mixedcase", JAY_BUTERA_ID),
        Ok(()),
        "@JAY-BUTERA is the same account as @jay-butera"
    );
}

/// The check no longer has any way to be satisfied by the account chrome.
///
/// The failure was not that the old comparison was too loose; it was that its
/// *input* was the wrong part of the page. Every pay page carries the LP's own
/// handle, so any check reading `document.body.innerText` is reading a string
/// that is present whoever is being paid. This pins the expression away from
/// it: a future edit that reaches for the body text again fails here rather
/// than in production with an escrow funded.
#[test]
fn the_recipient_check_does_not_read_the_rendered_page_text() {
    let js = PaymentStep::RequireRecipient {
        recipient: "jay-butera".to_string(),
        payee_id: JAY_BUTERA_ID.to_string(),
    }
    .expression_for_test();

    assert!(
        !js.contains("innerText"),
        "the pay page renders no recipient handle; reading its text is what broke \
         this check: {js}"
    );
    assert!(
        !js.contains("location.href") || js.contains("url: location.href"),
        "the URL may be reported for the operator, never matched on: {js}"
    );
    assert!(
        js.contains("txnUserDetails"),
        "the recipient must come from the page's own payee state: {js}"
    );
}

/// Display names are not a resolution, and nothing may compare them.
///
/// Casper's requirement, pinned: the pay page shows "Jay Butera" and that is
/// not evidence about which account gets the money. Two people share a name;
/// `casper` and `jay-butera` both render initials "JB". The display name is
/// carried for the operator's log and never compared.
#[test]
fn no_step_resolves_a_payee_by_display_name() {
    let steps = the_incident_payment();
    for step in &steps {
        let js = step.expression_for_test();
        assert!(
            !js.contains("displayName") || step_is_recipient_check(step),
            "only the recipient check may even read a display name: {js}"
        );
    }
    // And the recipient check reads it to report it, not to decide. The
    // comparison is over ids: a page carrying the right name and the wrong id
    // is refused.
    if node_available() {
        assert!(
            page_pays("nearmisspayee", JAY_BUTERA_ID).is_err(),
            "\"Joseph Butera\" renders as plausibly as \"Jay Butera\" and is not him"
        );
    }
}

fn step_is_recipient_check(step: &PaymentStep) -> bool {
    matches!(step, PaymentStep::RequireRecipient { .. })
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

/// The refusals and the pass, against what the live page actually answered.
///
/// The fixtures above model the pay page; this is the pay page. Each value
/// below is the verbatim output of the real `RequireRecipient` expression run
/// in the LP's own logged-in Chrome on 2026-09-06, one navigation per handle,
/// captured over CDP. The comparison they are fed is the same
/// `page_pays_only` that decides a live payment.
///
/// A mock can be wrong about Venmo in a way no assertion catches -- the
/// round-2 review found exactly that, a test proving the mock rather than the
/// page. These five rows cannot be, because nothing in this repository
/// produced them.
#[test]
fn the_live_pages_answer_the_way_the_fixtures_do() {
    // The id `GET /api/user/jay-butera` answered in the same session.
    let resolved = JAY_BUTERA_ID;

    let live = |json: &str| -> Result<(), String> {
        zecp2p_taker::venmo::page_pays_only(
            &serde_json::from_str::<serde_json::Value>(json).expect("recorded answer"),
            resolved,
        )
    };

    // ?recipients=jay-butera -- the order that was blocked with the escrow
    // funded. It passes.
    assert_eq!(
        live(
            r#"{"found":true,"why":"","url":"https://account.venmo.com/pay?recipients=jay-butera",
                "payees":[{"id":"2041148646359040020","username":"Jay-Butera",
                           "displayName":"Jay Butera"}]}"#
        ),
        Ok(())
    );

    // ?recipients=casper -- an allowlisted handle that is not the operator.
    // Venmo resolves it to Jordan Bryant, a stranger.
    assert!(live(
        r#"{"found":true,"why":"","url":"https://account.venmo.com/pay?recipients=casper",
            "payees":[{"id":"2261773692436480899","username":"casper",
                       "displayName":"Jordan Bryant"}]}"#
    )
    .is_err());

    // ?recipients=jaybutera -- one hyphen out, a different real person.
    assert!(live(
        r#"{"found":true,"why":"","url":"https://account.venmo.com/pay?recipients=jaybutera",
            "payees":[{"id":"3457650285086115910","username":"JayButera",
                       "displayName":"Joseph Butera"}]}"#
    )
    .is_err());

    // ?recipients=zz-no-such-handle-91731 -- a pay form renders, with no payee.
    assert!(live(
        r#"{"found":true,"why":"",
            "url":"https://account.venmo.com/pay?recipients=zz-no-such-handle-91731",
            "payees":[]}"#
    )
    .is_err());

    // ?recipients=Jay-Butera-2 -- the LP's own account, and the only page the
    // old check ever passed. Venmo will not pay you yourself, so there is no
    // payee to match.
    assert!(live(
        r#"{"found":true,"why":"","url":"https://account.venmo.com/pay?recipients=Jay-Butera-2",
            "payees":[]}"#
    )
    .is_err());
}
