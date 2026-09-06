//! `VenmoBrowser::pay` driven end to end against a fake CDP endpoint.
//!
//! `payment_page_test.rs` executes the generated JavaScript and inspects its
//! answers. That covers the predicates and covers none of the Rust that decides
//! what an answer *means*. The review made the gap concrete: deleting the
//! `RequireSendConfirmed` arm from `execute`, so the step fell into the old
//! `other =>` catch-all that evaluated the expression and discarded the result,
//! compiled without a warning and left every test green. The check ran, its
//! `false` was thrown away, and `pay` returned `Sent` -- the incident, back
//! again, with nothing red to show for it.
//!
//! So these tests drive the real `pay` against a fake `/json/list` and a fake
//! debugger socket, and assert on what `pay` returns rather than on what the
//! page said. A confirmation answering "not posted" must produce `Unconfirmed`
//! and never `Sent`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use zecp2p_taker::venmo::{NothingWasSent, PaymentRequest, SendMode, Unconfirmed, VenmoBrowser};

/// How the fake page answers the confirmation step.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirmation {
    /// The whole form went away: the payment posted.
    Posted,
    /// The confirmation sheet is still standing: nothing was sent.
    SheetStillUp,
    /// A sheet was already open before the drive clicked anything.
    SheetOpenBeforeWeClicked,
    /// The pay page loads a valid form for a different account: Jordan
    /// Bryant, who is who `?recipients=casper` resolves to on the live site.
    WrongPayeeOnThePage,
    /// The per-user read refuses: Venmo answers 500 for a handle nobody owns.
    /// The payment must stop here, before anything is navigated to.
    PayeeDoesNotResolve,
    /// The per-user read succeeds and answers a *different* canonical handle,
    /// which is what `jaybutera` -> `JayButera` does on the live site.
    PayeeResolvesToSomeoneElse,
}

/// A fake browser: an HTTP `/json/list` and a websocket that answers
/// `Runtime.evaluate` with whatever the scripted page would say.
///
/// Deliberately answers by *inspecting the expression it is given* rather than
/// by counting calls, so it cannot drift out of step with the real sequence
/// when a step is added or reordered.
struct FakeBrowser {
    addr: SocketAddr,
    /// Every expression the driver evaluated, in order.
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeBrowser {
    async fn start(confirmation: Confirmation) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_task = Arc::clone(&seen);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen_for_task);
                tokio::spawn(async move {
                    let _ = serve(stream, confirmation, seen).await;
                });
            }
        });

        FakeBrowser { addr, seen }
    }

    fn cdp_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn evaluated(&self) -> Vec<String> {
        self.seen.lock().expect("lock").clone()
    }
}

/// One connection: either the `/json/list` GET or the debugger websocket.
async fn serve(
    stream: tokio::net::TcpStream,
    confirmation: Confirmation,
    seen: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::{AsyncWriteExt, BufReader};

    let local = stream.local_addr()?;
    let mut reader = BufReader::new(stream);

    // Peek the request head without consuming the bytes the websocket
    // handshake still needs. `accept_hdr_async` re-reads them from the same
    // stream, so the head is read through the buffered reader and the reader
    // itself is handed on.
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let done = line == "\r\n" || line == "\n";
        head.push_str(&line);
        if done {
            break;
        }
    }

    // The websocket upgrade is the payment path; a plain GET is the listing.
    if head.to_ascii_lowercase().contains("upgrade: websocket") {
        let key = head
            .lines()
            .find_map(|l| {
                l.strip_prefix("Sec-WebSocket-Key: ")
                    .or_else(|| l.strip_prefix("sec-websocket-key: "))
            })
            .unwrap_or_default()
            .trim()
            .to_string();
        let accept = ws_accept(&key);
        let mut stream = reader.into_inner();
        let handshake = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(handshake.as_bytes()).await?;
        stream.flush().await?;

        let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        while let Some(Ok(message)) = socket.next().await {
            let Message::Text(text) = message else {
                continue;
            };
            let request: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let expression = request
                .get("params")
                .and_then(|p| p.get("expression"))
                .and_then(|e| e.as_str())
                .unwrap_or_default()
                .to_string();
            seen.lock().expect("lock").push(expression.clone());

            let value = answer_for(&expression, confirmation);
            let reply = serde_json::json!({
                "id": request.get("id").cloned().unwrap_or(serde_json::json!(1)),
                "result": { "result": { "value": value } }
            });
            if socket
                .send(Message::Text(reply.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
        return Ok(());
    }

    let tab = serde_json::json!([{
        "id": "TAB",
        "type": "page",
        "url": "https://account.venmo.com/pay?recipients=jay-butera",
        "webSocketDebuggerUrl": format!("ws://{local}/devtools/page/TAB"),
    }]);
    let body = tab.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let mut stream = reader.into_inner();
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// The `Sec-WebSocket-Accept` value for a handshake key, per RFC 6455.
fn ws_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64_encode(&hasher.finalize())
}

/// Minimal standard base64, so the fake needs no extra dependency.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// What the fake page answers for one expression.
///
/// Matched on the shape of the generated JavaScript. Every step before the
/// confirmation answers the way a healthy page would, so the only variable
/// under test is the confirmation itself.
fn answer_for(expression: &str, confirmation: Confirmation) -> serde_json::Value {
    // The confirmation report. Ordered first because it also mentions buttons.
    if expression.contains("signedOut") {
        return match confirmation {
            Confirmation::Posted => serde_json::json!({
                "ok": true, "sheet": false, "form": false,
                "payBtn": false, "signedOut": false,
                "url": "https://account.venmo.com/"
            }),
            Confirmation::SheetStillUp => serde_json::json!({
                "ok": false, "sheet": true, "form": true,
                "payBtn": true, "signedOut": false,
                "url": "https://account.venmo.com/pay?recipients=jay-butera"
            }),
            // Unreachable in practice: this mode refuses at the open-sheet
            // check, long before anything is clicked. Answered rather than
            // `todo!()`ed so a future step reordering surfaces as a failed
            // assertion instead of a panic in the fake.
            // Unreachable: these three refuse at the lookup or the recipient
            // check, long before anything is clicked. Answered rather than
            // `todo!()`ed so a reordering surfaces as a failed assertion, not
            // a panic in the fake.
            Confirmation::WrongPayeeOnThePage
            | Confirmation::PayeeDoesNotResolve
            | Confirmation::PayeeResolvesToSomeoneElse => serde_json::json!({
                "ok": false, "sheet": true, "form": true,
                "payBtn": true, "signedOut": false,
                "url": "https://account.venmo.com/pay?recipients=jay-butera"
            }),
            Confirmation::SheetOpenBeforeWeClicked => serde_json::json!({
                "ok": false, "sheet": true, "form": true,
                "payBtn": true, "signedOut": false,
                "url": "https://account.venmo.com/pay?recipients=jay-butera"
            }),
        };
    }
    // The open-sheet check: a healthy page has no confirmation open when the
    // drive starts, which is the state every honest payment begins from.
    if expression.contains("sheets:") {
        return match confirmation {
            Confirmation::SheetOpenBeforeWeClicked => serde_json::json!({
                "ok": false, "sheets": ["Pay Someone Else $9.99"]
            }),
            _ => serde_json::json!({ "ok": true, "sheets": [] }),
        };
    }
    // The per-user read, which is the first thing `pay` does and the reason
    // there is a payee id to check the page against at all. Matched on the
    // endpoint rather than on a fragment of the wrapper, so a rewrite of the
    // surrounding JavaScript does not silently stop being answered.
    if expression.contains("/api/user/") {
        return match confirmation {
            // What Venmo answers for a handle nobody owns: 500, and a body
            // that is not JSON.
            Confirmation::PayeeDoesNotResolve => serde_json::json!({
                "ok": false, "status": 500, "body": "Something went wrong"
            }),
            // What it answers for `jaybutera`: a real account, a different
            // person, under a canonical handle that is not the one we asked
            // for.
            Confirmation::PayeeResolvesToSomeoneElse => serde_json::json!({
                "ok": true, "id": "3457650285086115910", "username": "JayButera",
                "displayName": "Joseph Butera", "isActive": true
            }),
            _ => serde_json::json!({
                "ok": true, "id": JAY_BUTERA_ID, "username": "Jay-Butera",
                "displayName": "Jay Butera", "isActive": true
            }),
        };
    }
    // The recipient check answers the payees the page's own state carries.
    // A healthy pay form is addressed to the account the lookup resolved.
    if expression.contains("txnUserDetails") {
        return match confirmation {
            Confirmation::WrongPayeeOnThePage => serde_json::json!({
                "found": true, "why": "",
                "url": "https://account.venmo.com/pay?recipients=jay-butera",
                "payees": [{"id": "2261773692436480899", "username": "casper",
                            "displayName": "Jordan Bryant"}]
            }),
            _ => serde_json::json!({
                "found": true, "why": "",
                "url": "https://account.venmo.com/pay?recipients=jay-butera",
                "payees": [{"id": JAY_BUTERA_ID, "username": "Jay-Butera",
                            "displayName": "Jay Butera"}]
            }),
        };
    }
    // The amount readback answers the field's string.
    if expression.contains("the amount field is gone") {
        return serde_json::json!("2.01");
    }
    // The audience readback answers the control's label.
    if expression.contains("audience") || expression.contains("Private") {
        return serde_json::json!("Private");
    }
    // Presence polls and the confirmation wait answer a bool.
    if expression.contains("!== null") || expression.contains("!!el") {
        return serde_json::json!(true);
    }
    // The clicks answer their label.
    if expression.contains(".click()") {
        return serde_json::json!("Pay Jay Butera $2.01");
    }
    serde_json::json!(true)
}

/// Venmo's real id for `jay-butera`, from the live per-user read on
/// 2026-09-06. The fake answers it from the lookup and carries it on the pay
/// page, so the two halves of the check agree exactly as they do in
/// production.
const JAY_BUTERA_ID: &str = "2041148646359040020";

fn request() -> PaymentRequest {
    PaymentRequest {
        recipient: "jay-butera".to_string(),
        amount: "2.01".to_string(),
        note: "thanks 5df45b72".to_string(),
    }
}

/// The regression the review found, closed.
///
/// The page says the confirmation sheet is still up, which means the click did
/// nothing. `pay` must not return `Sent`.
#[tokio::test]
async fn a_confirmation_that_says_not_posted_never_returns_sent() {
    let fake = FakeBrowser::start(Confirmation::SheetStillUp).await;
    // One second of timeout: the confirmation poll runs to its deadline here,
    // and the test should not take the production 120 s to find that out.
    let browser = VenmoBrowser::new(fake.cdp_url(), 1);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let result = browser.pay(&tab, &request(), SendMode::Live).await;

    let error = result.expect_err("pay must not report a payment the page never confirmed");
    let unconfirmed = error
        .downcast_ref::<Unconfirmed>()
        .unwrap_or_else(|| panic!("expected Unconfirmed, got: {error:#}"));
    assert_eq!(unconfirmed.amount, "2.01");
    assert_eq!(unconfirmed.recipient, "jay-butera");
    assert!(
        unconfirmed.why.contains("still on the page"),
        "the reason must name what was seen, got {:?}",
        unconfirmed.why
    );

    // And the confirmation was actually asked, rather than the run failing
    // somewhere earlier for an unrelated reason.
    assert!(
        fake.evaluated().iter().any(|e| e.contains("signedOut")),
        "the confirmation step should have run"
    );
}

/// The other direction: a page that confirms the send does return `Sent`.
///
/// Without this the test above passes for a `pay` that never succeeds at all.
#[tokio::test]
async fn a_confirmed_send_returns_sent() {
    let fake = FakeBrowser::start(Confirmation::Posted).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let outcome = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect("a confirmed send is a success");

    match outcome {
        zecp2p_taker::venmo::PaymentOutcome::Sent { recipient, amount } => {
            assert_eq!(recipient, "jay-butera");
            assert_eq!(amount, "2.01");
        }
        other => panic!("expected Sent, got {other:?}"),
    }
}

/// A dry run stops before the first click and never reaches the confirmation.
///
/// It must not report `Sent`, and it must not be turned into `Unconfirmed`
/// either: nothing was attempted, so there is nothing to be unsure about.
#[tokio::test]
async fn a_dry_run_stops_before_the_click_and_is_not_unconfirmed() {
    let fake = FakeBrowser::start(Confirmation::SheetStillUp).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let outcome = browser
        .pay(&tab, &request(), SendMode::DryRun)
        .await
        .expect("a dry run is not an error");

    assert!(matches!(
        outcome,
        zecp2p_taker::venmo::PaymentOutcome::WouldHaveSent { .. }
    ));
    // Not "nothing clicked": `SetAudience` clicks the audience menu, which is
    // reversible and runs before the money line. What must not happen is a
    // click on a *money* button, which is the one that names the amount.
    assert!(
        !fake
            .evaluated()
            .iter()
            .any(|e| e.contains(".click()") && e.contains("2.01")),
        "a dry run must not click a button naming the amount"
    );
}

/// `fiat::pay` reads the outcome, and a dry run never reports the fiat gone.
///
/// The round-2 review's probe M8 changed the production match to map
/// `WouldHaveSent` to `Sent::Live` and every `auto::fiat` test still passed,
/// because the test built a closure that re-implemented the match instead of
/// calling the function. This one calls `fiat::pay`, so that mutation goes
/// red: a dry run drives the page, stops before the first click, and
/// `fiat_left()` must be false.
#[tokio::test]
async fn fiat_pay_reports_no_fiat_left_for_a_dry_run() {
    use alloy::primitives::{B256, U256};
    use zecp2p_taker::auto::{fiat, money::payment_cents, rail::FiatLeg};

    // SheetStillUp, so if the mode were ever ignored the run would click
    // through and fail loudly rather than quietly passing.
    let fake = FakeBrowser::start(Confirmation::SheetStillUp).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);

    let leg = FiatLeg {
        tag: None,
        recipient: "jay-butera".into(),
        payment: payment_cents(
            U256::from(2_010_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            10_000,
        )
        .expect("a payable amount"),
        not_before: chrono::DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
        intent_hash: B256::repeat_byte(0xa3),
        intent_amount_6dec: U256::from(2_010_000u64),
        rate_18dec: U256::from(1_000_000_000_000_000_000u128),
        intent_timestamp_ms: 1_756_000_000_000,
        payee_hash: B256::repeat_byte(0x85),
    };

    let sent = fiat::pay(&browser, &leg, "thanks 5df45b72", SendMode::DryRun)
        .await
        .expect("a dry run is not an error");

    assert!(
        !sent.fiat_left(),
        "a dry run must never report the fiat gone, got {sent:?}"
    );
    assert!(
        matches!(sent, fiat::Sent::DryRun { .. }),
        "a dry run maps to DryRun, got {sent:?}"
    );
    assert!(
        !fake
            .evaluated()
            .iter()
            .any(|e| e.contains(".click()") && e.contains("2.01")),
        "a dry run must not click a button naming the amount"
    );
}

/// And a live run that the page confirms does report the fiat gone.
///
/// Without this the test above is satisfied by a `fiat::pay` that always
/// answers `DryRun`.
#[tokio::test]
async fn fiat_pay_reports_the_fiat_gone_when_the_page_confirms() {
    use alloy::primitives::{B256, U256};
    use zecp2p_taker::auto::{fiat, money::payment_cents, rail::FiatLeg};

    let fake = FakeBrowser::start(Confirmation::Posted).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);

    let leg = FiatLeg {
        tag: None,
        recipient: "jay-butera".into(),
        payment: payment_cents(
            U256::from(2_010_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            10_000,
        )
        .expect("a payable amount"),
        not_before: chrono::DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
        intent_hash: B256::repeat_byte(0xa3),
        intent_amount_6dec: U256::from(2_010_000u64),
        rate_18dec: U256::from(1_000_000_000_000_000_000u128),
        intent_timestamp_ms: 1_756_000_000_000,
        payee_hash: B256::repeat_byte(0x85),
    };

    let sent = fiat::pay(&browser, &leg, "thanks 5df45b72", SendMode::Live)
        .await
        .expect("a confirmed send succeeds");

    assert!(sent.fiat_left(), "a confirmed live send spent money");
}

/// A sheet open before our own click stops the payment, in the driver.
///
/// The page-level tests show the predicate answers `ok: false`; this shows
/// `pay` acts on it. It must be an ordinary refusal and *not* `Unconfirmed`:
/// nothing was clicked, so there is no ambiguity about whether money left, and
/// treating it as unconfirmed would stall the rail and send an operator
/// looking for a payment that was never attempted.
#[tokio::test]
async fn a_sheet_open_before_our_click_refuses_without_ambiguity() {
    let fake = FakeBrowser::start(Confirmation::SheetOpenBeforeWeClicked).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("a pre-existing sheet must stop the payment");

    assert!(
        error.downcast_ref::<Unconfirmed>().is_none(),
        "nothing was clicked, so this is not the ambiguous case: {error:#}"
    );
    let text = format!("{error:#}");
    assert!(text.contains("already open"), "{text}");
    // It names the sheet so the operator knows what to close.
    assert!(text.contains("Pay Someone Else $9.99"), "{text}");

    // And no money button was ever pressed.
    assert!(
        !fake
            .evaluated()
            .iter()
            .any(|e| e.contains(".click()") && e.contains("2.01")),
        "no money button may be clicked when a stale sheet is refused"
    );
}

/// The driver refuses a page whose handle merely starts with ours.
///
/// The page-level test proves the predicate returns the handles; this proves
/// `execute` compares them as whole handles. Reverting that comparison to a
/// substring test makes this red -- without it the production path had no test
/// at all, which is the defect round 2 caught in the `fiat::pay` test.
///
/// `@Jay-Butera-2` is what the round-3 review found on the live account page.
/// Lowercased it contains `jay-butera`, so the old check would have filled in
/// an amount and clicked send on a payment to a different account.
#[tokio::test]
async fn the_driver_refuses_a_form_addressed_to_a_different_account() {
    let fake = FakeBrowser::start(Confirmation::WrongPayeeOnThePage).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("a different account must stop the payment");

    let text = format!("{error:#}");
    // It names who the page would actually have paid, so the operator can see
    // why, and the id rather than the name because the id is what decided.
    assert!(text.contains("2261773692436480899"), "{text}");
    assert!(text.contains("jay-butera"), "{text}");

    // Refused before anything was typed, let alone clicked: the recipient
    // check is the first thing after the form appears.
    assert!(
        !fake.evaluated().iter().any(|e| e.contains(".click()")),
        "nothing may be clicked when the payee does not match"
    );
    assert!(
        !fake.evaluated().iter().any(|e| e.contains("_valueTracker")),
        "no field may be filled when the payee does not match"
    );
}

/// A handle Venmo cannot resolve stops the payment before the browser moves.
///
/// This is the fail-closed half of the fix. `GET /api/user/<handle>` answers
/// 500 for a handle nobody owns, and that is a refusal rather than a reason to
/// open the pay page and look at it: the pay page renders a form for an
/// unresolvable handle too.
#[tokio::test]
async fn a_payee_that_does_not_resolve_stops_before_any_navigation() {
    let fake = FakeBrowser::start(Confirmation::PayeeDoesNotResolve).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("an unresolvable payee must stop the payment");

    let text = format!("{error:#}");
    assert!(text.contains("would not resolve @jay-butera"), "{text}");

    // Nothing was navigated to. The lookup runs before the step list, so the
    // browser never left whatever page it was on.
    assert!(
        !fake
            .evaluated()
            .iter()
            .any(|e| e.contains("location.href =")),
        "a payee that will not resolve must not open a pay page"
    );
    assert!(
        !fake.evaluated().iter().any(|e| e.contains(".click()")),
        "nothing may be clicked"
    );
}

/// A lookup that succeeds for the wrong account is still a refusal.
///
/// `jaybutera` is one hyphen from the payee and resolves to `JayButera`,
/// Joseph Butera, on the live site. A 200 is not the answer -- the canonical
/// username coming back equal to the one being paid is.
#[tokio::test]
async fn a_payee_that_resolves_to_another_account_is_refused() {
    let fake = FakeBrowser::start(Confirmation::PayeeResolvesToSomeoneElse).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("a handle that resolves to someone else must stop the payment");

    let text = format!("{error:#}");
    assert!(text.contains("JayButera"), "{text}");
    assert!(text.contains("Joseph Butera"), "{text}");

    assert!(
        !fake
            .evaluated()
            .iter()
            .any(|e| e.contains("location.href =")),
        "a payee resolving to someone else must not open a pay page"
    );
}

/// Every refusal that happens before the form is filled says so in its type.
///
/// The 2026-09-06 incident, from the coordinator's side. The recipient guard
/// refused `esc_c30ec31ce82148d6b7e3bbd2` one second after the journal's
/// `Paying` line went down, and the caller could not tell that refusal apart
/// from a browser that died mid-click. So it recorded `NeedsOperator`, which
/// held the single payment slot for the ~22 hours until the escrow's refund
/// height - for a payment the guard's own position in the step list proves was
/// never attempted.
///
/// A string match on the error would be a second copy of that reasoning, and
/// the wrong copy the first time somebody rewords a message. The claim is
/// structural instead: `pay` wraps errors only while it has not executed a
/// `Fill`, so the type is the proof.
#[tokio::test]
async fn a_refusal_before_the_form_is_filled_reports_that_nothing_was_sent() {
    for confirmation in [
        Confirmation::WrongPayeeOnThePage,
        Confirmation::PayeeDoesNotResolve,
        Confirmation::PayeeResolvesToSomeoneElse,
    ] {
        let fake = FakeBrowser::start(confirmation).await;
        let browser = VenmoBrowser::new(fake.cdp_url(), 5);
        let tab = browser.find_venmo_tab().await.expect("the fake tab");

        let error = browser
            .pay(&tab, &request(), SendMode::Live)
            .await
            .expect_err("this payee must stop the payment");

        assert!(
            error.downcast_ref::<NothingWasSent>().is_some(),
            "a refusal before the form was filled must be typed as one, so the caller can \
             free the payment slot instead of parking the rail: {error:#}"
        );

        // And the type's claim is true of the page: nothing typed, nothing
        // clicked. Asserted here as well as in the per-case tests, because it
        // is what makes the type honest rather than merely convenient.
        assert!(
            !fake.evaluated().iter().any(|e| e.contains("_valueTracker")),
            "nothing may be filled in"
        );
        assert!(
            !fake.evaluated().iter().any(|e| e.contains(".click()")),
            "nothing may be clicked"
        );
    }
}

/// The other half, and the one that keeps the first honest.
///
/// A failure *after* the form was filled stays ambiguous. `Unconfirmed` is the
/// stale-page case: both clicks went in and the page never showed the payment
/// posting, so the money may or may not have left. If that could come back as
/// `NothingWasSent` the coordinator would free the slot and let the next order
/// pay into an unreconciled feed, which is worse than the stall this change
/// exists to fix.
#[tokio::test]
async fn a_failure_after_the_click_is_never_reported_as_nothing_sent() {
    let fake = FakeBrowser::start(Confirmation::SheetStillUp).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("an unconfirmed send must not report success");

    assert!(
        error.downcast_ref::<Unconfirmed>().is_some(),
        "this is the ambiguous case and must stay ambiguous: {error:#}"
    );
    assert!(
        error.downcast_ref::<NothingWasSent>().is_none(),
        "a failure past the click must never claim no money moved: {error:#}"
    );
}

/// A sheet left open by an earlier drive is refused, and it is refused *after*
/// the form was filled in.
///
/// `RequireNoOpenSheet` sits between the amount readback and the first click,
/// so by then this drive has typed an amount and a note into the page. Nothing
/// has been clicked, but the honest answer is still the ambiguous one: the
/// sheet that is standing there was opened by something, and this run does not
/// know by what. The boundary is the first `Fill` rather than the first click
/// precisely so this case falls on the cautious side.
#[tokio::test]
async fn a_pre_existing_sheet_is_not_reported_as_nothing_sent() {
    let fake = FakeBrowser::start(Confirmation::SheetOpenBeforeWeClicked).await;
    let browser = VenmoBrowser::new(fake.cdp_url(), 5);
    let tab = browser.find_venmo_tab().await.expect("the fake tab");

    let error = browser
        .pay(&tab, &request(), SendMode::Live)
        .await
        .expect_err("a pre-existing sheet must stop the payment");

    assert!(
        error.downcast_ref::<NothingWasSent>().is_none(),
        "the form was already filled in by this drive, so this is not a provable \
         no-payment: {error:#}"
    );
}
