//! Driving an already-open Venmo tab over the Chrome DevTools Protocol.
//!
//! The operator logs into Venmo themselves and leaves the tab open. The agent
//! attaches to that tab over CDP and drives the existing session. It never sees
//! a password, never handles 2FA, and stores no cookies; if the session has
//! expired the agent stops and says so rather than trying to log in.
//!
//! Everything here is gated on [`SendMode`]. In [`SendMode::DryRun`] the agent
//! goes through discovery, staking checks, and page inspection, then stops at
//! the confirm button and reports what it would have sent. The two assertions
//! below run in both modes, so a dry run also says whether the page actually
//! took the amount.
//!
//! Two steps exist purely to be checked, and they are what NEW-3 in the
//! 2026-08-31 re-audit was about. [`PaymentStep::RequireRecipient`] runs before
//! anything is typed, because waiting on the amount field says a payment form is
//! on screen and nothing about whose. [`PaymentStep::RequireAmount`] reads the
//! amount back out of the page immediately before the click, because
//! [`PaymentStep::Fill`] sets a React-controlled input, and until this was
//! fixed it did so in a way React silently discards. Before that the sequence
//! ran Navigate, WaitFor, Fill, Fill, ConfirmSend with nothing read back at all:
//! the money left first and the amount was learned afterwards.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/// Venmo's amount field.
///
/// Read off the live page on 2026-09-02 rather than guessed. The field has no
/// `name` and no `data-testid`; `aria-label="Amount"` is the only stable handle
/// on it. The two selectors this replaced, `input[name='amount']` and
/// `[data-testid='amount-input']`, match nothing on the real page, so every
/// payment timed out waiting for a field that does not exist.
const AMOUNT_SELECTOR: &str = "input[aria-label='Amount']";
/// The note field, by its own id and test id.
///
/// Also corrected against the live page: it is `#payment-note`, not
/// `textarea[name='note']`.
const NOTE_SELECTOR: &str = "#payment-note, [data-testid='payment-note-input']";
/// The button that moves the money, named for the log and the dry run.
///
/// **This one was the dangerous one.** The previous selector ended in
/// `button[type='submit']`, and on the real payment page the first such button
/// is the *Confirm* button of the confirmation step; the page also carries two
/// avatar buttons and a cookie banner that are `type='submit'`. A selector that
/// broad can click a live money button the run never meant to reach.
///
/// The real flow is a "Pay" button that opens a confirmation, then "Confirm".
/// Both are plain MUI buttons with no id, no test id and no aria-label, so they
/// are matched on their exact text inside [`PaymentStep::ConfirmSend`]'s own
/// JavaScript; `:has-text()` is not CSS and `querySelector` cannot express it.
const SEND_SELECTOR: &str = "the \"Pay\" button, then \"Confirm\"";
/// The button that opens the confirmation.
const PAY_BUTTON: &str = "Pay";
/// The prefix of the button on the confirmation that actually sends.
///
/// Venmo labels it with the payee and the amount, e.g. "Pay Jay Butera $1.00",
/// so it cannot be matched by a fixed string. It is matched by this prefix and
/// then checked against the amount, which is stronger than an exact label would
/// have been: the button states what it is about to do and we read it back.
///
/// There is a decoy. The page also carries a button literally labelled
/// "Confirm" which stays disabled and belongs to something else entirely;
/// waiting for that one times out while the real confirmation sits open.
const CONFIRM_PREFIX: &str = "Pay ";

/// Whether this run is allowed to move money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    /// Stop before the irreversible click and report the intended payment.
    DryRun,
    /// Actually send.
    Live,
}

impl SendMode {
    pub fn is_dry_run(self) -> bool {
        matches!(self, SendMode::DryRun)
    }
}

/// A payment the agent intends to make.
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Venmo username without the leading @.
    pub recipient: String,
    /// Dollars and cents, as Venmo's own field expects it ("25.00").
    pub amount: String,
    pub note: String,
}

/// What happened when we tried.
#[derive(Debug, Clone)]
pub enum PaymentOutcome {
    /// Dry run: the page was reached and filled, nothing was sent.
    WouldHaveSent { recipient: String, amount: String },
    /// Live: Venmo accepted the payment.
    Sent { recipient: String, amount: String },
}

#[derive(Debug, Deserialize)]
struct CdpTarget {
    id: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "type", default)]
    target_type: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    ws_url: Option<String>,
}

/// A handle to the operator's logged-in browser.
pub struct VenmoBrowser {
    cdp_url: String,
    http: reqwest::Client,
    timeout: Duration,
}

impl VenmoBrowser {
    pub fn new(cdp_url: impl Into<String>, timeout_seconds: u64) -> Self {
        Self {
            cdp_url: cdp_url.into(),
            http: reqwest::Client::new(),
            timeout: Duration::from_secs(timeout_seconds),
        }
    }

    /// Find the open Venmo tab.
    ///
    /// Fails loudly when there isn't one: the agent is explicitly not allowed
    /// to open a session or log in on the operator's behalf.
    pub async fn find_venmo_tab(&self) -> Result<CdpTab> {
        let targets: Vec<CdpTarget> = self
            .http
            .get(format!("{}/json/list", self.cdp_url))
            .timeout(self.timeout)
            .send()
            .await
            .with_context(|| {
                format!(
                    "no browser answering CDP at {}. Start Chrome with \
                     --remote-debugging-port=9222 and log into Venmo in it.",
                    self.cdp_url
                )
            })?
            .json()
            .await
            .context("CDP endpoint returned something that is not a target list")?;

        let tab = targets
            .into_iter()
            .find(|t| t.target_type == "page" && t.url.contains("venmo.com"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no venmo.com tab open in the browser at {}. \
                     The agent does not log in; open Venmo and sign in first.",
                    self.cdp_url
                )
            })?;

        let ws_url = tab
            .ws_url
            .ok_or_else(|| anyhow::anyhow!("Venmo tab {} exposes no debugger socket", tab.id))?;

        Ok(CdpTab {
            id: tab.id,
            url: tab.url,
            ws_url,
        })
    }

    /// Check that the tab is still a logged-in session.
    ///
    /// Venmo bounces signed-out users to a login URL. Detecting that here turns
    /// an expired cookie into a clear message instead of a hung selector wait.
    ///
    /// The markers live in [`crate::auto::login::SIGNED_OUT_MARKERS`] rather
    /// than here so the payment path and the health check cannot end up
    /// disagreeing about what signed out looks like. Two copies of this list
    /// would drift, and the direction they drift matters: a payment path with
    /// the shorter list carries on into a login page.
    pub fn session_looks_live(tab: &CdpTab) -> bool {
        !crate::auto::login::url_is_signed_out(&tab.url)
    }

    /// Find the Venmo tab, or open one.
    ///
    /// [`Self::find_venmo_tab`] is the payment path's version and deliberately
    /// refuses to create anything: a payment that opened its own tab would be a
    /// payment driving a page nobody had signed into. This is the health
    /// check's version, and it exists because a browser restart leaves no Venmo
    /// tab at all. Without it, that case is indistinguishable from an expiry
    /// and the daemon waits forever for a tab nobody is going to open.
    pub async fn find_or_open_venmo_tab(&self) -> Result<CdpTab> {
        if let Ok(tab) = self.find_venmo_tab().await {
            return Ok(tab);
        }

        // `PUT /json/new?url=` is the CDP call that creates a tab. It answers
        // with the same target shape `/json/list` uses.
        let target: CdpTarget = self
            .http
            .put(format!(
                "{}/json/new?{}",
                self.cdp_url,
                urlencoding_minimal(crate::auto::login::SIGNIN_URL)
            ))
            .timeout(self.timeout)
            .send()
            .await
            .with_context(|| {
                format!(
                    "no browser answering CDP at {} to open a Venmo tab in",
                    self.cdp_url
                )
            })?
            .json()
            .await
            .context("the CDP endpoint would not open a new tab")?;

        let ws_url = target
            .ws_url
            .ok_or_else(|| anyhow::anyhow!("the new tab exposes no debugger socket"))?;

        Ok(CdpTab {
            id: target.id,
            url: if target.url.is_empty() {
                crate::auto::login::SIGNIN_URL.to_string()
            } else {
                target.url
            },
            ws_url,
        })
    }

    /// Read the session's state without driving anything.
    ///
    /// The distinction between "signed out" and "no tab" is the whole reason
    /// this returns a state rather than a bool: they need different repairs.
    pub async fn probe_session(&self) -> crate::auto::health::SessionState {
        use crate::auto::health::SessionState;

        match self.find_venmo_tab().await {
            Ok(tab) => {
                // The URL is what `/json/list` last reported, which can lag a
                // client-side navigation. Ask the page itself when we can; fall
                // back to the listing when the socket will not answer.
                let url = match self.current_url(&tab).await {
                    Ok(url) => url,
                    Err(_) => tab.url.clone(),
                };
                if crate::auto::login::url_is_signed_out(&url) {
                    return SessionState::SignedOut { url };
                }

                // A signed-in-looking URL is not a signed-in session. On
                // 2026-09-05 the hub's tab sat at `https://account.venmo.com/`
                // titled "Venmo | Welcome Jay" for hours after Venmo had
                // expired the session server-side: the page was a render left
                // over from when it worked, and nothing had navigated since.
                // A URL check calls that `Live`, the health loop goes back to
                // sleep, and the expiry is discovered by a fill.
                //
                // So ask the session itself. `session_is_authenticated` makes
                // one authenticated read; a 401 or a redirect to the sign-in
                // host is the answer the URL could not give.
                match self.session_is_authenticated(&tab).await {
                    Ok(true) => SessionState::Live { url },
                    Ok(false) => SessionState::SignedOut { url },
                    // The probe itself failed, which is not evidence either
                    // way. Reporting `SignedOut` here would trigger a re-login
                    // against a healthy session on any transient network
                    // blip, so the weaker URL answer stands.
                    Err(e) => {
                        tracing::debug!(
                            "could not confirm the Venmo session by request ({e:#}); \
                             falling back to the tab URL"
                        );
                        SessionState::Live { url }
                    }
                }
            }
            Err(e) => {
                // "No Venmo tab" and "no browser" are different failures with
                // different fixes, and `find_venmo_tab` reports both. The
                // listing is what tells them apart: if it answered at all, the
                // browser is up.
                let reachable = self
                    .http
                    .get(format!("{}/json/list", self.cdp_url))
                    .timeout(self.timeout)
                    .send()
                    .await
                    .is_ok();
                if reachable {
                    SessionState::NoTab
                } else {
                    SessionState::NoBrowser {
                        why: format!("{e:#}"),
                    }
                }
            }
        }
    }

    /// Whether the session behind the page is actually authenticated.
    ///
    /// One same-origin authenticated read, from the page, with its cookies. A
    /// 2xx means the session bearer is still good; a 401/403, or a redirect to
    /// the sign-in host, means it is not, however the address bar reads.
    ///
    /// `/api/account` was checked against the live hub on 2026-09-05: 200 with
    /// account data when cookies are sent, 401 when they are omitted. That
    /// second half is what makes it a liveness test rather than a reachability
    /// test. Anything that answers the same way signed in and signed out --
    /// `/api/user`, which 404s on this account, for one -- proves nothing.
    ///
    /// Deliberately a read. Nothing in this path may move money, which is the
    /// same rule the rest of this impl follows.
    async fn session_is_authenticated(&self, tab: &CdpTab) -> Result<bool> {
        const PROBE: &str = r#"
        (async () => {
          try {
            const r = await fetch('https://account.venmo.com/api/account', {
              credentials: 'include',
              headers: {'Accept': 'application/json'},
            });
            if (r.status === 401 || r.status === 403) return 'no';
            if (/id\.venmo\.com|\/signin/.test(r.url)) return 'no';
            if (r.ok) return 'yes';
            return 'unknown';
          } catch (e) { return 'unknown'; }
        })()"#;

        let value = self.evaluate(tab, PROBE).await?;
        // `evaluate` already unwraps one level, so the value is at
        // `result.value` -- the same path `wait_for_button` uses.
        let answer = value
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        match answer {
            "yes" => Ok(true),
            "no" => Ok(false),
            // An inconclusive probe is an error, not a verdict: the caller
            // falls back rather than acting on a guess.
            _ => anyhow::bail!("the session probe was inconclusive"),
        }
    }

    /// Ask the page for its own current URL.
    async fn current_url(&self, tab: &CdpTab) -> Result<String> {
        let value = self.evaluate(tab, "location.href").await?;
        Ok(value
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string())
    }

    /// Build the sequence of CDP steps a payment needs.
    ///
    /// Returned rather than executed so the dry run can print exactly what the
    /// live run would do, and so the irreversible step is a separate, explicit
    /// element the caller has to opt into.
    pub fn payment_steps(&self, req: &PaymentRequest) -> Vec<PaymentStep> {
        vec![
            PaymentStep::Navigate {
                url: format!("https://account.venmo.com/pay?recipients={}", req.recipient),
            },
            PaymentStep::WaitFor {
                selector: AMOUNT_SELECTOR.to_string(),
            },
            // Before anything is typed: the page has to be a payment to the
            // person we mean. Waiting on the amount field alone would let a
            // navigation that landed on a different, pre-filled payment carry
            // straight on into the fills and the click.
            PaymentStep::RequireRecipient {
                recipient: req.recipient.clone(),
            },
            PaymentStep::Fill {
                selector: AMOUNT_SELECTOR.to_string(),
                value: req.amount.clone(),
            },
            PaymentStep::Fill {
                selector: NOTE_SELECTOR.to_string(),
                value: req.note.clone(),
            },
            // Read the amount back out of the field, from the page, immediately
            // before the irreversible step. A React-controlled input can hold a
            // value the script never set, and this is the last moment the money
            // has not moved.
            PaymentStep::RequireAmount {
                selector: AMOUNT_SELECTOR.to_string(),
                expected: req.amount.clone(),
            },
            // Everything above is reversible. These are not.
            //
            // Two clicks, because that is what the live page does: "Pay" opens a
            // confirmation and "Confirm" completes it. They are separate steps
            // so each is individually irreversible, individually logged, and
            // individually dropped by a dry run, rather than one step that
            // guesses how many buttons the flow has.
            PaymentStep::ConfirmSend {
                selector: PAY_BUTTON.to_string(),
            },
            PaymentStep::WaitForConfirm {
                amount: req.amount.clone(),
            },
            PaymentStep::ConfirmNamedAmount {
                amount: req.amount.clone(),
            },
        ]
    }

    /// Run a payment, honouring [`SendMode`].
    ///
    /// In `DryRun` the confirm step is dropped before anything is executed.
    pub async fn pay(
        &self,
        tab: &CdpTab,
        req: &PaymentRequest,
        mode: SendMode,
    ) -> Result<PaymentOutcome> {
        if !Self::session_looks_live(tab) {
            anyhow::bail!(
                "the Venmo tab is on {} and looks signed out; sign in again and rerun",
                tab.url
            );
        }

        let steps = self.payment_steps(req);

        for step in &steps {
            if step.is_irreversible() {
                if mode.is_dry_run() {
                    tracing::info!(
                        recipient = %req.recipient,
                        amount = %req.amount,
                        "dry run: stopping before the send button"
                    );
                    return Ok(PaymentOutcome::WouldHaveSent {
                        recipient: req.recipient.clone(),
                        amount: req.amount.clone(),
                    });
                }
                tracing::warn!(
                    recipient = %req.recipient,
                    amount = %req.amount,
                    "sending a real Venmo payment"
                );
            }
            self.execute(tab, step).await?;
        }

        Ok(PaymentOutcome::Sent {
            recipient: req.recipient.clone(),
            amount: req.amount.clone(),
        })
    }

    async fn execute(&self, tab: &CdpTab, step: &PaymentStep) -> Result<()> {
        match step {
            PaymentStep::WaitFor { selector } => self.wait_for(tab, selector).await,

            // The two assertions are the point of NEW-3: their return values are
            // read, and a wrong answer stops the run before the click.
            PaymentStep::RequireRecipient { recipient } => {
                let value = self.evaluate(tab, &step.to_expression()).await?;
                let result = value.get("result").and_then(|r| r.get("value"));
                let ok = result
                    .and_then(|v| v.get("ok"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !ok {
                    let url = result
                        .and_then(|v| v.get("url"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("(unknown)");
                    anyhow::bail!(
                        "the Venmo page at {url} does not name @{recipient} anywhere. \
                         Refusing to fill in an amount and click send on a payment to \
                         someone else."
                    );
                }
                Ok(())
            }

            PaymentStep::RequireAmount { expected, .. } => {
                let value = self.evaluate(tab, &step.to_expression()).await?;
                let shown = value
                    .get("result")
                    .and_then(|r| r.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if !amount_matches(&shown, expected) {
                    anyhow::bail!(
                        "the Venmo amount field reads {shown:?} but this payment is for \
                         {expected:?}. The field did not take the value it was given, which \
                         a React-controlled input does silently. Not clicking send."
                    );
                }
                Ok(())
            }

            PaymentStep::WaitForConfirm { amount } => {
                self.wait_for_expression(
                    tab,
                    &step.to_expression(),
                    &format!("a confirmation button naming ${amount}"),
                )
                .await
            }

            PaymentStep::WaitForButton { label } => self.wait_for_button(tab, label).await,

            other => {
                self.evaluate(tab, &other.to_expression()).await?;
                Ok(())
            }
        }
    }

    /// Poll for a selector until it appears or the timeout runs out.
    async fn wait_for(&self, tab: &CdpTab, selector: &str) -> Result<()> {
        let deadline = std::time::Instant::now() + self.timeout;
        let expression = PaymentStep::WaitFor {
            selector: selector.to_string(),
        }
        .to_expression();
        loop {
            let value = self.evaluate(tab, &expression).await?;
            if value.get("result").and_then(|r| r.get("value")) == Some(&json!(true)) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "waited {}s for {selector} on the Venmo page and it never appeared",
                    self.timeout.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll an expression that answers true when the page is ready.
    async fn wait_for_expression(
        &self,
        tab: &CdpTab,
        expression: &str,
        what: &str,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            let value = self.evaluate(tab, expression).await?;
            if value.get("result").and_then(|r| r.get("value")) == Some(&json!(true)) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "waited {}s for {what} and it never appeared. The payment may be \
                     mid-flow; check the tab before retrying.",
                    self.timeout.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll for a button with this exact text until it is present and enabled.
    async fn wait_for_button(&self, tab: &CdpTab, label: &str) -> Result<()> {
        let deadline = std::time::Instant::now() + self.timeout;
        let expression = PaymentStep::WaitForButton {
            label: label.to_string(),
        }
        .to_expression();
        loop {
            let value = self.evaluate(tab, &expression).await?;
            if value.get("result").and_then(|r| r.get("value")) == Some(&json!(true)) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "waited {}s for an enabled {label:?} button on the Venmo page and it \
                     never appeared. The payment may be mid-flow; check the tab before \
                     retrying.",
                    self.timeout.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Evaluate JavaScript in the attached tab via CDP `Runtime.evaluate`.
    async fn evaluate(&self, tab: &CdpTab, expression: &str) -> Result<serde_json::Value> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let (mut socket, _) = tokio_tungstenite::connect_async(&tab.ws_url)
            .await
            .with_context(|| format!("could not attach to the Venmo tab at {}", tab.ws_url))?;

        let request = json!({
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "awaitPromise": true,
                "returnByValue": true,
            }
        });
        socket
            .send(Message::Text(request.to_string().into()))
            .await?;

        let reply = tokio::time::timeout(self.timeout, async {
            while let Some(message) = socket.next().await {
                let message = message?;
                if let Message::Text(text) = message {
                    let value: serde_json::Value = serde_json::from_str(&text)?;
                    if value.get("id") == Some(&json!(1)) {
                        return Ok::<_, anyhow::Error>(value);
                    }
                }
            }
            anyhow::bail!("the Venmo tab closed the debugger connection")
        })
        .await
        .context("timed out waiting for the browser to answer")??;

        if let Some(error) = reply.get("error") {
            anyhow::bail!("the browser rejected the step: {error}");
        }
        if let Some(details) = reply.get("result").and_then(|r| r.get("exceptionDetails")) {
            anyhow::bail!("the Venmo page raised an error: {details}");
        }

        Ok(reply
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

/// A single browser action.
#[derive(Debug, Clone)]
pub enum PaymentStep {
    Navigate {
        url: String,
    },
    WaitFor {
        selector: String,
    },
    Fill {
        selector: String,
        value: String,
    },
    /// Assert the page is a payment to this recipient before anything is typed.
    ///
    /// `WaitFor` on the amount field says a payment form is on screen, not whose
    /// it is. A navigation that landed somewhere else, or on a payment the
    /// operator had already part-filled, would otherwise be filled in and sent.
    RequireRecipient {
        recipient: String,
    },
    /// Read the amount back out of the field and require it to be what we set.
    ///
    /// The fill assigns `el.value` directly. React tracks a controlled input's
    /// value on the node's own value tracker, which a plain assignment does not
    /// update, so the field can revert to a stale value while the script
    /// believes it took. Nothing checked, and the next step spent the money.
    RequireAmount {
        selector: String,
        expected: String,
    },
    /// Wait for the confirmation button that names this amount.
    ///
    /// Venmo renders it as "Pay Jay Butera $1.00" once the confirmation opens.
    /// The page also holds a permanently disabled button labelled "Confirm"
    /// that belongs to something else; waiting on that one times out while the
    /// real confirmation is sitting open, which is exactly what happened on the
    /// first live attempt.
    WaitForConfirm {
        amount: String,
    },
    /// Click the confirmation button, having checked it names this amount.
    ///
    /// The label is the last statement the page makes about what it is about to
    /// do, so it is read rather than trusted: a button that says a different
    /// number is not clicked.
    ConfirmNamedAmount {
        amount: String,
    },
    /// Wait for a button with this exact text to appear and become enabled.
    ///
    /// Venmo's confirmation step renders after the Pay click, so the Confirm
    /// button does not exist when the sequence is built. Waiting for it by text
    /// keeps the second click from firing into a page that has not rendered it,
    /// which would otherwise look identical to a disabled button.
    WaitForButton {
        label: String,
    },
    /// The click that moves money.
    ConfirmSend {
        selector: String,
    },
}

impl PaymentStep {
    pub fn is_irreversible(&self) -> bool {
        matches!(
            self,
            PaymentStep::ConfirmSend { .. } | PaymentStep::ConfirmNamedAmount { .. }
        )
    }

    fn to_expression(&self) -> String {
        match self {
            PaymentStep::Navigate { url } => {
                format!("location.href = {}", json!(url))
            }
            // `wait_for` polls this rather than running it once. Same predicate,
            // so the two cannot drift: it answers whether the element is there,
            // it does not reach into whatever came back.
            PaymentStep::WaitFor { selector } => {
                format!("document.querySelector({}) !== null", json!(selector))
            }
            // Set the value through React's own tracker before dispatching the
            // event. A controlled input keeps its last known value on
            // `_valueTracker`; assigning `el.value` leaves the tracker holding
            // the old string, React's onChange sees no change, and its next
            // render puts the stale value back. Calling the native value setter
            // and then clearing the tracker is what makes React accept it.
            PaymentStep::Fill { selector, value } => format!(
                "(() => {{ \
                   const el = document.querySelector({sel}); \
                   if (!el) throw new Error('missing field: ' + {sel}); \
                   const proto = el instanceof HTMLTextAreaElement \
                     ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; \
                   const setter = Object.getOwnPropertyDescriptor(proto, 'value').set; \
                   el.focus(); \
                   if (el._valueTracker) {{ el._valueTracker.setValue(''); }} \
                   setter.call(el, {val}); \
                   el.dispatchEvent(new Event('input', {{bubbles:true}})); \
                   el.dispatchEvent(new Event('change', {{bubbles:true}})); \
                 }})()",
                sel = json!(selector),
                val = json!(value)
            ),
            // Returns the rendered recipient text so a mismatch can name it.
            PaymentStep::RequireRecipient { recipient } => format!(
                "(() => {{ \
                   const wanted = {want}; \
                   const hay = (document.body ? document.body.innerText : '') + ' ' + location.href; \
                   return {{ ok: hay.toLowerCase().includes(wanted.toLowerCase()), \
                             url: location.href }}; \
                 }})()",
                want = json!(recipient)
            ),
            // Returns what the field actually holds, so the caller compares.
            PaymentStep::RequireAmount { selector, .. } => format!(
                "(() => {{ \
                   const el = document.querySelector({sel}); \
                   if (!el) throw new Error('the amount field is gone: ' + {sel}); \
                   return String(el.value); \
                 }})()",
                sel = json!(selector)
            ),
            // Matches on the prefix, then requires the label to carry the
            // amount. Both halves matter: the prefix finds it, and the amount
            // is the page telling us what it will do.
            PaymentStep::WaitForConfirm { amount } => format!(
                "(() => {{ \
                   const pre = {pre}; const amt = {amt}; \
                   const el = [...document.querySelectorAll('button')] \
                     .find(b => {{ const t=(b.innerText||'').trim(); \
                                  return t.startsWith(pre) && t.includes(amt); }}); \
                   return !!el && !el.disabled; \
                 }})()",
                pre = json!(CONFIRM_PREFIX),
                amt = json!(amount)
            ),

            PaymentStep::ConfirmNamedAmount { amount } => format!(
                "(() => {{ \
                   const pre = {pre}; const amt = {amt}; \
                   const hits = [...document.querySelectorAll('button')] \
                     .filter(b => {{ const t=(b.innerText||'').trim(); \
                                     return t.startsWith(pre) && t.includes(amt); }}); \
                   if (hits.length === 0) throw new Error('no confirmation button naming ' + amt); \
                   if (hits.length > 1) throw new Error(hits.length + ' buttons name ' + amt); \
                   const el = hits[0]; \
                   if (el.disabled) throw new Error('the confirmation button is disabled'); \
                   const label = (el.innerText||'').trim(); \
                   el.click(); \
                   return label; \
                 }})()",
                pre = json!(CONFIRM_PREFIX),
                amt = json!(amount)
            ),

            PaymentStep::WaitForButton { label } => format!(
                "(() => {{ \
                   const want = {lab}; \
                   const el = [...document.querySelectorAll('button')] \
                     .find(b => (b.innerText || '').trim() === want); \
                   return !!el && !el.disabled; \
                 }})()",
                lab = json!(label)
            ),

            // Found by exact button text, not by `querySelector`. The live page
            // has no id, test id or aria-label on either button, and the
            // `button[type='submit']` this used to fall back to resolves to the
            // confirmation step's own Confirm button, plus two avatars and a
            // cookie banner. Matching text is narrower than that, not looser.
            //
            // Only "Pay" is clicked here. Venmo then renders a confirmation and
            // the caller runs a second ConfirmSend for it, so each click is its
            // own step with its own guard rather than one blind double-click.
            PaymentStep::ConfirmSend { selector } => format!(
                "(() => {{ \
                   const want = {sel}; \
                   const buttons = [...document.querySelectorAll('button')]; \
                   const el = buttons.find(b => (b.innerText || '').trim() === want); \
                   if (!el) throw new Error('no button labelled ' + want + ' on this page'); \
                   if (el.disabled) throw new Error('the ' + want + ' button is disabled'); \
                   el.click(); \
                   return want; \
                 }})()",
                sel = json!(selector)
            ),
        }
    }

    /// One line for the dry-run report.
    pub fn describe(&self) -> String {
        match self {
            PaymentStep::Navigate { url } => format!("open {url}"),
            PaymentStep::WaitFor { selector } => format!("wait for {selector}"),
            PaymentStep::Fill { selector, value } => format!("type {value:?} into {selector}"),
            PaymentStep::RequireRecipient { recipient } => {
                format!("check the page is a payment to @{recipient}")
            }
            PaymentStep::RequireAmount { selector, expected } => {
                format!("read {selector} back and require it to be {expected:?}")
            }
            PaymentStep::WaitForConfirm { amount } => {
                format!("wait for the confirmation button naming ${amount}")
            }
            PaymentStep::ConfirmNamedAmount { amount } => {
                format!("click the confirmation naming ${amount}  <-- sends the money")
            }
            PaymentStep::WaitForButton { label } => {
                format!("wait for the {label:?} button to appear and be enabled")
            }
            PaymentStep::ConfirmSend { selector } => {
                format!("click the {selector:?} button  <-- sends the money")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CdpTab {
    pub id: String,
    pub url: String,
    pub ws_url: String,
}

/// Percent-encode a URL for CDP's `/json/new?<url>` query.
///
/// Written out rather than pulled in: the only input is [`crate::auto::login::SIGNIN_URL`],
/// a constant in this repository, and a dependency to encode one known string is
/// a dependency to audit for nothing. It encodes conservatively, so a character
/// it does not know about is escaped rather than passed through.
fn urlencoding_minimal(url: &str) -> String {
    let mut out = String::with_capacity(url.len() * 2);
    for byte in url.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The health check drives the browser through this rather than through the
/// payment API, so the two paths cannot be confused for one another.
///
/// Everything here is login and inspection. Nothing in this impl can reach a
/// [`PaymentStep`], which is asserted in `auto::login`'s own tests.
impl crate::auto::health::SessionDriver for VenmoBrowser {
    async fn probe(&self) -> crate::auto::health::SessionState {
        self.probe_session().await
    }

    async fn run_step(&self, step: &crate::auto::login::LoginStep) -> Result<serde_json::Value> {
        let tab = self.find_or_open_venmo_tab().await?;
        self.evaluate(&tab, &step.to_expression()).await
    }

    async fn await_step(&self, step: &crate::auto::login::LoginStep, what: &str) -> Result<()> {
        let tab = self.find_or_open_venmo_tab().await?;
        self.wait_for_expression(&tab, &step.to_expression(), what)
            .await
    }

    async fn ensure_tab(&self) -> Result<()> {
        self.find_or_open_venmo_tab().await.map(|_| ())
    }
}

/// Convert a USDC amount (6 decimals) into the string Venmo's field wants.
///
/// Venmo takes whole cents. USDC has four more decimal places than that, and
/// the intent amount comes from swap output rather than a round number, so an
/// amount that is not a whole cent is the normal case rather than the exception.
///
/// This used to truncate: 5,009,999 units rendered `$5.00`, four hundredths of a
/// cent short of the intent. The verifier compares the attested payment against
/// the intent amount, so that payment could never be proven; the taker's real
/// dollars were gone and the escrow stayed shut. Rounding up instead means the
/// payment is never short. The taker overpays by less than a cent, which is
/// theirs to lose and provable, rather than losing the whole amount.
pub fn usdc_to_dollars(amount: alloy::primitives::U256) -> String {
    let units: u128 = amount.to::<u128>();

    // Ceiling division to whole cents: 10_000 USDC units make one cent.
    let cents = units.div_ceil(10_000);

    format!("{}.{:02}", cents / 100, cents % 100)
}

/// Whether the amount Venmo's field is showing is the amount we mean to send.
///
/// Venmo renders the field with its own formatting: a leading `$`, thousands
/// separators, sometimes a bare `25` for `25.00`. Comparing the raw strings
/// would refuse correct payments, and refusing to send after a fill has landed
/// is its own kind of stuck. So both sides are reduced to whole cents and
/// compared as numbers; anything that will not reduce is a mismatch.
pub fn amount_matches(shown: &str, expected: &str) -> bool {
    match (to_cents(shown), to_cents(expected)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Parse a rendered money string into whole cents.
fn to_cents(text: &str) -> Option<u128> {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if cleaned.is_empty() {
        return None;
    }

    let (whole, frac) = match cleaned.split_once('.') {
        // A second point is not a number.
        Some((_, rest)) if rest.contains('.') => return None,
        Some((w, f)) => (w, f),
        None => (cleaned.as_str(), ""),
    };

    // Venmo takes cents; more precision than that is not an amount we sent.
    if frac.len() > 2 {
        return None;
    }
    let cents: u128 = match frac.len() {
        0 => 0,
        1 => frac.parse::<u128>().ok()? * 10,
        _ => frac.parse().ok()?,
    };
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().ok()? };

    whole.checked_mul(100)?.checked_add(cents)
}

/// Whether an amount is exactly a whole number of cents.
///
/// A caller that would rather refuse a payment than overpay can check this
/// first; [`usdc_to_dollars`] rounds up when it is false.
pub fn is_whole_cents(amount: alloy::primitives::U256) -> bool {
    amount.to::<u128>() % 10_000 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn formats_usdc_the_way_venmo_expects() {
        assert_eq!(usdc_to_dollars(U256::from(25_000_000u64)), "25.00");
        assert_eq!(usdc_to_dollars(U256::from(1_500_000u64)), "1.50");
        assert_eq!(usdc_to_dollars(U256::from(999_990_000u64)), "999.99");
        assert_eq!(usdc_to_dollars(U256::from(50_000u64)), "0.05");
    }

    /// MEDIUM-1 in the 2026-08-31 audit. Truncation made a payment a fraction of
    /// a cent short of the intent, which the verifier will not match, so the
    /// taker's dollars left and the escrow never opened. These are the exact
    /// amounts the audit ran.
    #[test]
    fn a_payment_is_never_short_of_the_intent() {
        // Was "5.00", four hundredths of a cent short.
        assert_eq!(usdc_to_dollars(U256::from(5_009_999u64)), "5.01");
        // Was "25.99".
        assert_eq!(usdc_to_dollars(U256::from(25_999_999u64)), "26.00");
        // One unit above a whole cent still rounds up.
        assert_eq!(usdc_to_dollars(U256::from(1_000_001u64)), "1.01");
        // The smallest nonzero amount still asks for a cent, not nothing.
        assert_eq!(usdc_to_dollars(U256::from(1u64)), "0.01");
    }

    /// The rounding never goes the other way: what Venmo is asked for is always
    /// at least the intent, and never more than a cent above it.
    #[test]
    fn rounding_stays_within_one_cent_above() {
        for units in [1u64, 9_999, 10_000, 5_009_999, 25_999_999, 999_990_001] {
            let rendered = usdc_to_dollars(U256::from(units));
            let (dollars, cents) = rendered.split_once('.').expect("two parts");
            let paid_cents: u128 =
                dollars.parse::<u128>().unwrap() * 100 + cents.parse::<u128>().unwrap();
            let paid_units = paid_cents * 10_000;
            let wanted = u128::from(units);

            assert!(
                paid_units >= wanted,
                "{units} units rendered {rendered}, which is short"
            );
            assert!(
                paid_units - wanted < 10_000,
                "{units} units rendered {rendered}, more than a cent over"
            );
        }
    }

    #[test]
    fn whole_cents_are_recognised() {
        assert!(is_whole_cents(U256::from(5_000_000u64)));
        assert!(is_whole_cents(U256::from(10_000u64)));
        assert!(!is_whole_cents(U256::from(5_009_999u64)));
        assert!(!is_whole_cents(U256::from(1u64)));
    }

    /// Two clicks move money, because the live page has two: "Pay" opens a
    /// confirmation and "Confirm" completes it. Both are marked irreversible, so
    /// a dry run stops at the first and neither can be reached by accident.
    #[test]
    fn every_money_moving_step_is_marked_irreversible() {
        let steps = a_payment();
        let money: Vec<_> = steps.iter().filter(|s| s.is_irreversible()).collect();
        assert_eq!(money.len(), 2, "the live flow is Pay then Confirm");
        // The last thing done is a money step; nothing follows the send.
        assert!(steps.last().unwrap().is_irreversible());
        // And every reversible step comes before the first irreversible one, so
        // there is no check left stranded after the money has started moving.
        let first_money = steps.iter().position(|s| s.is_irreversible()).unwrap();
        assert!(
            steps[..first_money].iter().all(|s| !s.is_irreversible()),
            "a check must not sit after the first click"
        );
    }

    /// The amount readback is the last thing before the first click. This is the
    /// ordering NEW-3 was about, and the two-button flow must not have moved it.
    #[test]
    fn the_readback_is_the_last_step_before_any_money_moves() {
        let steps = a_payment();
        let first_money = steps.iter().position(|s| s.is_irreversible()).unwrap();
        assert!(
            matches!(steps[first_money - 1], PaymentStep::RequireAmount { .. }),
            "expected the amount readback immediately before the first click"
        );
    }

    fn a_payment() -> Vec<PaymentStep> {
        VenmoBrowser::new("http://127.0.0.1:9222", 60).payment_steps(&PaymentRequest {
            recipient: "test-payee".to_string(),
            amount: "25.00".to_string(),
            note: "thanks".to_string(),
        })
    }

    // ================================================================
    // NEW-3 in the 2026-08-31 re-audit: the flow was Navigate, WaitFor
    // (amount field), Fill, Fill, ConfirmSend. Nothing read the rendered
    // recipient, nothing re-read the amount after setting it, and the
    // fill was a plain `el.value =` that a React-controlled input can
    // silently discard. The money left before anyone learned the amount
    // had not taken.
    // ================================================================

    /// The amount is read back out of the page after it is filled, and that
    /// check sits between the last fill and the click.
    #[test]
    fn the_amount_is_verified_immediately_before_the_send() {
        let steps = a_payment();

        let confirm = steps
            .iter()
            .position(|s| s.is_irreversible())
            .expect("a send step");
        let verify = steps
            .iter()
            .position(|s| matches!(s, PaymentStep::RequireAmount { .. }))
            .expect("the amount must be verified");
        let last_fill = steps
            .iter()
            .rposition(|s| matches!(s, PaymentStep::Fill { .. }))
            .expect("a fill");

        assert!(last_fill < verify, "the check has to come after the fills");
        assert_eq!(verify + 1, confirm, "and nothing may come between it and the click");

        match &steps[verify] {
            PaymentStep::RequireAmount { expected, .. } => assert_eq!(expected, "25.00"),
            other => panic!("expected a RequireAmount, got {other:?}"),
        }
    }

    /// The recipient is checked before anything is typed, not merely waited on.
    ///
    /// `WaitFor` keys on the amount field, which says a payment form is on
    /// screen and nothing about whose it is. A navigation landing on a
    /// different, already part-filled payment satisfied it.
    #[test]
    fn the_recipient_is_checked_before_the_first_fill() {
        let steps = a_payment();

        let check = steps
            .iter()
            .position(|s| matches!(s, PaymentStep::RequireRecipient { .. }))
            .expect("the recipient must be checked");
        let first_fill = steps
            .iter()
            .position(|s| matches!(s, PaymentStep::Fill { .. }))
            .expect("a fill");

        assert!(check < first_fill, "check who we are paying before typing an amount");

        match &steps[check] {
            PaymentStep::RequireRecipient { recipient } => assert_eq!(recipient, "test-payee"),
            other => panic!("expected a RequireRecipient, got {other:?}"),
        }
    }

    /// The fill goes through React's native value setter and clears the value
    /// tracker. A plain `el.value =` leaves the tracker holding the old string,
    /// so React's onChange sees no change and its next render restores it.
    #[test]
    fn the_fill_sets_the_value_the_way_react_accepts() {
        let js = PaymentStep::Fill {
            selector: AMOUNT_SELECTOR.to_string(),
            value: "25.00".to_string(),
        }
        .to_expression();

        assert!(js.contains("_valueTracker"), "must reset React's value tracker: {js}");
        assert!(js.contains("getOwnPropertyDescriptor"), "must use the native setter: {js}");
        assert!(js.contains("HTMLTextAreaElement"), "the note field is a textarea: {js}");
        assert!(js.contains("new Event('input'"), "React listens for input");
        assert!(js.contains("new Event('change'"));
    }

    /// Every step that reaches for an element guards the null, including the
    /// click. `document.querySelector(...).click()` threw a TypeError that read
    /// as a page error rather than as "the button is not there".
    #[test]
    fn no_step_dereferences_a_missing_element() {
        for step in a_payment() {
            let js = step.to_expression();
            if !js.contains("querySelector") {
                continue;
            }
            // A step that only tests for presence (`!!el && !el.disabled`)
            // never dereferences, so it needs no guard. Everything that reaches
            // through the handle does.
            if js.contains("!!el") {
                continue;
            }
            // The confirmation step filters rather than finds, and guards on the
            // match count before touching hits[0].
            if js.contains("hits.length === 0") {
                continue;
            }
            assert!(
                js.contains("if (!el)") || js.contains("!== null"),
                "{js} dereferences whatever the lookup returned"
            );
        }
    }

    /// The live page on 2026-09-02: clicking "Pay" opens a confirmation whose
    /// button is labelled "Pay Jay Butera $1.00", while a *disabled* button
    /// literally labelled "Confirm" sits elsewhere on the same page. Waiting for
    /// "Confirm" timed out for 120s with the real confirmation open and the
    /// money unsent. The step must match the amount-bearing label instead.
    #[test]
    fn the_confirmation_is_matched_by_the_amount_it_names() {
        let js = PaymentStep::ConfirmNamedAmount {
            amount: "1.00".to_string(),
        }
        .to_expression();
        assert!(js.contains("startsWith"), "{js}");
        assert!(js.contains("1.00"), "{js}");
        // Exactly one match, or it refuses rather than clicking the first.
        assert!(js.contains("hits.length > 1"), "{js}");
        assert!(js.contains("el.disabled"), "{js}");
        // It must not be looking for the decoy.
        assert!(!js.contains("=== 'Confirm'"), "{js}");
    }

    /// And a disabled send button is not a click worth making.
    #[test]
    fn a_disabled_send_button_is_refused() {
        let js = PaymentStep::ConfirmSend {
            selector: PAY_BUTTON.to_string(),
        }
        .to_expression();
        assert!(js.contains("el.disabled"), "{js}");
        // The selector is matched on exact button text rather than on
        // `button[type='submit']`, which on the live page also matches two
        // avatars and a cookie banner, and whose first match is the
        // confirmation's own Confirm button.
        assert!(js.contains("innerText"), "{js}");
        assert!(!js.contains("type='submit'"), "{js}");
    }

    /// Venmo formats the field its own way, so the comparison is on cents
    /// rather than on the raw string. Refusing a correct payment would leave the
    /// taker stuck just as surely as sending a wrong one loses money.
    #[test]
    fn the_amount_check_compares_money_not_strings() {
        for shown in ["25.00", "$25.00", "25", "25.0", "$25", " 25.00 "] {
            assert!(amount_matches(shown, "25.00"), "{shown:?} is 25.00");
        }
        assert!(amount_matches("$1,250.00", "1250.00"), "thousands separator");
    }

    /// The failures this exists to catch: a field that kept a stale value, or
    /// one that ended up empty.
    #[test]
    fn a_field_that_did_not_take_the_value_is_a_mismatch() {
        assert!(!amount_matches("", "25.00"), "empty field");
        assert!(!amount_matches("0.00", "25.00"), "reverted to zero");
        assert!(!amount_matches("5.00", "25.00"), "a digit was dropped");
        assert!(!amount_matches("250.00", "25.00"), "ten times too much");
        assert!(!amount_matches("25.01", "25.00"), "a cent out is still out");
        assert!(!amount_matches("abc", "25.00"), "not a number");
        assert!(!amount_matches("25.000", "25.00"), "more precision than cents");
        assert!(!amount_matches("2.5.0", "25.00"), "not a number either");
    }

    /// The rendered amount is what `usdc_to_dollars` produced, so the two have
    /// to agree across the range the taker actually pays.
    #[test]
    fn every_amount_the_taker_renders_verifies_against_itself() {
        for units in [1u64, 9_999, 50_000, 1_000_001, 5_009_999, 25_999_999, 999_990_001] {
            let rendered = usdc_to_dollars(U256::from(units));
            assert!(
                amount_matches(&rendered, &rendered),
                "{units} rendered {rendered} and did not match itself"
            );
            // And Venmo's own `$` prefix does not break it.
            assert!(amount_matches(&format!("${rendered}"), &rendered));
        }
    }

    /// The dry run still stops before the click, and it now runs the two
    /// assertions on the way, so a dry run tells the operator whether the page
    /// would actually have taken the amount.
    #[test]
    fn the_dry_run_still_stops_at_the_click_but_checks_first() {
        let steps = a_payment();
        let up_to_the_click: Vec<_> = steps
            .iter()
            .take_while(|s| !s.is_irreversible())
            .collect();

        assert!(up_to_the_click
            .iter()
            .any(|s| matches!(s, PaymentStep::RequireRecipient { .. })));
        assert!(up_to_the_click
            .iter()
            .any(|s| matches!(s, PaymentStep::RequireAmount { .. })));
        assert!(!up_to_the_click.iter().any(|s| s.is_irreversible()));
    }

    /// The dry-run report has a line for every step, including the new ones.
    #[test]
    fn every_step_describes_itself() {
        for step in a_payment() {
            let line = step.describe();
            assert!(!line.is_empty());
        }
    }

    #[test]
    fn a_signed_out_tab_is_rejected() {
        let signed_out = CdpTab {
            id: "1".into(),
            url: "https://id.venmo.com/signin".into(),
            ws_url: "ws://x".into(),
        };
        assert!(!VenmoBrowser::session_looks_live(&signed_out));

        let live = CdpTab {
            id: "1".into(),
            url: "https://account.venmo.com/".into(),
            ws_url: "ws://x".into(),
        };
        assert!(VenmoBrowser::session_looks_live(&live));
    }
}
