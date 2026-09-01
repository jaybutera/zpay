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

/// Venmo's amount field, by name and by test id.
const AMOUNT_SELECTOR: &str = "input[name='amount'], [data-testid='amount-input']";
/// The note field.
const NOTE_SELECTOR: &str = "textarea[name='note'], [data-testid='note-input']";
/// The button that moves the money.
const SEND_SELECTOR: &str = "[data-testid='send-button'], button[type='submit']";

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
    pub fn session_looks_live(tab: &CdpTab) -> bool {
        let url = tab.url.to_ascii_lowercase();
        !(url.contains("/signin") || url.contains("/login") || url.contains("account/sign-in"))
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
            // Everything above is reversible. This is not.
            PaymentStep::ConfirmSend {
                selector: SEND_SELECTOR.to_string(),
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
    /// The click that moves money.
    ConfirmSend {
        selector: String,
    },
}

impl PaymentStep {
    pub fn is_irreversible(&self) -> bool {
        matches!(self, PaymentStep::ConfirmSend { .. })
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
            PaymentStep::ConfirmSend { selector } => format!(
                "(() => {{ \
                   const el = document.querySelector({sel}); \
                   if (!el) throw new Error('no send button: ' + {sel}); \
                   if (el.disabled) throw new Error('the send button is disabled'); \
                   el.click(); \
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
            PaymentStep::ConfirmSend { selector } => {
                format!("click {selector}  <-- sends the money")
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

    #[test]
    fn exactly_one_step_moves_money() {
        let steps = a_payment();
        assert_eq!(steps.iter().filter(|s| s.is_irreversible()).count(), 1);
        // and it is the last thing we do
        assert!(steps.last().unwrap().is_irreversible());
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
            assert!(
                js.contains("if (!el)") || js.contains("!== null"),
                "{js} dereferences whatever querySelector returned"
            );
        }
    }

    /// And a disabled send button is not a click worth making.
    #[test]
    fn a_disabled_send_button_is_refused() {
        let js = PaymentStep::ConfirmSend {
            selector: SEND_SELECTOR.to_string(),
        }
        .to_expression();
        assert!(js.contains("el.disabled"), "{js}");
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
