//! Driving an already-open Venmo tab over the Chrome DevTools Protocol.
//!
//! The operator logs into Venmo themselves and leaves the tab open. The agent
//! attaches to that tab over CDP and drives the existing session. It never sees
//! a password, never handles 2FA, and stores no cookies; if the session has
//! expired the agent stops and says so rather than trying to log in.
//!
//! Everything here is gated on [`SendMode`]. In [`SendMode::DryRun`] the agent
//! goes through discovery, staking checks, and page inspection, then stops at
//! the confirm button and reports what it would have sent.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

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
                selector: "input[name='amount'], [data-testid='amount-input']".to_string(),
            },
            PaymentStep::Fill {
                selector: "input[name='amount'], [data-testid='amount-input']".to_string(),
                value: req.amount.clone(),
            },
            PaymentStep::Fill {
                selector: "textarea[name='note'], [data-testid='note-input']".to_string(),
                value: req.note.clone(),
            },
            // Everything above is reversible. This is not.
            PaymentStep::ConfirmSend {
                selector: "[data-testid='send-button'], button[type='submit']".to_string(),
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
            other => {
                self.evaluate(tab, &other.to_expression()).await?;
                Ok(())
            }
        }
    }

    /// Poll for a selector until it appears or the timeout runs out.
    async fn wait_for(&self, tab: &CdpTab, selector: &str) -> Result<()> {
        let deadline = std::time::Instant::now() + self.timeout;
        let expression = format!(
            "document.querySelector({}) !== null",
            serde_json::to_string(selector)?
        );
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
            PaymentStep::WaitFor { selector } => {
                format!("document.querySelector({})", json!(selector))
            }
            PaymentStep::Fill { selector, value } => format!(
                "(() => {{ const el = document.querySelector({}); if (!el) throw new Error('missing field'); \
                 el.focus(); el.value = {}; el.dispatchEvent(new Event('input', {{bubbles:true}})); }})()",
                json!(selector),
                json!(value)
            ),
            PaymentStep::ConfirmSend { selector } => format!(
                "document.querySelector({}).click()",
                json!(selector)
            ),
        }
    }

    /// One line for the dry-run report.
    pub fn describe(&self) -> String {
        match self {
            PaymentStep::Navigate { url } => format!("open {url}"),
            PaymentStep::WaitFor { selector } => format!("wait for {selector}"),
            PaymentStep::Fill { selector, value } => format!("type {value:?} into {selector}"),
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
pub fn usdc_to_dollars(amount: alloy::primitives::U256) -> String {
    let units: u128 = amount.to::<u128>();
    format!("{}.{:02}", units / 1_000_000, (units % 1_000_000) / 10_000)
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

    #[test]
    fn exactly_one_step_moves_money() {
        let browser = VenmoBrowser::new("http://127.0.0.1:9222", 60);
        let steps = browser.payment_steps(&PaymentRequest {
            recipient: "alice".to_string(),
            amount: "25.00".to_string(),
            note: "thanks".to_string(),
        });
        assert_eq!(steps.iter().filter(|s| s.is_irreversible()).count(), 1);
        // and it is the last thing we do
        assert!(steps.last().unwrap().is_irreversible());
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
