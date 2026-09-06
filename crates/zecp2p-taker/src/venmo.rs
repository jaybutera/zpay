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
//!
//! # Who gets paid, and why the page cannot answer it
//!
//! A payment now begins with [`VenmoBrowser::resolve_payee`], one authenticated
//! `GET /api/user/<handle>` made before the browser is pointed anywhere. It is
//! the "per-user read" `1a168fa` named and the thing the pay page cannot
//! substitute for: the pay page renders the recipient as a **display name**
//! under "To", and the only `@handle` anywhere on it is the logged-in account's
//! own, from the chrome at the top of every page.
//!
//! That is not a detail. Until 2026-09-06 `RequireRecipient` scraped handles out
//! of `document.body.innerText`, so the set it searched never held the recipient
//! and always held the sender: it refused every legitimate payment and would
//! have approved a payment to the LP's own account. `docs/status/
//! venmo-recipient-guard-blocks-all-payments.md` is the measurement.
//!
//! So the recipient is established in two places that have to agree, and both
//! compare Venmo's numeric user id rather than a handle or a name:
//!
//! 1. the lookup resolves the ordered handle to an id, refusing a handle nobody
//!    owns (500) and a handle that comes back under a different canonical name;
//! 2. [`PaymentStep::RequireRecipient`] requires the loaded pay page's own state
//!    to name that id, and only that id.
//!
//! A display name is never compared anywhere. Two people share a name, and the
//! name is the one thing about a payee the page will happily show for anybody.

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

/// JavaScript that answers whether the page still carries a given note.
///
/// The note is how a confirmation is tied to *this* drive. It cannot be the
/// payee: Venmo's confirmation label renders a display name ("Jay Butera")
/// while the rail only ever knows the handle ("jay-butera"), so matching the
/// payee on the button text is not possible from what a `FiatLeg` carries. The
/// note is per-payment, this run typed it two steps earlier, and it is the same
/// string `locate_payment` later searches the feed for.
///
/// Read from the page's rendered text only, never from the note field. Reading
/// the field made this satisfiable by our own fill two steps earlier, so it
/// discriminated between sheets only when the field rejected the write -- an
/// assumption about Venmo nothing on record supports, and the round-2 review
/// showed the mock was the only thing enforcing it.
///
/// So this is now a *second* layer behind [`PaymentStep::RequireNoOpenSheet`],
/// which is the check that actually establishes the sheet is ours. If the live
/// sheet turns out not to render the note at all this adds nothing, and it
/// costs nothing either: the temporal check has already refused every sheet
/// this drive did not open.
const CARRIES_NOTE_JS: &str = "const carriesNote = (note) => {      const body = document.body ? document.body.innerText : '';      return body.includes(note);    };";

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

/// A live click that produced no evidence the payment posted.
///
/// Separated from every other failure because it is the only one whose right
/// answer is "look at the tab", not "retry" and not "the money left". On
/// 2026-09-05 order `esc_2c0cef0587c47bafd201e104` clicked through in three
/// seconds against a page left filled by an earlier drive, and the rail wrote
/// `paid` for $2.01 that never moved. A caller that cannot tell this apart from
/// a network error has to guess, and both guesses lose money: treating it as
/// sent strands the dollars, treating it as not-sent re-pays a payment that may
/// have gone through on a slow render.
#[derive(Debug)]
pub struct Unconfirmed {
    /// What we asked the page to do, for the operator who has to go look.
    pub recipient: String,
    pub amount: String,
    /// Why we could not confirm it, in the page's own terms.
    pub why: String,
}

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the Venmo page never confirmed the ${} payment to @{}: {}. \
             The money may or may not have left; do not record this order paid \
             and do not retry it until the tab has been looked at.",
            self.amount, self.recipient, self.why
        )
    }
}

impl std::error::Error for Unconfirmed {}

/// A payment that stopped before the form was ever filled in.
///
/// The other side of [`Unconfirmed`]. That type exists because a click with no
/// posted payment behind it is genuinely ambiguous; this one exists because the
/// steps that run *before* the first [`PaymentStep::Fill`] are not ambiguous at
/// all. They navigate, wait for a form, and read who the page is bound to.
/// None of them types a character, none of them clicks anything, and Venmo has
/// no way to send money nobody asked it to send.
///
/// So a failure there is a refusal, and the escrow behind it never had a
/// payment attempted against it. Recording that as "a payment may have left"
/// costs a full refund window: on 2026-09-06 order
/// `esc_c30ec31ce82148d6b7e3bbd2` was refused by the recipient guard one second
/// after its `Paying` line went down, with the Venmo balance unchanged at
/// $60.49 either side, and the resulting `NeedsOperator` held the single
/// payment slot for the ~22 hours until the escrow's refund height.
///
/// The proof is structural rather than textual. [`VenmoBrowser::pay`] tracks
/// whether it has executed a `Fill` yet, and only wraps errors from before the
/// first one. A caller therefore cannot get this type for a failure that
/// happened after the form was touched, whatever the error says.
#[derive(Debug)]
pub struct NothingWasSent {
    /// Who the order meant to pay, for the operator reading the log.
    pub recipient: String,
    pub amount: String,
    /// Which step refused, in its own words.
    pub why: String,
}

impl std::fmt::Display for NothingWasSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the ${} payment to @{} was refused before the form was filled in: {}. \
             No amount was typed and no button was clicked, so no money moved.",
            self.amount, self.recipient, self.why
        )
    }
}

impl std::error::Error for NothingWasSent {}

/// What happened when we tried.
#[derive(Debug, Clone)]
pub enum PaymentOutcome {
    /// Dry run: the page was reached and filled, nothing was sent.
    WouldHaveSent { recipient: String, amount: String },
    /// Live: Venmo accepted the payment *and the page said so*.
    ///
    /// Reached only through [`PaymentStep::RequireSendConfirmed`]. A click that
    /// returned without error is not enough and never was.
    Sent { recipient: String, amount: String },
}

/// Who Venmo says a handle is.
///
/// Produced only by [`VenmoBrowser::resolve_payee`], which is what makes it
/// evidence rather than a struct anyone can fill in: a `ResolvedPayee` in hand
/// means the live session was asked and answered, the canonical handle came
/// back equal to the one being paid, and the account is active. The steps that
/// check the pay page take one of these, so a payment cannot be built without
/// the lookup having run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPayee {
    /// The canonical handle, in Venmo's own casing.
    pub handle: String,
    /// Venmo's numeric user id, as a decimal string.
    ///
    /// The thing the pay page is bound to. It is not re-assignable and not
    /// case-sensitive, and it is the field `txnUserDetails` carries.
    pub id: String,
    /// The name the pay page will render under "To", for the log and the
    /// operator. Never compared against anything: a display name is not
    /// unique and is not a resolution.
    pub display_name: String,
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

    /// Ask Venmo who a handle is, before the browser is pointed at a pay form.
    ///
    /// `GET /api/user/<handle>` is the per-user read `1a168fa`'s message named
    /// as the real fix, chosen over the alternatives by probing the live
    /// session on 2026-09-06 rather than by guessing:
    ///
    /// | path | answer for `jay-butera` |
    /// |---|---|
    /// | `/api/user/<h>` | 200, `{"username":"Jay-Butera","id":"2041148646359040020",...}` |
    /// | `/api/users/<h>` | 404, the Next.js shell |
    /// | `/api/users?username=<h>` | 404, empty |
    /// | `/api/search/users?query=<h>` | 404, the Next.js shell |
    /// | `api.venmo.com/v1/users/<h>` | blocked cross-origin |
    ///
    /// It fails closed on a handle nobody owns: `zz-no-such-handle-91731`
    /// answers 500 `Something went wrong`, which is a refusal here rather than
    /// a fallback. And it does not fuzzy-match, which is the property that
    /// makes it worth anything: `jaybutera`, one hyphen away from the payee,
    /// resolves to `JayButera` -- Joseph Butera, a different person -- and the
    /// canonical-username check below refuses it.
    ///
    /// The numeric `id` is the value that matters downstream. A handle is
    /// re-assignable and Venmo renders it in whatever case its owner set; the
    /// id is neither, and it is the field the pay page carries in its own
    /// state, so it is what [`PaymentStep::RequireRecipient`] compares.
    ///
    /// Run from the page, with the session's cookies, exactly as
    /// [`Self::session_is_authenticated`] is. A signed-out session cannot
    /// resolve anybody and the empty answer is a refusal, so this is also the
    /// last liveness check before a payment.
    pub async fn resolve_payee(&self, tab: &CdpTab, handle: &str) -> Result<ResolvedPayee> {
        // Shape-checked before it reaches a URL, the same gate the pay address
        // goes through. Without it a handle carrying a slash or a `?` would be
        // a different path or a different query, and this function would report
        // on an account nobody asked about.
        let wanted = crate::payee::validate_username_shape(handle)
            .context("the handle to resolve is not shaped like a Venmo username")?;

        let expression = format!(
            "(async () => {{ \
               try {{ \
                 const r = await fetch('https://account.venmo.com/api/user/' + \
                   encodeURIComponent({handle}), \
                   {{credentials: 'include', headers: {{'Accept': 'application/json'}}}}); \
                 const text = await r.text(); \
                 if (!r.ok) return {{ok: false, status: r.status, \
                                     body: text.slice(0, 200)}}; \
                 let parsed; \
                 try {{ parsed = JSON.parse(text); }} \
                 catch (e) {{ return {{ok: false, status: r.status, \
                                       body: 'not JSON: ' + text.slice(0, 200)}}; }} \
                 return {{ok: true, id: String(parsed.id || ''), \
                          username: String(parsed.username || ''), \
                          displayName: String(parsed.displayName || ''), \
                          isActive: parsed.isActive === true}}; \
               }} catch (e) {{ return {{ok: false, status: 0, body: String(e)}}; }} \
             }})()",
            handle = json!(wanted)
        );

        let value = self.evaluate(tab, &expression).await?;
        let report = value
            .get("result")
            .and_then(|r| r.get("value"))
            .ok_or_else(|| anyhow::anyhow!("the payee lookup answered nothing"))?;

        let ok = report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            let status = report.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
            let body = report
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("(no body)");
            anyhow::bail!(
                "Venmo would not resolve @{wanted}: the per-user read answered {status} \
                 ({body}). A handle nobody owns answers 500 here, so this is a refusal \
                 and not a reason to try the pay page anyway. Nothing was navigated to \
                 and no money moved."
            );
        }

        let username = report
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let id = report
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let display_name = report
            .get("displayName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // An account with no id is not an account we can bind the pay page to,
        // and the binding is the whole point.
        if id.trim().is_empty() {
            anyhow::bail!(
                "Venmo resolved @{wanted} to an account with no id. Without one there is \
                 nothing to check the pay page against, so this refuses rather than \
                 falling back to the handle."
            );
        }

        // The canonical username Venmo answered has to *be* the one we were
        // told to pay. This is what catches `jaybutera` -> `JayButera`: the
        // lookup succeeds, the account is real, and it belongs to someone else.
        //
        // Case-insensitive because Venmo echoes a handle in its owner's chosen
        // case while the string we pay comes from the curator. Case is
        // presentation; the handle is not.
        if !crate::payee::normalize_venmo_username(&username).eq_ignore_ascii_case(wanted) {
            anyhow::bail!(
                "Venmo resolved @{wanted} to @{username} ({display_name}), which is a \
                 different account. The per-user read does not fuzzy-match, so a handle \
                 that comes back under another name is another person. Refusing before \
                 the pay page is opened."
            );
        }

        if !report
            .get("isActive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            anyhow::bail!(
                "Venmo says @{wanted} ({display_name}) is not an active account. \
                 Refusing to pay it."
            );
        }

        Ok(ResolvedPayee {
            handle: username,
            id,
            display_name,
        })
    }

    /// Build the sequence of CDP steps a payment needs.
    ///
    /// Returned rather than executed so the dry run can print exactly what the
    /// live run would do, and so the irreversible step is a separate, explicit
    /// element the caller has to opt into.
    ///
    /// `payee` is what [`Self::resolve_payee`] answered for `req.recipient`.
    /// It is a parameter rather than something built here because resolving is
    /// a network read against the live session and the steps have to stay a
    /// pure description the dry run can print.
    pub fn payment_steps(&self, req: &PaymentRequest, payee: &ResolvedPayee) -> Vec<PaymentStep> {
        vec![
            // Navigated to by the canonical handle Venmo itself answered, not
            // by the string the coordinator sent. They differ in case whenever
            // the owner set one, and using the resolved form means the page is
            // asked for the account the lookup actually checked.
            PaymentStep::Navigate {
                url: format!("https://account.venmo.com/pay?recipients={}", payee.handle),
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
                payee_id: payee.id.clone(),
            },
            PaymentStep::Fill {
                selector: AMOUNT_SELECTOR.to_string(),
                value: req.amount.clone(),
            },
            PaymentStep::Fill {
                selector: NOTE_SELECTOR.to_string(),
                value: req.note.clone(),
            },
            // No audience step, by decision on 2026-09-05. The account
            // default is Private and that is what a payment inherits, so
            // driving the control per payment was dropped.
            //
            // Nothing here *checks* the audience either, and that is the
            // deliberate half: a readback is a refusal, and a payment blocked
            // over a control the driver no longer touches stalls the rail for
            // no gain -- the escrow stays locked, the in-flight slot is held,
            // and an operator has to clear it. The per-payment steps are in
            // git on `venmo-private-audience` if that trade ever changes.
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
            // The last check before anything irreversible, and the one that
            // makes the sheet we later confirm demonstrably ours: it did not
            // exist a moment ago.
            PaymentStep::RequireNoOpenSheet,
            PaymentStep::ConfirmSend {
                selector: PAY_BUTTON.to_string(),
            },
            PaymentStep::WaitForConfirm {
                amount: req.amount.clone(),
                note: req.note.clone(),
            },
            PaymentStep::ConfirmNamedAmount {
                amount: req.amount.clone(),
                note: req.note.clone(),
            },
            // The click is not the payment. Nothing above this line has asked
            // Venmo whether it did anything, and until this step existed the
            // function returned success the instant the click JS returned.
            PaymentStep::RequireSendConfirmed {
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

        // Who is this? Asked before the browser is pointed anywhere, because a
        // pay page cannot answer it: it renders the recipient as a display
        // name, and the only `@handle` on it is the logged-in account's own.
        // The 2026-09-06 writeup is the measurement.
        // A failure here is `NothingWasSent` by construction: the browser has
        // not been pointed at a pay page yet, so there is not even a form to
        // fill in. This is also the step the 2026-09-06 recipient fix added,
        // and the step that refuses a handle Venmo resolves to somebody else.
        let payee = self
            .resolve_payee(tab, &req.recipient)
            .await
            .map_err(|e| {
                anyhow::Error::from(NothingWasSent {
                    recipient: req.recipient.clone(),
                    amount: req.amount.clone(),
                    why: format!(
                        "could not establish who @{} is, so nothing was navigated to: {e:#}",
                        req.recipient
                    ),
                })
            })?;

        tracing::info!(
            asked = %req.recipient,
            resolved = %payee.handle,
            id = %payee.id,
            name = %payee.display_name,
            "Venmo resolved the payee"
        );

        let steps = self.payment_steps(req, &payee);

        // Has any character been typed into the form yet?
        //
        // Everything before the first `Fill` is a navigation, a wait, or a
        // readback. None of them can move money, so a refusal there is a
        // provable "nothing was sent" rather than the ambiguity the journal's
        // `Paying` line assumes. Tracking it here, off the step actually
        // executed, is what makes that claim structural: a step reordered into
        // the prefix carries the guarantee with it, and a step added after the
        // first `Fill` cannot claim it by accident.
        //
        // `Fill` itself is the boundary and is deliberately on the far side of
        // it. It is the first step that changes the page, and a failure *inside*
        // one leaves a form in a state this function did not read back.
        let mut form_untouched = true;

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
            // A failed confirmation carries the recipient the step itself does
            // not know, so the operator reading the log is told who the money
            // was for as well as how much.
            let outcome = self
                .execute(tab, step)
                .await
                .map_err(|e| match e.downcast::<Unconfirmed>() {
                    Ok(u) => anyhow::Error::from(Unconfirmed {
                        recipient: req.recipient.clone(),
                        ..u
                    }),
                    Err(other) => other,
                });

            if let Err(e) = outcome {
                // Only while the form is still untouched. Past the first
                // `Fill` the honest answer is the ambiguous one, and this
                // function does not get to soften it.
                if form_untouched {
                    return Err(anyhow::Error::from(NothingWasSent {
                        recipient: req.recipient.clone(),
                        amount: req.amount.clone(),
                        why: format!("{e:#}"),
                    }));
                }
                return Err(e);
            }

            if matches!(step, PaymentStep::Fill { .. }) {
                form_untouched = false;
            }
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
            PaymentStep::RequireRecipient {
                recipient,
                payee_id,
            } => {
                let value = self.evaluate(tab, &step.to_expression()).await?;
                let report = value
                    .get("result")
                    .and_then(|r| r.get("value"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                page_pays_only(&report, payee_id).map_err(|why| {
                    anyhow::anyhow!(
                        "{why} This order pays @{recipient}. Refusing to fill in an amount \
                         and click send."
                    )
                })
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

            // Refused, not waited on: a sheet that is open now will still be
            // open in a second, and the answer does not improve with time.
            PaymentStep::RequireNoOpenSheet => {
                let value = self.evaluate(tab, &step.to_expression()).await?;
                let report = value.get("result").and_then(|r| r.get("value"));
                let ok = report
                    .and_then(|v| v.get("ok"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !ok {
                    let sheets = report
                        .and_then(|v| v.get("sheets"))
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    anyhow::bail!(
                        "a Venmo confirmation sheet is already open on this page ({sheets}). \
                         It was not opened by this payment, so nothing here has checked what \
                         it would send -- its amount, its payee and its audience were fixed \
                         before this run started. Close it in the browser and let the next \
                         attempt start from a clean form. Not clicking Pay."
                    );
                }
                Ok(())
            }

            PaymentStep::WaitForConfirm { amount, .. } => {
                self.wait_for_expression(
                    tab,
                    &step.to_expression(),
                    &format!("a confirmation button naming ${amount}"),
                )
                .await
            }

            PaymentStep::WaitForButton { label } => self.wait_for_button(tab, label).await,

            // The only step whose failure is neither "it worked" nor "it did
            // not". It gets its own error type so the rail can route it to a
            // human instead of to a retry or to the journal.
            PaymentStep::RequireSendConfirmed { amount } => {
                // Polled here rather than through `wait_for_expression`,
                // because the answer is a report and the failure text has to
                // name what was actually seen. The old arm mapped *every*
                // error to "the button was still on the page", including the
                // one that happens after a real send: a cross-document
                // navigation destroys the execution context, `evaluate`
                // fails, and the operator was told the click did nothing while
                // the money was gone.
                let expression = step.to_expression();
                let deadline = std::time::Instant::now() + self.timeout;
                // Overwritten every pass on purpose: what the operator needs is
                // what the page looked like when we gave up, not when we
                // started. Declared without an initialiser, because every path
                // through the loop body assigns it before the deadline check
                // reads it and a placeholder would be dead on the first pass.
                let mut last_seen: String;

                loop {
                    match self.evaluate(tab, &expression).await {
                        Ok(value) => {
                            let report = value.get("result").and_then(|r| r.get("value"));
                            let flag = |name: &str| {
                                report
                                    .and_then(|v| v.get(name))
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false)
                            };
                            if flag("ok") {
                                return Ok(());
                            }
                            // What the page is showing right now, in its own
                            // terms, for the operator who has to go and look.
                            let url = report
                                .and_then(|v| v.get("url"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("(unknown)");
                            last_seen = if flag("signedOut") {
                                format!(
                                    "the tab is on {url}, a signed-out page, so the session \
                                     expired at the click and the payment did not post"
                                )
                            } else if flag("sheet") {
                                format!(
                                    "the confirmation naming ${amount} is still on the page, \
                                     so the click did nothing"
                                )
                            } else if flag("payBtn") || flag("form") {
                                format!(
                                    "the pay form is still on the page at {url} with no \
                                     confirmation open, which is what Venmo shows when it \
                                     dismisses a confirmation without sending"
                                )
                            } else {
                                format!("the page at {url} did not look like a completed payment")
                            };
                        }
                        // Could not ask the page at all. This is the honest
                        // "neither verdict" case: a context destroyed by
                        // navigation looks exactly like this, and so does a
                        // closed tab, so it must not claim the click failed.
                        Err(e) => {
                            last_seen = format!(
                                "the page could not be asked whether the payment posted ({e:#}); \
                                 a navigation right after a successful send looks like this, \
                                 and so does a closed tab"
                            );
                        }
                    }

                    if std::time::Instant::now() >= deadline {
                        return Err(Unconfirmed {
                            recipient: String::new(),
                            amount: amount.clone(),
                            why: format!("{last_seen} (checked for {}s)", self.timeout.as_secs()),
                        }
                        .into());
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }

            // Explicitly listed, not a catch-all, and that is the point.
            //
            // This arm used to read `other => { evaluate; Ok(()) }`, which
            // meant any step not named above had its answer thrown away. The
            // review's revert C deleted the `RequireSendConfirmed` arm and
            // every test stayed green: the check still ran, its `false` was
            // discarded, and `pay` returned `Sent` -- the incident exactly,
            // reintroduced by a refactor with no compiler complaint and no red
            // test. A catch-all over a match whose arms decide whether money
            // moved is a silent failure waiting for the next edit.
            //
            // So the steps whose answer genuinely carries no verdict are named
            // one by one. Adding a variant to `PaymentStep` now fails to
            // compile until someone decides, here, what its answer means.
            PaymentStep::Navigate { .. } | PaymentStep::Fill { .. } => {
                self.evaluate(tab, &step.to_expression()).await?;
                Ok(())
            }

            // Both clicks. Their JavaScript throws on a missing or disabled
            // button, so `evaluate` surfacing the exception is the check; the
            // returned label is for the log. What they cannot tell us is
            // whether the payment posted, which is `RequireSendConfirmed`.
            PaymentStep::ConfirmSend { .. } | PaymentStep::ConfirmNamedAmount { .. } => {
                let value = self.evaluate(tab, &step.to_expression()).await?;
                let label = value
                    .get("result")
                    .and_then(|r| r.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no label)");
                tracing::info!(clicked = %label, "clicked a money button");
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
    ///
    /// `payee_id` is the numeric id [`VenmoBrowser::resolve_payee`] got from
    /// the per-user read, and it is what the page is required to name.
    /// `recipient` is carried only so the refusal can say which order was
    /// stopped; nothing compares against it here.
    RequireRecipient {
        recipient: String,
        payee_id: String,
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
    /// Refuse to click `Pay` while a confirmation sheet is already open.
    ///
    /// The rule is temporal and needs no assumption about Venmo's DOM: a
    /// confirmation that exists *before* our own click was not opened by this
    /// drive, whatever it says, and the sheet our click opens is the only one
    /// `WaitForConfirm` should ever find.
    ///
    /// This replaces binding the sheet to this payment by its note. That
    /// binding read the note field, which this run had filled two steps
    /// earlier, so it only discriminated when the field rejected the write --
    /// an "already-open sheets detach from the form beneath them" claim about
    /// Venmo that nothing on record supports. The round-2 review flipped the
    /// one line in the mock that hard-coded it and the wrong payee's sheet was
    /// clicked, which showed the test was proving the mock rather than the
    /// page.
    ///
    /// A pre-existing sheet is a refusal even when it is this order's own,
    /// from an earlier attempt. Its terms were fixed when it opened, before
    /// this drive ran a single readback, so a drive that clicked it would be
    /// sending something none of its own checks looked at. There is no
    /// automatic retry -- every `fiat.pay` failure writes `NeedsOperator` and
    /// fails the order -- so this is only ever reached after a human has seen
    /// the tab, and the right instruction to that human is to close the sheet
    /// and let the retry start from a clean form.
    RequireNoOpenSheet,
    /// Wait for the confirmation button that names this amount, on a sheet
    /// that carries this payment's own note.
    ///
    /// Venmo renders it as "Pay Jay Butera $1.00" once the confirmation opens.
    /// The page also holds a permanently disabled button labelled "Confirm"
    /// that belongs to something else; waiting on that one times out while the
    /// real confirmation is sitting open, which is exactly what happened on the
    /// first live attempt.
    ///
    /// The `note` is what makes this *this drive's* sheet. The label carries a
    /// display name ("Jay Butera") while the rail only knows the handle
    /// ("jay-butera"), so the payee cannot be matched on the button text. The
    /// note can: it is per-payment, it carries the tag `locate_payment` later
    /// searches the feed for, and this run typed it into the form two steps
    /// ago. A confirmation sheet left open by an earlier drive shows that
    /// drive's note, so it no longer satisfies this.
    WaitForConfirm {
        amount: String,
        note: String,
    },
    /// Click the confirmation button, having checked it names this amount and
    /// sits on a sheet carrying this payment's note.
    ///
    /// The label is the last statement the page makes about what it is about to
    /// do, so it is read rather than trusted: a button that says a different
    /// number is not clicked.
    ///
    /// Amount alone was not enough. A confirmation sheet an earlier drive left
    /// open, for a different payee at the same amount, matched the prefix and
    /// the amount and would have been clicked -- paying the previous drive's
    /// recipient. The note is checked with it, for the reason
    /// [`PaymentStep::WaitForConfirm`] gives.
    ConfirmNamedAmount {
        amount: String,
        note: String,
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
    /// Require the page to show that the payment actually posted.
    ///
    /// This is the step whose absence let order `esc_2c0cef0587c47bafd201e104`
    /// be written `paid` for $2.01 that never moved. Every step before this one
    /// answers a question about the *form*: is the recipient right, did the
    /// amount take, is there a button, was it enabled. None of them asks the
    /// only question that matters after the click, which is whether Venmo did
    /// anything.
    ///
    /// It is stated as a *disappearance*, not an appearance, and that choice is
    /// the whole point. A success banner is a race: it renders late, it is
    /// worded differently on different accounts, and a check that waits for one
    /// fails open the moment Venmo changes the copy. What Venmo does on every
    /// successful payment, and cannot not do, is take the payment form away --
    /// the amount field and the confirmation button both go, because the page
    /// navigates to the feed or the story. So this answers `true` only when the
    /// confirmation button naming this amount is *gone*.
    ///
    /// The stale-page failure is what makes the negative form necessary. The
    /// tab that produced the false success still had a filled form and a live
    /// confirmation button on it after both clicks; anything phrased as "find
    /// the evidence" would have had to out-guess a page that was already
    /// showing the wrong thing, and "the form is still sitting there" is
    /// exactly the state we are trying to catch.
    RequireSendConfirmed {
        amount: String,
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
            // Returns the payees the pay page itself is addressed to, by
            // Venmo's own numeric id.
            //
            // **Not** `document.body.innerText`, which is what this read
            // before 2026-09-06 and what made the guard useless. The pay page
            // renders the recipient only as a display name under "To"; the
            // sole `@handle` anywhere on it is the logged-in account's own,
            // from the chrome at the top of every page. So the handle set
            // never contained the recipient and always contained the sender,
            // and the check reduced to "am I paying myself?" answering yes for
            // exactly the case it should refuse.
            //
            // `__NEXT_DATA__.props.pageProps.txnUserDetails` is the page's own
            // server-rendered state for this form, and it carries the payee's
            // canonical handle and numeric id. Read off the live session on
            // 2026-09-06, it tracks the resolution exactly:
            //
            // | `?recipients=` | `txnUserDetails` |
            // |---|---|
            // | `jay-butera` | `Jay-Butera`, id 2041148646359040020 |
            // | `casper` | `casper`, id 2261773692436480899, Jordan Bryant |
            // | `jaybutera` | `JayButera`, id 3457650285086115910, Joseph Butera |
            // | `zz-no-such-handle-91731` | `[]` |
            // | `Jay-Butera-2` (our own) | `[]` -- Venmo will not pay yourself |
            //
            // The empty answers are the point: an unresolvable payee gives the
            // caller nothing to match, and it refuses.
            //
            // Still **not** `location.href`, and for a sharper reason than
            // before. Driving a `pushState` to a different handle on the live
            // page moved the URL and left both `txnUserDetails` and the
            // rendered "To" field on the original payee: the URL is the half
            // that can lie about who a loaded form pays, and the page state is
            // the half that agrees with what is rendered.
            //
            // The whole array is returned rather than a verdict, so the caller
            // compares and the refusal can name who the page was actually for.
            PaymentStep::RequireRecipient { .. } => "(() => { \
                   const el = document.getElementById('__NEXT_DATA__'); \
                   if (!el) return {found: false, why: 'the page carries no __NEXT_DATA__', \
                                    payees: [], url: location.href}; \
                   let data; \
                   try { data = JSON.parse(el.textContent); } \
                   catch (e) { return {found: false, why: '__NEXT_DATA__ is not JSON', \
                                       payees: [], url: location.href}; } \
                   const props = data && data.props && data.props.pageProps; \
                   const details = props && props.txnUserDetails; \
                   if (!Array.isArray(details)) \
                     return {found: false, why: 'the page state carries no txnUserDetails', \
                             payees: [], url: location.href}; \
                   return {found: true, why: '', url: location.href, \
                           payees: details.map(u => ({id: String(u && u.id || ''), \
                                                      username: String(u && u.username || ''), \
                                                      displayName: String(u && u.displayName || '')}))}; \
                 })()"
            .to_string(),
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
            // Any confirmation sheet at all, whatever it names. Matched on the
            // prefix plus a dollar amount rather than on *our* amount, because
            // the point is that a sheet opened before our click is not ours no
            // matter what it says -- a stale sheet for the same amount is
            // exactly the dangerous case.
            PaymentStep::RequireNoOpenSheet => format!(
                "(() => {{ \
                   const pre = {pre}; \
                   const open = [...document.querySelectorAll('button')] \
                     .map(b => (b.innerText||'').trim()) \
                     .filter(t => t.startsWith(pre) && /\\$[0-9]/.test(t)); \
                   return {{ ok: open.length === 0, sheets: open }}; \
                 }})()",
                pre = json!(CONFIRM_PREFIX)
            ),

            // The note has to be on the page as well as the amount on the
            // button. Both halves are about identity: the amount says what the
            // sheet will do, the note says which drive it belongs to.
            PaymentStep::WaitForConfirm { amount, note } => format!(
                "(() => {{ \
                   {helper} \
                   const pre = {pre}; const amt = {amt}; const note = {note}; \
                   if (note && !carriesNote(note)) return false; \
                   const el = [...document.querySelectorAll('button')] \
                     .find(b => {{ const t=(b.innerText||'').trim(); \
                                  return t.startsWith(pre) && t.includes(amt); }}); \
                   return !!el && !el.disabled; \
                 }})()",
                pre = json!(CONFIRM_PREFIX),
                amt = json!(amount),
                note = json!(note),
                helper = CARRIES_NOTE_JS
            ),

            PaymentStep::ConfirmNamedAmount { amount, note } => format!(
                "(() => {{ \
                   {helper} \
                   const pre = {pre}; const amt = {amt}; const note = {note}; \
                   if (note && !carriesNote(note)) \
                     throw new Error('the confirmation does not carry this payment\\'s note'); \
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
                amt = json!(amount),
                note = json!(note),
                helper = CARRIES_NOTE_JS
            ),

            // True only when the confirmation button naming this amount is
            // gone from the page. See the variant's own note for why this is
            // phrased as a disappearance rather than as a success banner: the
            // page that caused the incident still had the button on it.
            // The whole pay form has to be gone, and the page has to still be
            // a signed-in Venmo page.
            //
            // "The named button vanished" was too weak on its own: it is also
            // true of the sign-in page a session expiry redirects to, and of
            // Venmo dismissing the confirmation sheet on an error and dropping
            // back to the plain form (whose button reads "Pay", not
            // "Pay ... $2.01"). Both are the incident again with a different
            // page shape: no payment posted, and the check says sent.
            //
            // What a posted payment actually does is take the *form* away --
            // the amount field goes with the sheet. So all of these must hold:
            // no amount field, no bare "Pay" button, no confirmation naming
            // this amount, and a URL that is not one of Venmo's signed-out
            // pages. The bare-"Pay" clause is what catches the dismissed sheet.
            //
            // **What this still does not catch**, stated plainly because
            // 51795d6's message wrongly claimed otherwise: any *signed-in*
            // Venmo page with no form and no sheet answers `ok: true`. That is
            // the account home, a DataDome interstitial at the pay URL, a 5xx,
            // or Venmo unmounting the form to show an error panel. This proves
            // a negative and always will. The positive signal is the feed --
            // `fiat::attest` already searches it for the tagged note -- and
            // gating `Stage::Paid` on that story is the recorded follow-up,
            // conditioned on the rail running without an operator watching.
            //
            // Returns a report rather than a bool so the caller can say what it
            // saw instead of asserting a reason it never observed.
            PaymentStep::RequireSendConfirmed { amount } => format!(
                "(() => {{ \
                   const pre = {pre}; const amt = {amt}; const bare = {bare}; \
                   const sel = {sel}; const out = {out}; \
                   const href = (location.href || '').toLowerCase(); \
                   const signedOut = out.some(m => href.includes(m)); \
                   const labels = [...document.querySelectorAll('button')] \
                     .map(b => (b.innerText||'').trim()); \
                   const sheet = labels.some(t => t.startsWith(pre) && t.includes(amt)); \
                   const form = document.querySelector(sel) !== null; \
                   const payBtn = labels.some(t => t === bare); \
                   return {{ ok: !sheet && !form && !payBtn && !signedOut, \
                             sheet: sheet, form: form, payBtn: payBtn, \
                             signedOut: signedOut, url: location.href }}; \
                 }})()",
                pre = json!(CONFIRM_PREFIX),
                amt = json!(amount),
                bare = json!(PAY_BUTTON),
                sel = json!(AMOUNT_SELECTOR),
                out = json!(crate::auto::login::SIGNED_OUT_MARKERS)
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

    /// The step's JavaScript, for a test that runs it against a page.
    ///
    /// `to_expression` stays private: it is an implementation detail of
    /// `execute`, and a public one invites a caller to run a money step outside
    /// the mode gate. This accessor exists because asserting over the *text* of
    /// these expressions is not enough -- the 2026-09-05 false success was a
    /// sequence whose every expression was correct and whose result was still
    /// wrong -- so `tests/payment_page_test.rs` runs them against a mock page.
    #[doc(hidden)]
    pub fn expression_for_test(&self) -> String {
        self.to_expression()
    }

    /// One line for the dry-run report.
    pub fn describe(&self) -> String {
        match self {
            PaymentStep::Navigate { url } => format!("open {url}"),
            PaymentStep::WaitFor { selector } => format!("wait for {selector}"),
            PaymentStep::Fill { selector, value } => format!("type {value:?} into {selector}"),
            PaymentStep::RequireRecipient {
                recipient,
                payee_id,
            } => {
                format!("check the page's own state pays @{recipient}, Venmo user id {payee_id}")
            }
            PaymentStep::RequireAmount { selector, expected } => {
                format!("read {selector} back and require it to be {expected:?}")
            }
            PaymentStep::RequireNoOpenSheet => {
                "require no confirmation sheet to be open before clicking Pay".to_string()
            }
            PaymentStep::WaitForConfirm { amount, .. } => {
                format!("wait for the confirmation button naming ${amount}")
            }
            PaymentStep::ConfirmNamedAmount { amount, .. } => {
                format!("click the confirmation naming ${amount}  <-- sends the money")
            }
            PaymentStep::WaitForButton { label } => {
                format!("wait for the {label:?} button to appear and be enabled")
            }
            PaymentStep::ConfirmSend { selector } => {
                format!("click the {selector:?} button  <-- sends the money")
            }
            PaymentStep::RequireSendConfirmed { amount } => {
                format!("require the ${amount} confirmation to be gone, proving the send posted")
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

/// Whether the loaded pay page pays exactly the account we resolved, and nobody
/// else.
///
/// Takes the report `PaymentStep::RequireRecipient`'s expression answers and
/// the numeric id [`VenmoBrowser::resolve_payee`] established. Returns the
/// refusal text on any answer that is not one payee with that id.
///
/// Split out of `execute` so a test can run the real comparison against the
/// real expression's real output. The 2026-09-05 false success was a sequence
/// whose every expression was correct and whose result was still wrong, and
/// asserting over the text of the JavaScript would not have caught it.
///
/// Three ways to refuse, and each is a page state observed on the live site:
///
/// - **no payee.** `txnUserDetails` is `[]` for a handle Venmo cannot resolve,
///   and also for the logged-in account's own handle, because Venmo will not
///   let you pay yourself. Nothing to match, so nothing is paid.
/// - **the wrong payee.** The id on the page is not the id we resolved. This
///   is the case the old check could never see: `?recipients=casper` loads a
///   perfectly valid form that pays Jordan Bryant.
/// - **more than one payee.** Venmo's pay form takes multiple recipients and
///   splits the amount among them. A second payee is money leaving to someone
///   this order never named, so a page carrying one is refused even when ours
///   is among them.
///
/// Compared on the id alone. The handle is carried into the message for the
/// operator but is not what decides: a handle can be released and re-registered
/// by somebody else, and the id cannot.
pub fn page_pays_only(
    report: &serde_json::Value,
    payee_id: &str,
) -> std::result::Result<(), String> {
    let url = report
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");

    if !report
        .get("found")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let why = report
            .get("why")
            .and_then(|v| v.as_str())
            .unwrap_or("the page answered nothing about who it pays");
        return Err(format!(
            "the Venmo page at {url} cannot say who it pays: {why}. The rendered form is \
             not evidence -- it shows the recipient as a display name only -- so this \
             refuses rather than reading one."
        ));
    }

    let payees: Vec<(String, String)> = report
        .get("payees")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|u| {
                    let field = |name: &str| {
                        u.get(name)
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    };
                    (field("id"), field("username"))
                })
                .collect()
        })
        .unwrap_or_default();

    // Rendered for the operator: who the page would actually have paid.
    let describe = |list: &[(String, String)]| {
        if list.is_empty() {
            "nobody".to_string()
        } else {
            list.iter()
                .map(|(id, handle)| {
                    if handle.is_empty() {
                        format!("id {id}")
                    } else {
                        format!("@{handle} (id {id})")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    };

    match payees.as_slice() {
        [(id, _)] if id == payee_id => Ok(()),
        [] => Err(format!(
            "the Venmo page at {url} names no payee at all. Venmo answers an empty payee \
             list for a handle it cannot resolve, and for the logged-in account's own \
             handle, because it will not pay you yourself."
        )),
        [_] => Err(format!(
            "the Venmo page at {url} pays {}, but the payee resolved for this order is id \
             {payee_id}. The page loaded a valid form for a different account.",
            describe(&payees)
        )),
        many => Err(format!(
            "the Venmo page at {url} carries {} payees ({}). Venmo splits the amount among \
             them, so some of this money would go to an account this order never named.",
            many.len(),
            describe(&payees)
        )),
    }
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
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };

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
    ///
    /// This used to also assert that the *last* step was a money step, on the
    /// reasoning that nothing should follow the send. That was the wrong
    /// invariant and it is the one the 2026-09-05 false success was written
    /// under: if nothing may follow the click, then nothing can ever check that
    /// the click worked. What must not follow the click is another *fill* or
    /// another *click*; a read-only verification must.
    #[test]
    fn every_money_moving_step_is_marked_irreversible() {
        let steps = a_payment();
        let money: Vec<_> = steps.iter().filter(|s| s.is_irreversible()).collect();
        assert_eq!(money.len(), 2, "the live flow is Pay then Confirm");

        let last_money = steps.iter().rposition(|s| s.is_irreversible()).unwrap();
        // Nothing after the last click may touch the page. A `Fill` or a
        // `Navigate` there would be acting on a payment that has already gone.
        for step in &steps[last_money + 1..] {
            assert!(
                matches!(step, PaymentStep::RequireSendConfirmed { .. }),
                "only a read-only confirmation may follow the send, found {step:?}"
            );
        }
        // The two money steps are adjacent-or-separated only by waits, so no
        // check is stranded between them where it could not act on the answer.
        assert!(
            steps[..last_money]
                .iter()
                .filter(|s| s.is_irreversible())
                .count()
                == 1
        );
    }

    /// The step that closes the false-success hole: the sequence does not end
    /// on a click.
    ///
    /// Order `esc_2c0cef0587c47bafd201e104` on 2026-09-05 ran every step above
    /// this one without error, in about three seconds, against a page an
    /// earlier drive had left filled -- and `pay` returned success for $2.01
    /// that never left the account. Nothing in the sequence had ever asked
    /// Venmo whether it did anything.
    #[test]
    fn the_sequence_ends_by_confirming_the_send_rather_than_by_clicking() {
        let steps = a_payment();
        assert!(
            matches!(
                steps.last().unwrap(),
                PaymentStep::RequireSendConfirmed { .. }
            ),
            "the last step must be the confirmation, not the click: {:?}",
            steps.last().unwrap()
        );
        match steps.last().unwrap() {
            PaymentStep::RequireSendConfirmed { amount } => assert_eq!(amount, "25.00"),
            other => panic!("expected RequireSendConfirmed, got {other:?}"),
        }
    }

    /// The unconfirmed failure is its own type, and it survives being wrapped.
    ///
    /// The driver returns it through `anyhow`, and the coordinator downcasts it
    /// back out to tell the operator that the form is probably still on screen.
    /// If it stopped being downcastable that message would silently become a
    /// generic browser fault, which is the message that was wrong before.
    #[test]
    fn an_unconfirmed_send_is_a_distinguishable_error() {
        let err = anyhow::Error::from(Unconfirmed {
            recipient: "jay-butera".into(),
            amount: "2.01".into(),
            why: "the confirmation button was still on the page".into(),
        });
        let found = err
            .downcast_ref::<Unconfirmed>()
            .expect("an Unconfirmed must survive the trip through anyhow");
        assert_eq!(found.amount, "2.01");
        assert_eq!(found.recipient, "jay-butera");

        // And it must not read as either verdict. A message that says the money
        // left strands it; one that says it did not invites a double payment.
        let text = err.to_string();
        assert!(text.contains("may or may not have left"), "{text}");
        assert!(text.contains("do not record this order paid"), "{text}");
    }

    /// The confirmation must not itself be a money step.
    ///
    /// If it were marked irreversible a dry run would stop at it, which is
    /// harmless, but it would also read as "this moves money" to every future
    /// reader of `is_irreversible` -- and the point of the step is that it
    /// moves nothing and only reads.
    #[test]
    fn the_confirmation_moves_no_money_and_clicks_nothing() {
        let step = PaymentStep::RequireSendConfirmed {
            amount: "2.01".to_string(),
        };
        assert!(!step.is_irreversible());
        let js = step.to_expression();
        assert!(
            !js.contains("click"),
            "the confirmation must not click: {js}"
        );
        assert!(
            !js.contains("value") && !js.contains("location.href ="),
            "the confirmation must not write to the page: {js}"
        );
    }

    /// The amount readback is the last thing that *reads the form* before the
    /// first click. This is the ordering NEW-3 was about.
    ///
    /// `RequireNoOpenSheet` now sits between it and the click. That is allowed
    /// and only that: it reads no form control, writes nothing, and refuses on
    /// a condition the amount cannot change. What must never appear here is a
    /// step that touches the amount or the note after the readback, because
    /// then the value clicked would not be the value checked.
    #[test]
    fn the_readback_is_the_last_step_before_any_money_moves() {
        let steps = a_payment();
        let first_money = steps.iter().position(|s| s.is_irreversible()).unwrap();
        let verify = steps
            .iter()
            .position(|s| matches!(s, PaymentStep::RequireAmount { .. }))
            .expect("the amount must be verified");
        assert!(verify < first_money, "the readback comes before the click");
        for step in &steps[verify + 1..first_money] {
            assert!(
                matches!(step, PaymentStep::RequireNoOpenSheet),
                "only a read-only refusal may sit between the readback and the \
                 click, found {step:?}"
            );
        }
    }

    /// What `resolve_payee` would have answered for `test-payee`.
    ///
    /// Constructed directly here because these tests are about the *shape* of
    /// the step list, which does not depend on the lookup having run. Every
    /// test that is about the check itself goes through the real expression
    /// and the real comparison in `tests/payment_page_test.rs`.
    fn a_resolved_payee() -> ResolvedPayee {
        ResolvedPayee {
            handle: "test-payee".to_string(),
            id: "2041148646359040020".to_string(),
            display_name: "Test Payee".to_string(),
        }
    }

    fn a_payment() -> Vec<PaymentStep> {
        VenmoBrowser::new("http://127.0.0.1:9222", 60).payment_steps(
            &PaymentRequest {
                recipient: "test-payee".to_string(),
                amount: "25.00".to_string(),
                note: "thanks".to_string(),
            },
            &a_resolved_payee(),
        )
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
        // Nothing that touches the form may come between the readback and the
        // click. `RequireNoOpenSheet` may, because it reads no form control:
        // see `the_readback_is_the_last_step_before_any_money_moves`.
        for step in &steps[verify + 1..confirm] {
            assert!(
                matches!(step, PaymentStep::RequireNoOpenSheet),
                "unexpected step between the amount readback and the click: {step:?}"
            );
        }

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

        assert!(
            check < first_fill,
            "check who we are paying before typing an amount"
        );

        match &steps[check] {
            PaymentStep::RequireRecipient {
                recipient,
                payee_id,
            } => {
                assert_eq!(recipient, "test-payee");
                // The id, not the handle, is what the page is checked against.
                assert_eq!(payee_id, "2041148646359040020");
            }
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

        assert!(
            js.contains("_valueTracker"),
            "must reset React's value tracker: {js}"
        );
        assert!(
            js.contains("getOwnPropertyDescriptor"),
            "must use the native setter: {js}"
        );
        assert!(
            js.contains("HTMLTextAreaElement"),
            "the note field is a textarea: {js}"
        );
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
            // A step that never binds an element handle cannot dereference a
            // missing one. `!!el && !el.disabled` answers about a handle it
            // does not reach through; `.some(...)` binds none at all; and a
            // `.map(...)` over a NodeList reads each node's text without ever
            // holding a lookup result that could be null. Everything that does
            // reach through a handle is checked below.
            if js.contains("!!el") || js.contains(".some(") || js.contains(".map(b =>") {
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
            note: "thanks abcd1234".to_string(),
        }
        .to_expression();
        assert!(js.contains("startsWith"), "{js}");
        assert!(js.contains("1.00"), "{js}");
        // Exactly one match, or it refuses rather than clicking the first.
        assert!(js.contains("hits.length > 1"), "{js}");
        assert!(js.contains("el.disabled"), "{js}");
        // It must not be looking for the decoy.
        assert!(!js.contains("=== 'Confirm'"), "{js}");
        // And the amount alone does not identify a sheet: the note this run
        // typed has to be on it, or an earlier drive's confirmation for
        // another payee at the same amount would be clicked.
        assert!(js.contains("carriesNote"), "{js}");
        assert!(js.contains("thanks abcd1234"), "{js}");
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
        assert!(
            amount_matches("$1,250.00", "1250.00"),
            "thousands separator"
        );
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
        assert!(
            !amount_matches("25.000", "25.00"),
            "more precision than cents"
        );
        assert!(!amount_matches("2.5.0", "25.00"), "not a number either");
    }

    /// The rendered amount is what `usdc_to_dollars` produced, so the two have
    /// to agree across the range the taker actually pays.
    #[test]
    fn every_amount_the_taker_renders_verifies_against_itself() {
        for units in [
            1u64,
            9_999,
            50_000,
            1_000_001,
            5_009_999,
            25_999_999,
            999_990_001,
        ] {
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
        let up_to_the_click: Vec<_> = steps.iter().take_while(|s| !s.is_irreversible()).collect();

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
