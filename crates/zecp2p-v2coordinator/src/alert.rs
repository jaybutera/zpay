//! Getting an operator's attention, and deciding what deserves it.
//!
//! Finding 7: the only thing that reached a phone was the session keeper's
//! logout message. A held payment slot, a failed order, a paid order whose
//! release never landed, a dead sweep - each of those was a `tracing` line in a
//! journal nobody was reading, or nothing at all.
//!
//! # Shape
//!
//! One hook, run as a subprocess, handed a JSON alert on stdin. Not a built-in
//! client for any messaging service: where an alert should go is the LP's own
//! decision, and an LP running this is not necessarily the LP whose keeper
//! script posts to a particular chat. A subprocess makes "send it to my pager",
//! "append it to a file" and "post it to my own bot" all one line of config, and
//! makes none of them a code change.
//!
//! The hook is spawned with no shell. Alert bodies carry a payee handle, which
//! a caller chose, and a note, which a caller influenced; handing either to
//! `sh -c` would be handing a stranger a command line.
//!
//! # Suppression
//!
//! Every alert has a key, and a key repeats no more often than
//! `alerts.repeat_minutes`. The existing session keeper re-alerts every 20
//! minutes with no state at all, so the first real incident buries the channel
//! it is trying to be heard on; a stuck order here is one message and then a
//! reminder.
//!
//! Suppression is per process. A restart re-alerts, which is the right
//! direction: an operator who restarted the coordinator wants to know whether
//! the condition survived it.

use std::collections::HashMap;
use std::sync::Arc;

use crate::state::AppState;

/// How urgent an alert is. The hook receives it as a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Something is wrong and money may be at stake. A person should look now.
    Critical,
    /// Something needs attention before it becomes critical.
    Warning,
    /// A condition that had fired has cleared.
    Resolved,
}

/// One thing worth telling an operator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    /// What repeats are measured against. Two alerts about the same stuck order
    /// share a key; two different stuck orders do not.
    pub key: String,
    pub severity: Severity,
    /// One line, for a notification body.
    pub summary: String,
    /// What an operator should do about it, where there is a specific answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Structured context, so a hook can route or filter on it.
    pub detail: serde_json::Value,
}

impl Alert {
    /// A fill line nobody but a person can retire.
    ///
    /// The most expensive alert on the board: this state holds the payment slot
    /// with no automatic exit, which is the 2026-09-06 incident exactly.
    pub fn needs_operator(work: &str, held_minutes: i64, note: Option<&str>) -> Self {
        Self {
            key: format!("needs_operator:{work}"),
            severity: Severity::Critical,
            summary: format!(
                "a fill needs a person: work {work} has been waiting {held_minutes} minutes"
            ),
            action: Some(
                "read the payment feed, then retire the line with `resolve-fill` recording \
                 what you saw. Until then no other order can be paid."
                    .to_string(),
            ),
            detail: serde_json::json!({
                "work_id": work,
                "held_minutes": held_minutes,
                "note": note,
            }),
        }
    }

    /// The payment slot has been held longer than an ordinary trade takes.
    pub fn slot_held(work: &str, held_minutes: i64, state: &str) -> Self {
        Self {
            key: format!("slot_held:{work}"),
            severity: Severity::Warning,
            summary: format!(
                "the payment slot has been held {held_minutes} minutes by work {work} ({state})"
            ),
            action: Some(
                "no other order can be paid while this is held. Check whether the fill is \
                 progressing or stuck."
                    .to_string(),
            ),
            detail: serde_json::json!({
                "work_id": work,
                "held_minutes": held_minutes,
                "fill_state": state,
            }),
        }
    }

    /// The dollars have gone and the escrow has not released.
    ///
    /// Critical whatever its age, because it is the one state where the LP has
    /// paid and holds nothing for it.
    pub fn paid_not_released(order_id: &str, age_minutes: i64) -> Self {
        Self {
            key: format!("paid_stall:{order_id}"),
            severity: Severity::Critical,
            summary: format!(
                "order {order_id} has been paid but not released for {age_minutes} minutes"
            ),
            action: Some(
                "the dollars have left and the escrow has not. Check the attestation path: \
                 the escrow refunds to the user at T whether or not this resolves."
                    .to_string(),
            ),
            detail: serde_json::json!({
                "order_id": order_id,
                "age_minutes": age_minutes,
            }),
        }
    }

    /// A sweep pass has not finished in a long time.
    pub fn sweep_stale(minutes: u64) -> Self {
        Self {
            key: "sweep_stale".to_string(),
            severity: Severity::Critical,
            summary: format!("no sweep has completed in {minutes} minutes"),
            action: Some(
                "no order is being advanced: no funding is being noticed, no deadline \
                 checked, no refund offered. Check whether the coordinator is wedged."
                    .to_string(),
            ),
            detail: serde_json::json!({ "minutes_since_last_sweep": minutes }),
        }
    }

    /// Orders were cut off by the per-order watchdog.
    pub fn sweep_watchdog(count: usize, seconds: u64) -> Self {
        Self {
            key: "sweep_watchdog".to_string(),
            severity: Severity::Warning,
            summary: format!(
                "{count} order(s) hit the {seconds}s per-order watchdog in one sweep"
            ),
            action: Some(
                "a path with no timeout of its own is blocking. The orders are not lost - \
                 the next sweep re-enters - but something is taking far longer than it should."
                    .to_string(),
            ),
            detail: serde_json::json!({ "orders": count, "watchdog_seconds": seconds }),
        }
    }

    /// The fiat rail cannot pay right now.
    pub fn rail_unhealthy(reason: &str) -> Self {
        Self {
            key: "rail_unhealthy".to_string(),
            severity: Severity::Critical,
            summary: "the fiat rail cannot pay right now".to_string(),
            action: Some(
                "no escrow will be paid until this clears. Every order that locks meanwhile \
                 waits, and refunds at T."
                    .to_string(),
            ),
            detail: serde_json::json!({ "reason": reason }),
        }
    }

    /// The rail's float is running out.
    ///
    /// Rail-agnostic on purpose: this says a balance in cents is under a
    /// configured number, and nothing about where the money is held.
    pub fn low_balance(balance_cents: u64, threshold_cents: u64) -> Self {
        Self {
            key: "low_balance".to_string(),
            severity: Severity::Warning,
            summary: format!(
                "the fiat float is ${}.{:02}, under the ${}.{:02} alert threshold",
                balance_cents / 100,
                balance_cents % 100,
                threshold_cents / 100,
                threshold_cents % 100
            ),
            action: Some(
                "top the account up. Below the payment amount plus the configured reserve, \
                 this coordinator stops reserving the slot and orders wait rather than fail."
                    .to_string(),
            ),
            detail: serde_json::json!({
                "balance_cents": balance_cents,
                "threshold_cents": threshold_cents,
            }),
        }
    }

    /// The float is too low to take on a payment at all.
    pub fn float_exhausted(balance_cents: u64, needed_cents: u64) -> Self {
        Self {
            key: "float_exhausted".to_string(),
            severity: Severity::Critical,
            summary: format!(
                "the fiat float (${}.{:02}) will not cover the next payment plus reserve \
                 (${}.{:02})",
                balance_cents / 100,
                balance_cents % 100,
                needed_cents / 100,
                needed_cents % 100
            ),
            action: Some(
                "orders are being left unpaid rather than half-paid. Top up; nothing is \
                 lost, and the escrows refund at T if the float does not arrive first."
                    .to_string(),
            ),
            detail: serde_json::json!({
                "balance_cents": balance_cents,
                "needed_cents": needed_cents,
            }),
        }
    }

    /// Node calls are being served by a fallback endpoint.
    pub fn on_fallback_node(endpoint: &str) -> Self {
        Self {
            key: "node_fallback".to_string(),
            severity: Severity::Warning,
            summary: format!("node calls are going to a fallback endpoint ({endpoint})"),
            action: Some(
                "the primary endpoint is not answering. This is working, and it is one \
                 endpoint away from not working."
                    .to_string(),
            ),
            detail: serde_json::json!({ "endpoint": endpoint }),
        }
    }
}

/// Remembers what has already been said, so a condition is not repeated at the
/// rate the sweep notices it.
#[derive(Debug, Default)]
pub struct AlertHistory {
    last_sent: std::sync::Mutex<HashMap<String, std::time::Instant>>,
}

impl AlertHistory {
    /// Whether this key may be sent now, recording it if so.
    ///
    /// The check and the record are one operation under one lock: two sweeps
    /// noticing the same stuck order together would both pass a check followed
    /// by a separate write.
    pub fn should_send(&self, key: &str, repeat: std::time::Duration) -> bool {
        let Ok(mut seen) = self.last_sent.lock() else {
            // A poisoned lock must not silence alerts. Sending twice is the
            // safe direction here.
            return true;
        };
        let now = std::time::Instant::now();
        match seen.get(key) {
            Some(at) if now.duration_since(*at) < repeat => false,
            _ => {
                seen.insert(key.to_string(), now);
                true
            }
        }
    }

    /// Forgets a key, so a condition that clears and returns alerts again
    /// rather than waiting out the repeat window.
    pub fn clear(&self, key: &str) {
        if let Ok(mut seen) = self.last_sent.lock() {
            seen.remove(key);
        }
    }
}

/// Sends one alert, unless it was sent too recently.
///
/// Always logs, whether or not it delivers: an alert nobody configured a hook
/// for must still be findable afterwards, and the log is what an operator reads
/// when reconstructing what happened.
pub async fn fire(state: &Arc<AppState>, alert: Alert) {
    let repeat = std::time::Duration::from_secs(state.config.alerts.repeat_minutes * 60);
    if !state.alerts.should_send(&alert.key, repeat) {
        tracing::debug!(key = %alert.key, "alert suppressed as a repeat");
        return;
    }

    match alert.severity {
        Severity::Critical => tracing::error!(
            key = %alert.key,
            summary = %alert.summary,
            detail = %alert.detail,
            "ALERT"
        ),
        Severity::Warning => tracing::warn!(
            key = %alert.key,
            summary = %alert.summary,
            detail = %alert.detail,
            "ALERT"
        ),
        Severity::Resolved => tracing::info!(
            key = %alert.key,
            summary = %alert.summary,
            "alert cleared"
        ),
    }

    let command = state.config.alerts.notify_command.clone();
    if command.is_empty() {
        return;
    }
    let timeout = std::time::Duration::from_secs(state.config.alerts.notify_timeout_seconds.max(1));
    let payload = envelope(state, &alert);
    let key = alert.key.clone();
    if let Err(e) = run_hook(command, payload, timeout).await {
        // A failed hook is not an emergency of its own, and it must not
        // propagate: an alert that panicked the sweep would be worse than the
        // condition it was reporting.
        tracing::error!(
            key = %key,
            error = %format!("{e:#}"),
            "the notify hook failed, so this alert reached only the log"
        );
    }
}

/// What the hook reads on stdin.
///
/// Carries which coordinator it came from, because an operator may run more
/// than one and a message that does not say which is a message they have to
/// go and check. The instance name is configured, not derived from a hostname:
/// an LP running two coordinators on one host needs to tell them apart.
fn envelope(state: &Arc<AppState>, alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "schema": "zecp2p.alert.v1",
        "instance": state.instance_name(),
        "network": state.network_name(),
        "build": crate::version::GIT_HASH,
        "sent_at": chrono::Utc::now().to_rfc3339(),
        "key": alert.key,
        "severity": alert.severity,
        "summary": alert.summary,
        "action": alert.action,
        "detail": alert.detail,
    })
}

/// Runs the hook, writes the payload to its stdin, and kills it on timeout.
async fn run_hook(
    command: Vec<String>,
    payload: serde_json::Value,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("alerts.notify_command is empty"))?;

    // No shell. The body carries a handle and a note a caller influenced.
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context_msg("could not start alerts.notify_command")?;

    if let Some(mut stdin) = child.stdin.take() {
        let body = serde_json::to_vec(&payload)?;
        // Failing to write is not fatal on its own: a hook that ignores stdin
        // and takes everything from argv is a reasonable hook, and it closes
        // the pipe. The wait below is what decides whether it worked.
        let _ = stdin.write_all(&body).await;
        let _ = stdin.shutdown().await;
    }

    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(out) => {
            let out = out.with_context_msg("the notify hook could not be waited on")?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!(
                    "the notify hook exited {}: {}",
                    out.status,
                    stderr.trim().chars().take(400).collect::<String>()
                );
            }
            Ok(())
        }
        Err(_) => {
            // The child is not killed here: `wait_with_output` consumed it.
            // A hook that outlives its budget is left to the OS, and the
            // coordinator stops waiting - which is the property that matters,
            // since this runs at the end of a sweep.
            anyhow::bail!("the notify hook did not finish within {} s", timeout.as_secs())
        }
    }
}

/// `anyhow::Context` for types that do not implement it directly here.
trait ContextMsg<T> {
    fn with_context_msg(self, msg: &'static str) -> anyhow::Result<T>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> ContextMsg<T> for Result<T, E> {
    fn with_context_msg(self, msg: &'static str) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::anyhow!("{msg}: {e}"))
    }
}

/// Looks over everything worth alerting on, once per sweep.
///
/// Reads only. Every condition here is derived from state some other part of
/// the coordinator already wrote, so this cannot itself change what an order
/// does - which is what makes it safe to run at the end of every pass.
pub async fn scan(state: &Arc<AppState>) {
    let cfg = &state.config.alerts;

    // The sweep that has not finished. Checked here as well as by whatever
    // notices it externally, because a sweep slow enough to matter still runs
    // this at the end of the previous one.
    if cfg.sweep_age_minutes > 0 {
        if let Some(since) = state.since_last_sweep() {
            let minutes = since.as_secs() / 60;
            if minutes >= cfg.sweep_age_minutes {
                fire(state, Alert::sweep_stale(minutes)).await;
            }
        }
    }

    // A paid order whose release has not landed: the LP's money is out and
    // nothing is held against it.
    if cfg.paid_age_minutes > 0 {
        for order in state.store.open_orders() {
            if order.stage != crate::order::Stage::Paid {
                continue;
            }
            let age = (chrono::Utc::now() - order.updated_at).num_minutes();
            if age >= i64::try_from(cfg.paid_age_minutes).unwrap_or(i64::MAX) {
                fire(state, Alert::paid_not_released(&order.order_id, age)).await;
            } else {
                state.alerts.clear(&format!("paid_stall:{}", order.order_id));
            }
        }
    }

    // The journal: a line needing a person, and a slot held too long. Both come
    // from the same read.
    match state.sweep_journal().await {
        Ok(records) => scan_journal(state, &records).await,
        Err(e) => {
            tracing::debug!(error = %format!("{e:#}"), "could not read the journal to scan for alerts");
        }
    }

    // Serving from a fallback endpoint is working, and is one endpoint from
    // not working.
    if state.nodes.on_fallback() {
        let endpoint = crate::nodes::redact(&state.nodes.current().url);
        fire(state, Alert::on_fallback_node(&endpoint)).await;
    } else {
        state.alerts.clear("node_fallback");
    }
}

async fn scan_journal(
    state: &Arc<AppState>,
    records: &[zecp2p_taker::auto::journal::FillRecord],
) {
    use zecp2p_taker::auto::journal::FillState;

    let cfg = &state.config.alerts;
    let now = chrono::Utc::now();

    for record in records {
        let work = record.work_id().to_string();
        let age = (now - record.updated_at).num_minutes();

        match record.state {
            // No automatic exit exists for this state at all, so it is alerted
            // on immediately rather than after an age threshold.
            FillState::NeedsOperator => {
                fire(
                    state,
                    Alert::needs_operator(&work, age, record.note.as_deref()),
                )
                .await;
            }
            // Every other open state holds the payment slot. Held is normal;
            // held for a long time is not.
            s if s.is_open() => {
                if cfg.slot_age_minutes > 0
                    && age >= i64::try_from(cfg.slot_age_minutes).unwrap_or(i64::MAX)
                {
                    fire(state, Alert::slot_held(&work, age, &format!("{s:?}"))).await;
                } else {
                    state.alerts.clear(&format!("slot_held:{work}"));
                }
            }
            _ => {
                // Closed. Anything said about it has stopped being true.
                state.alerts.clear(&format!("slot_held:{work}"));
                state.alerts.clear(&format!("needs_operator:{work}"));
            }
        }
    }
}
