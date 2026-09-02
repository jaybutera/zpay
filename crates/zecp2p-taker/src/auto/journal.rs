//! Durable record of a fill in flight.
//!
//! There is exactly one moment in this pipeline where a crash is expensive: the
//! window between the Venmo payment landing and `fulfillIntent` confirming. On
//! either side of it a restart is cheap. Inside it, a daemon that has forgotten
//! what it did pays the same order twice, or cancels an intent whose fiat has
//! already left.
//!
//! So the rule is: **the journal is written before the money moves, not after.**
//! An entry that says `Paying` when the daemon starts up is not proof a payment
//! went out, and it is not proof one did not. It is proof that a human has to
//! look, which is the correct outcome, and it is strictly better than the
//! in-memory pipeline's answer of no record at all.
//!
//! The journal is also what makes "one fill at a time" durable.
//! `agent.rs::tick` returns after the first handled deposit, which gives that
//! property by accident of loop shape; a restart in the middle of a fill loses
//! it. [`Journal::in_flight`] restores it.

use alloy::primitives::{B256, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where a fill has got to.
///
/// The order matters: each state is entered *before* the action it names, so
/// finding one on restart says "this may have happened", never "this did".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillState {
    /// Deposit seen, nothing done.
    Seen,
    /// About to signal. A restart here means checking for our own
    /// `IntentSignaled` on this deposit before signalling again.
    Signalling,
    /// Intent exists on chain and is recorded. Safe to cancel.
    Signalled,
    /// About to click send in Venmo. **The dangerous state.** A restart here
    /// needs a human to check the Venmo feed before anything else happens.
    Paying,
    /// Venmo reported the payment sent. Fiat is gone; only the attestation
    /// stands between the taker and the escrowed USDC.
    Paid,
    /// `fulfillIntent` confirmed. Done.
    Fulfilled,
    /// Given back deliberately. Stake unlocked, maker's USDC released.
    Cancelled,
    /// Stopped and handed to a human, with the reason recorded.
    NeedsOperator,
}

impl FillState {
    /// Is this fill still holding the daemon's one in-flight slot?
    pub fn is_open(self) -> bool {
        !matches!(
            self,
            FillState::Fulfilled | FillState::Cancelled
        )
    }

    /// Has money left, as far as the journal knows or suspects?
    ///
    /// `Paying` counts. The entry is written before the click, so a crash there
    /// leaves a state that cannot distinguish "about to pay" from "paid", and
    /// the safe reading of an ambiguous record about real money is the
    /// expensive one.
    pub fn fiat_may_have_left(self) -> bool {
        matches!(self, FillState::Paying | FillState::Paid)
    }
}

/// One fill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillRecord {
    pub deposit_id: U256,
    pub session_id: B256,
    pub state: FillState,
    #[serde(default)]
    pub intent_hash: Option<B256>,
    /// Intent amount in 6-decimal USDC units.
    pub amount: U256,
    /// The intent's conversion rate, scaled by 1e18. Needed again at
    /// attestation time as `INTENT_RATE`, and getting it wrong there produced
    /// a `releaseAmount` short by $0.035 on the 2026-09-01 fill.
    pub conversion_rate: U256,
    /// The intent's on-chain signal time in milliseconds. Needed as
    /// `INTENT_TIMESTAMP_MS`; a mismatch reverts with
    /// `UPV: Snapshot timestamp mismatch`.
    #[serde(default)]
    pub signalled_at_ms: Option<u64>,
    pub recipient: String,
    /// Dollars as sent, e.g. "4.84".
    #[serde(default)]
    pub paid: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl FillRecord {
    pub fn new(deposit_id: U256, session_id: B256, amount: U256, conversion_rate: U256, recipient: String) -> Self {
        Self {
            deposit_id,
            session_id,
            state: FillState::Seen,
            intent_hash: None,
            amount,
            conversion_rate,
            signalled_at_ms: None,
            recipient,
            paid: None,
            note: None,
            updated_at: chrono::Utc::now(),
        }
    }
}

/// A newline-delimited JSON log, one line per state change.
///
/// Append-only on purpose. A journal that rewrites entries can lose the
/// previous state on a partial write, and the previous state is exactly what a
/// human needs when they arrive at a `Paying` record. Replaying to find the
/// latest per deposit is cheap at this volume.
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("could not create {}", parent.display()))?;
            }
        }
        Ok(Self { path })
    }

    /// Append a state change. Flushed before returning, because the caller's
    /// next act is the one this record exists to describe.
    pub fn record(&self, record: &FillRecord) -> Result<()> {
        use std::io::Write;

        let mut record = record.clone();
        record.updated_at = chrono::Utc::now();
        let line = serde_json::to_string(&record).context("could not serialise a fill record")?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("could not open the journal at {}", self.path.display()))?;
        writeln!(file, "{line}").context("could not write to the journal")?;
        file.flush().context("could not flush the journal")?;
        Ok(())
    }

    /// Every deposit's latest state.
    pub fn latest(&self) -> Result<Vec<FillRecord>> {
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("could not read {}", self.path.display()))
            }
        };

        // Last line per deposit wins. A malformed line is skipped rather than
        // fatal: a truncated final write must not make the whole journal
        // unreadable, which is precisely when it is needed most.
        let mut by_deposit: std::collections::BTreeMap<U256, FillRecord> = Default::default();
        for (n, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<FillRecord>(line) {
                Ok(record) => {
                    by_deposit.insert(record.deposit_id, record);
                }
                Err(e) => tracing::warn!(line = n + 1, error = %e, "skipping unreadable journal line"),
            }
        }
        Ok(by_deposit.into_values().collect())
    }

    /// The fill currently holding the daemon's one slot, if any.
    pub fn in_flight(&self) -> Result<Option<FillRecord>> {
        Ok(self.latest()?.into_iter().find(|r| r.state.is_open()))
    }

    /// Fills a restart must not touch without a human.
    ///
    /// Anything where the fiat may have left. The daemon refuses to start a new
    /// fill while one of these exists, because the alternative is paying the
    /// same order twice.
    pub fn needs_operator(&self) -> Result<Vec<FillRecord>> {
        Ok(self
            .latest()?
            .into_iter()
            .filter(|r| r.state.is_open() && r.state.fiat_may_have_left())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> FillRecord {
        FillRecord::new(
            U256::from(4499),
            B256::repeat_byte(0xaa),
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
            "test-payee".into(),
        )
    }

    fn journal() -> (tempfile::TempDir, Journal) {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();
        (dir, j)
    }

    #[test]
    fn an_absent_journal_is_empty_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("nothing.jsonl")).unwrap();
        assert!(j.latest().unwrap().is_empty());
        assert!(j.in_flight().unwrap().is_none());
    }

    #[test]
    fn the_latest_state_per_deposit_wins() {
        let (_dir, j) = journal();
        let mut r = record();
        j.record(&r).unwrap();
        r.state = FillState::Signalled;
        r.intent_hash = Some(B256::repeat_byte(0xbb));
        j.record(&r).unwrap();

        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].state, FillState::Signalled);
        assert_eq!(latest[0].intent_hash, Some(B256::repeat_byte(0xbb)));
    }

    #[test]
    fn a_finished_fill_releases_the_slot() {
        let (_dir, j) = journal();
        let mut r = record();
        j.record(&r).unwrap();
        assert!(j.in_flight().unwrap().is_some());
        r.state = FillState::Fulfilled;
        j.record(&r).unwrap();
        assert!(j.in_flight().unwrap().is_none());
    }

    /// The reason this module exists: a crash between the click and the receipt
    /// leaves a record a human has to read before the daemon does anything.
    #[test]
    fn a_paying_record_is_treated_as_money_that_may_have_left() {
        let (_dir, j) = journal();
        let mut r = record();
        r.state = FillState::Paying;
        j.record(&r).unwrap();

        let stuck = j.needs_operator().unwrap();
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].deposit_id, U256::from(4499));
        assert!(FillState::Paying.fiat_may_have_left());
    }

    /// A signalled-but-unpaid fill is recoverable without a human: cancel and
    /// retry costs gas and nothing else.
    #[test]
    fn a_signalled_record_does_not_need_an_operator() {
        let (_dir, j) = journal();
        let mut r = record();
        r.state = FillState::Signalled;
        j.record(&r).unwrap();
        assert!(j.needs_operator().unwrap().is_empty());
        assert!(j.in_flight().unwrap().is_some());
    }

    /// A truncated last line must not hide the records before it.
    #[test]
    fn a_partial_final_write_does_not_destroy_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fills.jsonl");
        let j = Journal::open(&path).unwrap();
        let mut r = record();
        r.state = FillState::Paid;
        j.record(&r).unwrap();

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{\"deposit_id\":\"nope").unwrap();

        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].state, FillState::Paid);
    }

    /// The rate and timestamp are carried because the attestation needs both,
    /// and a daemon that restarts after signalling cannot re-derive them from
    /// the payment alone.
    #[test]
    fn carries_what_the_attestation_will_need() {
        let (_dir, j) = journal();
        let mut r = record();
        r.state = FillState::Paid;
        r.signalled_at_ms = Some(1_756_000_000_000);
        j.record(&r).unwrap();

        let back = &j.latest().unwrap()[0];
        assert_eq!(back.conversion_rate, U256::from(990_881_148_896_019_200u128));
        assert_eq!(back.signalled_at_ms, Some(1_756_000_000_000));
    }
}
