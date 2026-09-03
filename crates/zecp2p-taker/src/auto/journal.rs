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
//!
//! # Two rails in one journal
//!
//! Both settlement systems write here, and both run live at the same time. That
//! makes the key a [`WorkId`] rather than a bare deposit id: Base numbers its
//! deposits from a contract counter and Zcash names its escrows by outpoint, so
//! the two namespaces are otherwise free to collide on a small integer, and a
//! journal that cannot tell deposit 4499 from an escrow called 4499 reports the
//! wrong fill as in flight.
//!
//! `rail` is `#[serde(default)]` to [`Rail::Base`], so a journal written before
//! the native escrow existed reads back as what it is rather than failing. That
//! default is only ever applied to *reading old lines*; every new record states
//! its rail, and [`Rail`] itself refuses an unrecognised value rather than
//! defaulting, because a Zcash escrow evaluated by the Base state machine never
//! broadcasts its release.
//!
//! # The one-slot rule is per rail
//!
//! "One fill at a time" exists because two open intents can double-spend the
//! same Venmo balance and lose track of which payment proves which. That reason
//! is about the Venmo account, which both rails share, so the slot is global:
//! [`Journal::in_flight`] answers across both. A caller that wants to know
//! whether one rail specifically is busy asks
//! [`Journal::in_flight_on`].

use alloy::primitives::{B256, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::auto::rail::{Rail, WorkId};

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
    /// Which settlement system this fill belongs to.
    ///
    /// Defaults to Base so a journal written before the native escrow existed
    /// still reads. See the module note: the default applies to old lines only.
    #[serde(default = "default_rail")]
    pub rail: Rail,
    /// Rail-local identity. The Base deposit id, or zero on a rail that has no
    /// such number; [`FillRecord::work_id`] is the key that actually
    /// distinguishes fills.
    pub deposit_id: U256,
    /// The escrow outpoint, on rails that name their work that way rather than
    /// by an integer. Absent on Base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outpoint: Option<String>,
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

fn default_rail() -> Rail {
    Rail::Base
}

impl FillRecord {
    /// A Base fill, keyed on its deposit id.
    pub fn new(deposit_id: U256, session_id: B256, amount: U256, conversion_rate: U256, recipient: String) -> Self {
        Self {
            rail: Rail::Base,
            deposit_id,
            outpoint: None,
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

    /// A native-escrow fill, keyed on its funding outpoint.
    ///
    /// `amount` and `conversion_rate` carry the same meaning they do on Base:
    /// the 6-decimal USD the enclave will be told to release, and the rate it
    /// is proved against. They are the escrow's `usd_amount_6dec` and
    /// `rate_18dec`, which is why the shared sizing works unchanged.
    pub fn new_zec(
        outpoint: String,
        amount: U256,
        conversion_rate: U256,
        recipient: String,
    ) -> Self {
        Self {
            rail: Rail::Zec,
            // The escrow has no deposit id; its identity is the outpoint.
            deposit_id: U256::ZERO,
            outpoint: Some(outpoint),
            session_id: B256::ZERO,
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

    /// The key this record is stored under, unique across both rails.
    pub fn work_id(&self) -> WorkId {
        match (&self.rail, &self.outpoint) {
            (Rail::Zec, Some(outpoint)) => WorkId {
                rail: Rail::Zec,
                local: outpoint.clone(),
            },
            (rail, _) => WorkId {
                rail: *rail,
                local: self.deposit_id.to_string(),
            },
        }
    }

    /// How this fill is named in a message to a human.
    pub fn describe(&self) -> String {
        self.work_id().to_string()
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
        let mut by_deposit: std::collections::BTreeMap<WorkId, FillRecord> = Default::default();
        for (n, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<FillRecord>(line) {
                Ok(record) => {
                    by_deposit.insert(record.work_id(), record);
                }
                Err(e) => tracing::warn!(line = n + 1, error = %e, "skipping unreadable journal line"),
            }
        }
        Ok(by_deposit.into_values().collect())
    }

    /// The fill currently holding the daemon's one slot, if any.
    ///
    /// Across both rails. The slot is global because the constraint it enforces
    /// is about the shared Venmo account, not about either chain.
    pub fn in_flight(&self) -> Result<Option<FillRecord>> {
        Ok(self.latest()?.into_iter().find(|r| r.state.is_open()))
    }

    /// The open fill on one rail specifically, if any.
    ///
    /// For a caller reporting per-rail status. It is not the slot check: a
    /// daemon that used this to decide whether it may start work would run one
    /// fill per rail concurrently, which is two open payments against one Venmo
    /// balance.
    pub fn in_flight_on(&self, rail: Rail) -> Result<Option<FillRecord>> {
        Ok(self
            .latest()?
            .into_iter()
            .find(|r| r.rail == rail && r.state.is_open()))
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

    /// The collision the WorkId key exists to prevent. A Base deposit and a
    /// Zcash escrow can carry the same local name, and a journal that conflates
    /// them overwrites one fill's state with the other's.
    #[test]
    fn the_two_rails_do_not_overwrite_each_other() {
        let (_dir, j) = journal();

        let mut base = record();
        base.state = FillState::Signalled;
        j.record(&base).unwrap();

        let mut zec = FillRecord::new_zec(
            base.deposit_id.to_string(),
            U256::from(1_500_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "jay-butera".into(),
        );
        zec.state = FillState::Paid;
        j.record(&zec).unwrap();

        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 2, "one rail overwrote the other: {latest:#?}");

        let on_base = j.in_flight_on(Rail::Base).unwrap().expect("base fill");
        assert_eq!(on_base.state, FillState::Signalled);
        let on_zec = j.in_flight_on(Rail::Zec).unwrap().expect("zec fill");
        assert_eq!(on_zec.state, FillState::Paid);
    }

    /// The slot is global, not per rail. It exists because two open payments
    /// draw on one Venmo balance, and that account does not know which chain
    /// settles them.
    #[test]
    fn the_in_flight_slot_spans_both_rails() {
        let (_dir, j) = journal();
        let zec = FillRecord::new_zec(
            "d599b8cd:0".into(),
            U256::from(1_500_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "jay-butera".into(),
        );
        j.record(&zec).unwrap();

        // A Base daemon asking whether it may start work must see the escrow.
        let held = j.in_flight().unwrap().expect("the slot is taken");
        assert_eq!(held.rail, Rail::Zec);
        assert!(j.in_flight_on(Rail::Base).unwrap().is_none());
    }

    /// A journal written before the native escrow existed has no `rail` field.
    /// It must read back as the Base fill it is, not fail and not become a
    /// Zcash escrow.
    #[test]
    fn a_journal_written_before_the_second_rail_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.jsonl");
        std::fs::write(
            &path,
            r#"{"deposit_id":"0x1193","session_id":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"paid","amount":"0x4a63ad","conversion_rate":"0xdc0e2ecfa4dfe00","recipient":"test-payee","updated_at":"2026-09-01T12:00:00Z"}
"#,
        )
        .unwrap();

        let j = Journal::open(&path).unwrap();
        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].rail, Rail::Base, "an old line is a Base fill");
        assert_eq!(latest[0].state, FillState::Paid);
        assert_eq!(latest[0].outpoint, None);
        assert_eq!(latest[0].work_id().to_string(), "base/4499");
    }

    /// Every new record states its rail on the wire, so the default above never
    /// has to be relied on for anything this build wrote.
    #[test]
    fn a_new_record_writes_its_rail_out() {
        let base = serde_json::to_string(&record()).unwrap();
        assert!(base.contains(r#""rail":"base""#), "{base}");

        let zec = serde_json::to_string(&FillRecord::new_zec(
            "d599b8cd:0".into(),
            U256::from(1_500_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "jay-butera".into(),
        ))
        .unwrap();
        assert!(zec.contains(r#""rail":"zec""#), "{zec}");
        assert!(zec.contains(r#""outpoint":"d599b8cd:0""#), "{zec}");
    }

    /// The dangerous state is dangerous on both rails: on Base the fiat is gone
    /// until `fulfillIntent`, on Zcash until the release is mined.
    #[test]
    fn an_escrow_left_mid_payment_also_needs_an_operator() {
        let (_dir, j) = journal();
        let mut zec = FillRecord::new_zec(
            "d599b8cd:0".into(),
            U256::from(1_500_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "jay-butera".into(),
        );
        zec.state = FillState::Paying;
        j.record(&zec).unwrap();

        let stuck = j.needs_operator().unwrap();
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].rail, Rail::Zec);
        assert_eq!(stuck[0].describe(), "zec/d599b8cd:0");
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
