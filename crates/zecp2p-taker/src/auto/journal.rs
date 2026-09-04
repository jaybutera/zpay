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

/// Which record holds the payment slot against `mine`, if any.
///
/// The gate both daemons use, as a pure function over the journal's latest
/// states so it can be tested without a chain, a browser or a process.
///
/// R4-1: the rule is "any open record that is not mine", and it has to be a
/// scan rather than a first-match against `in_flight`, because `latest` is
/// ordered by `WorkId` and `Rail::Base` sorts before `Rail::Zec`. A taker that
/// matched only the first record was told its own open Base deposit was the
/// holder and carried on, never seeing the coordinator's `Paying` line behind
/// it.
pub fn holder_among(latest: &[FillRecord], mine: &WorkId) -> Option<FillRecord> {
    latest
        .iter()
        .find(|r| r.state.is_open() && &r.work_id() != mine)
        .cloned()
}

/// Whether an open record means a payment for that work item may already have
/// gone out.
///
/// The states past reservation. `Seen` is not one of them: it is written before
/// any network call and means only that somebody intends to pay.
///
/// R6-2: both daemons need this against their *own* work id, not just against
/// somebody else's. The taker re-enters its own deposits routinely - an error
/// anywhere after the payment rewinds the scan cursor - and without this check
/// it wrote a fresh `Seen` over its own `Paid` line, signalled a second intent
/// and paid again. The `Paid` line also vanished from every later reader,
/// including the startup check that exists to catch exactly this.
pub fn may_already_have_paid(state: FillState) -> bool {
    matches!(
        state,
        FillState::Signalling | FillState::Paying | FillState::Paid | FillState::NeedsOperator
    )
}

/// The work item's own record, when it says a payment may already have gone.
///
/// Separate from [`holder_among`], which is about *other* work: this is the
/// question "have I already paid for this one", and the two have different
/// answers for `Seen`.
pub fn own_payment_underway(latest: &[FillRecord], mine: &WorkId) -> Option<FillRecord> {
    latest
        .iter()
        .find(|r| &r.work_id() == mine && r.state.is_open() && may_already_have_paid(r.state))
        .cloned()
}

/// Why a fill may not start or continue.
#[derive(Debug, Clone)]
pub enum SlotVerdict {
    /// Nothing in the journal stops this fill.
    Free,
    /// This work item already has a fill that may have moved money.
    OwnPaymentUnderway(FillRecord),
    /// Another work item holds the one slot.
    HeldByAnother(FillRecord),
}

impl SlotVerdict {
    pub fn is_free(&self) -> bool {
        matches!(self, SlotVerdict::Free)
    }

    /// What to tell an operator, and what it means for their money.
    pub fn why(&self, mine_describes: &str) -> String {
        match self {
            SlotVerdict::Free => String::new(),
            SlotVerdict::OwnPaymentUnderway(r) => format!(
                "{mine_describes} already has a fill recorded as {:?}. The journal is \
                 written before the send button, so money may already have gone out for \
                 it; re-entering would pay twice. Read the Venmo feed and finish or \
                 cancel that fill before this one is filled again.",
                r.state
            ),
            SlotVerdict::HeldByAnother(r) => format!(
                "{} holds the one payment slot ({:?}). One payment at a time: there is \
                 one Venmo balance, and two entries of the same amount to the same handle \
                 cannot be told apart in the feed.",
                r.describe(),
                r.state
            ),
        }
    }
}

/// The whole slot decision for one work item, in one place.
///
/// R6-a: both daemons and the tests call *this*, rather than each assembling
/// the same two checks in the right order. A test that rebuilt the logic proved
/// only that the test was self-consistent - reverting the real call site to an
/// unconditional append left every such test green.
///
/// The order matters. The own-work question comes first, because "I may have
/// already paid for this" and "somebody else is paying" call for different
/// answers, and the first is the more expensive mistake.
pub fn slot_verdict(latest: &[FillRecord], mine: &WorkId) -> SlotVerdict {
    if let Some(own) = own_payment_underway(latest, mine) {
        return SlotVerdict::OwnPaymentUnderway(own);
    }
    if let Some(holder) = holder_among(latest, mine) {
        return SlotVerdict::HeldByAnother(holder);
    }
    SlotVerdict::Free
}

/// The gate a fill must pass before it touches a chain, and the reservation it
/// takes if it does.
///
/// R6-a: this is the *call site*, not a helper beside it. A test that rebuilt
/// the decision proved only that the test agreed with itself - the reviewer
/// reverted `handle_one` to an unconditional append and every such test stayed
/// green. `handle_one` now calls this and nothing else, so a test that calls it
/// exercises the same code, and removing the call breaks the build rather than
/// passing quietly.
///
/// Returns the reservation on success. `Err` carries why not, ready to be shown
/// to an operator.
pub fn open_fill(
    journal: &Journal,
    mine: &WorkId,
    describes: &str,
    make: impl FnOnce() -> FillRecord,
) -> Result<Result<FillRecord, String>> {
    let mut refused = None;
    let claimed = journal.claim_if(|existing| {
        let verdict = slot_verdict(existing, mine);
        if !verdict.is_free() {
            refused = Some(verdict.why(describes));
            return None;
        }
        Some(make())
    })?;

    match (claimed, refused) {
        (Some(record), _) => Ok(Ok(record)),
        (None, Some(why)) => Ok(Err(why)),
        (None, None) => anyhow::bail!("the payment slot could not be reserved"),
    }
}

/// An advisory exclusive lock held for the life of the value.
///
/// `flock(2)`, which is per open file description and released when the handle
/// closes - including if the process dies, which matters here: a daemon killed
/// mid-append must not leave the journal locked against its own restart.
///
/// Advisory and cooperative: it binds the two daemons in this repository
/// because both take it, and it is not a defence against a third writer that
/// does not. That is the right tool for the job - both writers are ours.
struct FileLock {
    /// The descriptor, not a borrow of the handle: the caller still needs
    /// `&mut File` to write while the lock is held.
    #[cfg(unix)]
    fd: std::os::unix::io::RawFd,
}

impl FileLock {
    fn exclusive(file: &std::fs::File, path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // Blocking: the critical section is one small append, and waiting
            // for it is always better than writing over somebody's line.
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("could not lock the journal at {}", path.display())
                });
            }
            Ok(Self { fd })
        }
        #[cfg(not(unix))]
        {
            let _ = (file, path);
            Ok(Self {})
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // Best-effort: closing the handle releases it anyway.
            unsafe { libc::flock(self.fd, libc::LOCK_UN) };
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
        let mut record = record.clone();
        record.updated_at = chrono::Utc::now();
        let line = serde_json::to_string(&record).context("could not serialise a fill record")?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)
            .with_context(|| format!("could not open the journal at {}", self.path.display()))?;

        // Exclusive for the duration of the append, so a reader in another
        // process never sees a half-written line and two writers never
        // interleave. See `write_line` for why one syscall is not enough on its
        // own.
        let _lock = FileLock::exclusive(&file, &self.path)?;

        // R6-a: this updates a fill; it does not open one. Opening goes through
        // `open_fill`, which decides and claims under this same lock.
        //
        // The check is here rather than left to a reviewer's memory because the
        // bypass is one line and the consequence is a second payment: a caller
        // that appended a fresh record for unseen work would write straight over
        // the gate, and the reviewer's reproduction of exactly that is what this
        // refusal exists to make impossible. It costs one read of a file already
        // open and already locked.
        let existing = Self::parse(&std::fs::read_to_string(&self.path).with_context(|| {
            format!("could not read the journal at {}", self.path.display())
        })?);
        let work = record.work_id();
        if !existing.iter().any(|r| r.work_id() == work) {
            anyhow::bail!(
                "refusing to open a fill for {work} through `record`. A first line for a \
                 work item is a claim on the one payment slot, and it has to be taken \
                 through `open_fill`, which decides and writes under one lock. Appending \
                 it directly is how the same escrow gets paid twice."
            );
        }

        Self::write_line(&mut file, &line, &self.path)
    }

    /// Appends a line without the gate, for tests and for recovery tooling.
    ///
    /// The escape hatch `record` deliberately does not give: it opens a fill
    /// without deciding anything. Callers are test fixtures staging a journal
    /// state, and an operator following the recovery runbook, who has read the
    /// Venmo feed and is the one making the decision.
    ///
    /// Production code takes `open_fill` instead. Nothing in either daemon
    /// calls this.
    pub fn append_unchecked(&self, record: &FillRecord) -> Result<()> {
        let mut record = record.clone();
        record.updated_at = chrono::Utc::now();
        let line = serde_json::to_string(&record).context("could not serialise a fill record")?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("could not open the journal at {}", self.path.display()))?;
        let _lock = FileLock::exclusive(&file, &self.path)?;
        Self::write_line(&mut file, &line, &self.path)
    }

    /// Appends one line in a single `write` syscall.
    ///
    /// R4-2: this used to be `writeln!(file, "{line}")` on an unbuffered
    /// `File`, which is **two** syscalls - the JSON, then a bare newline
    /// (confirmed with strace). Two processes appending at the same instant
    /// could therefore produce `AB\n\n`: one malformed line that `latest`
    /// skips with a warning, so *both* records disappear - including a
    /// `Paying` line, which is the one record whose absence lets the same
    /// escrow be paid twice.
    ///
    /// The newline goes into the buffer and one `write_all` issues it. On an
    /// `O_APPEND` file a single write under `PIPE_BUF` is atomic on Linux, so
    /// even without the lock above two appends can no longer split each other.
    /// Both together are deliberate: the lock also covers the read side.
    fn write_line(file: &mut std::fs::File, line: &str, path: &Path) -> Result<()> {
        use std::io::Write;

        // R5-e: a `write_all` that dies partway - a full disk is the realistic
        // way - leaves a line with no terminating newline, and the next append
        // glues onto it. That makes *two* records into one unparseable line
        // rather than one, and `parse` skips it, so a `Paying` line can vanish
        // along with whatever followed it.
        //
        // Under the same lock as the append, so no reader sees the gap: if the
        // file does not end in a newline, end it before writing.
        if Self::needs_terminator(file, path)? {
            tracing::warn!(
                journal = %path.display(),
                "the journal did not end in a newline, which means an earlier append was \
                 cut short. Terminating it so this record does not glue onto the remains."
            );
            file.write_all(b"\n").with_context(|| {
                format!("could not terminate the journal at {}", path.display())
            })?;
        }

        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        file.write_all(buf.as_bytes())
            .with_context(|| format!("could not write to the journal at {}", path.display()))?;
        file.flush()
            .with_context(|| format!("could not flush the journal at {}", path.display()))?;
        Ok(())
    }

    /// Whether the file's last byte is something other than a newline.
    ///
    /// An empty file needs no terminator. Anything else that does not end in
    /// `\n` is the remains of an append that did not finish.
    fn needs_terminator(file: &std::fs::File, path: &Path) -> Result<bool> {
        use std::io::{Read, Seek, SeekFrom};

        let len = file
            .metadata()
            .with_context(|| format!("could not stat the journal at {}", path.display()))?
            .len();
        if len == 0 {
            return Ok(false);
        }

        // Read the last byte through a separate handle: this one is `O_APPEND`,
        // and seeking it would not move where a write lands anyway.
        let mut reader = std::fs::File::open(path)
            .with_context(|| format!("could not read the journal at {}", path.display()))?;
        reader
            .seek(SeekFrom::End(-1))
            .with_context(|| format!("could not seek the journal at {}", path.display()))?;
        let mut last = [0u8; 1];
        reader
            .read_exact(&mut last)
            .with_context(|| format!("could not read the journal at {}", path.display()))?;
        Ok(last[0] != b'\n')
    }

    /// Reads the journal, decides, and appends - all under one lock.
    ///
    /// R4-3: the daemons' slot check was a read, then some work, then a write,
    /// with nothing holding the file in between. Each narrowed its own window,
    /// but between two *processes* the exposure was as wide as whatever ran
    /// between them - four network calls on the taker's side - and they share
    /// one Venmo account. This closes it: the decision and the claim happen
    /// with the lock held, so no other process can observe the gap.
    ///
    /// `decide` is handed every record's latest state. Returning `None` means
    /// "do not claim", and nothing is written.
    pub fn claim_if(
        &self,
        decide: impl FnOnce(&[FillRecord]) -> Option<FillRecord>,
    ) -> Result<Option<FillRecord>> {
        // Opened for append *and* read: the same handle carries the lock, so
        // there is no moment between deciding and appending.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)
            .with_context(|| format!("could not open the journal at {}", self.path.display()))?;
        let _lock = FileLock::exclusive(&file, &self.path)?;

        let existing = Self::parse(&std::fs::read_to_string(&self.path).with_context(|| {
            format!("could not read the journal at {}", self.path.display())
        })?);

        let Some(mut record) = decide(&existing) else {
            return Ok(None);
        };
        record.updated_at = chrono::Utc::now();
        let line = serde_json::to_string(&record).context("could not serialise a fill record")?;
        Self::write_line(&mut file, &line, &self.path)?;
        Ok(Some(record))
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

        Ok(Self::parse(&contents))
    }

    /// Last line per work item wins.
    ///
    /// A malformed line is skipped rather than fatal: a truncated final write
    /// must not make the whole journal unreadable, which is precisely when it
    /// is needed most. `write_line` and the lock exist so that a *concurrent*
    /// write cannot produce one of these in the first place.
    fn parse(contents: &str) -> Vec<FillRecord> {
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
        by_deposit.into_values().collect()
    }

    /// The fill currently holding the daemon's one slot, if any.
    ///
    /// Across both rails. The slot is global because the constraint it enforces
    /// is about the shared Venmo account, not about either chain.
    pub fn in_flight(&self) -> Result<Option<FillRecord>> {
        Ok(self.latest()?.into_iter().find(|r| r.state.is_open()))
    }

    /// The open fill holding the slot against `mine`, if any.
    ///
    /// R4-1: [`Self::in_flight`] returns the *first* open record, and `latest`
    /// is ordered by `WorkId`, where `Rail::Base` sorts before `Rail::Zec`. So
    /// a caller that compared `in_flight()` to its own work id was told "that
    /// is you, carry on" whenever its own Base record happened to be open -
    /// and never saw the coordinator's `Paying` line on the Zec rail behind it.
    /// The taker re-enters its own deposits routinely after a restart, because
    /// `start_block` rescans `lookback_blocks`, so this was reachable rather
    /// than theoretical.
    ///
    /// Every open record that is not `mine` counts.
    pub fn holder_against(&self, mine: &WorkId) -> Result<Option<FillRecord>> {
        Ok(holder_among(&self.latest()?, mine))
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
        j.append_unchecked(&r).unwrap();
        r.state = FillState::Signalled;
        r.intent_hash = Some(B256::repeat_byte(0xbb));
        j.append_unchecked(&r).unwrap();

        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].state, FillState::Signalled);
        assert_eq!(latest[0].intent_hash, Some(B256::repeat_byte(0xbb)));
    }

    #[test]
    fn a_finished_fill_releases_the_slot() {
        let (_dir, j) = journal();
        let mut r = record();
        j.append_unchecked(&r).unwrap();
        assert!(j.in_flight().unwrap().is_some());
        r.state = FillState::Fulfilled;
        j.append_unchecked(&r).unwrap();
        assert!(j.in_flight().unwrap().is_none());
    }

    /// The reason this module exists: a crash between the click and the receipt
    /// leaves a record a human has to read before the daemon does anything.
    #[test]
    fn a_paying_record_is_treated_as_money_that_may_have_left() {
        let (_dir, j) = journal();
        let mut r = record();
        r.state = FillState::Paying;
        j.append_unchecked(&r).unwrap();

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
        j.append_unchecked(&r).unwrap();
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
        j.append_unchecked(&r).unwrap();

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
        j.append_unchecked(&base).unwrap();

        let mut zec = FillRecord::new_zec(
            base.deposit_id.to_string(),
            U256::from(1_500_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "jay-butera".into(),
        );
        zec.state = FillState::Paid;
        j.append_unchecked(&zec).unwrap();

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
        j.append_unchecked(&zec).unwrap();

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
        j.append_unchecked(&zec).unwrap();

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
        j.append_unchecked(&r).unwrap();

        let back = &j.latest().unwrap()[0];
        assert_eq!(back.conversion_rate, U256::from(990_881_148_896_019_200u128));
        assert_eq!(back.signalled_at_ms, Some(1_756_000_000_000));
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use alloy::primitives::{B256, U256};

    fn zec(byte: u8, state: FillState) -> FillRecord {
        let mut r = FillRecord::new_zec(
            format!("{}:0", hex::encode([byte; 32])),
            U256::from(700_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "alice".into(),
        );
        r.state = state;
        r
    }

    fn base(id: u64, state: FillState) -> FillRecord {
        let mut r = FillRecord::new(
            U256::from(id),
            B256::repeat_byte(0xaa),
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
            "alice".into(),
        );
        r.state = state;
        r
    }

    #[test]
    fn a_zec_record_holds_the_slot_against_the_takers_own_base_deposit() {
        // R4-1. `in_flight` returns the *first* open record, and `latest` is
        // ordered by `WorkId` with `Rail::Base` before `Rail::Zec`. So a taker
        // comparing `in_flight()` to its own work id was told "that is you,
        // carry on" whenever its own Base record was open, and never saw the
        // coordinator's `Paying` line behind it. The taker re-enters its own
        // deposits after a restart, because `start_block` rescans
        // `lookback_blocks`, so this was reachable.
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();

        // The taker's own deposit, open, on the rail that sorts first.
        j.append_unchecked(&base(4499, FillState::Signalled)).unwrap();
        // And the coordinator, mid-payment, on the rail that sorts second.
        j.append_unchecked(&zec(0xcc, FillState::Paying)).unwrap();

        let mine = WorkId::base(U256::from(4499));

        // The old check: the first open record is the taker's own, so it reads
        // as "nobody else holds the slot".
        let first = j.in_flight().unwrap().unwrap();
        assert_eq!(first.work_id(), mine, "Base really does sort first");

        // The fixed check sees the coordinator.
        let holder = j
            .holder_against(&mine)
            .unwrap()
            .expect("the coordinator's Paying line must hold the slot");
        assert_eq!(holder.rail, Rail::Zec);
        assert_eq!(holder.state, FillState::Paying);
    }

    #[test]
    fn a_work_items_own_record_does_not_hold_the_slot_against_itself() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();
        j.append_unchecked(&base(4499, FillState::Signalled)).unwrap();
        assert!(j
            .holder_against(&WorkId::base(U256::from(4499)))
            .unwrap()
            .is_none());
    }

    #[test]
    fn an_append_is_one_write_so_two_writers_cannot_split_a_line() {
        // R4-2. `writeln!` on an unbuffered `File` is two syscalls - the JSON,
        // then a bare newline - so two processes appending at the same instant
        // could produce one malformed line, which `parse` skips: both records
        // vanish, including a `Paying` line, which is the one whose absence
        // lets an escrow be paid twice.
        //
        // Threads rather than processes, because the failure is in the write
        // pattern rather than in the process boundary, and `flock` is per open
        // file description so each `record` call takes its own.
        //
        // Verifying this by reverting: restoring `writeln!` alone leaves this
        // passing, because the lock in `record` keeps two appenders apart on
        // its own. Revert the lock as well to see the split. The two are
        // deliberate belt and braces - the lock is advisory and binds only
        // programs that take it, while the single write holds against anything.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fills.jsonl");
        let j = std::sync::Arc::new(Journal::open(&path).unwrap());

        let mut threads = Vec::new();
        for t in 0..8u8 {
            let j = j.clone();
            threads.push(std::thread::spawn(move || {
                for i in 0..25u8 {
                    // Distinct work ids, so every record must survive.
                    j.append_unchecked(&zec(t * 25 + i, FillState::Paying)).unwrap();
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 200, "lines were lost or split");
        for (n, line) in lines.iter().enumerate() {
            serde_json::from_str::<FillRecord>(line)
                .unwrap_or_else(|e| panic!("line {} is not a record: {e}\n{line}", n + 1));
        }
        // And every distinct work item is still readable.
        assert_eq!(Journal::open(&path).unwrap().latest().unwrap().len(), 200);
    }

    #[test]
    fn a_torn_last_line_is_terminated_before_the_next_append() {
        // R5-e. A `write_all` cut short by a full disk leaves a line with no
        // newline; the next append glues onto it and makes both records
        // unparseable, so `parse` drops them - including, potentially, a
        // `Paying` line and whatever followed it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fills.jsonl");
        let j = Journal::open(&path).unwrap();

        j.append_unchecked(&zec(0x01, FillState::Paying)).unwrap();

        // The disk fills up partway through the second append.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"rail\":\"zec\",\"deposit_i").unwrap();
        }
        assert!(!std::fs::read_to_string(&path).unwrap().ends_with('\n'));

        // The next append must not glue onto the fragment.
        j.append_unchecked(&zec(0x02, FillState::Seen)).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 3, "the fragment and the new record were merged");
        // The first and last parse; only the fragment is lost, which is the
        // most that can be saved.
        serde_json::from_str::<FillRecord>(lines[0]).expect("the first record survived");
        serde_json::from_str::<FillRecord>(lines[2]).expect("the new record is readable");

        // And both readable records come back.
        let latest = j.latest().unwrap();
        assert_eq!(latest.len(), 2, "a readable record was lost: {latest:?}");
    }

    #[test]
    fn claim_if_decides_and_appends_under_one_lock() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();

        // Nothing there: the claim goes down.
        let claimed = j
            .claim_if(|existing| {
                assert!(existing.is_empty());
                Some(zec(0x01, FillState::Seen))
            })
            .unwrap();
        assert!(claimed.is_some());

        // Now the decision sees it, and declining writes nothing.
        let before = std::fs::read_to_string(dir.path().join("fills.jsonl")).unwrap();
        let declined = j
            .claim_if(|existing| {
                assert_eq!(existing.len(), 1);
                None
            })
            .unwrap();
        assert!(declined.is_none());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("fills.jsonl")).unwrap(),
            before,
            "declining must not write"
        );
    }

    #[test]
    fn only_one_of_many_racing_claimants_takes_the_slot() {
        // What `claim_if` is for: the read and the write are one critical
        // section, so exactly one of a crowd wins.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fills.jsonl");
        let j = std::sync::Arc::new(Journal::open(&path).unwrap());
        let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut threads = Vec::new();
        for t in 0..8u8 {
            let j = j.clone();
            let winners = winners.clone();
            threads.push(std::thread::spawn(move || {
                let got = j
                    .claim_if(|existing| {
                        if existing.iter().any(|r| r.state.is_open()) {
                            return None;
                        }
                        // The decision takes time, the way a real one does: the
                        // coordinator reads the chain and the taker makes four
                        // network calls between its read and its claim. If the
                        // lock does not span the decision, every thread sees an
                        // empty journal here and every one of them claims.
                        std::thread::sleep(std::time::Duration::from_millis(40));
                        Some(zec(t, FillState::Paying))
                    })
                    .unwrap();
                if got.is_some() {
                    winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(
            winners.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "more than one claimant took the one slot"
        );
    }
}
