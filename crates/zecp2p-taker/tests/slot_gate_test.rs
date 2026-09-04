//! The payment slot as both daemons see it.
//!
//! `zecp2p-v2coordinator` pays Venmo from the same account this taker does, and
//! the two coordinate through one journal file. The gate is `holder_among`, and
//! these are the cases that matter when the other daemon is the holder.

use alloy::primitives::{B256, U256};
use zecp2p_taker::auto::journal::{
    holder_among, open_fill, slot_verdict, FillRecord, FillState, Journal, SlotVerdict,
};
use zecp2p_taker::auto::rail::{Rail, WorkId};

fn zec_record(byte: u8, state: FillState) -> FillRecord {
    let mut r = FillRecord::new_zec(
        format!("{}:0", hex::encode([byte; 32])),
        U256::from(700_000u64),
        U256::from(1_000_000_000_000_000_000u128),
        "alice".into(),
    );
    r.state = state;
    r
}

fn base_record(deposit: u64, state: FillState) -> FillRecord {
    let mut r = FillRecord::new(
        U256::from(deposit),
        B256::repeat_byte(0xaa),
        U256::from(4_875_437u64),
        U256::from(990_881_148_896_019_200u128),
        "alice".into(),
    );
    r.state = state;
    r
}

#[test]
fn the_coordinator_mid_payment_holds_the_slot_against_a_taker_deposit() {
    // The case the shared journal exists for: the coordinator is driving a
    // browser, and this taker must not start a fill.
    let journal = vec![zec_record(0xcc, FillState::Paying)];
    let holder = holder_among(&journal, &WorkId::base(U256::from(4499)))
        .expect("the coordinator holds the slot");
    assert_eq!(holder.rail, Rail::Zec);
    assert_eq!(holder.state, FillState::Paying);
}

#[test]
fn a_coordinator_record_is_seen_behind_the_takers_own_open_deposit() {
    // R4-1. `latest` is ordered by `WorkId`, and `Rail::Base` sorts before
    // `Rail::Zec`, so the taker's own record comes first. A gate that compared
    // only the first record read "that is me, carry on" and never saw the
    // coordinator. The taker re-enters its own deposits after a restart,
    // because `start_block` rescans `lookback_blocks`, so this is reachable
    // rather than theoretical.
    let mine = WorkId::base(U256::from(4499));
    let journal = vec![
        base_record(4499, FillState::Signalled),
        zec_record(0xcc, FillState::Paying),
    ];

    // The ordering really is what the finding says.
    assert_eq!(journal[0].work_id(), mine);
    assert!(journal[0].state.is_open());

    let holder = holder_among(&journal, &mine)
        .expect("the coordinator's Paying line must hold the slot");
    assert_eq!(holder.rail, Rail::Zec, "the taker's own record was returned");
}

#[test]
fn every_open_coordinator_state_holds_the_slot() {
    // Not just `Paying`. `Seen` is the coordinator's reservation, written
    // before its chain call; `Paid` is a payment waiting on an attestation;
    // `NeedsOperator` is a payment nobody has reconciled. All of them mean the
    // one Venmo balance is committed.
    let mine = WorkId::base(U256::from(4499));
    for state in [
        FillState::Seen,
        FillState::Paying,
        FillState::Paid,
        FillState::NeedsOperator,
    ] {
        let journal = vec![zec_record(0xcc, state)];
        assert!(
            holder_among(&journal, &mine).is_some(),
            "{state:?} on the other rail must hold the slot"
        );
    }
}

#[test]
fn a_finished_coordinator_trade_frees_the_slot() {
    let mine = WorkId::base(U256::from(4499));
    for state in [FillState::Fulfilled, FillState::Cancelled] {
        let journal = vec![zec_record(0xcc, state)];
        assert!(
            holder_among(&journal, &mine).is_none(),
            "{state:?} is finished and must not hold the slot"
        );
    }
}

#[test]
fn the_gate_reads_what_the_other_daemon_actually_wrote() {
    // End to end through the file, so the shapes cannot drift: the coordinator
    // writes a Zec record, the taker reads it back and is blocked.
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("fills.jsonl");

    // The coordinator's side.
    let coordinator = Journal::open(&shared).unwrap();
    coordinator.append_unchecked(&zec_record(0xcc, FillState::Paying)).unwrap();

    // The taker's side, a separate handle on the same file.
    let taker = Journal::open(&shared).unwrap();
    let holder = taker
        .holder_against(&WorkId::base(U256::from(4499)))
        .unwrap()
        .expect("the taker must see the coordinator's claim");
    assert_eq!(holder.state, FillState::Paying);
    assert_eq!(holder.rail, Rail::Zec);

    // And once the coordinator finishes, the taker may proceed.
    coordinator.append_unchecked(&zec_record(0xcc, FillState::Fulfilled)).unwrap();
    assert!(taker
        .holder_against(&WorkId::base(U256::from(4499)))
        .unwrap()
        .is_none());
}

#[test]
fn the_gate_the_taker_runs_refuses_a_coordinator_reservation() {
    // R6-a. The earlier version of this test rebuilt the decision inside the
    // test, so it proved only that the test agreed with itself: the reviewer
    // reverted `handle_one` to an unconditional append and all seven of these
    // stayed green. This calls `slot_verdict`, which is the function
    // `handle_one` calls - at the top, and again inside `claim_if` under the
    // lock - so a change to the rule shows up here.
    let journal = vec![zec_record(0xcc, FillState::Seen)];
    let mine = WorkId::base(U256::from(4499));

    let verdict = slot_verdict(&journal, &mine);
    assert!(!verdict.is_free(), "the taker would reserve on top of the coordinator");
    assert!(matches!(verdict, SlotVerdict::HeldByAnother(_)));
    assert!(
        verdict.why("deposit 4499").contains("one payment slot"),
        "the refusal must say why: {}",
        verdict.why("deposit 4499")
    );
}

#[test]
fn the_gate_refuses_a_deposit_this_taker_may_already_have_paid() {
    // R6-2. The taker re-enters its own deposits routinely: an error anywhere
    // after the payment rewinds the scan cursor. Without this, the reservation
    // wrote a fresh `Seen` over the `Paid` line, a second intent was signalled,
    // a second payment went out - and the `Paid` line vanished from every later
    // reader, including the startup check meant to catch exactly this.
    // R9-1: the states from `Paying` on. The pre-payment ones are displaceable,
    // because a crash in one of them would otherwise lock the deposit out for
    // good, and the compare-and-set stops the crashed attempt coming back.
    let mine = WorkId::base(U256::from(4499));
    for state in [
        FillState::Paying,
        FillState::Paid,
        FillState::NeedsOperator,
    ] {
        let journal = vec![base_record(4499, state)];
        let verdict = slot_verdict(&journal, &mine);
        assert!(
            matches!(verdict, SlotVerdict::OwnPaymentUnderway(_)),
            "{state:?} on this deposit must stop it being filled again, got {verdict:?}"
        );
        assert!(
            verdict.why("deposit 4499").contains("pay twice"),
            "the refusal must name the risk: {}",
            verdict.why("deposit 4499")
        );
    }
}

#[test]
fn a_standing_reservation_may_be_displaced_but_a_payment_may_not() {
    // R8-1 blocked a second reservation, which closed a burying hole and opened
    // a stall: a crash between reserving and the next write left a `Seen`
    // nobody would advance, and the deposit was refused forever.
    //
    // R9-1 splits the two. A pre-payment line may be displaced, because the
    // compare-and-set makes that safe - the displaced holder cannot advance and
    // cannot give the slot back. A line at `Paying` or past it may not, because
    // those mean money may already have gone out.
    let mine = WorkId::base(U256::from(4499));

    for displaceable in [
        FillState::Seen,
        FillState::Signalling,
        FillState::Signalled,
    ] {
        let journal = vec![base_record(4499, displaceable)];
        assert!(
            slot_verdict(&journal, &mine).is_free(),
            "{displaceable:?} is pre-payment: a crash there must not lock the deposit out"
        );
    }

    for blocking in [
        FillState::Paying,
        FillState::Paid,
        FillState::NeedsOperator,
    ] {
        let journal = vec![base_record(4499, blocking)];
        assert!(
            matches!(
                slot_verdict(&journal, &mine),
                SlotVerdict::OwnPaymentUnderway(_)
            ),
            "{blocking:?} means money may have moved and must still block"
        );
    }
}

#[test]
fn a_closed_line_does_not_stop_a_retry() {
    // The other half: a fill that ended - crashed and was cancelled, or
    // declined - must not lock its deposit out forever. Only an *open* line
    // holds the slot.
    let mine = WorkId::base(U256::from(4499));
    for state in [FillState::Cancelled, FillState::Fulfilled] {
        let journal = vec![base_record(4499, state)];
        assert!(
            slot_verdict(&journal, &mine).is_free(),
            "{state:?} is finished and must not block a retry"
        );
    }
}

#[test]
fn a_finished_own_fill_does_not_stop_the_deposit() {
    let mine = WorkId::base(U256::from(4499));
    for state in [FillState::Fulfilled, FillState::Cancelled] {
        let journal = vec![base_record(4499, state)];
        assert!(
            slot_verdict(&journal, &mine).is_free(),
            "{state:?} is finished and must not block the deposit"
        );
    }
}

#[test]
fn racing_reservations_leave_exactly_one_holder() {
    // The same thing under real contention, with a decision that takes time -
    // which is what the taker's does: three chain calls and an HTTP round-trip.
    let dir = tempfile::tempdir().unwrap();
    let journal = std::sync::Arc::new(Journal::open(dir.path().join("fills.jsonl")).unwrap());
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut threads = Vec::new();
    for t in 0..6u8 {
        let journal = journal.clone();
        let winners = winners.clone();
        threads.push(std::thread::spawn(move || {
            // Half the threads are takers, half are coordinators.
            let (mine, record) = if t % 2 == 0 {
                (
                    WorkId::base(U256::from(4000 + t as u64)),
                    base_record(4000 + t as u64, FillState::Seen),
                )
            } else {
                let r = zec_record(t, FillState::Seen);
                (r.work_id(), r)
            };
            let got = journal
                .claim_if(|existing| {
                    if holder_among(existing, &mine).is_some() {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    Some(record.clone())
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
        "more than one daemon reserved the one payment slot"
    );
}

// ---------- the real call site ----------
//
// R6-a: everything above tests the decision. These test the entry point
// `handle_one` actually calls - `open_fill` - so a call site that stopped
// asking would fail here rather than pass quietly. Reverting `handle_one` to an
// unconditional `journal.record` now breaks the build, because `open_fill` is
// the only thing that returns the reservation it needs.

fn open_for(journal: &Journal, deposit: u64) -> Result<FillRecord, String> {
    open_fill(
        journal,
        &WorkId::base(U256::from(deposit)),
        &format!("deposit {deposit}"),
        || base_record(deposit, FillState::Seen),
    )
    .expect("the journal is readable")
}

#[test]
fn open_fill_refuses_while_the_coordinator_holds_the_slot() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    journal.append_unchecked(&zec_record(0xcc, FillState::Paying)).unwrap();

    let refused = open_for(&journal, 4499).expect_err("the fill must be refused");
    assert!(refused.contains("one payment slot"), "{refused}");

    // And nothing was written: a refused fill leaves no trace to clean up.
    let open = journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.state.is_open())
        .count();
    assert_eq!(open, 1, "the refused fill wrote a reservation anyway");
}

#[test]
fn open_fill_refuses_a_deposit_that_may_already_have_been_paid() {
    // R6-2 at the call site. An error after the payment rewinds the scan
    // cursor, so the next poll arrives here on a deposit already paid for.
    for state in [FillState::Paying, FillState::Paid, FillState::NeedsOperator] {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
        journal.append_unchecked(&base_record(4499, state)).unwrap();

        let refused = open_for(&journal, 4499).expect_err(&format!(
            "a deposit recorded as {state:?} must not be filled again"
        ));
        assert!(refused.contains("pay twice"), "{refused}");
    }
}

#[test]
fn open_fill_will_not_write_seen_over_a_paid_line() {
    // The specific damage: a fresh `Seen` over `Paid` hides the payment from
    // every later reader, including the startup check meant to catch it.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let mut paid = base_record(4499, FillState::Paid);
    paid.paid = Some("2.00".into());
    journal.append_unchecked(&paid).unwrap();

    let refused = open_for(&journal, 4499).expect_err("a paid deposit must not be re-entered");
    assert!(refused.contains("pay twice"), "{refused}");

    // The `Paid` line is still what a reader sees.
    let latest = journal.latest().unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].state, FillState::Paid, "the Paid line was overwritten");
    assert!(!journal.needs_operator().unwrap().is_empty(), "the startup check went blind");
}

#[test]
fn open_fill_takes_the_slot_when_it_is_free() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let record = open_for(&journal, 4499).expect("a free slot is taken");
    assert_eq!(record.state, FillState::Seen);

    // And it now holds the slot against the coordinator.
    let held = journal
        .holder_against(&WorkId::base(U256::from(4500)))
        .unwrap();
    assert!(held.is_some(), "the reservation did not hold the slot");
}

#[test]
fn only_one_of_two_daemons_opens_a_fill() {
    // Both entry points, racing on one file, with a decision that takes time.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fills.jsonl");
    let journal = std::sync::Arc::new(Journal::open(&path).unwrap());
    let winners = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut threads = Vec::new();
    for t in 0..6u8 {
        let journal = journal.clone();
        let winners = winners.clone();
        threads.push(std::thread::spawn(move || {
            let deposit = 4000 + t as u64;
            let got = open_fill(
                &journal,
                &WorkId::base(U256::from(deposit)),
                &format!("deposit {deposit}"),
                || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    base_record(deposit, FillState::Seen)
                },
            )
            .unwrap();
            if got.is_ok() {
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
        "more than one fill opened against one Venmo balance"
    );
}

#[test]
fn a_first_line_cannot_be_appended_around_the_gate() {
    // R6-a, the structural half. The reviewer's reproduction was to revert
    // `handle_one` to `journal.record(&fresh_record)`, and every test stayed
    // green because none of them exercised that path - a gate is only as good
    // as the absence of a way round it.
    //
    // `record` now refuses to open a fill. It updates one that exists; opening
    // goes through `open_fill`, which decides and claims under one lock. So the
    // bypass fails where it is written rather than passing quietly, and a
    // reviewer reverting the call site sees it immediately.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    // The coordinator holds the slot.
    journal
        .append_unchecked(&zec_record(0xcc, FillState::Paying))
        .unwrap();

    // The bypass: a fresh record for work the journal has never seen.
    let err = journal
        .record(&base_record(4499, FillState::Seen))
        .expect_err("record must not open a fill");
    let text = format!("{err:#}");
    assert!(
        text.contains("open_fill"),
        "the refusal must name the way in: {text}"
    );
    assert!(text.contains("paid twice"), "{text}");

    // And nothing was written, so the coordinator still holds the slot alone.
    let open: Vec<_> = journal
        .latest()
        .unwrap()
        .into_iter()
        .filter(|r| r.state.is_open())
        .collect();
    assert_eq!(open.len(), 1, "the bypass wrote a line: {open:?}");
    assert_eq!(open[0].rail, Rail::Zec);
}

#[test]
fn record_still_updates_a_fill_that_exists() {
    // The other half: every legitimate use is an update, and none of them may
    // be broken by the refusal above.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let mut record = open_fill(
        &journal,
        &WorkId::base(U256::from(4499)),
        "deposit 4499",
        || base_record(4499, FillState::Seen),
    )
    .unwrap()
    .expect("the slot is free");

    for state in [
        FillState::Signalling,
        FillState::Signalled,
        FillState::Paying,
        FillState::Paid,
        FillState::Fulfilled,
    ] {
        record.state = state;
        journal
            .record(&record)
            .unwrap_or_else(|e| panic!("{state:?} must be recordable: {e:#}"));
    }

    let latest = journal.latest().unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].state, FillState::Fulfilled);
}

#[test]
fn a_dry_run_gives_the_slot_back() {
    // R6-b. A dry run reserves and then stops, and on a journal shared with
    // `zecp2p-v2coordinator` a `Seen` line left behind blocks that coordinator
    // from paying anything - so a rehearsal would stall live trades until an
    // operator noticed. The reservation is given back.
    //
    // This drives the same two library calls `handle_one` makes: `open_fill` to
    // reserve, then `record` to close it out.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let record = open_fill(
        &journal,
        &WorkId::base(U256::from(4499)),
        "deposit 4499",
        || base_record(4499, FillState::Seen),
    )
    .unwrap()
    .expect("the slot is free");

    // Mid-dry-run: the coordinator is blocked.
    assert!(
        journal
            .holder_against(&WorkId::zec("aa", 0))
            .unwrap()
            .is_some(),
        "the reservation should hold the slot while it stands"
    );

    // The dry run ends the way `handle_one` ends it: through the shared
    // compare-and-set, not a direct write. R8-c: this test used to call
    // `record` with a comment claiming it matched the call site, which stopped
    // being true when every give-back moved to `release_if_still_ours`.
    zecp2p_taker::auto::journal::release_if_still_ours(
        &journal,
        &record,
        FillState::Cancelled,
        "dry run: nothing was signalled",
    );

    assert!(
        journal
            .holder_against(&WorkId::zec("aa", 0))
            .unwrap()
            .is_none(),
        "a dry run left its reservation behind, blocking the coordinator"
    );
}

// ---------- the shared give-back ----------

#[test]
fn a_give_back_will_not_write_over_a_line_that_moved_on() {
    // R7-1, the whole class. Every reservation give-back in both daemons wrote
    // its new state blind: `record` checked the work id existed and nothing
    // more. So a second coordinator that reserved, found no logged-in browser
    // and retracted would write `Cancelled` over the *winner's* `Paying` line,
    // and the next sweep read a free slot and paid again.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    // This instance reserves.
    let ours = open_fill(
        &journal,
        &WorkId::base(U256::from(4499)),
        "deposit 4499",
        || base_record(4499, FillState::Seen),
    )
    .unwrap()
    .expect("the slot is free");

    // Somebody else moves the same fill on - the winner, mid-browser.
    let mut theirs = ours.clone();
    theirs.state = FillState::Paying;
    journal.record(&theirs).unwrap();

    // Now this instance gives up and releases what it thinks it holds.
    zecp2p_taker::auto::journal::release_if_still_ours(
        &journal,
        &ours,
        FillState::Cancelled,
        "no logged-in browser",
    );

    let latest = journal.latest().unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(
        latest[0].state,
        FillState::Paying,
        "the give-back cancelled a claim that was not its own"
    );
}

#[test]
fn a_give_back_does_release_a_line_that_is_still_ours() {
    // The other half: the compare-and-set must not break the ordinary case, or
    // every refused fill would leave the slot held.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let ours = open_fill(
        &journal,
        &WorkId::base(U256::from(4499)),
        "deposit 4499",
        || base_record(4499, FillState::Seen),
    )
    .unwrap()
    .expect("the slot is free");

    zecp2p_taker::auto::journal::release_if_still_ours(
        &journal,
        &ours,
        FillState::Cancelled,
        "the chain says not yet",
    );

    assert!(
        journal
            .holder_against(&WorkId::zec("aa", 0))
            .unwrap()
            .is_none(),
        "the slot was not released, so nothing else can ever pay"
    );
}

#[test]
fn two_taker_instances_do_not_both_pay_one_deposit() {
    // R8-1, the reviewer's reproduction, driven through the real sequence.
    //
    // The earlier version of this test jumped instance B from a stale `Seen`
    // straight to the `Paying` claim, which the pipeline never does - so it
    // never exercised the write that actually caused the double payment. The
    // real order is: reserve, `Signalling`, sign the intent, `Signalled`, read
    // it back, then claim `Paying`. The damage was at `Signalling`, four steps
    // before the guard.
    //
    // A takes the deposit and gets as far as `Paying` - it is in the browser.
    // B, which reserved earlier while A was staking, then walks its own
    // sequence. Before the fix, B's `Signalling` landed *over* A's open
    // `Paying` line and buried it: `latest` keeps the last line per work item,
    // so A's payment vanished from every reader including `needs_operator`. B
    // then reached its claim, found the latest line was its own, and paid.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = WorkId::base(U256::from(4499));

    // Both instances reserve. An own `Seen` is allowed through, because that is
    // what a retry looks like, so this is the state the real race starts from.
    let a = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("A takes the free slot");
    // B holds a reservation from before A took one: B reserved, went slow in
    // gating and staking, and A got there first. R9-1 allows that displacement,
    // because refusing it turns a crash into a permanent stall - the protection
    // is at B's next write, not at its reservation.
    let mut b = base_record(4499, FillState::Seen);
    b.updated_at = chrono::Utc::now() - chrono::Duration::seconds(30);

    // A runs its sequence to the click.
    let a = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &a,
        FillState::Signalling,
    )
    .unwrap()
    .expect("A may signal");
    let a = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &a,
        FillState::Signalled,
    )
    .unwrap()
    .expect("A's intent is on chain");
    let a = zecp2p_taker::auto::journal::advance_if_still_ours(&journal, &a, FillState::Paying)
        .unwrap()
        .expect("A claims and is now in the browser");

    // B now walks the same sequence. Its very first step must refuse: A's
    // `Paying` line is standing where B's `Signalling` would land.
    let refused = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &b,
        FillState::Signalling,
    )
    .unwrap()
    .expect_err("B must not write over A's claim");
    assert!(
        matches!(refused, SlotVerdict::OwnPaymentUnderway(_)),
        "B was told the wrong thing: {refused:?}"
    );

    // Nothing was signalled and nothing spent, so there is nothing to undo -
    // which is the point of refusing at the first write rather than the last.
    let lines: Vec<_> = journal.latest().unwrap();
    assert_eq!(lines.len(), 1, "one line per work item");
    assert_eq!(
        lines[0].state,
        FillState::Paying,
        "A's claim was buried, so the next reader sees a deposit nobody is paying"
    );
    assert_eq!(
        lines[0].updated_at, a.updated_at,
        "the surviving line is not A's"
    );

    // And the startup check can still see A's payment, which is what burying it
    // destroyed.
    assert!(
        !journal.needs_operator().unwrap().is_empty(),
        "A's in-flight payment is invisible to the check that exists to catch it"
    );
}

#[test]
fn a_signalled_intent_cannot_be_advanced_by_the_attempt_that_lost_it() {
    // R7-c said an outstanding intent must not become two. R9-1 changes *where*
    // that is enforced, not whether: a `Signalled` line may now be displaced,
    // because otherwise a crash there locks the deposit out forever. What stops
    // a second payment is that the displaced attempt cannot go on - its next
    // write finds a line that is not its own.
    //
    // The cost is an intent that expires rather than being cancelled, which is
    // the lesser harm against a deposit nobody can ever fill again.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = WorkId::base(U256::from(4499));

    let stale = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("the slot was free");
    let stale = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &stale,
        FillState::Signalled,
    )
    .unwrap()
    .expect("its intent is on chain");

    // A restart fills the deposit again.
    let fresh = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("a crashed attempt must not lock the deposit out");

    // The stale attempt cannot reach a payment.
    assert!(
        zecp2p_taker::auto::journal::advance_if_still_ours(
            &journal,
            &stale,
            FillState::Paying,
        )
        .unwrap()
        .is_err(),
        "the displaced attempt signalled a second payment"
    );
    let _ = fresh;
}

#[test]
fn a_finished_fill_cannot_be_reopened_through_record() {
    // R7-a. `record` required the work id to exist, but not the fill to be
    // running - so a caller holding a stale record could continue a
    // `Cancelled` or `Fulfilled` fill, which is opening a new one with the gate
    // skipped.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let mut record = open_fill(
        &journal,
        &WorkId::base(U256::from(4499)),
        "deposit 4499",
        || base_record(4499, FillState::Seen),
    )
    .unwrap()
    .expect("the slot is free");

    record.state = FillState::Cancelled;
    journal.record(&record).unwrap();

    // The stale caller tries to carry on.
    record.state = FillState::Paying;
    let err = journal
        .record(&record)
        .expect_err("a finished fill must not be reopened");
    assert!(format!("{err:#}").contains("open_fill"), "{err:#}");
}

#[test]
fn a_crash_between_reserving_and_signalling_self_heals() {
    // R9-1. R8-1 made *any* open own line block a new fill, which closed the
    // burying hole and opened a stall: a crash between the reservation and the
    // next write leaves a `Seen` nobody will ever advance, and the deposit is
    // then refused forever. Worse, it is silent - `Seen` is not
    // `fiat_may_have_left`, so `needs_operator` lists nothing.
    //
    // Displacing an own *pre-payment* reservation is safe under the
    // compare-and-set: whoever held it can no longer advance (its next write
    // finds a line that is not its own) and its give-back declines for the same
    // reason. What must still block is an own `Paying`/`Paid`/`NeedsOperator`,
    // because those mean money may have moved.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = WorkId::base(U256::from(4499));

    // The crashed attempt: a reservation and nothing after it.
    let orphan = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("the slot was free");

    // After the restart the deposit must be fillable again.
    let fresh = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("a crashed reservation must not lock the deposit out forever");

    // And the orphan cannot come back to life: its next write refuses, so the
    // displacement cannot turn into two fills running at once.
    let refused = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &orphan,
        FillState::Signalling,
    )
    .unwrap()
    .expect_err("the displaced holder must not be able to advance");
    assert!(matches!(refused, SlotVerdict::OwnPaymentUnderway(_)), "{refused:?}");

    // Its give-back declines too, so it cannot free the slot under the new fill.
    zecp2p_taker::auto::journal::release_if_still_ours(
        &journal,
        &orphan,
        FillState::Cancelled,
        "the orphan gives up",
    );
    let latest = journal.latest().unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].state, FillState::Seen);
    assert_eq!(
        latest[0].updated_at, fresh.updated_at,
        "the orphan cancelled the new fill's reservation"
    );

    // The new fill can go on and pay.
    zecp2p_taker::auto::journal::advance_if_still_ours(&journal, &fresh, FillState::Signalling)
        .unwrap()
        .expect("the fresh fill owns the slot now");
}

#[test]
fn a_crash_after_paying_still_blocks_a_retry() {
    // The other side of the same rule: `Paying` and everything past it must
    // keep blocking, because those mean money may already have gone out. This
    // is the case R8-1 was for, and relaxing `Seen` must not relax these.
    for state in [
        FillState::Paying,
        FillState::Paid,
        FillState::NeedsOperator,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
        let work = WorkId::base(U256::from(4499));

        let held = open_fill(&journal, &work, "deposit 4499", || {
            base_record(4499, FillState::Seen)
        })
        .unwrap()
        .expect("the slot was free");
        zecp2p_taker::auto::journal::advance_if_still_ours(&journal, &held, state)
            .unwrap()
            .expect("the fill advances");

        let refused = open_fill(&journal, &work, "deposit 4499", || {
            base_record(4499, FillState::Seen)
        })
        .unwrap()
        .expect_err(&format!("{state:?} must still block a retry"));
        assert!(refused.contains("pay twice"), "{refused}");
    }
}

#[test]
fn a_post_payment_fact_lands_even_past_a_closed_line() {
    // R9-SF1. `record_outcome`'s fallback went through `record`, which refuses
    // to continue a closed fill - so a `Paid` write whose line had been
    // cancelled bailed, stopping the fill before its attestation with the
    // dollars already gone. And the next poll then found a closed line, treated
    // the work as free, and started again.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = WorkId::base(U256::from(4499));

    let held = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("the slot was free");

    // Somebody closes the line underneath this fill.
    let mut cancelled = held.clone();
    cancelled.state = FillState::Cancelled;
    journal.record(&cancelled).unwrap();

    // The payment went out anyway, and that fact has to land.
    let mut paid = held.clone();
    paid.state = FillState::Paid;
    paid.paid = Some("2.00".into());
    let written = zecp2p_taker::auto::journal::record_outcome(&journal, &held, &paid)
        .expect("a spent-dollars fact must never be dropped");
    assert_eq!(written.state, FillState::Paid);

    // And a reader sees it, so nothing treats the deposit as free.
    let latest = journal.latest().unwrap();
    assert_eq!(latest[0].state, FillState::Paid);
    assert!(
        !journal.needs_operator().unwrap().is_empty(),
        "the payment is invisible to the operator list"
    );
}

#[test]
fn a_forced_write_reaches_the_operator_list() {
    // R9-SF3. A forced `NeedsOperator` over a `Paying` line used to leave
    // `needs_operator` empty, because `NeedsOperator` is not
    // `fiat_may_have_left` - so the fact that a payment was in flight survived
    // only as prose inside a note. That is the opposite of what forcing is for.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    let work = WorkId::base(U256::from(4499));

    let held = open_fill(&journal, &work, "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("the slot was free");
    let paying = zecp2p_taker::auto::journal::advance_if_still_ours(
        &journal,
        &held,
        FillState::Paying,
    )
    .unwrap()
    .expect("it claims");

    // A stale caller forces `NeedsOperator` over that line.
    let mut stuck = held.clone();
    stuck.state = FillState::NeedsOperator;
    stuck.note = Some("the browser step failed".into());
    zecp2p_taker::auto::journal::record_outcome(&journal, &held, &stuck)
        .expect("the outcome lands");

    let flagged = journal.needs_operator().unwrap();
    assert!(
        !flagged.is_empty(),
        "a forced write buried a payment and told nobody"
    );
    // And the note names this fill's own line, not somebody else's work.
    let note = flagged[0].note.clone().unwrap_or_default();
    assert!(
        note.contains("written over") && note.contains("Paying"),
        "the note does not say what it replaced: {note}"
    );
    let _ = paying;
}

#[test]
fn every_open_fill_is_visible_to_an_operator() {
    // R9: `Seen`, `Signalling` and `Signalled` all hold the global slot, and a
    // daemon restarting behind one starts cleanly and then skips every deposit.
    // `open_fills` is what a status command prints so that stall is not silent.
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("fills.jsonl")).unwrap();

    let held = open_fill(&journal, &WorkId::base(U256::from(4499)), "deposit 4499", || {
        base_record(4499, FillState::Seen)
    })
    .unwrap()
    .expect("the slot was free");

    assert_eq!(journal.open_fills().unwrap().len(), 1, "the reservation is invisible");

    zecp2p_taker::auto::journal::release_if_still_ours(
        &journal,
        &held,
        FillState::Cancelled,
        "done",
    );
    assert!(
        journal.open_fills().unwrap().is_empty(),
        "a closed fill is still being listed"
    );
}
