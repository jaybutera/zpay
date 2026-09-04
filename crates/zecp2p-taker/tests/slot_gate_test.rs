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
    let mine = WorkId::base(U256::from(4499));
    for state in [
        FillState::Signalling,
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
fn a_deposits_own_seen_line_does_not_stop_it() {
    // `Seen` is a reservation, written before any network call. It must not
    // lock a deposit out of its own first payment - only the states past it do.
    let mine = WorkId::base(U256::from(4499));
    let journal = vec![base_record(4499, FillState::Seen)];
    assert!(slot_verdict(&journal, &mine).is_free());
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

    let mut record = open_fill(
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

    // The dry run ends the way `handle_one` ends it.
    record.state = FillState::Cancelled;
    record.note = Some("dry run: nothing was signalled".into());
    journal.record(&record).unwrap();

    assert!(
        journal
            .holder_against(&WorkId::zec("aa", 0))
            .unwrap()
            .is_none(),
        "a dry run left its reservation behind, blocking the coordinator"
    );
}
