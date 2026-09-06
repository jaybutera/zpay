//! Retiring a stuck fill, and the things an operator override must not become.
//!
//! `NeedsOperator` had no exit. `record_outcome` only writes over it when the
//! same fill reaches a later state, and a fill whose rail refused never will -
//! so on 2026-09-06 one refused payment held the single payment slot against
//! both daemons until its escrow's refund height, about 22 hours later, with no
//! command able to clear it.
//!
//! `Journal::resolve_needs_operator` is that command's engine. The tests here
//! are less about it working than about the four things it must not do: write
//! over a payment somebody is driving, pass for the machine's own proof that
//! nothing was sent, land without evidence, or let a refund broadcast against
//! money an operator has just said left the account.

use alloy::primitives::U256;
use zecp2p_taker::auto::journal::{
    record_may_already_have_paid, FillRecord, FillState, Finding, Journal, Resolution,
};
use zecp2p_taker::auto::rail::WorkId;

fn journal() -> (tempfile::TempDir, Journal) {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();
    (dir, j)
}

fn zec_record(byte: u8, state: FillState) -> FillRecord {
    let mut r = FillRecord::new_zec(
        format!("{}:0", hex::encode([byte; 32])),
        U256::from(200_000u64),
        U256::from(1_000_000_000_000_000_000u128),
        "jay-butera".into(),
    );
    r.state = state;
    r
}

/// The line as an operator would actually be shown it: written, then read back,
/// so its `updated_at` is the journal's own stamp rather than the constructor's.
fn write_and_read(journal: &Journal, record: &FillRecord) -> FillRecord {
    journal.append_unchecked(record).unwrap();
    let work = record.work_id();
    journal
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == work)
        .expect("the line we just wrote")
}

fn resolution(finding: Finding) -> Resolution {
    Resolution {
        operator: "casper".into(),
        feed_evidence: "balance $60.49 unchanged; newest outgoing payment is $1.50, \
                        three hours old; no $2.00 debit"
            .into(),
        finding,
        resolved_at: chrono::Utc::now(),
    }
}

#[test]
fn retiring_a_stuck_fill_releases_the_payment_slot() {
    // The 2026-09-06 shape: one `NeedsOperator` line, and every other order
    // waiting behind it.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    let blocked = WorkId::base(U256::from(4499));
    assert!(
        zecp2p_taker::auto::journal::holder_among(&j.latest().unwrap(), &blocked).is_some(),
        "the stuck fill must hold the slot before it is retired, or this proves nothing"
    );

    j.resolve_needs_operator(&stuck, resolution(Finding::NoPaymentWasSent))
        .expect("an operator may retire a needs_operator line");

    assert!(
        zecp2p_taker::auto::journal::holder_among(&j.latest().unwrap(), &blocked).is_none(),
        "retiring the fill must free the slot; that is the whole point of the command"
    );
    assert!(j.in_flight().unwrap().is_none());
}

#[test]
fn a_retired_fill_carries_who_did_it_and_what_they_saw() {
    // The audit trail is the justification for the override existing at all. A
    // released slot with no record of who released it is indistinguishable from
    // the daemon having quietly cleared its own block.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    let before = chrono::Utc::now();
    j.resolve_needs_operator(&stuck, resolution(Finding::NoPaymentWasSent))
        .unwrap();

    let retired = j
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == stuck.work_id())
        .unwrap();

    let audit = retired.resolution.expect("the retired line carries its resolution");
    assert_eq!(audit.operator, "casper");
    assert!(audit.feed_evidence.contains("$60.49"));
    assert_eq!(audit.finding, Finding::NoPaymentWasSent);
    assert!(audit.resolved_at >= before);

    // And it survives the file, which is where an auditor reads it.
    let found = j.resolutions().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].resolution.as_ref().unwrap().operator, "casper");
}

#[test]
fn the_reason_the_fill_stopped_is_kept_alongside_the_operators_account() {
    // Both halves matter to whoever reads this next: why the rail refused, and
    // what the person who looked concluded.
    let (_d, j) = journal();
    let mut record = zec_record(0xa8, FillState::NeedsOperator);
    record.note = Some("the Venmo leg failed: the page does not name @jay-butera".into());
    let stuck = write_and_read(&j, &record);

    j.resolve_needs_operator(&stuck, resolution(Finding::NoPaymentWasSent))
        .unwrap();

    let note = j
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == stuck.work_id())
        .unwrap()
        .note
        .expect("a note");
    assert!(
        note.contains("does not name @jay-butera"),
        "the original reason must survive: {note}"
    );
    assert!(note.contains("casper"), "the operator must be named: {note}");
}

#[test]
fn an_override_is_not_readable_as_the_machines_own_proof() {
    // `Cancelled` is written only by a compare-and-set on a pre-payment line,
    // and it means the code established nothing was sent. `Resolved` means a
    // person looked. Collapsing them would let "somebody said so" pass for
    // "this was proved", which is the one distinction an override has to keep.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    let retired = j
        .resolve_needs_operator(&stuck, resolution(Finding::NoPaymentWasSent))
        .unwrap();

    assert_eq!(retired.state, FillState::Resolved);
    assert_ne!(retired.state, FillState::Cancelled);
    assert_ne!(retired.state, FillState::Fulfilled);
    assert!(!retired.state.is_open(), "a retired fill holds no slot");
}

#[test]
fn a_payment_in_flight_may_not_be_retired() {
    // The dangerous case. A `Paying` line belongs to whichever process is
    // driving the browser right now; writing over it would take that payment
    // out of the record entirely, and the next order would read a free slot.
    let (_d, j) = journal();
    let live = write_and_read(&j, &zec_record(0xa8, FillState::Paying));

    let refused = j
        .resolve_needs_operator(&live, resolution(Finding::NoPaymentWasSent))
        .expect_err("a Paying line must not be retired");
    let message = format!("{refused:#}");
    assert!(
        message.contains("Paying"),
        "the refusal must name the state it found: {message}"
    );

    // And the line is untouched.
    let after = j.latest().unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].state, FillState::Paying);
}

#[test]
fn every_state_that_is_not_needs_operator_is_refused() {
    // Not just `Paying`. A `Paid` line is an attestation this operator has not
    // performed; a closed line holds nothing and retiring it would be writing
    // history for no reason.
    for state in [
        FillState::Seen,
        FillState::Signalling,
        FillState::Signalled,
        FillState::Paying,
        FillState::Paid,
        FillState::Fulfilled,
        FillState::Cancelled,
    ] {
        let (_d, j) = journal();
        let record = write_and_read(&j, &zec_record(0xa8, state));
        assert!(
            j.resolve_needs_operator(&record, resolution(Finding::NoPaymentWasSent))
                .is_err(),
            "{state:?} must not be retirable by an operator command"
        );
    }
}

#[test]
fn a_fill_the_journal_has_never_seen_cannot_be_retired() {
    // Resolving unknown work would open a fill through the back door: an append
    // for a work id with no history, past every gate.
    let (_d, j) = journal();
    let stranger = zec_record(0xff, FillState::NeedsOperator);

    assert!(
        j.resolve_needs_operator(&stranger, resolution(Finding::NoPaymentWasSent))
            .is_err(),
        "work with no journal history must not be resolvable"
    );
    assert!(j.latest().unwrap().is_empty(), "nothing may be written");
}

#[test]
fn a_line_written_again_since_the_operator_read_it_is_refused() {
    // The operator read the journal, went to the Venmo feed, came back. In
    // between, the daemon recorded something about this fill. Their evidence is
    // about a line that is no longer the current one.
    let (_d, j) = journal();
    let shown = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    // A second `NeedsOperator`, so the *state* check passes and only the
    // timestamp catches it.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut again = shown.clone();
    again.note = Some("a second failure while the operator was reading the feed".into());
    j.append_unchecked(&again).unwrap();

    let refused = j
        .resolve_needs_operator(&shown, resolution(Finding::NoPaymentWasSent))
        .expect_err("a stale read must be refused");
    assert!(
        format!("{refused:#}").contains("Read it again"),
        "the refusal must say what to do: {refused:#}"
    );
}

#[test]
fn an_override_with_no_name_on_it_is_refused() {
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    let mut anonymous = resolution(Finding::NoPaymentWasSent);
    anonymous.operator = "   ".into();

    assert!(
        j.resolve_needs_operator(&stuck, anonymous).is_err(),
        "an anonymous override answers nothing when somebody asks about it later"
    );
    assert_eq!(j.latest().unwrap()[0].state, FillState::NeedsOperator);
}

#[test]
fn an_override_with_no_feed_evidence_is_refused() {
    // The entire basis for releasing the slot is that a human read the feed.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    let mut blank = resolution(Finding::NoPaymentWasSent);
    blank.feed_evidence = String::new();

    assert!(
        j.resolve_needs_operator(&stuck, blank).is_err(),
        "releasing the slot without saying what the feed showed is a delete with extra steps"
    );
    assert_eq!(j.latest().unwrap()[0].state, FillState::NeedsOperator);
}

#[test]
fn an_operator_who_found_the_payment_does_not_open_the_refund() {
    // The sharpest edge in the whole change. `Resolved` is a closed state, so
    // read as a bare state it is not `may_already_have_paid` - and the refund
    // endpoint asks exactly that question. An operator who has just recorded
    // that the dollars left must not thereby unlock a refund that races the
    // LP's release for money the user has already been paid.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    j.resolve_needs_operator(&stuck, resolution(Finding::PaymentWasSent))
        .unwrap();

    let retired = j
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == stuck.work_id())
        .unwrap();

    assert_eq!(retired.state, FillState::Resolved);
    assert!(
        !retired.state.is_open(),
        "the slot is still released: the queue must not stall on a settled question"
    );
    assert!(
        record_may_already_have_paid(&retired),
        "a fill an operator says was paid must keep reading as 'money may have left', \
         or the refund endpoint will broadcast against it"
    );
}

#[test]
fn an_operator_who_found_no_payment_does_open_the_refund() {
    // The other finding, and the reason the two are separate fields rather than
    // one. Nothing was sent, so the escrow is the user's to refund.
    let (_d, j) = journal();
    let stuck = write_and_read(&j, &zec_record(0xa8, FillState::NeedsOperator));

    j.resolve_needs_operator(&stuck, resolution(Finding::NoPaymentWasSent))
        .unwrap();

    let retired = j
        .latest()
        .unwrap()
        .into_iter()
        .find(|r| r.work_id() == stuck.work_id())
        .unwrap();

    assert!(
        !record_may_already_have_paid(&retired),
        "nothing was sent, so nothing should stand between the user and their refund"
    );
}
