//! The payment slot as both daemons see it.
//!
//! `zecp2p-v2coordinator` pays Venmo from the same account this taker does, and
//! the two coordinate through one journal file. The gate is `holder_among`, and
//! these are the cases that matter when the other daemon is the holder.

use alloy::primitives::{B256, U256};
use zecp2p_taker::auto::journal::{holder_among, FillRecord, FillState, Journal};
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
    coordinator.record(&zec_record(0xcc, FillState::Paying)).unwrap();

    // The taker's side, a separate handle on the same file.
    let taker = Journal::open(&shared).unwrap();
    let holder = taker
        .holder_against(&WorkId::base(U256::from(4499)))
        .unwrap()
        .expect("the taker must see the coordinator's claim");
    assert_eq!(holder.state, FillState::Paying);
    assert_eq!(holder.rail, Rail::Zec);

    // And once the coordinator finishes, the taker may proceed.
    coordinator.record(&zec_record(0xcc, FillState::Fulfilled)).unwrap();
    assert!(taker
        .holder_against(&WorkId::base(U256::from(4499)))
        .unwrap()
        .is_none());
}
