//! The one payment slot, and the journal read that survives a restart.
//!
//! Round 1 of the audit found two ways to pay the same escrow twice, and both
//! come from the same mistake: the coordinator held its "am I paying" state in
//! memory and in the order store, and asked neither of them a question a crash
//! could answer.
//!
//! # The crash window
//!
//! `settle` wrote a `Paying` line to the journal, then drove a browser for up
//! to two minutes, then wrote `Paid` to the order store. A crash anywhere in
//! between left the store saying `Locked` - which on restart means "the LP may
//! pay" - and left the journal saying `Paying`, which nothing read. So a
//! restart paid again, and the second payment is unrecoverable: the escrow
//! releases once.
//!
//! The taker does not have this bug, because it gates on `journal.in_flight()`
//! before it starts. This module is that gate, and it is a *read of the
//! journal* rather than a second copy of the fact: the journal is the only
//! record written before the click, so it is the only record a crash cannot
//! have skipped.
//!
//! # The slot claimed too late
//!
//! `another_payment_in_flight` matched `Stage::Paid`, but an order in the
//! middle of `settle` is still `Locked`. Order A drives the browser, the sweep
//! reaches order B twenty seconds later, B sees nobody at `Paid`, and B pays
//! too. Two feed entries of the same amount to the same handle is exactly the
//! situation `locate_payment` refuses to resolve - after both payments have
//! left.
//!
//! So the slot is claimed **before** the journal write and is held across the
//! whole of `settle`, and it is claimed in the journal, where a crash leaves it
//! claimed rather than silently free.

use anyhow::{Context, Result};

use zecp2p_taker::auto::journal::{FillRecord, FillState, Journal};
use zecp2p_taker::auto::rail::WorkId;

/// Whether an open journal record must hold the payment slot.
///
/// R2-2: this used to be `fiat_may_have_left() || state == Paying`, which let
/// `NeedsOperator` through. That is the state `settle` writes when `fiat::pay`
/// fails - the case whose whole meaning is "a payment may have left and a human
/// has to look" - so the slot was freed by exactly the outcome that most needs
/// it held. The next order for the same handle then paid, into a feed that
/// already had an entry nobody had reconciled.
///
/// The rule is the taker's: **every open record holds the slot.** `is_open` is
/// false only for `Fulfilled` and `Cancelled`, both of which are somebody
/// having decided the fill is over. Anything else - `Seen`, `Signalling`,
/// `Signalled`, `Paying`, `Paid`, `NeedsOperator` - is unfinished work against
/// one Venmo balance, and `Journal::in_flight` treats all of it the same way.
fn holds_the_slot(state: FillState) -> bool {
    state.is_open()
}

/// Whether an open record for *this* work item means a payment may already
/// have gone out for it.
///
/// Narrower than [`holds_the_slot`], because the two answers differ: a `Seen`
/// line for this order is its own claim on the slot and must not lock the order
/// out of its first payment, whereas a `Seen` line for a *different* order
/// still occupies the one balance.
fn may_already_have_paid(state: FillState) -> bool {
    state.fiat_may_have_left()
        || matches!(
            state,
            FillState::Paying | FillState::NeedsOperator | FillState::Signalling
        )
}

/// Why a payment may not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotRefusal {
    /// This escrow already has a payment recorded as under way.
    ///
    /// The dangerous one. The record was written before the click, so it means
    /// "money may already have gone to this handle for this escrow" and a
    /// human has to read the Venmo feed to say which.
    ThisOrderMayHavePaid { work: String, state: FillState },
    /// Another work item holds the one slot.
    HeldByAnother { work: String, state: FillState },
}

impl std::fmt::Display for SlotRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotRefusal::ThisOrderMayHavePaid { work, state } => write!(
                f,
                "the journal already records {work} as {state:?}. That line is written \
                 before the send button, so a payment for this escrow may already have \
                 left. Refusing to send a second one: check the Venmo feed, then either \
                 mark the fill paid or let the escrow refund at T."
            ),
            SlotRefusal::HeldByAnother { work, state } => write!(
                f,
                "{work} holds the one payment slot ({state:?}). One payment at a time: \
                 two entries of the same amount to the same handle cannot be told apart \
                 in the feed, and by then both have left."
            ),
        }
    }
}

/// The journal identity of an order's fill.
///
/// The outpoint, so it is the same key the taker's journal uses and the same
/// key a human reads. An order with no funding outpoint cannot be paid, so
/// this is only called once one exists.
pub fn work_id_for(funding_txid: &[u8; 32], vout: u32) -> WorkId {
    WorkId::zec(&zecp2p_escrow::rpc::txid_to_display(funding_txid), vout)
}

/// May a payment for `work` start right now?
///
/// Reads the journal from disk every time. That is the point: the in-memory
/// view of who is paying is exactly what a crash destroys, and this question is
/// only worth asking against something durable.
pub fn may_claim(journal: &Journal, work: &WorkId) -> Result<Result<(), SlotRefusal>> {
    let latest = journal
        .latest()
        .context("could not read the journal back; refusing to pay without it")?;

    for record in latest {
        if !holds_the_slot(record.state) {
            continue;
        }
        let holder = record.work_id();

        if &holder == work {
            // Our own record. `Seen` is a claim that never reached the browser
            // and may be retried; anything from `Signalling` on means a payment
            // for this escrow may already have left, and `NeedsOperator` says
            // so outright.
            if may_already_have_paid(record.state) {
                return Ok(Err(SlotRefusal::ThisOrderMayHavePaid {
                    work: holder.to_string(),
                    state: record.state,
                }));
            }
            continue;
        }

        // Somebody else's open fill. All of it counts, including `Paid` (that
        // order is waiting on an attestation for a payment already in the feed)
        // and `NeedsOperator` (a human has not yet said what happened to a
        // payment that may have gone out). A second payment of the same amount
        // to the same handle would make both unprovable.
        return Ok(Err(SlotRefusal::HeldByAnother {
            work: holder.to_string(),
            state: record.state,
        }));
    }

    Ok(Ok(()))
}

/// Whether the journal says a payment for this escrow may have gone out.
///
/// For a caller that is about to do something a payment would make unsafe -
/// broadcasting a refund, above all. R2-4: the refund endpoint gated on the
/// order's *stage*, and `order.fail` leaves the stage `Failed`, which that
/// endpoint accepted. So the one path whose message is "a payment may have
/// left" produced a stage the refund endpoint would broadcast against, and the
/// refund would race a release for money already paid.
///
/// The journal is the authority here for the same reason it is the slot: it is
/// written before the click, so it knows things the stage cannot.
pub fn fiat_may_have_left(journal: &Journal, work: &WorkId) -> Result<bool> {
    let latest = journal
        .latest()
        .context("could not read the journal back")?;
    Ok(latest
        .into_iter()
        .any(|r| &r.work_id() == work && may_already_have_paid(r.state)))
}

/// Takes the slot before anything slow happens.
///
/// R3-3: the read and the `Paying` write used to be separated by a chain
/// round-trip and the rail's preflight. Inside one process the global mutex
/// covers that, but the journal is meant to be the slot *between* daemons, and
/// a second daemon reading the file during that window sees it free. So the
/// claim goes down immediately after the read, while the mutex is still held,
/// and the file says "taken" from that moment on.
///
/// The state is `Seen`, not `Paying`, and the difference matters. `Seen` holds
/// the slot against every other work item, because [`holds_the_slot`] counts
/// every open record - but it does not assert that money may have moved, so
/// this order can still [`retract`] it when the chain check or the preflight
/// refuses. `Paying` is written later, by [`claim`], and is never retracted:
/// past that point a crash means a human reads the Venmo feed.
pub fn reserve(
    journal: &Journal,
    work: &WorkId,
    usd_amount_6dec: u64,
    recipient: &str,
) -> Result<FillRecord> {
    let mut record = FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(usd_amount_6dec),
        alloy::primitives::U256::from(zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC),
        recipient.to_string(),
    );
    record.state = FillState::Seen;
    journal
        .record(&record)
        .context("could not reserve the payment slot")?;
    Ok(record)
}

/// Gives the slot back, having reserved it and then decided not to pay.
///
/// Only ever called on a [`reserve`] that has not become a [`claim`]: the chain
/// said no, the rail cannot start, the deadline passed. Nothing has been sent,
/// so `Cancelled` is the truth and it frees the slot for the next order.
///
/// A failure here leaves the slot held by a `Seen` line, which blocks payments
/// until an operator looks - the safe direction, and the reason this is
/// best-effort rather than fatal.
pub fn retract(journal: &Journal, mut record: FillRecord, why: &str) {
    record.state = FillState::Cancelled;
    record.note = Some(format!("not paid: {why}"));
    if let Err(e) = journal.record(&record) {
        tracing::error!(
            error = %e,
            "could not release the payment slot after deciding not to pay; it stays held"
        );
    }
}

/// Writes the claim that must precede a payment.
///
/// Separate from [`may_claim`] so the sequence at the call site reads in the
/// order it happens: check, claim, pay. The claim is `Paying`, which is the
/// ambiguous state - written before the click precisely so that a crash is
/// recorded as "may have paid" rather than as nothing at all.
pub fn claim(
    journal: &Journal,
    reserved: FillRecord,
    intent_hash: alloy::primitives::B256,
    intent_timestamp_ms: u64,
) -> Result<FillRecord> {
    let mut record = reserved;
    record.state = FillState::Paying;
    record.intent_hash = Some(intent_hash);
    record.signalled_at_ms = Some(intent_timestamp_ms);
    journal
        .record(&record)
        .context("could not write the journal entry that must precede a payment")?;
    Ok(record)
}

/// Releases the slot: the trade is finished and settled.
///
/// R3-1: nothing wrote this, so a `Paid` line stayed open forever and one
/// completed trade blocked every later one. Worse across daemons: the taker
/// refuses to start at all while an open record says the fiat may have left,
/// so a finished coordinator trade would keep the taker from restarting.
///
/// `Fulfilled` is the right state rather than a new one: it is what the taker
/// writes when `fulfillIntent` confirms, and here the release landing on chain
/// is the same fact - the escrow has paid out against the payment, and there is
/// nothing left for anybody to reconcile.
///
/// Best-effort by design. It runs after the release is on chain, so a failure
/// to write it cannot lose money; it can only leave the slot held, which the
/// next operator sees as a stuck fill rather than as a double payment.
pub fn fulfilled(
    journal: &Journal,
    work: &WorkId,
    usd_amount_6dec: u64,
    recipient: &str,
    release_txid: &str,
) -> Result<()> {
    let mut record = FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(usd_amount_6dec),
        alloy::primitives::U256::from(zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC),
        recipient.to_string(),
    );
    record.state = FillState::Fulfilled;
    record.note = Some(format!("released in {release_txid}"));
    journal
        .record(&record)
        .context("could not record the fill as fulfilled; the slot will stay held")
}

/// Whether the journal says this escrow's fiat leg **definitely** completed.
///
/// R3-4: a `Paid` line with an order still at `Locked` is the post-payment
/// store write having failed. The dollars are gone and the order does not say
/// so; failing that order abandons the release the LP has already paid for, so
/// the right move is to finish it.
///
/// `Paid` only, and deliberately not `Paying`. The two are not the same claim:
/// `Paying` is written *before* the click and means nobody knows whether money
/// moved, so releasing on it would hand the escrow to the LP for a payment that
/// may never have happened - the user loses their ZEC and got no dollars. That
/// case stays a refusal for a human, which is what `NeedsOperator` and the
/// `Failed` order are for.
pub fn definitely_paid(journal: &Journal, work: &WorkId) -> Result<bool> {
    let latest = journal.latest().context("could not read the journal back")?;
    Ok(latest
        .into_iter()
        .any(|r| &r.work_id() == work && r.state == FillState::Paid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, U256};

    fn journal() -> (tempfile::TempDir, Journal) {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path().join("fills.jsonl")).unwrap();
        (dir, j)
    }

    fn zec_work(byte: u8) -> WorkId {
        work_id_for(&[byte; 32], 0)
    }

    fn write(journal: &Journal, work: &WorkId, state: FillState) {
        let mut r = FillRecord::new_zec(
            work.local.clone(),
            U256::from(700_000u64),
            U256::from(1_000_000_000_000_000_000u128),
            "alice".into(),
        );
        r.state = state;
        journal.record(&r).unwrap();
    }

    #[test]
    fn an_empty_journal_lets_a_payment_start() {
        let (_d, j) = journal();
        assert_eq!(may_claim(&j, &zec_work(1)).unwrap(), Ok(()));
    }

    #[test]
    fn a_paying_record_for_this_order_refuses_a_second_payment() {
        // The crash window. The store says `Locked` after a restart, so the
        // only thing that knows a payment may have left is this line.
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Paying);

        let refusal = may_claim(&j, &work).unwrap().expect_err("must refuse");
        assert!(matches!(refusal, SlotRefusal::ThisOrderMayHavePaid { .. }));
        assert!(
            refusal.to_string().contains("check the Venmo feed"),
            "the message must tell a human what to do: {refusal}"
        );
    }

    #[test]
    fn a_paid_record_for_this_order_also_refuses() {
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Paid);
        assert!(may_claim(&j, &work).unwrap().is_err());
    }

    #[test]
    fn another_orders_paying_record_holds_the_slot() {
        // The late-claim bug: order A is mid-browser and still `Locked` in the
        // store, so only the journal knows the slot is taken.
        let (_d, j) = journal();
        write(&j, &zec_work(0xaa), FillState::Paying);

        let refusal = may_claim(&j, &zec_work(0xbb)).unwrap().expect_err("must refuse");
        assert!(matches!(refusal, SlotRefusal::HeldByAnother { .. }));
        assert!(refusal.to_string().contains("One payment at a time"));
    }

    #[test]
    fn another_orders_paid_record_also_holds_the_slot() {
        // That order is waiting on an attestation for a payment sitting in the
        // feed. A second identical payment makes both unprovable.
        let (_d, j) = journal();
        write(&j, &zec_work(0xaa), FillState::Paid);
        assert!(may_claim(&j, &zec_work(0xbb)).unwrap().is_err());
    }

    #[test]
    fn a_finished_fill_releases_the_slot() {
        let (_d, j) = journal();
        let other = zec_work(0xaa);
        write(&j, &other, FillState::Paying);
        write(&j, &other, FillState::Fulfilled);
        // Last line per work item wins, so the slot is free again.
        assert_eq!(may_claim(&j, &zec_work(0xbb)).unwrap(), Ok(()));
    }

    #[test]
    fn a_seen_record_for_this_order_does_not_block_it() {
        // `Seen` is written before anything is attempted. It must not lock an
        // order out of its own first payment.
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Seen);
        assert_eq!(may_claim(&j, &work).unwrap(), Ok(()));
    }

    #[test]
    fn the_claim_survives_reopening_the_journal() {
        // What a restart sees. The claim is only worth anything if it is on
        // disk before the browser opens.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fills.jsonl");
        let work = zec_work(7);
        {
            let j = Journal::open(&path).unwrap();
            let reserved = reserve(&j, &work, 700_000, "alice").unwrap();
            claim(&j, reserved, B256::repeat_byte(0x11), 1_700_000_000_000).unwrap();
        }
        let reopened = Journal::open(&path).unwrap();
        let refusal = may_claim(&reopened, &work).unwrap().expect_err("must refuse");
        assert!(matches!(refusal, SlotRefusal::ThisOrderMayHavePaid { .. }));
    }

    #[test]
    fn a_base_rail_fill_holds_the_slot_too() {
        // One Venmo balance, two rails. The taker's own journal note makes this
        // point: a per-rail slot is two concurrent payments.
        let (_d, j) = journal();
        let mut base = FillRecord::new(
            U256::from(4499),
            B256::repeat_byte(0xaa),
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
            "alice".into(),
        );
        base.state = FillState::Paying;
        j.record(&base).unwrap();

        assert!(may_claim(&j, &zec_work(0xbb)).unwrap().is_err());
    }
}
