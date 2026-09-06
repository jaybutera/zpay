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
//!
//! # One LP's leg, not the network's
//!
//! Everything in this module is scoped to a single LP instance, and that is a
//! property to keep rather than an accident to build on. zpay is permissionless
//! in principle: anybody may run a coordinator and become an LP, so nothing
//! here may assume there is one of them.
//!
//! The scoping is structural. The slot is the *journal file*, whose path comes
//! from this deployment's config and defaults under its own `state_dir`; the
//! queue is this deployment's own order store, in the same place. What the slot
//! serialises is therefore "the daemons sharing this journal", which is exactly
//! one LP's Venmo account - the thing the feed-ambiguity argument is about. A
//! second LP runs its own coordinator with its own state directory, its own
//! journal and its own session, and neither one's parked fill, queue position
//! or operator override is visible to the other.
//!
//! Two rules follow, and both are load-bearing:
//!
//! - **No account is named in this crate.** The recipient is carried on the
//!   order and the sender comes from the configured session. A handle written
//!   into coordinator logic would make that instance the only one that works.
//! - **Nothing here may reach across instances.** A global registry of paying
//!   LPs, a shared journal, a queue keyed on anything but this store's own
//!   orders - each would turn one operator's stuck fill into everybody's
//!   problem, which is the shape of the outage this queue exists to prevent,
//!   scaled up to the network.

use anyhow::{Context, Result};

use zecp2p_taker::auto::journal::{FillRecord, FillState, Journal};
use zecp2p_taker::auto::rail::WorkId;

// R7-2: the rule lives in `zecp2p_taker::auto::journal` and nothing here
// restates it. This module had its own `holds_the_slot` and
// `may_already_have_paid`, and the two copies drifted: the coordinator gained
// an own-work guard in round 5 that the taker did not get until round 6, and
// the taker's `Signalled` case was missing from this one. Two daemons sharing
// one Venmo balance need one definition of "may I pay".
//
// The record form rather than the bare-state one: an operator-retired line
// carries a human's finding about the dollars, and a state alone cannot report
// it. The refund endpoint is the caller that must not get this wrong.
use zecp2p_taker::auto::journal::record_may_already_have_paid;

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

/// Whether the journal says a payment for this escrow may have gone out.
///
/// For a caller about to do something a payment would make unsafe -
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
    Ok(fiat_may_have_left_in(&latest, work))
}

/// The same question, asked of a journal somebody else has already read.
///
/// R5-3. The sweep's deadline check asks this once per held-back order per
/// pass, and the answer comes from the same file every time. This is the half
/// that decides; [`AppState::sweep_journal`] is the half that reads, and it
/// says which callers may use a shared read and which must not.
///
/// One rule, in one place, whichever way the records arrived.
pub fn fiat_may_have_left_in(latest: &[FillRecord], work: &WorkId) -> bool {
    latest
        .iter()
        .any(|r| &r.work_id() == work && record_may_already_have_paid(r))
}

/// The order at the head of the pay queue, among those ready to pay.
///
/// Serialising the Venmo leg is a requirement - one balance, one drive, and two
/// feed entries of the same amount to the same handle cannot be told apart.
/// Serving that queue in an *arbitrary* order is not. Before this, every locked
/// order raced for the slot on each sweep and the winner was whichever task the
/// runtime got to first, so an order could be passed over repeatedly while
/// later ones went ahead of it. Under load that is unbounded: nothing made a
/// waiting order's turn come round.
///
/// So the queue is explicit and it is FIFO on `created_at`, which is the order
/// users arrived in and the only one they can predict. An order that is not at
/// the head yields the tick and comes back on the next sweep; it is not
/// refused, and nothing is written for it.
///
/// Ties are broken on `order_id`, so the answer is total and every task in a
/// sweep computes the same head from the same list. Two orders created in the
/// same millisecond would otherwise each be able to see the other as prior and
/// both yield - a queue that stalls itself.
///
/// `ready` is the orders eligible to pay right now. The caller supplies it,
/// because eligibility is the driver's question - stage, deadlines, funding -
/// and this is only the ordering.
pub fn head_of_queue(ready: &[crate::order::Order]) -> Option<&crate::order::Order> {
    ready
        .iter()
        .min_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.order_id.cmp(&b.order_id))
        })
}

/// Whether the journal will refuse this order's payment for the whole of this
/// sweep, whatever else happens.
///
/// Round 1, question 2. FIFO alone reintroduced the outage in a narrower shape:
/// `blocker_for` correctly refuses an order indistinguishable in the feed from
/// a parked fill, but a refused order stays `Locked`, and `waiting_to_pay`
/// lists every `Locked` order - so it stayed the head for the ~24 hours until
/// its own deadline, and everything behind it yielded to it for that long. One
/// user opening an order of the same amount to the same handle as a parked fill
/// was enough to close the rail again.
///
/// So the queue steps over an order it can prove will not be served. The proof
/// has to be about something that cannot change within the sweep, or stepping
/// over would be a race rather than a decision:
///
/// - A **parked** fill it could be confused with. `NeedsOperator` is cleared
///   only by a human running `resolve-fill`, so within a sweep this answer is
///   stable, and the order is genuinely unservable rather than merely losing a
///   race.
/// - Its **own** open line past a reservation, which is the "I may already have
///   paid for this" case. Only that fill's own progress or an operator clears
///   it, and neither happens while this order waits its turn.
///
/// Deliberately **not** a live holder. `holder_among` says somebody is paying
/// right now, which is exactly the condition that resolves on its own moments
/// later - skipping an order for that would hand its place to a younger order
/// over a transient, which is the unfairness the queue exists to remove. An
/// order blocked only by a live payment keeps the head and takes the slot when
/// it frees.
///
/// Read from the journal snapshot the caller already has, so a sweep does not
/// re-read the file once per waiting order.
pub fn is_blocked_for_this_sweep(latest: &[FillRecord], order: &crate::order::Order) -> bool {
    let Some(funding) = &order.funding else {
        // No outpoint, no fill: this order cannot be at the pay step at all.
        // Not blocked, and the driver's own checks will move it on.
        return false;
    };
    let work = work_id_for(&funding.txid, funding.vout);

    // Its own line, past the states a fresh attempt may displace.
    let own_underway = latest.iter().any(|r| {
        r.work_id() == work
            && r.state.is_open()
            && !zecp2p_taker::auto::journal::is_displaceable_reservation(r.state)
    });
    if own_underway {
        return true;
    }

    // A parked fill this payment could not be told apart from in the feed.
    let applicant = fill_for(&work, order);
    latest.iter().any(|r| {
        r.work_id() != work
            && r.state == FillState::NeedsOperator
            && zecp2p_taker::auto::journal::could_be_confused_in_the_feed(r, &applicant)
    })
}

/// The record this order would claim the slot with.
///
/// One builder, used by both [`take`] and [`is_blocked_for_this_sweep`], so the
/// amount and handle the queue reasons about are the same ones the slot
/// decision will see. Two constructions of this shape would be two chances to
/// disagree about whether an order is confusable, and a queue that skipped an
/// order the slot would have served is a queue that loses somebody's turn.
fn fill_for(work: &WorkId, order: &crate::order::Order) -> FillRecord {
    let mut record = FillRecord::new_zec(
        work.local.clone(),
        alloy::primitives::U256::from(order.quote.usd_amount_6dec),
        alloy::primitives::U256::from(zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC),
        order.handle.clone(),
    );
    record.state = FillState::Seen;
    record
}

/// The queue, with the orders that cannot be served this sweep stepped over.
///
/// FIFO among the rest, so an order's turn is still decided by when its user
/// arrived. Skipping is not losing a place: a stepped-over order is back in
/// contention the moment its blocker clears, ahead of everything younger.
pub fn servable<'a>(
    latest: &[FillRecord],
    ready: &'a [crate::order::Order],
) -> Vec<&'a crate::order::Order> {
    ready
        .iter()
        .filter(|o| !is_blocked_for_this_sweep(latest, o))
        .collect()
}

/// Whether it is this order's turn, once unservable orders are stepped over.
///
/// What `settle` asks. An order blocked for the whole sweep does not hold the
/// head, so the queue behind it moves; an order merely waiting on a live
/// payment does hold it, because that clears on its own and giving its place
/// away would be the unfairness the queue removes.
pub fn is_next_to_pay(
    latest: &[FillRecord],
    ready: &[crate::order::Order],
    order_id: &str,
) -> bool {
    // Not in the list at all: fail open. The caller has already decided this
    // order may pay, and a list that does not contain it is a caller that did
    // not supply one. Failing open costs at worst a race for the slot, which
    // the journal arbitrates safely; failing closed would stop a payment over a
    // bookkeeping disagreement.
    if !ready.iter().any(|o| o.order_id == order_id) {
        return true;
    }

    let servable = servable(latest, ready);

    let head = servable.iter().min_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.order_id.cmp(&b.order_id))
    });

    match head {
        // Somebody can be served. It is their turn, and an order that is not
        // them waits - including one that is itself blocked, which gains
        // nothing from walking into a refusal it would only be stuck behind.
        Some(head) => head.order_id == order_id,
        // Nothing in the queue can be served this sweep, so there is no turn to
        // be behind. Everyone goes on to the slot check, which is where the
        // reason each of them cannot pay actually lives.
        None => true,
    }
}

/// Takes the slot, deciding and claiming under one file lock.
///
/// R4-3: the read and the write used to be separate calls with the decision
/// between them. Within one process the global mutex covered that; between the
/// two daemons nothing did, and they share one Venmo account. `claim_if` holds
/// `flock` across both, so no other process can observe the gap.
///
/// The state written is `Seen`, not `Paying`, and the difference matters.
/// `Seen` holds the slot against every other work item, because
/// `slot_verdict` counts every open record - but it does not assert that
/// money may have moved, so this order can still [`retract`] it when the chain
/// check or the preflight refuses. `Paying` comes later, from [`claim`].
///
/// A `Paying` line is retracted in exactly one place: the rail refusing before
/// it filled the form in, where `NothingWasSent` proves nothing was typed and
/// nothing clicked. Everywhere else a crash past `Paying` still means a human
/// reads the feed. That exception rests entirely on the type being unforgeable
/// - see `venmo::NothingWasSent`.
///
/// Returns the refusal when somebody else holds the slot, so the caller can
/// tell "wait" from "this escrow may already have been paid".
pub fn take(
    journal: &Journal,
    work: &WorkId,
    usd_amount_6dec: u64,
    recipient: &str,
) -> Result<Result<FillRecord, SlotRefusal>> {
    let mut refusal = None;
    let claimed = journal.claim_if(|existing| {
        // The record first, so the decision can see what this payment would be:
        // a parked fill blocks only an amount-and-handle it could be confused
        // with in the feed. Nothing is written unless the verdict is free.
        let mut applicant = FillRecord::new_zec(
            work.local.clone(),
            alloy::primitives::U256::from(usd_amount_6dec),
            alloy::primitives::U256::from(zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC),
            recipient.to_string(),
        );
        applicant.state = FillState::Seen;

        // R7-2: the shared rule, not a second copy of it. `slot_verdict_for`
        // asks the own-work question first and everybody else's second, and
        // both daemons ask it the same way - the two copies had already drifted
        // once, and a drift here is a payment.
        match zecp2p_taker::auto::journal::slot_verdict_for(existing, &applicant) {
            zecp2p_taker::auto::journal::SlotVerdict::Free => {}
            zecp2p_taker::auto::journal::SlotVerdict::OwnPaymentUnderway(r) => {
                refusal = Some(SlotRefusal::ThisOrderMayHavePaid {
                    work: work.to_string(),
                    state: r.state,
                });
                return None;
            }
            zecp2p_taker::auto::journal::SlotVerdict::HeldByAnother(r) => {
                refusal = Some(SlotRefusal::HeldByAnother {
                    work: r.work_id().to_string(),
                    state: r.state,
                });
                return None;
            }
        }

        Some(applicant)
    })?;

    match claimed {
        Some(record) => Ok(Ok(record)),
        None => Ok(Err(refusal.unwrap_or(SlotRefusal::HeldByAnother {
            work: "another fill".into(),
            state: FillState::Seen,
        }))),
    }
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
pub fn retract(journal: &Journal, record: FillRecord, why: &str) {
    zecp2p_taker::auto::journal::release_if_still_ours(
        journal,
        &record,
        FillState::Cancelled,
        why,
    );
}

/// Writes the claim that must precede a payment.
///
/// Separate from [`take`] so the sequence at the call site reads in the order
/// it happens: take the slot, decide, claim, pay. The claim is `Paying`, the
/// ambiguous state - written before the click precisely so that a crash is
/// recorded as "may have paid" rather than as nothing at all.
///
/// It is given back only for a `NothingWasSent` refusal, which proves the form
/// was never filled. See [`take`]'s note.
pub fn claim(
    journal: &Journal,
    reserved: FillRecord,
    intent_hash: alloy::primitives::B256,
    intent_timestamp_ms: u64,
) -> Result<Result<FillRecord, SlotRefusal>> {
    let work = reserved.work_id();

    // R4-3: the slot is read again, under the lock, immediately before the
    // `Paying` line goes down. The reservation closed most of the window, but
    // "most" is not the standard for the last write before money moves: between
    // the reservation and here sit a chain round-trip and the rail's preflight.
    //
    // R7-2: through the same `slot_verdict` the taker uses, so the own-work
    // case - a second instance already paying this order - cannot be caught on
    // one daemon and missed on the other.
    let mut lost = None;
    let written = journal.claim_if(|existing| {
        // `may_continue`, not `slot_verdict`: this fill is mid-flight and is
        // holding its own reservation, so the question is "is the latest line
        // still mine" rather than "is the slot free". The taker asks the same
        // one at the same point.
        if let Err(verdict) = zecp2p_taker::auto::journal::may_continue(existing, &reserved) {
            lost = Some(match verdict {
                zecp2p_taker::auto::journal::SlotVerdict::HeldByAnother(r) => {
                    SlotRefusal::HeldByAnother {
                        work: r.work_id().to_string(),
                        state: r.state,
                    }
                }
                zecp2p_taker::auto::journal::SlotVerdict::OwnPaymentUnderway(r) => {
                    SlotRefusal::ThisOrderMayHavePaid {
                        work: work.to_string(),
                        state: r.state,
                    }
                }
                zecp2p_taker::auto::journal::SlotVerdict::Free => unreachable!("Err is not Free"),
            });
            return None;
        }
        let mut record = reserved.clone();
        record.state = FillState::Paying;
        record.intent_hash = Some(intent_hash);
        record.signalled_at_ms = Some(intent_timestamp_ms);
        Some(record)
    })?;

    if let Some(refusal) = lost {
        // R6-1: a *typed* refusal, not a stringified one. The caller has to
        // tell `HeldByAnother` from `ThisOrderMayHavePaid`, because the
        // responses are opposites: give the reservation back for the first, and
        // never touch the journal for the second. Collapsing both into an
        // `anyhow` bail is what made `settle` retract over a `Paying` line
        // somebody else had already written - cancelling the winner's claim
        // while its dollars were in flight.
        return Ok(Err(refusal));
    }
    written
        .map(Ok)
        .ok_or_else(|| anyhow::anyhow!("the payment slot could not be claimed"))
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
pub fn fulfilled(journal: &Journal, paid: &FillRecord, release_txid: &str) -> Result<()> {
    // R9-2: the caller passes the `Paid` record it is actually holding, so the
    // compare-and-set matches on a normal trade. This used to rebuild that
    // record from scratch with a fresh timestamp, which never matched - so
    // every completed trade took the forced path and logged an error naming the
    // line it "wrote over". The one alarm meant to flag a real bury fired on
    // every single trade, which is the fastest way to teach an operator to
    // ignore it.
    let mut done = paid.clone();
    done.state = FillState::Fulfilled;
    done.note = Some(format!("released in {release_txid}"));

    // Already fulfilled is not an error. A second call - a restart finishing an
    // order whose release landed before the crash - has nothing to do.
    let latest = journal.latest().context("could not read the journal back")?;
    let work = paid.work_id();
    if latest
        .iter()
        .any(|r| r.work_id() == work && r.state == FillState::Fulfilled)
    {
        return Ok(());
    }

    zecp2p_taker::auto::journal::record_outcome(journal, paid, &done)
        .map(|_| ())
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
mod queue_tests {
    use super::*;

    fn order_at(id: &str, created: &str) -> crate::order::Order {
        let mut o = crate::order::Order::for_test(id);
        o.created_at = chrono::DateTime::parse_from_rfc3339(created)
            .unwrap()
            .with_timezone(&chrono::Utc);
        o
    }

    #[test]
    fn the_oldest_waiting_order_is_served_first() {
        let queue = vec![
            order_at("esc_c", "2026-09-06T20:10:00Z"),
            order_at("esc_a", "2026-09-06T20:00:00Z"),
            order_at("esc_b", "2026-09-06T20:05:00Z"),
        ];
        assert_eq!(head_of_queue(&queue).unwrap().order_id, "esc_a");
        // Through the function `settle` calls, with an empty journal so
        // nothing is blocked: a helper exercised only by tests proves the test.
        assert!(is_next_to_pay(&[], &queue, "esc_a"));
        assert!(!is_next_to_pay(&[], &queue, "esc_b"));
        assert!(!is_next_to_pay(&[], &queue, "esc_c"));
    }

    #[test]
    fn the_answer_does_not_depend_on_the_order_the_list_arrives_in() {
        // Every task in a sweep computes the head from its own read of the
        // store, and the store is a hash map. If the answer moved with the
        // iteration order, two tasks could each believe the other was ahead.
        let a = order_at("esc_a", "2026-09-06T20:00:00Z");
        let b = order_at("esc_b", "2026-09-06T20:05:00Z");
        let c = order_at("esc_c", "2026-09-06T20:10:00Z");

        for queue in [
            vec![a.clone(), b.clone(), c.clone()],
            vec![c.clone(), b.clone(), a.clone()],
            vec![b.clone(), a.clone(), c.clone()],
        ] {
            assert_eq!(head_of_queue(&queue).unwrap().order_id, "esc_a");
        }
    }

    #[test]
    fn orders_created_in_the_same_instant_still_have_exactly_one_head() {
        // A tie that both sides lose is a queue that stalls itself: each order
        // sees another it considers prior, so neither ever pays. The order id
        // breaks it, and it breaks it the same way for every reader.
        let queue = vec![
            order_at("esc_b", "2026-09-06T20:00:00Z"),
            order_at("esc_a", "2026-09-06T20:00:00Z"),
        ];
        assert_eq!(head_of_queue(&queue).unwrap().order_id, "esc_a");

        let at_the_head = queue
            .iter()
            .filter(|o| is_next_to_pay(&[], &queue, &o.order_id))
            .count();
        assert_eq!(at_the_head, 1, "exactly one order may be served");
    }

    #[test]
    fn serving_the_head_brings_the_next_order_round() {
        // What makes the wait bounded. The head pays and leaves `Locked`, so
        // the order behind it becomes the head rather than waiting on anything
        // else to happen.
        let mut queue = vec![
            order_at("esc_a", "2026-09-06T20:00:00Z"),
            order_at("esc_b", "2026-09-06T20:05:00Z"),
            order_at("esc_c", "2026-09-06T20:10:00Z"),
        ];
        for expected in ["esc_a", "esc_b", "esc_c"] {
            assert_eq!(head_of_queue(&queue).unwrap().order_id, expected);
            queue.retain(|o| o.order_id != expected);
        }
        assert!(head_of_queue(&queue).is_none());
    }

    /// A journal line for an order, in a given state.
    fn line_for(order: &crate::order::Order, state: FillState) -> FillRecord {
        let funding = order.funding.as_ref().expect("the fixture is funded");
        let work = work_id_for(&funding.txid, funding.vout);
        let mut r = super::fill_for(&work, order);
        r.state = state;
        r
    }

    fn funded(id: &str, created: &str, usd_6dec: u64, handle: &str) -> crate::order::Order {
        let mut o = order_at(id, created);
        o.quote.usd_amount_6dec = usd_6dec;
        o.handle = handle.into();
        let mut txid = [0x9au8; 32];
        txid[0] = id.as_bytes()[id.len() - 1];
        o.funding = Some(crate::order::Funding {
            txid,
            vout: 0,
            confirmations: 30,
            required: 2,
        });
        o
    }

    /// A parked fill for another work item, at a chosen amount and handle.
    fn parked(usd_6dec: u64, handle: &str) -> FillRecord {
        let work = work_id_for(&[0xf1u8; 32], 0);
        let mut r = FillRecord::new_zec(
            work.local.clone(),
            alloy::primitives::U256::from(usd_6dec),
            alloy::primitives::U256::from(1_000_000_000_000_000_000u128),
            handle.into(),
        );
        r.state = FillState::NeedsOperator;
        r
    }

    #[test]
    fn the_queue_steps_over_a_head_a_parked_fill_blocks() {
        // R1-2. The head is refused by `blocker_for` and stays `Locked`, so
        // without this it stays the head until its own deadline - about 24
        // hours - and everything behind it yields to it for that long.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let behind = funded("esc_b", "2026-09-06T20:05:00Z", 700_000, "bob");
        let queue = vec![head.clone(), behind.clone()];
        let journal = vec![parked(2_000_000, "alice")];

        assert!(
            is_blocked_for_this_sweep(&journal, &head),
            "the head is confusable with the parked fill and must be refused"
        );
        assert!(!is_blocked_for_this_sweep(&journal, &behind));

        assert!(
            !is_next_to_pay(&journal, &queue, "esc_a"),
            "a blocked head must not hold the queue"
        );
        assert!(
            is_next_to_pay(&journal, &queue, "esc_b"),
            "the order behind must be served rather than waiting out somebody \
             else's deadline"
        );
    }

    #[test]
    fn a_live_payment_does_not_cost_the_head_its_place() {
        // The distinction that makes stepping over a decision rather than a
        // race. `Paying` clears on its own moments later; handing the head's
        // place to a younger order over that would be exactly the unfairness
        // the queue was built to remove.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let behind = funded("esc_b", "2026-09-06T20:05:00Z", 700_000, "bob");
        let queue = vec![head.clone(), behind.clone()];

        // Somebody else is mid-drive.
        let mut elsewhere = parked(500_000, "carol");
        elsewhere.state = FillState::Paying;
        let journal = vec![elsewhere];

        assert!(
            !is_blocked_for_this_sweep(&journal, &head),
            "a live payment elsewhere is not a reason to skip an order"
        );
        assert!(
            is_next_to_pay(&journal, &queue, "esc_a"),
            "the head keeps its place while another payment is in flight"
        );
        assert!(!is_next_to_pay(&journal, &queue, "esc_b"));
    }

    #[test]
    fn an_order_that_may_already_have_paid_is_stepped_over_too() {
        // Its own line past a reservation. Only that fill's own progress or an
        // operator clears it, so it is stable within a sweep - and an order
        // that would be refused for "I may already have paid for this" must not
        // hold the queue while a human decides.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let behind = funded("esc_b", "2026-09-06T20:05:00Z", 700_000, "bob");
        let queue = vec![head.clone(), behind.clone()];
        let journal = vec![line_for(&head, FillState::NeedsOperator)];

        assert!(is_blocked_for_this_sweep(&journal, &head));
        assert!(is_next_to_pay(&journal, &queue, "esc_b"));
    }

    #[test]
    fn a_crashed_reservation_does_not_cost_an_order_its_turn() {
        // `Seen` and the two signalling states are displaceable: a fresh
        // attempt takes them over, so an order carrying one is servable and
        // keeps its place. Treating them as blocked would send an order to the
        // back of the queue for having crashed once.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let queue = vec![head.clone()];

        for state in [
            FillState::Seen,
            FillState::Signalling,
            FillState::Signalled,
        ] {
            let journal = vec![line_for(&head, state)];
            assert!(
                !is_blocked_for_this_sweep(&journal, &head),
                "{state:?} is displaceable, so the order is still servable"
            );
            assert!(is_next_to_pay(&journal, &queue, "esc_a"));
        }
    }

    #[test]
    fn stepping_over_is_not_losing_a_place() {
        // A skipped order returns to the front the moment its blocker clears,
        // ahead of everything younger. Skipping is per-sweep, not a demotion.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let behind = funded("esc_b", "2026-09-06T20:05:00Z", 700_000, "bob");
        let queue = vec![head.clone(), behind.clone()];

        let blocked = vec![parked(2_000_000, "alice")];
        assert!(is_next_to_pay(&blocked, &queue, "esc_b"));

        // The operator retires the parked fill.
        let mut retired = parked(2_000_000, "alice");
        retired.state = FillState::Resolved;
        let cleared = vec![retired];

        assert!(
            is_next_to_pay(&cleared, &queue, "esc_a"),
            "the older order takes the head back once its blocker is gone"
        );
        assert!(!is_next_to_pay(&cleared, &queue, "esc_b"));
    }

    #[test]
    fn a_queue_of_nothing_but_blocked_orders_still_lets_them_reach_the_slot() {
        // When every waiting order is blocked there is no queue to be behind,
        // and holding them all here would only hide the refusal. They go on to
        // the slot check, which is where the reason lives.
        let head = funded("esc_a", "2026-09-06T20:00:00Z", 2_000_000, "alice");
        let queue = vec![head.clone()];
        let journal = vec![parked(2_000_000, "alice")];

        assert!(servable(&journal, &queue).is_empty());
        assert!(
            is_next_to_pay(&journal, &queue, "esc_a"),
            "an order with nobody ahead of it must reach the refusal that names its reason"
        );
    }

    #[test]
    fn an_unfunded_order_is_not_treated_as_blocked() {
        // No outpoint means no fill, so it cannot be at the pay step at all and
        // the driver's own checks move it on.
        let mut o = order_at("esc_a", "2026-09-06T20:00:00Z");
        o.funding = None;
        assert!(!is_blocked_for_this_sweep(&[], &o));
    }

    #[test]
    fn an_order_nobody_listed_is_not_held_back() {
        // Fails open. The caller has already decided this order may pay, and a
        // list that does not contain it is a caller that did not supply one -
        // which costs at worst the old racing behaviour, safely arbitrated by
        // the journal, rather than a payment stopped over bookkeeping.
        assert!(is_next_to_pay(&[], &[], "esc_a"));

        // And an order the list does not mention, while others wait. The
        // caller has already decided this one may pay; the worst case is a
        // race for the slot, which the journal arbitrates safely.
        let queue = vec![order_at("esc_b", "2026-09-06T20:00:00Z")];
        assert!(is_next_to_pay(&[], &queue, "esc_a"));

        // An order that *is* listed still waits its turn.
        assert!(!is_next_to_pay(
            &[],
            &[
                order_at("esc_a", "2026-09-06T20:05:00Z"),
                order_at("esc_b", "2026-09-06T20:00:00Z"),
            ],
            "esc_a"
        ));
    }
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
        journal.append_unchecked(&r).unwrap();
    }

    #[test]
    fn an_empty_journal_lets_a_payment_start() {
        let (_d, j) = journal();
        assert!(take(&j, &zec_work(1), 700_000, "alice").unwrap().is_ok());
    }

    #[test]
    fn a_paying_record_for_this_order_refuses_a_second_payment() {
        // The crash window. The store says `Locked` after a restart, so the
        // only thing that knows a payment may have left is this line.
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Paying);

        let refusal = take(&j, &work, 700_000, "alice")
            .unwrap()
            .expect_err("must refuse");
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
        assert!(take(&j, &work, 700_000, "alice").unwrap().is_err());
    }

    #[test]
    fn another_orders_paying_record_holds_the_slot() {
        // The late-claim bug: order A is mid-browser and still `Locked` in the
        // store, so only the journal knows the slot is taken.
        let (_d, j) = journal();
        write(&j, &zec_work(0xaa), FillState::Paying);

        let refusal = take(&j, &zec_work(0xbb), 700_000, "alice")
            .unwrap()
            .expect_err("must refuse");
        assert!(matches!(refusal, SlotRefusal::HeldByAnother { .. }));
        assert!(refusal.to_string().contains("One payment at a time"));
    }

    #[test]
    fn another_orders_paid_record_also_holds_the_slot() {
        // That order is waiting on an attestation for a payment sitting in the
        // feed. A second identical payment makes both unprovable.
        let (_d, j) = journal();
        write(&j, &zec_work(0xaa), FillState::Paid);
        assert!(take(&j, &zec_work(0xbb), 700_000, "alice").unwrap().is_err());
    }

    #[test]
    fn a_finished_fill_releases_the_slot() {
        let (_d, j) = journal();
        let other = zec_work(0xaa);
        write(&j, &other, FillState::Paying);
        write(&j, &other, FillState::Fulfilled);
        // Last line per work item wins, so the slot is free again.
        assert!(take(&j, &zec_work(0xbb), 700_000, "alice").unwrap().is_ok());
    }

    #[test]
    fn a_crashed_reservation_does_not_lock_the_order_out() {
        // R9-1. R8-1 blocked a second `Seen`, which stopped one burying case
        // and created a stall: a coordinator killed between reserving and its
        // chain call left a line nobody would advance, and every later order
        // then waited on it forever - silently, because `Seen` never reaches an
        // operator's list.
        //
        // Displacing it is safe under the compare-and-set: the crashed attempt
        // cannot advance afterwards, and cannot give the slot back either.
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Seen);
        assert!(
            take(&j, &work, 700_000, "alice").unwrap().is_ok(),
            "a crashed reservation locked the order out"
        );
    }

    #[test]
    fn an_order_being_paid_still_blocks_a_second_attempt() {
        // The states that mean money may have moved still block, which is the
        // case R8-1 was for. R9-1 relaxes only the pre-payment ones.
        for state in [FillState::Paying, FillState::Paid, FillState::NeedsOperator] {
            let (_d, j) = journal();
            let work = zec_work(1);
            write(&j, &work, state);
            assert!(
                take(&j, &work, 700_000, "alice").unwrap().is_err(),
                "{state:?} must still block"
            );
        }
    }

    #[test]
    fn a_cancelled_record_lets_the_order_try_again() {
        let (_d, j) = journal();
        let work = zec_work(1);
        write(&j, &work, FillState::Seen);
        write(&j, &work, FillState::Cancelled);
        assert!(take(&j, &work, 700_000, "alice").unwrap().is_ok());
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
            let reserved = take(&j, &work, 700_000, "alice").unwrap().unwrap();
            claim(&j, reserved, B256::repeat_byte(0x11), 1_700_000_000_000)
                .unwrap()
                .expect("the claim succeeds");
        }
        let reopened = Journal::open(&path).unwrap();
        let refusal = take(&reopened, &work, 700_000, "alice")
            .unwrap()
            .expect_err("must refuse");
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
        j.append_unchecked(&base).unwrap();

        assert!(take(&j, &zec_work(0xbb), 700_000, "alice").unwrap().is_err());
    }
}
