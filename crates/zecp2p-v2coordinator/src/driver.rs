//! What moves an order forward, and the order it does it in.
//!
//! This is the only module that can spend money, and every step it takes is
//! gated by a check written somewhere else. The sequence below is the safety
//! argument of spec 5.3 to 5.6, and it is a sequence rather than a set:
//!
//! 1. Find the funding output. Nothing is committed by looking.
//! 2. Wait for the depth `required_depth` asks for. `lp::evaluate` decides.
//! 3. Announce to the attestor, and record what it said. Nothing is committed
//!    by announcing either, but the announcement is drawn once and never
//!    redrawn: a second `R` for the same event would be a different outcome
//!    point, and the user's pre-signature is encrypted under the first.
//! 4. Take the user's pre-signature and verify it. **This is the gate.** The LP
//!    pays after it and never before.
//! 5. Pay the dollars, with the journal written first.
//! 6. Get the payment attested, hand the attestation to the attestor, and
//!    receive the outcome scalar.
//! 7. Decrypt, assemble, broadcast.
//!
//! Steps 5 through 7 are the ones where stopping costs money, so each records
//! what it did before it does it, and each is safe to re-enter.

use std::sync::Arc;

use anyhow::{bail, Context, Result};

use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::lp_client::WireTerms;

use crate::funding::choose_funding;
use crate::order::{Funding, Order, Stage};
use crate::state::AppState;

/// Advances one order as far as it can go right now.
///
/// Called on a timer for every open order. It is written to be re-entered: any
/// step that has already happened is detected from the order's own recorded
/// state rather than from where the loop thinks it is.
pub async fn advance(state: &Arc<AppState>, order_id: &str) -> Result<()> {
    // One advance at a time for this order. The sweep and the task `presign`
    // starts both arrive here, and two of them running together would read the
    // same stage, pass the same guard, and pay - or broadcast - twice.
    let lock = state.order_lock(order_id).await;
    let _held = lock.lock().await;

    // Re-read *inside* the lock: whoever held it before may have moved the
    // order on, and the stage this task saw before waiting is now stale.
    let Some(order) = state.store.get(order_id) else {
        return Ok(());
    };
    if !order.stage.is_open() {
        return Ok(());
    }

    match order.stage {
        Stage::AwaitingZec | Stage::Confirming => watch_funding(state, order).await,
        Stage::NeedsPresignature => check_deadlines(state, order).await,
        Stage::Locked => settle(state, order).await,
        Stage::Paid => finish_payment(state, order).await,
        Stage::Refundable => Ok(()),
        _ => Ok(()),
    }
}

/// Looks for the funding output, and moves the order along as it confirms.
async fn watch_funding(state: &Arc<AppState>, mut order: Order) -> Result<()> {
    let scanner = state.scanner.clone();
    let script = order.script_pubkey.clone();
    let address = order.address.clone();
    let from_height = order.opened_height;

    let found = tokio::task::spawn_blocking(move || {
        scanner.outputs_paying(&script, &address, from_height)
    })
    .await
    .context("the funding scan did not complete")?;

    let found = match found {
        Ok(f) => f,
        Err(e) => {
            // A scan that failed is not proof the escrow is unfunded. Log it
            // and try again on the next tick; the order stays refundable at T
            // whatever happens here.
            tracing::warn!(order = %order.order_id, error = %e, "the funding scan failed");
            return Ok(());
        }
    };

    let Some(output) = choose_funding(&found, order.quote.amount_zat) else {
        if !found.is_empty() {
            tracing::info!(
                order = %order.order_id,
                count = found.len(),
                want = order.quote.amount_zat,
                "outputs at the address, none for the quoted amount"
            );
        }
        return check_deadlines(state, order).await;
    };

    // The scanner found an outpoint; the escrow crate decides what it is worth.
    let txid = output.txid;
    let vout = output.vout;
    let utxo = state
        .with_chain(move |chain| {
            chain
                .utxo(&txid, vout)
                .map_err(|e| anyhow::anyhow!("could not read the funding output: {e}"))
        })
        .await?;

    let Some(utxo) = utxo else {
        // Seen by the scanner but not by `gettxout`: either in the mempool
        // only, or spent. Both are "wait".
        return Ok(());
    };

    if utxo.script_pubkey != order.script_pubkey {
        // The scanner matched an address and the node reports a different
        // script. Nothing here is trustworthy enough to settle against.
        tracing::warn!(
            order = %order.order_id,
            "the output the scan found does not pay this escrow's script"
        );
        return Ok(());
    }

    let required = zecp2p_escrow::depth::required_depth(order.quote.usd_amount_6dec);
    let confirmations = utxo.confirmations;

    let first_sighting = order.funding.is_none();
    order.funding = Some(Funding {
        txid,
        vout,
        confirmations,
        required,
    });
    if first_sighting {
        tracing::info!(
            order = %order.order_id,
            txid = %zecp2p_escrow::rpc::txid_to_display(&txid),
            vout,
            "funding output seen"
        );
    }

    if confirmations < required {
        order.stage = Stage::Confirming;
        order.touch();
        state.store.put(&order)?;
        return Ok(());
    }

    // Deep enough. The lock time is recorded once, here, and never recomputed:
    // it is committed by `terms_hash` and it is the cut for the feed search.
    if order.lock_confirmed_ms.is_none() {
        order.lock_confirmed_ms = Some(chrono::Utc::now().timestamp_millis() as u64);
    }
    order.stage = Stage::Confirming;
    order.touch();
    state.store.put(&order)?;

    announce(state, order).await
}

/// Announces the escrow to the attestor and records the answer.
///
/// Drawn once. A second announcement for the same event would carry a fresh
/// `R`, and therefore a different outcome point, and the pre-signature the user
/// already made is encrypted under the first one. The attestor refuses a second
/// announcement per event for the same reason; this does not rely on that.
async fn announce(state: &Arc<AppState>, mut order: Order) -> Result<()> {
    if order.announcement.is_some() {
        order.stage = Stage::NeedsPresignature;
        order.touch();
        state.store.put(&order)?;
        return Ok(());
    }

    let canonical = order
        .canonical_terms()
        .ok_or_else(|| anyhow::anyhow!("announcing before the escrow locked"))?;

    let announced = state
        .with_attestor(move |client| {
            client
                .announce(&canonical)
                .map_err(|e| anyhow::anyhow!("the attestor would not announce: {e}"))
        })
        .await;

    let announced = match announced {
        Ok(a) => a,
        Err(e) => {
            // Nothing is committed yet, so a failed announcement is a retry
            // rather than a loss. The order stays where it is.
            tracing::warn!(order = %order.order_id, error = %e, "announcement failed; will retry");
            return Ok(());
        }
    };

    // The attestor names itself in the announcement. When this coordinator has
    // a pinned key, the two must agree: the page is shown whatever is relayed
    // here, so a coordinator that accepted any `P` could relay one whose scalar
    // it holds and decrypt the user's pre-signature without ever paying.
    if let Some(pinned) = &state.attestor_pubkey {
        let announced_p = hex::decode(&announced.p).unwrap_or_default();
        if announced_p != pinned.serialize() {
            order.fail(format!(
                "the attestor announced key {} but this coordinator pins {}. Nothing was \
                 signed and nothing was paid; the escrow is refundable at block {}.",
                announced.p,
                hex::encode(pinned.serialize()),
                order.refund_height
            ));
            state.store.put(&order)?;
            bail!("the attestor's key is not the pinned one");
        }
    }

    // The terms hash the attestor pinned must be the one these terms produce,
    // or the announcement is for different terms than the page will sign.
    let expected = hex::encode(
        order
            .canonical_terms()
            .expect("canonical terms exist at this point")
            .terms_hash(),
    );
    if announced.terms_hash != expected {
        order.fail(format!(
            "the attestor pinned terms hash {} and these terms hash to {}. Nothing was \
             paid; the escrow is refundable at block {}.",
            announced.terms_hash, expected, order.refund_height
        ));
        state.store.put(&order)?;
        bail!("the attestor pinned a different terms hash");
    }

    order.announcement = Some(crate::order::Announcement {
        event_id: announced.event_id,
        r: announced.r,
        p: announced.p,
        terms_hash: announced.terms_hash,
    });
    order.stage = Stage::NeedsPresignature;
    order.touch();
    state.store.put(&order)?;
    tracing::info!(order = %order.order_id, "announced; waiting for the pre-signature");
    Ok(())
}

/// Moves an unfunded or unsigned order to its terminal state when a deadline
/// has passed. Nothing here spends anything.
async fn check_deadlines(state: &Arc<AppState>, mut order: Order) -> Result<()> {
    let (height, _) = match state.chain_head().await {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(error = %e, "could not read the height for a deadline check");
            return Ok(());
        }
    };

    let refund_height = match u32::try_from(order.refund_height) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    if state.policy.may_refund_at(refund_height, height) {
        if order.stage != Stage::Refundable {
            order.stage = Stage::Refundable;
            order.touch();
            state.store.put(&order)?;
        }
        return Ok(());
    }

    // Past the pay deadline with nothing sent. Nobody has lost anything: the
    // LP never paid, and the user refunds at T.
    if !state.policy.may_pay_before(refund_height, height)
        && !order.stage.fiat_may_have_left()
        && order.stage != Stage::Unpaid
    {
        {
            order.stage = Stage::Unpaid;
            order.touch();
            state.store.put(&order)?;
            tracing::info!(
                order = %order.order_id,
                "past the pay deadline unpaid; the user refunds at T"
            );
        }
    }
    Ok(())
}

/// Verifies a pre-signature and, if it holds, locks the escrow.
///
/// This is the gate of spec 5.3 step 5, and it is the whole reason the LP can
/// pay: a pre-signature that verifies against `u_pub` and `Y` is a promise that
/// the release the LP will assemble is spendable once the attestor answers.
///
/// The digest it verifies against is built from *this order's* split, not from
/// anything the request carried. A caller who could choose the digest could
/// have the LP verify a signature over a transaction that pays somewhere else.
pub fn verify_pre_signature(state: &AppState, order: &Order, pre_signature_hex: &str) -> Result<()> {
    let announcement = order
        .announcement
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this escrow has not been announced yet"))?;

    let raw = hex::decode(pre_signature_hex.trim())
        .context("the pre-signature is not hex")?;
    let pre_sig = secp256k1_zkp::EcdsaAdaptorSignature::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("a pre-signature is 162 bytes of adaptor signature"))?;

    let digest = order.release_digest()?;

    let u_pub = secp256k1_zkp::PublicKey::from_slice(&order.u_pub)
        .context("this order's user key is not a point")?;
    let r = secp256k1_zkp::PublicKey::from_slice(
        &hex::decode(&announcement.r).context("the announcement's R is not hex")?,
    )
    .context("the announcement's R is not a point")?;
    let p = secp256k1_zkp::PublicKey::from_slice(
        &hex::decode(&announcement.p).context("the announcement's P is not hex")?,
    )
    .context("the announcement's P is not a point")?;

    let event_id: [u8; 32] = hex::decode(&announcement.event_id)
        .context("the event id is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the event id is not 32 bytes"))?;
    let terms_hash: [u8; 32] = hex::decode(&announcement.terms_hash)
        .context("the terms hash is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the terms hash is not 32 bytes"))?;

    let y = zecp2p_escrow::dlc::outcome_point(&state.secp, &r, &p, &event_id, &terms_hash)
        .map_err(|e| anyhow::anyhow!("could not compute the outcome point: {e}"))?;

    zecp2p_escrow::dlc::verify_pre_signature(&state.secp, &pre_sig, &digest, &u_pub, &y)
        .map_err(|e| {
            anyhow::anyhow!(
                "the pre-signature does not verify against u_pub and Y ({e}); the LP will not pay"
            )
        })
}

/// The paid path: check, pay, attest, release.
async fn settle(state: &Arc<AppState>, order: Order) -> Result<()> {
    let Some(fiat) = state.fiat.clone() else {
        tracing::debug!(
            order = %order.order_id,
            "locked, but no fiat rail is configured; nothing will be paid"
        );
        return Ok(());
    };

    let funding = order
        .funding
        .ok_or_else(|| anyhow::anyhow!("settling an order with no funding outpoint"))?;
    let work = crate::slot::work_id_for(&funding.txid, funding.vout);

    // **The critical section starts here.**
    //
    // R2-1: the slot check below is a read of the journal, and the matching
    // write is three `await` points away - a chain round-trip and the rail's
    // preflight sit between them. The per-order lock does not help, because the
    // two racing tasks are two *different* orders. So two of them read an empty
    // journal, both passed, both wrote `Paying`, and both paid; the reviewer
    // reproduced exactly that, two payments with an overlap of two.
    //
    // A read-then-write on a shared resource has to happen inside one lock.
    // This is that lock, it is global, and it is held until the payment's
    // outcome is on disk. Another order arriving meanwhile waits here rather
    // than observing the gap.
    //
    // Skipped rather than queued: an order that waited would hold this task
    // for as long as a browser drive takes, and the sweep will come back for
    // it in seconds anyway.
    // R3-7: one operation, not a check followed by an acquire. `try_lock` both
    // asks and takes, so there is no window between them in which a third task
    // could slip in - and skipping rather than queueing keeps this task from
    // being held for as long as a browser drive takes, since the sweep returns
    // in seconds.
    let Some(_paying) = state.try_pay_lock() else {
        tracing::info!(
            order = %order.order_id,
            "waiting for the payment slot: another order is paying"
        );
        return Ok(());
    };

    // Re-read the order under the lock. Whoever held it before may have moved
    // this very order on - the presign task and the sweep both arrive here -
    // and the copy read before the wait is stale.
    let Some(order_now) = state.store.get(&order.order_id) else {
        return Ok(());
    };
    if order_now.stage != Stage::Locked {
        tracing::debug!(
            order = %order.order_id,
            stage = order_now.stage.as_str(),
            "no longer waiting to be paid"
        );
        return Ok(());
    }
    let mut order = order_now;

    // The one payment slot: read and claimed under one file lock, so the
    // window a second daemon could read through does not exist. `take` writes a
    // `Seen` line, which holds the slot without asserting money may have moved
    // - so it can still be given back below if the chain or the rail says no.
    let reserved = match crate::slot::take(
        &state.journal,
        &work,
        order.quote.usd_amount_6dec,
        &order.handle,
    )? {
        Ok(record) => record,
        Err(refusal) => match &refusal {
            // Somebody else holds it: wait, and try again on the next sweep.
            // Nothing is wrong with this order.
            crate::slot::SlotRefusal::HeldByAnother { .. } => {
                // R5-d: the deadline check runs even while the slot is held.
                // Returning early left an order past `T` sitting at `locked`
                // for as long as another trade took, so the page never offered
                // the refund the user was entitled to.
                tracing::info!(order = %order.order_id, reason = %refusal, "waiting for the payment slot");
                drop(_paying);
                return check_deadlines(state, order).await;
            }
            crate::slot::SlotRefusal::ThisOrderMayHavePaid { .. } => {
                // R3-4: `Paid` here is not an error, it is the post-payment
                // store write having failed. The dollars are gone and the
                // release is the only thing that recovers them, so the order is
                // finished rather than failed.
                if crate::slot::definitely_paid(&state.journal, &work).unwrap_or(false) {
                    tracing::warn!(
                        order = %order.order_id,
                        "the journal says this escrow was PAID and the order does not, which \
                         is the post-payment store write having failed. Recording the \
                         payment and going on to the release: abandoning it would leave the \
                         LP having paid for an escrow that refunds to the user."
                    );
                    order.payment = Some(crate::order::Payment {
                        sent_at: chrono::Utc::now(),
                        cents: order.quote.net_cents,
                    });
                    order.stage = Stage::Paid;
                    order.touch();
                    state.store.put(&order)?;
                    drop(_paying);
                    return finish_payment(state, order).await;
                }
                tracing::error!(order = %order.order_id, reason = %refusal, "refusing to pay twice");
                order.fail(refusal.to_string());
                state.store.put(&order)?;
                return Ok(());
            }
        },
    };

    let watched = watched_escrow(state, &order)?;

    // Re-read the chain and re-ask whether paying is allowed. The state that
    // said this escrow was payable was computed on an earlier tick, and the
    // chain has moved since.
    //
    // Two questions, not one. `require_payable` asks the escrow crate whether
    // the lock, the depth, the pre-signature and the deadlines allow a payment.
    // It does **not** read the consensus branch id (R1-3): `lp::evaluate` never
    // touches it, and this coordinator's own module docs claimed a check that
    // was not being made. A network upgrade inside the 24-hour refund window
    // changes the ZIP 244 sighash, so the pre-signature the user made stops
    // authorising the transaction the LP will build - and the LP finds out
    // after it has paid the dollars. The taker's rail asks first, and so does
    // this.
    let policy = state.policy;
    let check = watched.clone();
    let terms = watched.terms.clone();
    let payable = state
        .with_chain(move |chain| {
            // The funding output, re-read. `lp::evaluate` below does this too,
            // via `chain.utxo`, and refuses on a script or amount mismatch or
            // insufficient depth - so a reorg that unwound the funding between
            // the lock and the payment is caught there rather than here. This
            // call is left to `evaluate` deliberately: a second, separate
            // reading of the same outpoint could disagree with the one the
            // decision is made on.
            zecp2p_escrow::lp::check_branch(chain, &terms).map_err(|e| {
                anyhow::anyhow!(
                    "{e}. The pre-signature was made for another consensus branch, so the \
                     release it authorises would not verify. Not paying this escrow."
                )
            })?;
            zecp2p_taker::auto::zec::require_payable(chain, &check, &policy)
        })
        .await;

    if let Err(e) = payable {
        tracing::info!(order = %order.order_id, reason = %format!("{e:#}"), "not payable yet");
        crate::slot::retract(&state.journal, reserved, "the chain says not yet");
        // R3-8: off the pay lock before a chain read. `check_deadlines` talks
        // to the node, and holding the one global payment lock across it makes
        // every other order wait on a call that has nothing to do with paying.
        drop(_paying);
        return check_deadlines(state, order).await;
    }

    let leg = match watched.fiat_leg(state.config.quote.max_payment_cents) {
        Ok(leg) => leg,
        Err(e) => {
            crate::slot::retract(&state.journal, reserved, "the payment is over the cap");
            return Err(e)
                .context("this escrow agreed a payment this coordinator will not send");
        }
    };

    // Can this rail pay at all? Asked before the journal entry, because a rail
    // that cannot start has provably sent nothing, and an escrow whose LP never
    // began is one the user refunds at T. Failing the order here would strand
    // the ZEC in a terminal state over an operator problem - a signed-out
    // browser, a stale cookie - that a restart fixes.
    if let Err(e) = fiat.preflight().await {
        tracing::warn!(
            order = %order.order_id,
            error = %format!("{e:#}"),
            "the fiat rail cannot pay right now; nothing was sent and the escrow stays refundable"
        );
        crate::slot::retract(&state.journal, reserved, "the fiat rail cannot start");
        // Off the lock before the chain read in `check_deadlines`. See R3-8.
        drop(_paying);
        return check_deadlines(state, order).await;
    }

    // The claim goes down before the click, and it is what the check above
    // reads on the next tick or after a restart. `fiat::pay` deliberately
    // writes nothing itself, and a crash between here and Venmo cannot be told
    // from a completed payment - so the expensive reading of that ambiguity is
    // recorded first, and a human resolves it from the feed.
    let mut record = match crate::slot::claim(
        &state.journal,
        reserved.clone(),
        leg.intent_hash,
        leg.intent_timestamp_ms,
    )? {
        Ok(record) => record,

        // R5-1: somebody else holds the slot. The reservation goes back, or
        // this order's own `Seen` blocks every other order - including the one
        // that won - until an operator clears it. Nothing was sent, so
        // `Cancelled` is the truth.
        Err(refusal @ crate::slot::SlotRefusal::HeldByAnother { .. }) => {
            tracing::info!(
                order = %order.order_id,
                reason = %refusal,
                "lost the payment slot before the click; giving the reservation back"
            );
            crate::slot::retract(&state.journal, reserved, "lost the slot before paying");
            drop(_paying);
            return check_deadlines(state, order).await;
        }

        // R6-1: a payment for *this* work item is already under way, which on
        // one state directory means a second coordinator got here first, and on
        // a restart means this order's own earlier attempt. Either way the
        // journal's `Paying` line belongs to whoever is driving the browser
        // right now.
        //
        // **Retracting here is the bug that was here.** It wrote `Cancelled`
        // over the winner's claim while its dollars were in flight, so the next
        // sweep read a free slot, re-took the order and paid a second time -
        // undoing the single-instance guard entirely. The journal is not
        // touched on this path.
        Err(refusal) => {
            tracing::error!(
                order = %order.order_id,
                reason = %refusal,
                "another payment for this escrow is already under way; not retracting and \
                 not paying"
            );
            order.fail(refusal.to_string());
            state.store.put(&order)?;
            return Ok(());
        }
    };

    let paid = match fiat.pay(&leg).await {
        Ok(p) => p,
        Err(e) => {
            // The payment may still have gone out: the browser is driven and
            // the failure could be anywhere in it. The journal already says
            // `Paying`, which is the ambiguous state a human resolves.
            // R8-1: post-payment, so this must land - `record_outcome` tries
            // the compare-and-set first and, if another line is standing here,
            // writes anyway and names what it wrote over. Losing this line
            // silently means the next order pays into an unreconciled feed.
            let mut stuck = record.clone();
            stuck.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
            stuck.note = Some(format!(
                "the Venmo leg failed: {e}. This coordinator's payment may or may not \
                 have left; read the feed."
            ));
            if let Err(write_err) =
                zecp2p_taker::auto::journal::record_outcome(&state.journal, &record, &stuck)
            {
                tracing::error!(
                    order = %order.order_id,
                    error = %format!("{write_err:#}"),
                    "the Venmo leg failed AND the journal could not record it. The slot may \
                     read as free to the next order; check the feed before anything else runs."
                );
            }
            order.fail(format!(
                "the payment could not be completed: {e}. Check the Venmo feed before \
                 anything else: a payment may have left."
            ));
            state.store.put(&order)?;
            bail!("the fiat leg failed for {}: {e}", order.order_id);
        }
    };

    if !paid.fiat_left {
        // A dry run. The escrow is untouched and the user refunds at T, so the
        // slot goes back: nothing was sent, and holding it would stall every
        // other order behind a rail that never intends to pay.
        tracing::warn!(
            order = %order.order_id,
            "the fiat rail did not send: serve.live_payments is false"
        );
        crate::slot::retract(&state.journal, record, "the rail was in dry-run mode");
        return Ok(());
    }

    // The dollars are gone. From here nothing may abort the release: it is the
    // only thing that recovers the payment, and the escrow's timeout branch is
    // running against it.
    //
    // R2-3: this used to write the journal first with `?`, so a failed journal
    // write - a full disk, a permissions change - bailed with the store still
    // at `Locked`. The next sweep then read `Paying`, correctly refused to pay
    // twice, and failed the order: dollars gone, release never attempted, and
    // the LP's own escrow left to the user's refund. Two changes:
    //
    // The **order store goes first**, because it is what `finish_payment` reads
    // to know a payment happened, and it is what a restart reads. Then the
    // journal, which is the operator's record and the slot.
    //
    // And **neither write can stop the release.** A write that fails is logged
    // at error and the release is attempted anyway. That is the right trade:
    // the worst case of proceeding is a release whose bookkeeping is missing,
    // which a human can reconcile from the chain; the worst case of stopping is
    // an escrow that refunds to the user after the LP has paid them.
    order.payment = Some(crate::order::Payment {
        sent_at: chrono::Utc::now(),
        cents: paid.cents,
    });
    order.stage = Stage::Paid;
    order.touch();
    if let Err(e) = state.store.put(&order) {
        tracing::error!(
            order = %order.order_id,
            error = %format!("{e:#}"),
            "the dollars have gone and this order could not be written to disk.              Continuing to the release anyway: the payment is unrecoverable without it.              A restart before the release lands will not know this order was paid."
        );
    }

    let mut paid_line = record.clone();
    paid_line.state = zecp2p_taker::auto::journal::FillState::Paid;
    paid_line.paid = Some(leg.payment.to_venmo_string());
    if let Err(e) =
        zecp2p_taker::auto::journal::record_outcome(&state.journal, &record, &paid_line)
            .map(|written| record = written)
    {
        tracing::error!(
            order = %order.order_id,
            error = %format!("{e:#}"),
            "the dollars have gone and the journal could not be updated. The slot stays              held by the Paying line, which is the safe direction; continuing to the release."
        );
    }
    tracing::info!(order = %order.order_id, cents = paid.cents, "the dollars have gone");

    // The payment slot is released here, by dropping the guard, and not before:
    // the order is `Paid` on disk and the journal line is written, so any other
    // order arriving now reads a slot that is properly held by a `Paid` record.
    // `finish_payment` does not need the lock - it pays nothing - and holding it
    // through an attestation would stall every other trade for minutes.
    drop(_paying);

    finish_payment(state, order).await
}

/// Everything after the money left: attest, get the scalar, broadcast.
///
/// Re-entrant. Nothing here is gated on human approval, because by this point
/// the fiat is gone and the release is the only thing that recovers it; asking
/// permission to finish is asking permission to lose the payment.
async fn finish_payment(state: &Arc<AppState>, mut order: Order) -> Result<()> {
    let Some(fiat) = state.fiat.clone() else {
        return Ok(());
    };
    if let Some(txid) = order.release_txid.clone() {
        // A restart on an order that already released. The slot may still be
        // held by a `Paid` line from before the crash, and nothing else will
        // ever free it.
        order.stage = Stage::Released;
        order.touch();
        state.store.put(&order)?;
        release_slot(state, &order, &txid);
        return Ok(());
    }

    let watched = watched_escrow(state, &order)?;
    let leg = watched.fiat_leg(state.config.quote.max_payment_cents)?;

    let attestation = fiat
        .attest(&leg)
        .await
        .context("the payment could not be attested; the fiat has already left")?;

    let canonical = order
        .canonical_terms()
        .ok_or_else(|| anyhow::anyhow!("no canonical terms for a paid order"))?;
    let event_id = order
        .announcement
        .as_ref()
        .map(|a| a.event_id.clone())
        .ok_or_else(|| anyhow::anyhow!("a paid order with no announcement"))?;

    let scalar = state
        .with_attestor(move |client| {
            client
                .attest(&event_id, &canonical, attestation)
                .map_err(|e| anyhow::anyhow!("the attestor would not sign the outcome: {e}"))
        })
        .await?;

    broadcast_release(state, order.clone(), scalar).await
}

/// Decrypts the pre-signature with the attestor's scalar, assembles the
/// release, and broadcasts it.
async fn broadcast_release(
    state: &Arc<AppState>,
    mut order: Order,
    scalar: [u8; 32],
) -> Result<()> {
    let announcement = order
        .announcement
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("releasing an unannounced escrow"))?;
    let pre_signature_hex = order
        .pre_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("releasing an escrow with no pre-signature"))?;

    let s = secp256k1_zkp::SecretKey::from_slice(&scalar)
        .context("the attestor's scalar is not a valid secp256k1 scalar")?;

    // Check the scalar is the one this outcome point was built for, before
    // spending anything on it.
    let r = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&announcement.r)?)?;
    let p = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&announcement.p)?)?;
    let event_id: [u8; 32] = hex::decode(&announcement.event_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the event id is not 32 bytes"))?;
    let terms_hash: [u8; 32] = hex::decode(&announcement.terms_hash)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the terms hash is not 32 bytes"))?;
    let y = zecp2p_escrow::dlc::outcome_point(&state.secp, &r, &p, &event_id, &terms_hash)
        .map_err(|e| anyhow::anyhow!("could not recompute the outcome point: {e}"))?;
    zecp2p_escrow::dlc::verify_outcome_secret(&state.secp, &s, &y)
        .map_err(|e| anyhow::anyhow!("the attestor's scalar does not match the outcome point: {e}"))?;

    let pre_sig = secp256k1_zkp::EcdsaAdaptorSignature::from_slice(&hex::decode(pre_signature_hex)?)
        .map_err(|_| anyhow::anyhow!("the stored pre-signature is not 162 bytes"))?;

    let sig_u = zecp2p_escrow::dlc::decrypt_pre_signature(&pre_sig, &s)
        .map_err(|e| anyhow::anyhow!("the pre-signature would not decrypt: {e}"))?;

    let funding = order
        .funding
        .ok_or_else(|| anyhow::anyhow!("releasing an escrow with no funding outpoint"))?;
    let terms = order.escrow_terms(&funding);
    let split = order.release_split();
    let digest = order.release_digest()?;

    // The LP's own signature over the same digest.
    let sig_l = state.sign_release_digest(&digest);

    // `encode_signature` normalises S. Adaptor decryption can yield a high-S
    // signature, which is valid by consensus and refused by every mempool, so
    // skipping this leaves the LP's money in an escrow it cannot spend.
    let sig_u_1 = secp256k1::ecdsa::Signature::from_der(&sig_u.serialize_der())
        .context("the decrypted signature does not re-encode")?;
    let script_sig = zecp2p_escrow::script::release_script_sig(
        &zecp2p_escrow::tx::encode_signature(&sig_u_1),
        &zecp2p_escrow::tx::encode_signature(&sig_l),
        &terms
            .redeem_script()
            .map_err(|e| anyhow::anyhow!("could not rebuild the redeem script: {e}"))?,
    );

    let raw = zecp2p_escrow::tx::serialize_release_split(&terms, &split, &script_sig)
        .map_err(|e| anyhow::anyhow!("could not serialize the release: {e}"))?;

    let refund_height = u32::try_from(order.refund_height)
        .map_err(|_| anyhow::anyhow!("this escrow's refund height is not a block height"))?;
    let policy = state.policy;

    let txid = state
        .with_chain(move |chain| {
            zecp2p_escrow::lp::broadcast_release_until_deadline(
                chain,
                &policy,
                refund_height,
                &raw,
                || std::thread::sleep(std::time::Duration::from_secs(15)),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .await;

    match txid {
        Ok(txid) => {
            // Not named `display`: that shadows `tracing::field::display`,
            // which the macro below resolves through `%`.
            let release_txid = zecp2p_escrow::rpc::txid_to_display(&txid);
            order.release_txid = Some(release_txid.clone());
            order.stage = Stage::Released;
            order.touch();

            // R4-d: this used to be `put(&order)?`, which bailed after the
            // release was already on chain - leaving the store at `Paid` with
            // no txid, so the next sweep re-attested and re-broadcast. The
            // second broadcast is harmless on its own (the node answers
            // "already in the chain", which `is_already_accepted` maps to
            // success) but the second `/attest` is not free: the attestor signs
            // one outcome per event, and burning the call on a retry costs the
            // one thing that can complete a release.
            //
            // So a failure here is loud and not fatal, and the slot is released
            // regardless: the trade is finished on chain whatever this file
            // says.
            if let Err(e) = state.store.put(&order) {
                tracing::error!(
                    order = %order.order_id,
                    txid = %release_txid,
                    error = %format!("{e:#}"),
                    "the release is on chain and this order could not be written to disk. \
                     Reconcile from the txid: the escrow has paid out."
                );
            }

            // The slot is released here and nowhere else. Until this line the
            // journal still says `Paid`, which holds the slot - correctly, since
            // a payment without a release is exactly the state a human needs to
            // see. Now the escrow has paid out against it and there is nothing
            // left to reconcile.
            release_slot(state, &order, &release_txid);

            tracing::info!(order = %order.order_id, txid = %release_txid, "released");
            Ok(())
        }
        Err(e) => {
            // The fiat has left and the release did not land. This is the one
            // state that always needs a human: the release still spends, and it
            // is now racing the user's refund.
            order.fail(format!(
                "the dollars were sent and the release did not broadcast: {e}. The release \
                 is still valid and is now racing the refund at block {}.",
                order.refund_height
            ));
            state.store.put(&order)?;
            Err(e)
        }
    }
}

/// Marks the fill fulfilled, which is what frees the payment slot.
///
/// Best-effort: it runs after the release is on chain, so failing to write it
/// cannot lose money. It can only leave the slot held, which surfaces as a
/// stuck fill an operator clears rather than as a second payment.
fn release_slot(state: &AppState, order: &Order, release_txid: &str) {
    let Some(funding) = order.funding else {
        return;
    };
    let work = crate::slot::work_id_for(&funding.txid, funding.vout);

    // R9-2: the line as it actually stands, so the compare-and-set matches on a
    // normal trade. Rebuilding it here - which is what this did - produced a
    // fresh timestamp that never matched, so every completed trade took the
    // forced path and logged an error about writing over a line it had not.
    let held = match state.journal.latest() {
        Ok(latest) => latest.into_iter().find(|r| r.work_id() == work),
        Err(e) => {
            tracing::error!(
                order = %order.order_id,
                error = %format!("{e:#}"),
                "could not read the journal to release the slot; it stays held"
            );
            return;
        }
    };
    let Some(held) = held else {
        // No line at all. Nothing holds the slot, so nothing to release.
        return;
    };

    if let Err(e) = crate::slot::fulfilled(&state.journal, &held, release_txid) {
        tracing::error!(
            order = %order.order_id,
            error = %format!("{e:#}"),
            "the release landed but the fill could not be marked fulfilled. The payment \
             slot stays held, so no further order will be paid until this is cleared."
        );
    }
}

/// The escrow as the taker's ZEC rail wants to see it.
fn watched_escrow(
    state: &AppState,
    order: &Order,
) -> Result<zecp2p_taker::auto::zec::WatchedEscrow> {
    let funding = order
        .funding
        .ok_or_else(|| anyhow::anyhow!("this order has no funding outpoint"))?;
    let canonical = order
        .canonical_terms()
        .ok_or_else(|| anyhow::anyhow!("this order has not locked"))?;
    let _ = state;
    Ok(zecp2p_taker::auto::zec::WatchedEscrow {
        terms: order.escrow_terms(&funding),
        canonical,
        recipient: order.handle.clone(),
        // Only ever true because `verify_pre_signature` returned Ok and the
        // order was moved to `Locked` as a result.
        pre_signature_verified: order.pre_signature.is_some(),
        venmo_paid: order.payment.is_some(),
        outcome_secret_held: false,
    })
}

/// The wire terms for an order, for a caller that wants to show them.
pub fn wire_terms(order: &Order) -> Option<WireTerms> {
    order.canonical_terms().as_ref().map(WireTerms::from_terms)
}

/// Sweeps every open order on a timer.
///
/// Each order is advanced on its own task. The sweep used to `await` them in
/// turn, which meant one order driving a browser for two minutes held up the
/// funding scan for every other order behind it in the list - including orders
/// approaching `T` whose users were waiting to be told they could refund.
///
/// Concurrency here is safe because it is not concurrency over the things that
/// must be serialised: `advance` takes the per-order lock, so one order is
/// never advanced twice at once, and the payment slot in `slot.rs` is global,
/// so only one order can be paying whatever the sweep does.
pub async fn run(state: Arc<AppState>, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let mut tasks = tokio::task::JoinSet::new();
        for order in state.store.open_orders() {
            let state = state.clone();
            let id = order.order_id;
            tasks.spawn(async move {
                if let Err(e) = advance(&state, &id).await {
                    tracing::warn!(order = %id, error = %format!("{e:#}"), "could not advance");
                }
            });
        }
        // Waited out before the next tick, so a stalled order cannot make the
        // sweeps pile up on top of each other.
        while tasks.join_next().await.is_some() {}
    }
}
