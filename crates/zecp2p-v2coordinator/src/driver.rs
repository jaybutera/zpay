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
async fn settle(state: &Arc<AppState>, mut order: Order) -> Result<()> {
    let Some(fiat) = state.fiat.clone() else {
        tracing::debug!(
            order = %order.order_id,
            "locked, but no fiat rail is configured; nothing will be paid"
        );
        return Ok(());
    };

    // One payment in flight at a time. Two feed entries of the same amount to
    // the same handle is a situation `locate_payment` refuses to resolve, and
    // by then both payments have left.
    if let Some(other) = state.store.another_payment_in_flight(&order.order_id) {
        tracing::info!(
            order = %order.order_id,
            other = %other,
            "waiting: another order has a payment in flight"
        );
        return Ok(());
    }

    let watched = watched_escrow(state, &order)?;

    // Re-read the chain and re-ask whether paying is allowed. The state that
    // said this escrow was payable was computed on an earlier tick, and the
    // chain has moved since.
    let policy = state.policy;
    let check = watched.clone();
    let payable = state
        .with_chain(move |chain| {
            zecp2p_taker::auto::zec::require_payable(chain, &check, &policy)
        })
        .await;

    if let Err(e) = payable {
        tracing::info!(order = %order.order_id, reason = %e, "not payable yet");
        return check_deadlines(state, order).await;
    }

    let leg = watched
        .fiat_leg(state.config.quote.max_payment_cents)
        .context("this escrow agreed a payment this coordinator will not send")?;

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
        return check_deadlines(state, order).await;
    }

    // The journal entry goes down before the click. `fiat::pay` deliberately
    // writes nothing, and a crash between here and Venmo cannot be told from a
    // completed payment - so the safe reading of the ambiguity is recorded
    // first, and a human resolves it from the feed.
    let mut record = zecp2p_taker::auto::journal::FillRecord::new_zec(
        order
            .funding
            .map(|f| {
                format!(
                    "{}:{}",
                    zecp2p_escrow::rpc::txid_to_display(&f.txid),
                    f.vout
                )
            })
            .unwrap_or_else(|| order.order_id.clone()),
        alloy::primitives::U256::from(order.quote.usd_amount_6dec),
        alloy::primitives::U256::from(zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC),
        order.handle.clone(),
    );
    record.state = zecp2p_taker::auto::journal::FillState::Paying;
    record.intent_hash = Some(leg.intent_hash);
    record.signalled_at_ms = Some(leg.intent_timestamp_ms);
    state
        .journal
        .record(&record)
        .context("could not write the journal entry that must precede a payment")?;

    let paid = match fiat.pay(&leg).await {
        Ok(p) => p,
        Err(e) => {
            // The payment may still have gone out: the browser is driven and
            // the failure could be anywhere in it. The journal already says
            // `Paying`, which is the ambiguous state a human resolves.
            record.state = zecp2p_taker::auto::journal::FillState::NeedsOperator;
            record.note = Some(format!("the Venmo leg failed: {e}"));
            let _ = state.journal.record(&record);
            order.fail(format!(
                "the payment could not be completed: {e}. Check the Venmo feed before \
                 anything else: a payment may have left."
            ));
            state.store.put(&order)?;
            bail!("the fiat leg failed for {}: {e}", order.order_id);
        }
    };

    if !paid.fiat_left {
        // A dry run. The escrow is untouched and the user refunds at T.
        tracing::warn!(
            order = %order.order_id,
            "the fiat rail did not send: serve.live_payments is false"
        );
        return Ok(());
    }

    record.state = zecp2p_taker::auto::journal::FillState::Paid;
    record.paid = Some(leg.payment.to_venmo_string());
    state.journal.record(&record)?;

    order.payment = Some(crate::order::Payment {
        sent_at: chrono::Utc::now(),
        cents: paid.cents,
    });
    order.stage = Stage::Paid;
    order.touch();
    state.store.put(&order)?;
    tracing::info!(order = %order.order_id, cents = paid.cents, "the dollars have gone");

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
    if order.release_txid.is_some() {
        order.stage = Stage::Released;
        order.touch();
        state.store.put(&order)?;
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
            order.release_txid = Some(zecp2p_escrow::rpc::txid_to_display(&txid));
            order.stage = Stage::Released;
            order.touch();
            state.store.put(&order)?;
            tracing::info!(
                order = %order.order_id,
                txid = %zecp2p_escrow::rpc::txid_to_display(&txid),
                "released"
            );
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
pub async fn run(state: Arc<AppState>, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        for order in state.store.open_orders() {
            if let Err(e) = advance(&state, &order.order_id).await {
                tracing::warn!(order = %order.order_id, error = %format!("{e:#}"), "could not advance");
            }
        }
    }
}
