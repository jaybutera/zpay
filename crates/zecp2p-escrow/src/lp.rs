//! The LP's side of the protocol, spec 5.3 to 5.6 and section 7.
//!
//! The LP is the party with money at risk: it pays Venmo before it can claim,
//! and nothing it does after paying is guaranteed to succeed. So the ordering
//! here is the whole safety argument, and it is expressed as a state machine
//! rather than a sequence of calls, so that "pay" is unreachable from a state
//! where the escrow is not yet confirmed or the pre-signature has not verified.

use crate::attestation::PaymentAttestation;
use crate::chain::{ChainClient, ChainError, Utxo};
use crate::deadlines::EscrowPolicy;
use crate::terms::CanonicalTerms;
use crate::tx::EscrowTerms;

/// Where an escrow stands from the LP's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LpState {
    /// The user has sent terms and a pre-signature; nothing is on chain yet.
    AwaitingLock,
    /// The escrow output exists but has not reached the depth for its size.
    AwaitingDepth { confirmations: u32, required: u32 },
    /// Confirmed to the required depth and inside `PAY_DEADLINE`. The LP may
    /// pay Venmo. This is the only state from which paying is allowed.
    ReadyToPay,
    /// Paid, waiting on the enclave and the attestor.
    AwaitingAttestation,
    /// The attestor's scalar is in hand and the release can be assembled.
    ReadyToRelease,
    /// Past `PAY_DEADLINE` without having paid. The LP does nothing further and
    /// the user refunds at `T`; this is the "nobody loses" row of section 8.
    AbandonedUnpaid,
    /// Paid, but past `BROADCAST_DEADLINE` without a release. Still worth
    /// broadcasting, and now racing the refund, which is the LP's loss.
    PaidPastMargin,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LpError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("the escrow output pays a script other than the agreed P2SH address")]
    WrongEscrowScript,
    #[error("the escrow holds {found} zat, the terms say {expected}")]
    WrongAmount { found: u64, expected: u64 },
    #[error(
        "the node reports consensus branch {found:#x}, the terms were built for {expected:#x}"
    )]
    BranchMismatch { found: u32, expected: u32 },
    #[error("the pre-signature does not verify; the LP must not pay")]
    BadPreSignature,
    #[error("refusing to pay from state {0:?}")]
    NotPayable(LpState),
    #[error("the terms carry a refund height of {0}, which is not a valid block height")]
    RefundHeightOutOfRange(u64),
    #[error(
        "height {height} is past the broadcast deadline {deadline} and the node still says: \
         {last}"
    )]
    BroadcastDeadlinePassed {
        height: u32,
        deadline: u32,
        last: String,
    },
    /// The caller's `sleep` hook ended the loop between attempts.
    ///
    /// Distinct from [`LpError::BroadcastDeadlinePassed`], which means the
    /// chain has moved past the point where the release still wins its race
    /// with the refund. This means only that *this attempt* stopped: the
    /// deadline has not passed, the release is still worth broadcasting, and
    /// the caller is expected to come back.
    #[error("stopped retrying the broadcast before the deadline; the node last said: {last}")]
    BroadcastGaveUp { last: String },
}

/// Whether the LP has paid, and whether it holds the attestor's scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LpProgress {
    pub pre_signature_verified: bool,
    pub venmo_paid: bool,
    pub outcome_secret_held: bool,
}

/// Decides the LP's state from the chain, the clock and its own progress.
///
/// This is a pure function of observable facts. It never pays and never
/// broadcasts; the caller does that, and only from the states that permit it.
pub fn evaluate(
    chain: &impl ChainClient,
    terms: &EscrowTerms,
    canonical: &CanonicalTerms,
    policy: &EscrowPolicy,
    progress: LpProgress,
) -> Result<LpState, LpError> {
    let current = chain.height()?;
    // Every deadline comes from the `T` burned into the redeem script, not from
    // an observed lock height. The script's CLTV is the only clock the chain
    // honours, so a lock height recorded a block late would put the LP's
    // margins somewhere the chain does not agree with - and at worst leave
    // `ReadyToPay` reachable at the very height the user can refund.
    let refund_height = u32::try_from(terms.refund_height)
        .map_err(|_| LpError::RefundHeightOutOfRange(terms.refund_height))?;

    if progress.outcome_secret_held {
        return Ok(LpState::ReadyToRelease);
    }

    if progress.venmo_paid {
        return Ok(
            if policy.within_broadcast_margin_of(refund_height, current) {
                LpState::AwaitingAttestation
            } else {
                LpState::PaidPastMargin
            },
        );
    }

    // Not paid. Past the pay deadline the LP stops, whatever the escrow looks
    // like: paying inside the margin is how a release loses the race to the
    // refund after money has already gone out.
    if !policy.may_pay_before(refund_height, current) {
        return Ok(LpState::AbandonedUnpaid);
    }

    let Some(utxo) = chain.utxo(&terms.funding_txid, terms.vout)? else {
        // Either not yet mined, or unwound by a reorg. Both are "wait".
        return Ok(LpState::AwaitingLock);
    };

    check_escrow_matches(terms, canonical, &utxo)?;

    let required = crate::depth::required_depth(canonical.usd_amount_6dec);
    if utxo.confirmations < required {
        return Ok(LpState::AwaitingDepth {
            confirmations: utxo.confirmations,
            required,
        });
    }

    // The pre-signature is checked before the LP is ever told it may pay
    // (spec 5.3 step 5). A pre-signature that does not verify means the LP
    // pays nothing and the user refunds.
    if !progress.pre_signature_verified {
        return Err(LpError::BadPreSignature);
    }

    Ok(LpState::ReadyToPay)
}

/// The escrow output must be the one the terms describe, not merely an output
/// at that outpoint.
fn check_escrow_matches(
    terms: &EscrowTerms,
    canonical: &CanonicalTerms,
    utxo: &Utxo,
) -> Result<(), LpError> {
    let expected = terms
        .script_pubkey()
        .expect("terms carry valid keys by construction");
    if utxo.script_pubkey != expected {
        return Err(LpError::WrongEscrowScript);
    }
    if utxo.amount_zat != canonical.amount_zat {
        return Err(LpError::WrongAmount {
            found: utxo.amount_zat,
            expected: canonical.amount_zat,
        });
    }
    Ok(())
}

/// The guard the caller must pass before sending a Venmo payment.
///
/// Separate from `evaluate` so that paying is a deliberate act with its own
/// check, rather than something that follows from a state having been computed
/// some blocks ago.
pub fn may_send_payment(state: &LpState) -> Result<(), LpError> {
    match state {
        LpState::ReadyToPay => Ok(()),
        other => Err(LpError::NotPayable(other.clone())),
    }
}

/// Confirms the node is on the branch the terms were built for.
///
/// A branch change between quoting and releasing produces a different sighash,
/// so the release the user pre-signed becomes unspendable. Checking it before
/// paying turns a silent loss into a refusal.
pub fn check_branch(chain: &impl ChainClient, terms: &EscrowTerms) -> Result<(), LpError> {
    let found = chain.consensus_branch_id()?;
    if found != terms.consensus_branch_id {
        return Err(LpError::BranchMismatch {
            found,
            expected: terms.consensus_branch_id,
        });
    }
    Ok(())
}

/// What the LP passes to the existing prover, spec 5.4 step 3.
///
/// Named here so the mapping from escrow terms to prover environment is in one
/// reviewable place rather than spread through a shell invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverRequest {
    pub intent_hash: [u8; 32],
    pub intent_amount_6dec: u64,
    pub payee_hash: [u8; 32],
    /// The enclave only matches payments at or after this snapshot, which is
    /// why it is the lock-confirmed time and not the current time.
    pub intent_timestamp_ms: u64,
    pub rate_18dec: u128,
}

impl ProverRequest {
    pub fn from_terms(t: &CanonicalTerms) -> Self {
        Self {
            intent_hash: t.intent_hash(),
            intent_amount_6dec: t.usd_amount_6dec,
            payee_hash: t.payee_hash,
            intent_timestamp_ms: t.lock_confirmed_ms,
            rate_18dec: t.rate_18dec,
        }
    }
}

/// The LP's check on an attestation before it bothers the attestor with it.
///
/// The attestor performs the authoritative check; doing it here too means a
/// failed proof is caught locally rather than costing an `/attest` call that
/// consumes the one announcement for this event.
pub fn attestation_matches_terms(
    attestation: &PaymentAttestation,
    terms: &CanonicalTerms,
) -> bool {
    attestation.intent_hash == terms.intent_hash()
        && attestation.release_amount >= terms.usd_amount_6dec as u128
}

/// Broadcasts a release, retrying the answers that mean "not yet".
///
/// R8-3: zebra answers an unknown-input spend either after 60 s or instantly
/// from its rejection cache, and both clear when the missing input is mined.
/// An LP that has paid the fiat and reads one of those as final has stopped for
/// no reason. This retries them, and only them, until `BROADCAST_DEADLINE`.
///
/// A `Rejected` is a verdict and returns immediately: the transaction is wrong
/// and retrying it will not change that. An `Unreachable` is retried too, since
/// it says nothing about the transaction.
///
/// # Stopping early
///
/// `sleep` returns `false` to end the loop between attempts. That is how a
/// caller puts a wall-clock budget on one *attempt* at broadcasting without
/// giving up on the release: the coordinator runs this inside its sweep, and
/// the deadline it loops to is tens of minutes away.
///
/// Stopping is offered at the sleep and nowhere else, so an attempt is never
/// abandoned part-way through: the loop has just been told the node cannot
/// judge the transaction yet, and nothing is in flight. A caller that always
/// returns `true` gets the original behaviour, which is to retry until the
/// deadline.
///
/// Ending early is reported as [`LpError::BroadcastGaveUp`] carrying the node's
/// last word, so a caller can tell "we stopped" from "the chain refused".
pub fn broadcast_release_until_deadline(
    chain: &impl ChainClient,
    policy: &EscrowPolicy,
    refund_height: u32,
    raw_tx: &[u8],
    mut sleep: impl FnMut() -> bool,
) -> Result<[u8; 32], LpError> {
    let deadline = policy.broadcast_deadline_for_refund_height(refund_height);

    loop {
        match chain.broadcast(raw_tx) {
            Ok(txid) => return Ok(txid),
            Err(e) if !e.is_retryable() => return Err(LpError::Chain(e)),
            Err(e) => {
                let height = chain.height().map_err(LpError::Chain)?;
                if height > deadline {
                    // Past the margin the release still spends, but it now
                    // races the refund, and that race is the LP's loss (4.5).
                    // Report the node's last word rather than looping forever.
                    return Err(LpError::BroadcastDeadlinePassed {
                        height,
                        deadline,
                        last: e.to_string(),
                    });
                }
                if !sleep() {
                    return Err(LpError::BroadcastGaveUp {
                        last: e.to_string(),
                    });
                }
            }
        }
    }
}
