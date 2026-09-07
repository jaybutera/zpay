//! R8-3: a node saying "not yet" is not a node saying "no".
//!
//! Zebra answers a spend whose input it cannot find in two ways - after 60 s
//! with `could not find transparent input UTXO`, and instantly from its
//! rejection cache with `will be rejected from the mempool until the next chain
//! tip block`. Both clear once the missing input is mined. An LP that has
//! already sent the fiat and reads either as final has stopped for no reason,
//! and the user refunds at `T`.

use std::cell::RefCell;

use zecp2p_escrow::chain::{ChainClient, ChainError, Utxo};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::lp::{broadcast_release_until_deadline, LpError};

/// A node that answers a scripted sequence, then accepts.
struct ScriptedNode {
    answers: RefCell<Vec<Result<[u8; 32], ChainError>>>,
    height: RefCell<u32>,
}

impl ScriptedNode {
    fn new(answers: Vec<Result<[u8; 32], ChainError>>, height: u32) -> Self {
        Self {
            answers: RefCell::new(answers),
            height: RefCell::new(height),
        }
    }
}

impl ChainClient for ScriptedNode {
    fn height(&self) -> Result<u32, ChainError> {
        Ok(*self.height.borrow())
    }
    fn consensus_branch_id(&self) -> Result<u32, ChainError> {
        Ok(0x37a5_165b)
    }
    fn utxo(&self, _t: &[u8; 32], _v: u32) -> Result<Option<Utxo>, ChainError> {
        Ok(None)
    }
    fn broadcast(&self, _raw: &[u8]) -> Result<[u8; 32], ChainError> {
        let mut a = self.answers.borrow_mut();
        if a.is_empty() {
            return Ok([0xaa; 32]);
        }
        a.remove(0)
    }
}

/// The two texts zebra actually returns, copied from the run.
const SLOW: &str = "transaction did not pass consensus validation: could not find transparent \
                    input UTXO in the best chain or mempool (code -25)";
const CACHED: &str = "the transaction will be rejected from the mempool until the next chain \
                      tip block: transaction did not pass consensus validation: could not find \
                      transparent input UTXO (code -1)";

#[test]
fn both_unknown_input_answers_are_retryable_and_a_script_failure_is_not() {
    assert!(
        ChainError::NotYet(SLOW.into()).is_retryable(),
        "the 60-second answer clears when the input is mined"
    );
    assert!(
        ChainError::NotYet(CACHED.into()).is_retryable(),
        "the cached answer clears at the next block"
    );
    assert!(ChainError::Unreachable("timeout".into()).is_retryable());

    // A script failure is a verdict about the transaction itself.
    assert!(
        !ChainError::Rejected("ScriptInvalid (code -25)".into()).is_retryable(),
        "a bad signature does not become good by waiting"
    );
}

#[test]
fn a_release_is_retried_through_not_yet_and_then_accepted() {
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;
    let node = ScriptedNode::new(
        vec![
            Err(ChainError::NotYet(SLOW.into())),
            Err(ChainError::NotYet(CACHED.into())),
            Err(ChainError::Unreachable("connection reset".into())),
            Ok([0x42; 32]),
        ],
        3_400_000,
    );

    let mut naps = 0;
    let txid =
        broadcast_release_until_deadline(&node, &policy, refund_height, &[0u8; 8], || { naps += 1; true })
            .expect("a release must survive three temporary answers");
    assert_eq!(txid, [0x42; 32]);
    assert_eq!(naps, 3, "each temporary answer should have cost one wait");
}

#[test]
fn a_script_failure_stops_immediately() {
    // Retrying a transaction the script refused would loop until the deadline
    // for nothing, and hide the real reason.
    let policy = EscrowPolicy::mainnet_default();
    let node = ScriptedNode::new(
        vec![Err(ChainError::Rejected("ScriptInvalid (code -25)".into()))],
        3_400_000,
    );

    let mut naps = 0;
    let err = broadcast_release_until_deadline(
        &node,
        &policy,
        3_500_000,
        &[0u8; 8],
        || { naps += 1; true },
    )
    .expect_err("a script failure is a verdict");
    assert!(matches!(err, LpError::Chain(ChainError::Rejected(_))), "got {err}");
    assert_eq!(naps, 0, "a verdict must not be retried at all");
}

#[test]
fn retrying_stops_at_the_broadcast_deadline() {
    // Past the margin the release still spends, but it races the refund, and
    // that race is the LP's loss (spec 4.5). Looping past it hides the problem.
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;
    let deadline = policy.broadcast_deadline_for_refund_height(refund_height);

    let node = ScriptedNode::new(
        (0..100)
            .map(|_| Err(ChainError::NotYet(SLOW.into())))
            .collect(),
        deadline + 1,
    );

    let mut naps = 0;
    let err = broadcast_release_until_deadline(
        &node,
        &policy,
        refund_height,
        &[0u8; 8],
        || { naps += 1; true },
    )
    .expect_err("past the deadline the LP must stop and say why");
    match err {
        LpError::BroadcastDeadlinePassed { height, deadline: d, last } => {
            assert_eq!(d, deadline);
            assert!(height > d);
            assert!(
                last.contains("could not find transparent input"),
                "the node's last word must be reported: {last}"
            );
        }
        other => panic!("expected BroadcastDeadlinePassed, got {other}"),
    }
    assert_eq!(naps, 0, "it should not wait once already past the deadline");
}

#[test]
fn a_release_inside_the_margin_keeps_trying() {
    // The boundary: one block before the deadline it still retries.
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;
    let deadline = policy.broadcast_deadline_for_refund_height(refund_height);

    let node = ScriptedNode::new(
        vec![Err(ChainError::NotYet(CACHED.into())), Ok([0x43; 32])],
        deadline,
    );
    let mut naps = 0;
    let txid =
        broadcast_release_until_deadline(&node, &policy, refund_height, &[0u8; 8], || { naps += 1; true })
            .expect("at the deadline itself the LP still tries");
    assert_eq!(txid, [0x43; 32]);
    assert_eq!(naps, 1);
}

/// R11-5: the strings a node answers a re-broadcast with. Both mean the
/// release is in the mempool or already mined, and both were reported to the
/// LP as a rejection telling them to "rerun attest to resend" a release that
/// had already been mined. Observed from zebra on regtest.
#[test]
fn a_re_broadcast_reads_as_success() {
    for m in [
        "transaction already exists in mempool",
        "transaction was committed to the best chain",
        "txn-already-known",
        "txn-already-in-mempool",
    ] {
        assert!(
            zecp2p_escrow::rpc::is_already_accepted(m),
            "{m} should read as success"
        );
    }
}

/// The other half: a real refusal must not be laundered into success, or a
/// release the chain rejected would be reported as paid.
#[test]
fn a_real_rejection_still_reads_as_a_rejection() {
    for m in [
        "transaction did not pass consensus validation: ScriptInvalid",
        "insufficient fee",
        "transaction is locked until after block height 400",
        "could not find transparent input UTXO",
    ] {
        assert!(
            !zecp2p_escrow::rpc::is_already_accepted(m),
            "{m} must not read as success"
        );
    }
}

/// A caller that stops between attempts really stops, and says so distinctly.
///
/// The coordinator puts a wall-clock budget on one attempt this way, because it
/// runs this loop inside its sweep and the deadline the loop retries to is tens
/// of minutes off. The property that matters is that the loop *returns*: an
/// early exit implemented as a no-op sleep would spin against the node as fast
/// as it could answer, which is worse than the blocking it replaced.
#[test]
fn a_caller_can_stop_retrying_between_attempts() {
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;

    // Far more refusals than the caller will sit through, and a height well
    // inside the deadline, so nothing but the caller's own decision can end it.
    let node = ScriptedNode::new(
        (0..1000)
            .map(|_| Err(ChainError::NotYet(SLOW.into())))
            .collect(),
        3_400_000,
    );

    let mut attempts = 0;
    let err = broadcast_release_until_deadline(&node, &policy, refund_height, &[0u8; 8], || {
        attempts += 1;
        // Two naps, then stop. Standing in for a budget running out.
        attempts < 3
    })
    .expect_err("stopping early is not success");

    match err {
        LpError::BroadcastGaveUp { last } => {
            assert!(
                last.contains("could not find transparent input"),
                "the node's last word should survive: {last}"
            );
        }
        other => panic!("stopping early must be distinguishable from a refusal, got {other}"),
    }
    assert_eq!(attempts, 3, "the loop must return on the refusal, not spin");
}

/// Stopping early is not the deadline passing, and the two must not be confused.
///
/// `BroadcastDeadlinePassed` means the chain has moved past the point where the
/// release still beats the refund - the trade is lost. `BroadcastGaveUp` means
/// only that this attempt stopped: the release is still worth broadcasting and
/// the caller is expected to come back. A caller that treated the second as the
/// first would abandon a release it could still land.
#[test]
fn giving_up_early_is_not_the_deadline_passing() {
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;
    let deadline = policy.broadcast_deadline_for_refund_height(refund_height);

    // Inside the deadline: stopping here is the caller's choice.
    let inside = ScriptedNode::new(
        (0..10).map(|_| Err(ChainError::NotYet(SLOW.into()))).collect(),
        deadline - 100,
    );
    let err = broadcast_release_until_deadline(&inside, &policy, refund_height, &[0u8; 8], || false)
        .expect_err("the caller stopped");
    assert!(
        matches!(err, LpError::BroadcastGaveUp { .. }),
        "inside the deadline, stopping is the caller's decision: {err}"
    );

    // Past the deadline the chain decides, whatever the caller would have done.
    let past = ScriptedNode::new(
        (0..10).map(|_| Err(ChainError::NotYet(SLOW.into()))).collect(),
        deadline + 1,
    );
    let err = broadcast_release_until_deadline(&past, &policy, refund_height, &[0u8; 8], || true)
        .expect_err("past the deadline the LP must stop");
    assert!(
        matches!(err, LpError::BroadcastDeadlinePassed { .. }),
        "past the deadline the chain decides, not the caller: {err}"
    );
}

/// A caller that never stops gets exactly the old behaviour.
///
/// The signature changed for every existing caller, so the no-change case is
/// worth pinning: `|| true` must still retry to the deadline and report it the
/// way it always did.
#[test]
fn always_returning_true_is_the_original_behaviour() {
    let policy = EscrowPolicy::mainnet_default();
    let refund_height = 3_500_000;
    let deadline = policy.broadcast_deadline_for_refund_height(refund_height);

    let node = ScriptedNode::new(
        (0..100).map(|_| Err(ChainError::NotYet(SLOW.into()))).collect(),
        deadline + 1,
    );
    let mut naps = 0;
    let err = broadcast_release_until_deadline(&node, &policy, refund_height, &[0u8; 8], || {
        naps += 1;
        true
    })
    .expect_err("past the deadline this still stops");
    assert!(matches!(err, LpError::BroadcastDeadlinePassed { .. }), "{err}");
}
