//! Heights and margins, spec sections 3 and 7, and criterion 13.
//!
//! The criterion asks that every height be derived from `BLOCK_SECONDS` and
//! `REFUND_DELAY` config, and that the same binary work with a different
//! `REFUND_DELAY`. These tests are the standing check on that.

use zecp2p_escrow::deadlines::{EscrowPolicy, PolicyError, MAINNET_BLOCK_SECONDS};

#[test]
fn the_mainnet_defaults_match_spec_section_3() {
    let p = EscrowPolicy::mainnet_default();
    assert_eq!(p.block_seconds, 75);
    assert_eq!(p.refund_delay_blocks, 1152);
    // 1152 blocks at 75 s is 24 hours.
    assert_eq!(p.refund_delay_blocks * p.block_seconds, 24 * 3600);
    assert_eq!(p.pay_deadline_blocks, 60);
    assert_eq!(p.broadcast_deadline_blocks, 40);
    p.validate().unwrap();
}

#[test]
fn the_deadlines_sit_where_section_7_puts_them() {
    let p = EscrowPolicy::mainnet_default();
    let lock = 3_400_000;

    assert_eq!(p.proposed_refund_height(lock), 3_401_152);
    assert_eq!(p.pay_deadline_for_refund_height(p.proposed_refund_height(lock)), 3_401_152 - 60);
    assert_eq!(p.broadcast_deadline_for_refund_height(p.proposed_refund_height(lock)), 3_401_152 - 40);

    // The pay deadline is strictly earlier than the broadcast deadline, which
    // is the whole point: the LP stops paying while it still has room to get a
    // release confirmed.
    assert!(p.pay_deadline_for_refund_height(p.proposed_refund_height(lock)) < p.broadcast_deadline_for_refund_height(p.proposed_refund_height(lock)));
}

#[test]
fn the_lp_may_not_pay_at_or_after_the_pay_deadline() {
    // Spec 7 says "at or after", so the boundary block itself is barred.
    let p = EscrowPolicy::mainnet_default();
    let lock = 3_400_000;
    let deadline = p.pay_deadline_for_refund_height(p.proposed_refund_height(lock));

    assert!(p.may_pay_before(p.proposed_refund_height(lock), deadline - 1));
    assert!(!p.may_pay_before(p.proposed_refund_height(lock), deadline), "the deadline block itself is too late");
    assert!(!p.may_pay_before(p.proposed_refund_height(lock), deadline + 1));
}

#[test]
fn the_user_may_refund_at_t_and_not_before() {
    let p = EscrowPolicy::mainnet_default();
    let lock = 3_400_000;
    let t = p.proposed_refund_height(lock);

    assert!(!p.may_refund_at(p.proposed_refund_height(lock), t - 1), "CLTV rejects a refund before T");
    assert!(p.may_refund_at(p.proposed_refund_height(lock), t), "the refund is valid at exactly T");
    assert!(p.may_refund_at(p.proposed_refund_height(lock), t + 1_000));
}

#[test]
fn the_broadcast_margin_closes_before_t() {
    let p = EscrowPolicy::mainnet_default();
    let lock = 3_400_000;
    let margin = p.broadcast_deadline_for_refund_height(p.proposed_refund_height(lock));

    assert!(p.within_broadcast_margin_of(p.proposed_refund_height(lock), margin));
    assert!(!p.within_broadcast_margin_of(p.proposed_refund_height(lock), margin + 1));
    // Past the margin the release is still a valid transaction; it simply
    // races the refund, which is the LP's loss (spec 4.5).
    assert!(margin < p.proposed_refund_height(lock));
}

#[test]
fn a_different_refund_delay_moves_every_height_with_it() {
    // Criterion 13 in its testable form: nothing is hard-coded to the 1152
    // default.
    let mut short = EscrowPolicy::mainnet_default();
    short.refund_delay_blocks = 200;
    short.validate().unwrap();

    let lock = 100_000;
    assert_eq!(short.proposed_refund_height(lock), 100_200);
    assert_eq!(short.pay_deadline_for_refund_height(short.proposed_refund_height(lock)), 100_140);
    assert_eq!(short.broadcast_deadline_for_refund_height(short.proposed_refund_height(lock)), 100_160);

    assert!(short.may_pay_before(short.proposed_refund_height(lock), 100_139));
    assert!(!short.may_pay_before(short.proposed_refund_height(lock), 100_140));
    assert!(short.may_refund_at(short.proposed_refund_height(lock), 100_200));
    assert!(!short.may_refund_at(short.proposed_refund_height(lock), 100_199));
}

#[test]
fn a_faster_chain_keeps_the_same_wall_clock_window() {
    // NU7 proposes 25 s blocks. The refund window should stay 24 hours, which
    // means three times the blocks.
    let at_75 = EscrowPolicy::from_refund_hours(MAINNET_BLOCK_SECONDS, 24).unwrap();
    let at_25 = EscrowPolicy::from_refund_hours(25, 24).unwrap();

    assert_eq!(at_75.refund_delay_blocks, 1152);
    assert_eq!(at_25.refund_delay_blocks, 3456);
    assert_eq!(at_25.refund_delay_blocks, at_75.refund_delay_blocks * 3);

    // And the margins scale too, so the LP keeps the same real time to pay.
    assert_eq!(
        at_75.pay_deadline_blocks * at_75.block_seconds,
        at_25.pay_deadline_blocks * at_25.block_seconds
    );
}

#[test]
fn a_policy_whose_margins_exceed_its_delay_is_refused() {
    // A refund delay shorter than the paying margin would mean the LP is never
    // allowed to pay at all, and the escrow could only ever refund.
    let mut p = EscrowPolicy::mainnet_default();
    p.refund_delay_blocks = 60;
    assert_eq!(
        p.validate(),
        Err(PolicyError::DelayTooShort {
            delay: 60,
            pay: 60
        })
    );
}

#[test]
fn a_policy_with_inverted_deadlines_is_refused() {
    // If the pay deadline came after the broadcast deadline, the LP would be
    // told it may still pay past the point it must already have broadcast.
    let mut p = EscrowPolicy::mainnet_default();
    p.pay_deadline_blocks = 30;
    p.broadcast_deadline_blocks = 40;
    assert_eq!(
        p.validate(),
        Err(PolicyError::DeadlinesInverted {
            pay: 30,
            broadcast: 40
        })
    );
}

#[test]
fn a_zero_block_time_is_refused_rather_than_dividing_by_zero() {
    assert_eq!(
        EscrowPolicy::from_refund_hours(0, 24),
        Err(PolicyError::ZeroBlockTime)
    );
}
