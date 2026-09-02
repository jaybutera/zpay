//! The fill pipeline: what the 2026-09-01 fill did by hand, as a state machine.
//!
//! That fill worked and took a person the whole way through it. This is the
//! sequence it followed, with every value derived rather than typed:
//!
//! ```text
//! stake       -> approve USDC to the StakeVault, depositStake(amount)
//! gating      -> POST /v3/sign for the signature, expiry and referral fee
//! signal      -> signalIntent with all three, plus the deposit's real rate
//! pay         -> Venmo, the exact ceil-to-cents dollars, guarded
//! attest      -> the enclave, with INTENT_RATE and INTENT_TIMESTAMP_MS set
//! fulfil      -> fulfillIntent, which needs no gating signature
//! ```
//!
//! # Gates
//!
//! Two of these steps are irreversible in different ways, and each has a gate
//! that phase 1 leaves closed. [`Gate::Signal`] spends gas and locks stake;
//! [`Gate::Pay`] spends real dollars. `Approval::Ask` stops and reports, which
//! is the manual flow with the arithmetic done for you. `Approval::Auto` is
//! phase 2.
//!
//! # Ordering
//!
//! The order is not arbitrary. Everything that can fail for free is placed
//! before anything that costs money:
//!
//! - Cookie health is checked before `signalIntent`, not before the attestation,
//!   because a dead cookie discovered after the payment means the fiat is gone
//!   and only `cancelIntent` recovers the stake.
//! - The payment amount is computed and capped before the intent is signalled,
//!   so a cap breach costs nothing.
//! - The journal entry is written before each irreversible step, never after.

use alloy::primitives::{B256, U256};

use crate::auto::{
    cookie::CookieHealth,
    journal::{FillRecord, FillState},
    money::PaymentAmount,
};

/// A step that cannot be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// `signalIntent`: costs gas, locks stake for 14 days.
    Signal,
    /// The Venmo send button: costs real dollars.
    Pay,
}

impl Gate {
    pub fn describe(self) -> &'static str {
        match self {
            Gate::Signal => "signal an intent (spends gas, locks stake for 14 days)",
            Gate::Pay => "send a real Venmo payment (irreversible)",
        }
    }
}

/// Whether the daemon may take an irreversible step unattended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Phase 1: stop, report exactly what would happen, and wait for a human.
    Ask,
    /// Phase 2: proceed, with the cap and the guards carrying the weight.
    Auto,
}

impl Approval {
    pub fn allows(self, _gate: Gate) -> bool {
        matches!(self, Approval::Auto)
    }
}

/// What the pipeline decided to do next, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Do this next.
    Proceed(Action),
    /// Stop. A human has to act; the reason is written for them.
    Halt(String),
    /// Nothing to do for this deposit.
    Done,
}

/// The pipeline's next action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    EnsureStake { amount: U256 },
    Signal,
    Pay { amount: PaymentAmount },
    Attest { intent_hash: B256 },
    Fulfil { intent_hash: B256 },
}

/// Everything the pipeline needs to decide, gathered before it decides.
///
/// Passed in rather than fetched here so the decision is a pure function and
/// can be tested without a chain, a browser or an enclave.
#[derive(Debug, Clone)]
pub struct Context {
    pub record: FillRecord,
    pub cookie: CookieHealth,
    pub free_stake: U256,
    pub payment: PaymentAmount,
    pub approval: Approval,
    /// Another fill already holds the slot.
    pub other_in_flight: bool,
}

/// Decide the next step.
///
/// The whole ordering argument in this module's docs is expressed here, and the
/// tests below are the argument's proof.
pub fn next(context: &Context) -> Step {
    let record = &context.record;

    match record.state {
        // Handed to a human deliberately. Nothing else moves until they act,
        // and the reason they need is the one recorded at the time.
        FillState::NeedsOperator => Step::Halt(
            record
                .note
                .clone()
                .unwrap_or_else(|| "this fill was handed to an operator".into()),
        ),

        FillState::Fulfilled | FillState::Cancelled => Step::Done,

        FillState::Seen | FillState::Signalling => {
            if context.other_in_flight {
                return Step::Halt(
                    "another fill is already in flight. This daemon runs one at a time: \
                     two open intents can double-spend the same Venmo balance and lose \
                     track of which payment proves which intent."
                        .into(),
                );
            }
            // Before the gas, before the stake lock, before anything: can we
            // finish? A dead cookie found after the payment is the expensive
            // failure this ordering exists to prevent.
            if !context.cookie.is_usable() {
                return Step::Halt(format!(
                    "not signalling: {}. Checked before signalling on purpose; \
                     discovering this after the Venmo payment would mean the fiat \
                     is gone and only cancelIntent recovers the stake.",
                    context.cookie.explain()
                ));
            }
            if context.free_stake < record.amount {
                return Step::Proceed(Action::EnsureStake {
                    amount: record.amount,
                });
            }
            if !context.approval.allows(Gate::Signal) {
                return Step::Halt(format!(
                    "would {} for deposit {} ({} units at rate {}), then pay ${} to @{}. \
                     Approval is set to ask.",
                    Gate::Signal.describe(),
                    record.deposit_id,
                    record.amount,
                    record.conversion_rate,
                    context.payment,
                    record.recipient
                ));
            }
            Step::Proceed(Action::Signal)
        }

        FillState::Signalled => {
            if !context.approval.allows(Gate::Pay) {
                return Step::Halt(format!(
                    "would {}: ${} to @{} for intent {}. Approval is set to ask.",
                    Gate::Pay.describe(),
                    context.payment,
                    record.recipient,
                    record
                        .intent_hash
                        .map(|h| h.to_string())
                        .unwrap_or_else(|| "(unrecorded)".into())
                ));
            }
            Step::Proceed(Action::Pay {
                amount: context.payment,
            })
        }

        // Written before the click. A daemon that finds this on startup cannot
        // tell whether the money left, and the safe reading of that ambiguity
        // is the expensive one.
        FillState::Paying => Step::Halt(format!(
            "deposit {} was left mid-payment: ${} to @{}. The journal is written \
             before the send button, so this may or may not have gone out. Check \
             the Venmo feed before doing anything else. If it was sent, resume at \
             the attestation; if not, cancel the intent.",
            record.deposit_id, context.payment, record.recipient
        )),

        FillState::Paid => {
            let Some(intent_hash) = record.intent_hash else {
                return Step::Halt(format!(
                    "deposit {} is recorded as paid but carries no intent hash. \
                     The payment cannot be bound to an intent without it; find the \
                     IntentSignaled log for this deposit and repair the journal.",
                    record.deposit_id
                ));
            };
            Step::Proceed(Action::Attest { intent_hash })
        }
    }
}

/// The attestation environment, so the two corrections from the 2026-09-01 fill
/// cannot be forgotten.
///
/// Both were caught by reading rather than by a revert, and both are mechanical:
/// the daemon holds the intent it just created, so neither value can be unset.
///
/// - `INTENT_RATE` unset defaults the prover to 1e18. Against deposit 4499's
///   0.990881148896019200 that produced `releaseAmount 4,840,000` instead of
///   4,875,437, which would have reverted at `UPV: Snapshot rate mismatch`.
/// - `INTENT_TIMESTAMP_MS` must be the intent's on-chain signal time, or
///   fulfilment reverts with `UPV: Snapshot timestamp mismatch`.
pub fn attestation_env(record: &FillRecord, payee_hash: B256) -> Result<Vec<(String, String)>, String> {
    let intent_hash = record
        .intent_hash
        .ok_or_else(|| "no intent hash recorded; cannot build an attestation".to_string())?;
    let timestamp_ms = record.signalled_at_ms.ok_or_else(|| {
        "no signal timestamp recorded. The verifier compares the attested snapshot \
         against the intent stored on chain and reverts with \"UPV: Snapshot \
         timestamp mismatch\"; guessing it wastes the payment."
            .to_string()
    })?;

    Ok(vec![
        ("INTENT_HASH".into(), intent_hash.to_string()),
        ("INTENT_AMOUNT".into(), record.amount.to_string()),
        ("INTENT_RATE".into(), record.conversion_rate.to_string()),
        ("INTENT_TIMESTAMP_MS".into(), timestamp_ms.to_string()),
        ("PAYEE_HASH".into(), payee_hash.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::money::payment_cents;

    fn amount() -> PaymentAmount {
        payment_cents(
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
            10_000,
        )
        .unwrap()
    }

    fn record(state: FillState) -> FillRecord {
        let mut r = FillRecord::new(
            U256::from(4499),
            B256::repeat_byte(0xaa),
            U256::from(4_875_437u64),
            U256::from(990_881_148_896_019_200u128),
            "test-payee".into(),
        );
        r.state = state;
        if state != FillState::Seen && state != FillState::Signalling {
            r.intent_hash = Some(B256::repeat_byte(0xbb));
            r.signalled_at_ms = Some(1_756_000_000_000);
        }
        r
    }

    fn context(state: FillState, approval: Approval) -> Context {
        Context {
            record: record(state),
            cookie: CookieHealth::Usable,
            free_stake: U256::from(10_000_000u64),
            payment: amount(),
            approval,
            other_in_flight: false,
        }
    }

    #[test]
    fn a_fresh_deposit_with_stake_signals() {
        let c = context(FillState::Seen, Approval::Auto);
        assert_eq!(next(&c), Step::Proceed(Action::Signal));
    }

    #[test]
    fn short_stake_is_topped_up_first() {
        let mut c = context(FillState::Seen, Approval::Auto);
        c.free_stake = U256::ZERO;
        assert_eq!(
            next(&c),
            Step::Proceed(Action::EnsureStake {
                amount: U256::from(4_875_437u64)
            })
        );
    }

    /// The ordering claim, tested: a dead cookie stops the fill before the gas
    /// and the stake lock, not after the payment.
    #[test]
    fn a_dead_cookie_stops_the_fill_before_signalling() {
        let mut c = context(FillState::Seen, Approval::Auto);
        c.cookie = CookieHealth::Missing;
        match next(&c) {
            Step::Halt(why) => {
                assert!(why.contains("not signalling"), "{why}");
                assert!(why.contains("refresh-cookie"), "{why}");
            }
            other => panic!("expected a halt, got {other:?}"),
        }
    }

    #[test]
    fn phase_one_stops_at_the_signal_gate_and_says_what_it_would_do() {
        let c = context(FillState::Seen, Approval::Ask);
        match next(&c) {
            Step::Halt(why) => {
                assert!(why.contains("locks stake"), "{why}");
                assert!(why.contains("4.84"), "{why}");
                assert!(why.contains("test-payee"), "{why}");
            }
            other => panic!("expected a halt, got {other:?}"),
        }
    }

    #[test]
    fn phase_one_stops_again_at_the_payment_gate() {
        let c = context(FillState::Signalled, Approval::Ask);
        match next(&c) {
            Step::Halt(why) => assert!(why.contains("irreversible"), "{why}"),
            other => panic!("expected a halt, got {other:?}"),
        }
    }

    #[test]
    fn phase_two_pays_a_signalled_intent() {
        let c = context(FillState::Signalled, Approval::Auto);
        assert_eq!(next(&c), Step::Proceed(Action::Pay { amount: amount() }));
    }

    /// The expensive ambiguity. A daemon must never resolve this itself.
    #[test]
    fn a_fill_left_mid_payment_always_halts() {
        for approval in [Approval::Ask, Approval::Auto] {
            let c = context(FillState::Paying, approval);
            match next(&c) {
                Step::Halt(why) => assert!(why.contains("Check the Venmo feed"), "{why}"),
                other => panic!("expected a halt, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_paid_fill_goes_to_the_enclave() {
        let c = context(FillState::Paid, Approval::Auto);
        assert_eq!(
            next(&c),
            Step::Proceed(Action::Attest {
                intent_hash: B256::repeat_byte(0xbb)
            })
        );
    }

    #[test]
    fn one_fill_at_a_time_is_enforced() {
        let mut c = context(FillState::Seen, Approval::Auto);
        c.other_in_flight = true;
        match next(&c) {
            Step::Halt(why) => assert!(why.contains("one at a time"), "{why}"),
            other => panic!("expected a halt, got {other:?}"),
        }
    }

    #[test]
    fn a_finished_fill_is_done() {
        assert_eq!(next(&context(FillState::Fulfilled, Approval::Auto)), Step::Done);
        assert_eq!(next(&context(FillState::Cancelled, Approval::Auto)), Step::Done);
    }

    /// Both corrections from the live fill are carried, and the rate is the
    /// intent's rather than the prover's 1e18 default.
    #[test]
    fn the_attestation_environment_carries_the_rate_and_the_timestamp() {
        let env = attestation_env(&record(FillState::Paid), B256::repeat_byte(0xcc)).unwrap();
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("INTENT_RATE"), "990881148896019200");
        assert_ne!(get("INTENT_RATE"), "1000000000000000000");
        assert_eq!(get("INTENT_TIMESTAMP_MS"), "1756000000000");
        assert_eq!(get("INTENT_AMOUNT"), "4875437");
    }

    /// Guessing the timestamp wastes a payment that has already been made, so
    /// a missing one is refused rather than defaulted to the wall clock.
    #[test]
    fn a_missing_timestamp_refuses_rather_than_guessing() {
        let mut r = record(FillState::Paid);
        r.signalled_at_ms = None;
        let err = attestation_env(&r, B256::ZERO).expect_err("must refuse");
        assert!(err.contains("timestamp mismatch"), "{err}");
    }
}
