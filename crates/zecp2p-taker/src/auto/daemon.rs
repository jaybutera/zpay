//! Phase 1: the whole fill, driven, with a human at the two money-moving steps.
//!
//! This is the loop the design's phase 1 describes. It watches our glue, reads
//! the terms, prices the payment, fetches the gating signature, and then
//! **stops and asks** before staking and again before paying. Every value the
//! human used to derive by hand is computed and shown to them; what they still
//! do is approve.
//!
//! # Why the gates are where they are
//!
//! The two prompts sit at the two irreversible steps, and nothing else in the
//! loop can spend anything. `signalIntent` costs gas and locks stake for 14
//! days; the Venmo send button costs real dollars and cannot be recalled. Every
//! check that can fail for free runs before the first prompt: the payment cap,
//! the payee match, the cookie health, and the curator's willingness to sign.
//!
//! `fulfillIntent` is deliberately **not** gated. By the time it runs the fiat
//! has already left, and the only thing standing between the taker and the
//! escrowed USDC is that call. Asking a human for permission to finish is
//! asking them for permission to not lose money.

use alloy::primitives::{Address, U256};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};

use crate::auto::{
    cookie::CookieStore,
    intent::IntentTerms,
    money::PaymentAmount,
    pipeline::Gate,
    watch::GlueDeposit,
};

/// How a gate is answered.
pub trait Confirm {
    /// Ask, and report whether the human said yes.
    fn confirm(&self, gate: Gate, prompt: &str) -> Result<bool>;
}

/// Ask on the terminal, and require the word rather than a keystroke.
///
/// A bare `y` is too easy to hit by reflex on a prompt that spends money, and
/// the two gates spend different things, so each wants its own word.
pub struct TerminalConfirm;

impl Confirm for TerminalConfirm {
    fn confirm(&self, gate: Gate, prompt: &str) -> Result<bool> {
        let word = gate.confirm_word();
        println!("\n{prompt}");
        print!("Type {word} to proceed, anything else to stop: ");
        std::io::stdout().flush().ok();

        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("could not read the confirmation")?;
        Ok(line.trim().eq_ignore_ascii_case(word))
    }
}

/// Answer every gate the same way, for tests and for `--yes`.
pub struct FixedConfirm(pub bool);

impl Confirm for FixedConfirm {
    fn confirm(&self, _gate: Gate, prompt: &str) -> Result<bool> {
        tracing::warn!("gate answered without a human: {prompt}");
        Ok(self.0)
    }
}

/// What one deposit's pass through the loop produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to do; already fulfilled, or not ours.
    Skipped { why: String },
    /// A human declined at a gate. Nothing was spent.
    Declined { gate: Gate },
    /// Stopped before spending, because something would have failed.
    Blocked { why: String },
    /// Intent signalled and payment sent; the attestation is next.
    Paid { amount: PaymentAmount },
    /// The whole fill completed.
    Fulfilled,
}

/// The plan for one deposit, built before anything is spent.
///
/// Every field here is derived rather than typed, which is the difference
/// between phase 1 and the manual flow it replaces. The human sees this and
/// approves it; they no longer compute it.
#[derive(Debug, Clone)]
pub struct FillPlan {
    pub deposit: GlueDeposit,
    pub terms: IntentTerms,
    pub recipient: String,
    pub payment: PaymentAmount,
    /// Stake that will be locked, and for how long.
    pub stake_needed: U256,
    pub taker: Address,
}

impl FillPlan {
    /// What the human is asked to approve before the gas and the stake lock.
    pub fn signal_prompt(&self) -> String {
        format!(
            "About to signal an intent on deposit {}.\n\
             \n\
             \x20 amount        {} units ({} USDC)\n\
             \x20 rate          {}\n\
             \x20 will pay      ${} to @{}\n\
             \x20 stake locked  {} units, for 14 days after fulfilment\n\
             \x20 taker         {}\n\
             \n\
             This spends gas and locks the stake. It does not send any money to\n\
             Venmo; that is the next gate.",
            self.deposit.deposit_id,
            self.terms.amount,
            format_usdc(self.terms.amount),
            self.terms.conversion_rate,
            self.payment,
            self.recipient,
            self.stake_needed,
            self.taker,
        )
    }

    /// What the human is asked to approve before the money leaves.
    pub fn pay_prompt(&self, intent_hash: alloy::primitives::B256) -> String {
        format!(
            "About to send a real Venmo payment. This cannot be undone.\n\
             \n\
             \x20 to            @{}\n\
             \x20 amount        ${}\n\
             \x20 for intent    {}\n\
             \x20 deposit       {}\n\
             \n\
             The payee was checked against the deposit's own on-chain payee hash,\n\
             and the amount was derived from the intent and capped. If either\n\
             looks wrong, stop here: after this the dollars are gone and only the\n\
             enclave attestation recovers them.",
            self.recipient, self.payment, intent_hash, self.deposit.deposit_id,
        )
    }
}

fn format_usdc(units: U256) -> String {
    let units = units.to::<u128>();
    format!("{}.{:06}", units / 1_000_000, units % 1_000_000)
}

/// Check the cookie before anything is spent.
///
/// Separated out because *when* this runs is the whole point: a dead cookie
/// found here costs nothing, and the same cookie found dead after the Venmo
/// payment means the fiat is gone and only `cancelIntent` recovers the stake.
pub fn require_usable_session(store: &CookieStore) -> Result<()> {
    let health = store.health()?;
    if !health.is_usable() {
        bail!(
            "{}\n\nChecked before signalling on purpose: failing here costs \
             nothing.",
            health.explain()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::money::payment_cents;
    use alloy::primitives::B256;

    fn plan() -> FillPlan {
        FillPlan {
            deposit: GlueDeposit {
                session_id: B256::repeat_byte(0xaa),
                deposit_id: U256::from(4499),
                amount: U256::from(4_875_437u64),
                block_number: 50_762_833,
                tx_hash: B256::repeat_byte(0xbb),
            },
            terms: IntentTerms {
                intent_hash: B256::repeat_byte(0xcc),
                deposit_id: U256::from(4499),
                amount: U256::from(4_875_437u64),
                conversion_rate: U256::from(990_881_148_896_019_200u128),
                timestamp: 1_788_315_013,
                payee_hash: B256::repeat_byte(0xdd),
                block_number: 50_762_833,
            },
            recipient: "test-payee".into(),
            payment: payment_cents(
                U256::from(4_875_437u64),
                U256::from(990_881_148_896_019_200u128),
                10_000,
            )
            .unwrap(),
            stake_needed: U256::from(4_875_437u64),
            taker: Address::repeat_byte(0x11),
        }
    }

    /// The human approving the stake lock has to see what it costs them, and
    /// that includes the 14 days the stake is committed for.
    #[test]
    fn the_signal_prompt_names_the_stake_and_its_duration() {
        let prompt = plan().signal_prompt();
        assert!(prompt.contains("4875437"), "{prompt}");
        assert!(prompt.contains("14 days"), "{prompt}");
        assert!(prompt.contains("4.84"), "{prompt}");
        assert!(prompt.contains("test-payee"), "{prompt}");
        // It must be clear that this gate does not move fiat.
        assert!(prompt.contains("does not send any money"), "{prompt}");
    }

    /// The payment prompt is the last thing a human sees before the money is
    /// unrecoverable, so it names the handle, the amount and the way out.
    #[test]
    fn the_pay_prompt_names_the_handle_the_amount_and_the_point_of_no_return() {
        let prompt = plan().pay_prompt(B256::repeat_byte(0xcc));
        assert!(prompt.contains("@test-payee"), "{prompt}");
        assert!(prompt.contains("$4.84"), "{prompt}");
        assert!(prompt.contains("cannot be undone"), "{prompt}");
        assert!(prompt.contains("stop here"), "{prompt}");
    }

    /// The rate-aware amount, not the rate-blind one. Four cents on a $5 order
    /// is the whole taker margin.
    #[test]
    fn the_prompt_shows_the_rate_aware_amount() {
        let prompt = plan().signal_prompt();
        assert!(prompt.contains("$4.84"), "{prompt}");
        assert!(!prompt.contains("$4.88"), "{prompt}");
    }

    /// Each gate wants its own word. A single `y` for both is a keystroke away
    /// from approving a payment when you meant to approve a signal, so the
    /// words differ and neither is a bare letter.
    #[test]
    fn the_two_gates_take_different_words() {
        assert_eq!(Gate::Signal.confirm_word(), "signal");
        assert_eq!(Gate::Pay.confirm_word(), "pay");
        assert_ne!(Gate::Signal.confirm_word(), Gate::Pay.confirm_word());
        for gate in [Gate::Signal, Gate::Pay] {
            assert!(
                gate.confirm_word().len() > 1,
                "a one-character confirmation is a reflex away from spending money"
            );
        }
    }

    /// A gate answered without a human must default to no. `FixedConfirm(true)`
    /// exists for tests and for an explicit `--yes`, and it says so in the log.
    #[test]
    fn an_unattended_gate_does_not_approve_itself() {
        assert!(!FixedConfirm(false).confirm(Gate::Pay, "").unwrap());
        assert!(FixedConfirm(true).confirm(Gate::Pay, "").unwrap());
    }

    #[test]
    fn a_dead_cookie_blocks_before_anything_is_spent() {
        let dir = tempfile::tempdir().unwrap();
        let store = CookieStore::new(dir.path().join("absent.json"), 24);
        let err = require_usable_session(&store).expect_err("must block");
        assert!(err.to_string().contains("costs nothing"), "{err}");
    }
}
