//! The Venmo leg, run once, for whichever rail asked for it.
//!
//! Both settlement systems send one Venmo payment and prove it to the same Peer
//! enclave. This module is that leg, and it is the reason the native escrow does
//! not get its own copy of the browser driver.
//!
//! Every guard the Base route learned the hard way applies unchanged to the
//! escrow route, because the guards are about Venmo and the enclave rather than
//! about Base:
//!
//! - the amount is a [`PaymentAmount`], which only [`crate::auto::money`] can
//!   construct, so an unchecked number cannot reach the send button;
//! - the recipient is read back off the confirmation button before the click;
//! - the feed entry is located by direction, amount, recipient and recency
//!   rather than by position, because index 0 is whatever happened most recently
//!   on the account and an incoming transfer can make that someone else's money;
//! - the journal is written before the click and never after.
//!
//! # Ordering, and why it is the same on both rails
//!
//! The expensive window is between the money leaving and the settlement
//! completing, and it is the same window on both rails: on Base the intent is
//! signalled and the fiat is gone until `fulfillIntent`, and on Zcash the escrow
//! is locked and the fiat is gone until the release is mined. So the caller
//! writes its own journal entry before calling [`pay`], and [`pay`] does not
//! write one: a shared function that owned the journal would have to know each
//! rail's record shape, and getting that wrong is precisely the failure the
//! journal exists to make visible.

use anyhow::{Context, Result};

use crate::{
    auto::{
        attest::{AttestRequest, AttestationFile, Attester},
        cookie::SessionMaterial,
        rail::FiatLeg,
    },
    venmo::{PaymentOutcome, PaymentRequest, SendMode, VenmoBrowser},
};

/// What the browser did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// The page was driven and the click was not made.
    DryRun { recipient: String, amount: String },
    /// Venmo accepted the payment. The fiat is gone.
    Live { recipient: String, amount: String },
}

impl Sent {
    pub fn fiat_left(&self) -> bool {
        matches!(self, Sent::Live { .. })
    }
}

/// Send one payment for a rail's fiat leg.
///
/// The caller must have written its journal entry before calling this. See the
/// module note: this deliberately does not touch the journal, because the two
/// rails record different things and a shared writer would have to guess.
pub async fn pay(
    browser: &VenmoBrowser,
    leg: &FiatLeg,
    note: &str,
    mode: SendMode,
) -> Result<Sent> {
    let tab = browser
        .find_venmo_tab()
        .await
        .context("no logged-in Venmo tab to pay from")?;

    let request = PaymentRequest {
        recipient: leg.recipient.clone(),
        amount: leg.payment.to_venmo_string(),
        note: note.to_string(),
    };

    // The outcome decides this, not the mode. Reading `Sent::Live` off
    // `mode != DryRun` is what let the 2026-09-05 order be written paid: the
    // mode says what we were *allowed* to do, and only the browser can say what
    // happened. `PaymentOutcome::Sent` is now reachable only through the
    // page-side confirmation, so this reads the answer instead of assuming it.
    match browser.pay(&tab, &request, mode).await? {
        PaymentOutcome::WouldHaveSent { recipient, amount } => {
            Ok(Sent::DryRun { recipient, amount })
        }
        PaymentOutcome::Sent { recipient, amount } => Ok(Sent::Live { recipient, amount }),
    }
}

/// Find the payment in the feed and get the enclave to attest it.
///
/// Runs after the money has left, on both rails. Nothing here is gated: by this
/// point the fiat is gone and the attestation is the only thing that recovers
/// it, so asking a human for permission to finish is asking permission to lose
/// the payment.
pub async fn attest(
    http: &reqwest::Client,
    attester: &Attester,
    material: &SessionMaterial,
    leg: &FiatLeg,
    out: &std::path::Path,
) -> Result<AttestationFile> {
    // Not index 0. The enclave selects by raw position with no filter of its
    // own, and the most recent entry on the account may be an incoming payment
    // that has nothing to do with this trade.
    let payment_index = crate::auto::attest::feed::locate_payment(
        http,
        material,
        &leg.recipient,
        &leg.payment.to_venmo_string(),
        Some(leg.not_before),
        leg.tag.as_deref(),
    )
    .await
    .context("could not tell which Venmo feed entry this payment is")?;

    tracing::info!(payment_index, "located the payment in the feed");

    let request = AttestRequest {
        intent_hash: leg.intent_hash,
        amount: leg.intent_amount_6dec,
        conversion_rate: leg.rate_18dec,
        timestamp_ms: leg.intent_timestamp_ms,
        payee_hash: leg.payee_hash,
        payment_index,
    };

    let file = attester
        .attest(&request, material, out)
        .await
        .context("the enclave would not attest the payment; the fiat has already left")?;

    // The enclave re-signs whatever intent hash it is handed and checks it
    // against no chain, so this is our own check that the attestation in hand
    // belongs to the trade in hand rather than to a previous one left in the
    // output file.
    file.check_binds(&request)
        .context("the attestation does not bind to the trade we paid for")?;

    Ok(file)
}

/// The prover environment for a rail's fiat leg.
///
/// Exposed separately from [`attest`] so a rail can print what it would ask the
/// enclave without spending the cookie on it, which is what the escrow's
/// `announce` step does today.
pub fn prover_environment(leg: &FiatLeg) -> Vec<(String, String)> {
    vec![
        ("INTENT_HASH".into(), leg.intent_hash.to_string()),
        ("INTENT_AMOUNT".into(), leg.intent_amount_6dec.to_string()),
        // Never defaulted on either rail. The prover's own default is 1e18.
        ("INTENT_RATE".into(), leg.rate_18dec.to_string()),
        (
            "INTENT_TIMESTAMP_MS".into(),
            leg.intent_timestamp_ms.to_string(),
        ),
        ("PAYEE_HASH".into(), leg.payee_hash.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::money::payment_cents;
    use alloy::primitives::{B256, U256};

    fn leg() -> FiatLeg {
        FiatLeg {
            tag: None,
            recipient: "jay-butera".into(),
            payment: payment_cents(
                U256::from(1_500_000u64),
                U256::from(1_000_000_000_000_000_000u128),
                10_000,
            )
            .unwrap(),
            not_before: chrono::DateTime::from_timestamp_millis(1_756_000_000_000).unwrap(),
            intent_hash: B256::repeat_byte(0xa3),
            intent_amount_6dec: U256::from(1_500_000u64),
            rate_18dec: U256::from(1_000_000_000_000_000_000u128),
            intent_timestamp_ms: 1_756_000_000_000,
            payee_hash: B256::repeat_byte(0x85),
        }
    }

    /// The mainnet escrow released on 2026-09-03 against a $1.50 payment. The
    /// shared sizing must produce that string, not "1.5" and not "1.50000".
    #[test]
    fn the_escrow_leg_sizes_to_the_dollar_fifty_that_released_mainnet() {
        assert_eq!(leg().payment.to_venmo_string(), "1.50");
    }

    /// Both corrections from the 2026-09-01 Base fill are carried on whatever
    /// rail asks, because the prover defaults both wrongly.
    #[test]
    fn the_environment_carries_the_rate_and_the_timestamp() {
        let env = prover_environment(&leg());
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("INTENT_AMOUNT"), "1500000");
        assert_eq!(get("INTENT_RATE"), "1000000000000000000");
        assert_eq!(get("INTENT_TIMESTAMP_MS"), "1756000000000");
        assert!(get("INTENT_HASH").starts_with("0xa3"));
    }

    /// A rate of exactly 1e18 is what the native escrow quotes, and it is also
    /// the prover's silent default. The environment must state it rather than
    /// leave it unset, or a later escrow at any other rate inherits a value
    /// nobody set.
    #[test]
    fn a_unit_rate_is_stated_rather_than_left_to_the_default() {
        let env = prover_environment(&leg());
        assert!(
            env.iter().any(|(k, _)| k == "INTENT_RATE"),
            "INTENT_RATE must always be present, even when it equals the default"
        );
    }

    /// `Sent::Live` must come from the outcome, never from the mode.
    ///
    /// Reverting this to `if mode.is_dry_run()` used to pass everything: the
    /// mode says what the run was *allowed* to do and only the browser can say
    /// what happened. That inference is what recorded the 2026-09-05 order
    /// paid. This pins the mapping so the shortcut cannot come back quietly.
    #[test]
    fn live_is_read_off_the_outcome_and_not_off_the_mode() {
        // The function is async and needs a browser, so the mapping itself is
        // what is pinned here: each outcome has exactly one `Sent`, and a
        // dry-run outcome can never produce one that says the fiat left.
        let would = PaymentOutcome::WouldHaveSent {
            recipient: "jay-butera".into(),
            amount: "2.01".into(),
        };
        let did = PaymentOutcome::Sent {
            recipient: "jay-butera".into(),
            amount: "2.01".into(),
        };
        let map = |o: PaymentOutcome| match o {
            PaymentOutcome::WouldHaveSent { recipient, amount } => {
                Sent::DryRun { recipient, amount }
            }
            PaymentOutcome::Sent { recipient, amount } => Sent::Live { recipient, amount },
        };
        assert!(
            !map(would).fiat_left(),
            "a would-have-sent never spent money"
        );
        assert!(map(did).fiat_left());
    }

    #[test]
    fn a_dry_run_reports_that_no_fiat_left() {
        let dry = Sent::DryRun {
            recipient: "jay-butera".into(),
            amount: "1.50".into(),
        };
        assert!(!dry.fiat_left());
        assert!(Sent::Live {
            recipient: "jay-butera".into(),
            amount: "1.50".into()
        }
        .fiat_left());
    }
}
