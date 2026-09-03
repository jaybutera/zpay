//! The native Zcash escrow as a rail the daemon can watch.
//!
//! The escrow protocol itself lives in `zecp2p-escrow` and is not reimplemented
//! here. This module is the adapter: it turns `zecp2p_escrow::lp::evaluate`'s
//! answer into the [`RailState`] the shared loop understands, and it builds the
//! [`FiatLeg`] that the shared Venmo code pays.
//!
//! # Why this is an adapter and not a second state machine
//!
//! `lp::evaluate` is the safety argument for the escrow: it is the thing that
//! makes `ReadyToPay` unreachable from a state where the escrow is not confirmed
//! to depth, the pre-signature has not verified, or the pay deadline has passed.
//! Rewriting that judgement here would mean two implementations of it, and the
//! one this daemon called would be the one nobody reviewed. So `evaluate` is
//! called, and this module only translates.
//!
//! The translation is deliberately lossy in one direction only. Every escrow
//! state that is not `ReadyToPay` maps to something that does not pay, and the
//! states that mean a person must look ([`LpState::PaidPastMargin`]) map to
//! `NeedsOperator` rather than to a wait. A mapping that erred the other way
//! would let the shared loop pay out of a state the escrow crate refuses.
//!
//! # What the terms bind
//!
//! The escrow's `intentHash` is `sha256("zecp2p-intent-v1" || canonical_terms)`,
//! not an on-chain intent. It commits to the funding outpoint, the amount, both
//! public keys, the refund height, the USD amount, the rate, the payee hash and
//! the moment the lock confirmed. That is what makes the attestation
//! non-transferable between escrows: change any of it and the hash moves, and
//! `payment_details` refuses an attestation for a different one.

use alloy::primitives::{B256, U256};
use anyhow::{bail, Context, Result};

use zecp2p_escrow::{
    chain::ChainClient,
    deadlines::EscrowPolicy,
    lp::{evaluate, LpProgress, LpState},
    rpc::txid_to_display,
    terms::CanonicalTerms,
    tx::EscrowTerms,
};

use crate::auto::{
    money::payment_cents,
    rail::{FiatLeg, Rail, RailState, WorkId},
};

/// One escrow this daemon is watching.
///
/// Held rather than rediscovered: an escrow is announced to the attestor once,
/// and the pre-signature drawn at announce time is never regenerated, so the
/// daemon must carry the identity it announced rather than rebuild it. The
/// escrow crate's own run record is the durable copy; this is the in-memory
/// view the loop reads.
#[derive(Debug, Clone)]
pub struct WatchedEscrow {
    pub terms: EscrowTerms,
    pub canonical: CanonicalTerms,
    /// The Venmo handle behind `canonical.payee_hash`, checked against the
    /// curator before this struct is built.
    pub recipient: String,
    /// Whether the user's pre-signature has verified. The escrow crate refuses
    /// to reach `ReadyToPay` without it, and it is the LP's only assurance that
    /// the release it will assemble is actually spendable.
    pub pre_signature_verified: bool,
    /// Whether the Venmo payment has gone out.
    pub venmo_paid: bool,
    /// Whether the attestor's scalar is in hand.
    pub outcome_secret_held: bool,
}

impl WatchedEscrow {
    pub fn work_id(&self) -> WorkId {
        WorkId::zec(&txid_to_display(&self.terms.funding_txid), self.terms.vout)
    }

    fn progress(&self) -> LpProgress {
        LpProgress {
            pre_signature_verified: self.pre_signature_verified,
            venmo_paid: self.venmo_paid,
            outcome_secret_held: self.outcome_secret_held,
        }
    }

    /// The fiat leg this escrow needs paid.
    ///
    /// The cap is applied here rather than trusted from the terms. The escrow's
    /// `usd_amount_6dec` is a number the LP quoted and the user accepted, and
    /// this daemon's cap is the operator's own ceiling on any single payment;
    /// a trade that agreed on more than the operator will send must refuse
    /// before the browser opens, not after.
    pub fn fiat_leg(&self, cap_cents: u64) -> Result<FiatLeg> {
        let amount_6dec = U256::from(self.canonical.usd_amount_6dec);
        let rate = U256::from(self.canonical.rate_18dec);

        // The same sizing function the Base rail uses. The escrow quotes
        // `usd_amount_6dec` against `rate_18dec` exactly as an intent does, so
        // the arithmetic is identical and there is no second implementation of
        // it to disagree with the first.
        let payment = payment_cents(amount_6dec, rate, cap_cents).with_context(|| {
            format!(
                "escrow {} agreed a payment this daemon will not send",
                self.work_id()
            )
        })?;

        // The moment the escrow reached its confirmation depth is the cut for
        // the feed search, and it is also what the terms committed to as
        // `lock_confirmed_ms`. A payment cannot predate the lock it settles, so
        // an earlier feed entry of the same amount to the same handle is
        // somebody else's payment.
        let not_before = chrono::DateTime::from_timestamp_millis(
            i64::try_from(self.canonical.lock_confirmed_ms)
                .context("the escrow's lock time does not fit a timestamp")?,
        )
        .context("the escrow's lock time is not a valid instant")?;

        Ok(FiatLeg {
            recipient: self.recipient.clone(),
            payment,
            not_before,
            intent_hash: B256::from(self.canonical.intent_hash()),
            intent_amount_6dec: amount_6dec,
            rate_18dec: rate,
            // The enclave is given the lock time, not the current time: it only
            // matches payments at or after the snapshot it is told about.
            intent_timestamp_ms: self.canonical.lock_confirmed_ms,
            payee_hash: B256::from(self.canonical.payee_hash),
        })
    }
}

/// Read this escrow's state off the chain and translate it for the shared loop.
///
/// `chain` is the escrow crate's own client, so this sees exactly what
/// `lp::evaluate` sees rather than a second view of the same node.
pub fn state_of(
    chain: &impl ChainClient,
    escrow: &WatchedEscrow,
    policy: &EscrowPolicy,
    cap_cents: u64,
) -> Result<RailState> {
    // The branch check comes first and it is not optional. A network upgrade
    // between the pre-signature and the release changes the sighash, so the
    // signature the user pre-signed stops being valid for the transaction the
    // LP will build. Discovering that after paying is the whole loss.
    if let Err(e) = zecp2p_escrow::lp::check_branch(chain, &escrow.terms) {
        return Ok(RailState::NeedsOperator {
            why: format!(
                "{e}. The pre-signature was made for another consensus branch, so the \
                 release it authorises would not verify. Do not pay this escrow."
            ),
        });
    }

    let lp_state = evaluate(
        chain,
        &escrow.terms,
        &escrow.canonical,
        policy,
        escrow.progress(),
    )
    .with_context(|| format!("could not evaluate escrow {}", escrow.work_id()))?;

    Ok(match lp_state {
        LpState::AwaitingLock => RailState::Waiting {
            why: format!(
                "escrow {} is not on chain yet, or a reorg unwound it",
                escrow.work_id()
            ),
        },
        LpState::AwaitingDepth {
            confirmations,
            required,
        } => RailState::Waiting {
            why: format!(
                "escrow {} has {confirmations} of the {required} confirmations its size requires",
                escrow.work_id()
            ),
        },
        LpState::ReadyToPay => RailState::ReadyToPay(escrow.fiat_leg(cap_cents)?),
        LpState::AwaitingAttestation => {
            RailState::AwaitingSettlement(escrow.fiat_leg(cap_cents)?)
        }
        LpState::ReadyToRelease => RailState::AwaitingSettlement(escrow.fiat_leg(cap_cents)?),
        // Nobody has lost anything: the LP never paid, and the user refunds at
        // T. This is a terminal wait rather than an operator problem.
        LpState::AbandonedUnpaid => RailState::Waiting {
            why: format!(
                "escrow {} passed its pay deadline unpaid. Nothing was sent; the user \
                 refunds at T and this daemon does nothing further.",
                escrow.work_id()
            ),
        },
        // Paid, and now racing the user's refund. Still worth broadcasting, and
        // never something a loop should decide on its own.
        LpState::PaidPastMargin => RailState::NeedsOperator {
            why: format!(
                "escrow {} was paid but is past the broadcast deadline. The release is \
                 now racing the refund, which is the LP's loss if it arrives second. \
                 Broadcast it by hand and check which landed.",
                escrow.work_id()
            ),
        },
    })
}

/// The guard before the browser opens.
///
/// A second call to the escrow crate's own `may_send_payment`, deliberately.
/// The state was computed some blocks ago and paying is a distinct act; the
/// escrow crate makes that point in its own docs and this rail honours it
/// rather than trusting a value it is holding.
pub fn require_payable(chain: &impl ChainClient, escrow: &WatchedEscrow, policy: &EscrowPolicy) -> Result<()> {
    let state = evaluate(
        chain,
        &escrow.terms,
        &escrow.canonical,
        policy,
        escrow.progress(),
    )?;
    zecp2p_escrow::lp::may_send_payment(&state)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| {
            format!(
                "re-checked immediately before opening the browser, because the state \
                 that said this escrow was payable was computed earlier and the chain \
                 has moved since"
            )
        })
}

/// Build the canonical terms for an escrow from what a run already knows.
///
/// The field order and the string forms are the escrow crate's business; this
/// only refuses the combinations that cannot produce a usable intent hash, so a
/// mistyped value fails here rather than at the enclave after the fiat has left.
#[allow(clippy::too_many_arguments)]
pub fn canonical_terms(
    terms: &EscrowTerms,
    usd_amount_6dec: u64,
    rate_18dec: u128,
    payee_hash: [u8; 32],
    lock_confirmed_ms: u64,
    platform_fee_zat: u64,
    treasury_script: Vec<u8>,
) -> Result<CanonicalTerms> {
    if usd_amount_6dec == 0 {
        bail!("an escrow for $0.00 has nothing to pay and nothing to release");
    }
    if rate_18dec == 0 {
        bail!("a rate of zero prices every escrow at nothing");
    }
    if payee_hash == [0u8; 32] {
        bail!(
            "the payee hash is unset. The enclave binds the attestation to the account \
             that was actually paid, and a zero hash matches no maker; resolve the \
             handle with the curator first."
        );
    }
    if lock_confirmed_ms == 0 {
        bail!(
            "lock_confirmed_ms is unset. It is both the enclave's snapshot and the cut \
             for finding the payment in the feed; zero would admit a payment from any time."
        );
    }

    // A fee with nowhere to pay it, or a treasury with nothing to pay it, means
    // the two sides of the trade are about to build different transactions from
    // the same terms. Refuse here rather than at the sighash.
    if (platform_fee_zat == 0) != treasury_script.is_empty() {
        bail!(
            "platform_fee_zat is {platform_fee_zat} and the treasury script is {} bytes. \
             They must both be set or both be empty: a fee with no destination cannot be \
             paid, and a destination with no fee is an output the release does not carry.",
            treasury_script.len()
        );
    }

    Ok(CanonicalTerms {
        funding_txid: terms.funding_txid,
        vout: terms.vout,
        amount_zat: terms.amount_zat,
        u_pub: terms.u_pub,
        l_pub: terms.l_pub,
        refund_height: terms.refund_height,
        usd_amount_6dec,
        rate_18dec,
        payee_hash,
        lock_confirmed_ms,
        platform_fee_zat,
        treasury_script,
    })
}

/// This rail's identity, for callers that enumerate rails.
pub const RAIL: Rail = Rail::Zec;

#[cfg(test)]
mod tests {
    use super::*;
    use zecp2p_escrow::chain::FakeChain;

    /// The keys from the mainnet run's shape, though not its actual keys: any
    /// valid compressed point serves, and the escrow crate builds the script.
    fn keys() -> ([u8; 33], [u8; 33]) {
        let secp = secp256k1_zkp::Secp256k1::new();
        let u = secp256k1_zkp::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let l = secp256k1_zkp::SecretKey::from_slice(&[0x22; 32]).unwrap();
        (
            u.public_key(&secp).serialize(),
            l.public_key(&secp).serialize(),
        )
    }

    fn escrow() -> WatchedEscrow {
        let (u_pub, l_pub) = keys();
        let terms = EscrowTerms {
            funding_txid: [0xd5; 32],
            vout: 0,
            amount_zat: 200_000,
            u_pub,
            l_pub,
            refund_height: 3_471_833,
            consensus_branch_id: 0xc8e7_1055,
        };
        let canonical = canonical_terms(
            &terms,
            1_500_000,
            1_000_000_000_000_000_000,
            [0x85; 32],
            1_756_000_000_000,
            400,
            vec![0x76, 0xa9, 20, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x88, 0xac],
        )
        .unwrap();
        WatchedEscrow {
            terms,
            canonical,
            recipient: "jay-butera".into(),
            pre_signature_verified: true,
            venmo_paid: false,
            outcome_secret_held: false,
        }
    }

    fn chain_at(height: u32, confirmations: u32) -> FakeChain {
        let mut chain = FakeChain::new(height, 0xc8e7_1055);
        let e = escrow();
        chain.add_utxo(
            e.terms.funding_txid,
            e.terms.vout,
            zecp2p_escrow::chain::Utxo {
                script_pubkey: e.terms.script_pubkey().unwrap(),
                amount_zat: 200_000,
                confirmations,
            },
        );
        chain
    }

    fn policy() -> EscrowPolicy {
        EscrowPolicy::mainnet_default()
    }

    /// The mainnet escrow's own numbers: 200,000 zat against a $1.50 payment.
    /// The shared sizing must land on the string the browser typed that day.
    #[test]
    fn the_fiat_leg_reproduces_the_mainnet_dollar_fifty() {
        let leg = escrow().fiat_leg(10_000).unwrap();
        assert_eq!(leg.payment.to_venmo_string(), "1.50");
        assert_eq!(leg.recipient, "jay-butera");
        assert_eq!(leg.intent_amount_6dec, U256::from(1_500_000u64));
    }

    /// The intent hash is the terms hash, and it moves when any term moves.
    /// This is what stops an attestation for one escrow releasing another.
    #[test]
    fn changing_any_term_changes_the_intent_hash() {
        let base = escrow().fiat_leg(10_000).unwrap().intent_hash;

        let mut other = escrow();
        other.canonical.usd_amount_6dec = 1_500_001;
        assert_ne!(base, other.fiat_leg(10_000).unwrap().intent_hash);

        let mut other = escrow();
        other.canonical.amount_zat = 200_001;
        assert_ne!(base, other.fiat_leg(10_000).unwrap().intent_hash);

        let mut other = escrow();
        other.canonical.payee_hash = [0x86; 32];
        assert_ne!(base, other.fiat_leg(10_000).unwrap().intent_hash);
    }

    /// The operator's cap outranks whatever the escrow's terms agreed. A trade
    /// larger than this daemon will send must refuse before the browser opens.
    #[test]
    fn the_operator_cap_refuses_an_oversized_escrow() {
        let mut big = escrow();
        big.canonical.usd_amount_6dec = 50_000_000;
        let err = big.fiat_leg(2_500).expect_err("must refuse");
        let msg = format!("{err:#}");
        assert!(msg.contains("exceeds"), "{msg}");
    }

    /// The cut for the feed search is the lock time, not the wall clock. An
    /// escrow that used "now" would match a payment made before it locked.
    #[test]
    fn the_feed_cut_is_the_lock_time() {
        let leg = escrow().fiat_leg(10_000).unwrap();
        assert_eq!(leg.not_before.timestamp_millis(), 1_756_000_000_000);
        assert_eq!(leg.intent_timestamp_ms, 1_756_000_000_000);
    }

    /// Depth is the escrow crate's judgement, and this rail reports it as a
    /// wait rather than paying through it.
    #[test]
    fn an_under_confirmed_escrow_waits_and_does_not_pay() {
        let chain = chain_at(3_470_000, 1);
        let state = state_of(&chain, &escrow(), &policy(), 10_000).unwrap();
        match state {
            RailState::Waiting { why } => assert!(why.contains("confirmations"), "{why}"),
            other => panic!("expected a wait, got {other:?}"),
        }
    }

    /// Confirmed to depth, inside the deadlines, pre-signature verified: this
    /// is the one state that pays, and it carries the leg.
    #[test]
    fn a_confirmed_escrow_is_ready_to_pay() {
        let chain = chain_at(3_470_700, 20);
        let state = state_of(&chain, &escrow(), &policy(), 10_000).unwrap();
        match state {
            RailState::ReadyToPay(leg) => assert_eq!(leg.payment.to_venmo_string(), "1.50"),
            other => panic!("expected ReadyToPay, got {other:?}"),
        }
    }

    /// The pre-signature is the LP's only assurance the release is spendable.
    /// Without it the escrow crate errors, and this rail must not paper over it.
    #[test]
    fn an_unverified_pre_signature_never_reaches_ready_to_pay() {
        let chain = chain_at(3_470_700, 20);
        let mut e = escrow();
        e.pre_signature_verified = false;
        let result = state_of(&chain, &e, &policy(), 10_000);
        assert!(result.is_err(), "an unverified pre-signature must not pay");
    }

    /// A branch change invalidates the pre-signature. Paying afterwards spends
    /// fiat against a release nobody will accept, so this refuses before the
    /// escrow crate is even asked for a state.
    #[test]
    fn a_branch_change_stops_the_rail_before_it_can_pay() {
        let mut chain = chain_at(3_470_700, 20);
        chain.branch_id = 0x0000_0001;
        match state_of(&chain, &escrow(), &policy(), 10_000).unwrap() {
            RailState::NeedsOperator { why } => {
                assert!(why.contains("Do not pay"), "{why}");
                assert!(why.contains("branch"), "{why}");
            }
            other => panic!("expected NeedsOperator, got {other:?}"),
        }
    }

    /// Past the pay deadline the LP stops, and nobody has lost anything: this
    /// is a wait, not an operator problem.
    #[test]
    fn past_the_pay_deadline_it_waits_rather_than_paging_a_human() {
        // Inside the last `pay_deadline_blocks` before T.
        let chain = chain_at(3_471_800, 20);
        match state_of(&chain, &escrow(), &policy(), 10_000).unwrap() {
            RailState::Waiting { why } => assert!(why.contains("pay deadline"), "{why}"),
            other => panic!("expected a wait, got {other:?}"),
        }
    }

    /// Paid but past the broadcast margin is the one state that costs the LP
    /// money, and it always goes to a human.
    #[test]
    fn paid_past_the_margin_needs_an_operator() {
        let chain = chain_at(3_471_800, 20);
        let mut e = escrow();
        e.venmo_paid = true;
        match state_of(&chain, &e, &policy(), 10_000).unwrap() {
            RailState::NeedsOperator { why } => assert!(why.contains("racing the refund"), "{why}"),
            other => panic!("expected NeedsOperator, got {other:?}"),
        }
    }

    /// `require_payable` asks the chain again rather than trusting a state
    /// computed earlier. An escrow that has since passed its deadline refuses.
    #[test]
    fn the_pay_guard_rechecks_the_chain() {
        let ready = chain_at(3_470_700, 20);
        assert!(require_payable(&ready, &escrow(), &policy()).is_ok());

        let moved_on = chain_at(3_471_800, 20);
        let err = require_payable(&moved_on, &escrow(), &policy()).expect_err("must refuse");
        assert!(format!("{err:#}").contains("re-checked"), "{err:#}");
    }

    /// The terms builder refuses what cannot produce a usable attestation,
    /// before any money moves rather than at the enclave afterwards.
    #[test]
    fn degenerate_terms_are_refused_up_front() {
        let (u_pub, l_pub) = keys();
        let terms = EscrowTerms {
            funding_txid: [0xd5; 32],
            vout: 0,
            amount_zat: 200_000,
            u_pub,
            l_pub,
            refund_height: 3_471_833,
            consensus_branch_id: 0xc8e7_1055,
        };
        assert!(canonical_terms(&terms, 0, 1, [0x85; 32], 1, 0, Vec::new()).is_err());

        // Round-1 review F6: half a fee is refused. A fee with no destination
        // cannot be paid, and a destination with no fee is an output the
        // release does not carry; either way this daemon and the user's client
        // would build different transactions from what both call the same
        // terms, and nothing would say so until the release failed to
        // broadcast.
        let treasury = vec![
            0x76, 0xa9, 20, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x88, 0xac,
        ];
        let err = canonical_terms(&terms, 1_500_000, 1, [0x85; 32], 1, 400, Vec::new())
            .expect_err("a fee with no destination must be refused");
        assert!(err.to_string().contains("both be set or both be empty"));
        let err = canonical_terms(&terms, 1_500_000, 1, [0x85; 32], 1, 0, treasury.clone())
            .expect_err("a destination with no fee must be refused");
        assert!(err.to_string().contains("both be set or both be empty"));

        // And the honest pairing builds.
        canonical_terms(&terms, 1_500_000, 1, [0x85; 32], 1, 400, treasury)
            .expect("a complete fee must build");
        assert!(canonical_terms(&terms, 1_500_000, 0, [0x85; 32], 1, 0, Vec::new()).is_err());
        let err = canonical_terms(&terms, 1_500_000, 1, [0u8; 32], 1, 0, Vec::new()).expect_err("must refuse");
        assert!(err.to_string().contains("payee hash"), "{err}");
        let err = canonical_terms(&terms, 1_500_000, 1, [0x85; 32], 0, 0, Vec::new()).expect_err("must refuse");
        assert!(err.to_string().contains("any time"), "{err}");
    }

    /// The work id names the outpoint in the order a human pastes back into
    /// `paid_path`, which is the explorer's order and not the wire's.
    #[test]
    fn the_work_id_uses_the_display_txid() {
        let id = escrow().work_id();
        assert_eq!(id.rail, Rail::Zec);
        assert!(id.local.ends_with(":0"), "{id}");
        assert_eq!(id.local.len(), 64 + 2);
    }
}
