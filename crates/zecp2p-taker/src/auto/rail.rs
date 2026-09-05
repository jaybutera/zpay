//! The two settlement rails, and what they have in common.
//!
//! zecp2p settles an offramp two ways. The deployed one puts USDC into a zk-p2p
//! deposit on Base and releases it with `fulfillIntent`; the native one locks
//! ZEC in a 2-of-2 P2SH on Zcash and releases it by decrypting an adaptor
//! pre-signature. Casper's instruction is to run both live in parallel rather
//! than cut over, so this module is the vocabulary that lets one daemon hold
//! both without either learning about the other.
//!
//! # What is actually shared
//!
//! Very little of the *settlement* and almost all of the *fiat*. Both rails
//! send one Venmo payment and prove it to the same Peer enclave, and every
//! expensive mistake this repository has recorded lives on that side:
//!
//! - the rate-aware sizing in [`crate::auto::money`], where a rate-blind
//!   conversion of deposit 4499 read four cents high;
//! - the exact-text "Pay" match in [`crate::venmo`], where a substring match
//!   also hits "Pay without confirming" and skips the confirmation;
//! - `locate_payment` in [`crate::auto::attest::feed`], where a hardcoded index
//!   0 would have attested an unrelated incoming payment.
//!
//! Duplicating any of those per rail would mean two chances to relearn them, so
//! the rails do not own them. A rail supplies [`FiatLeg`]: who to pay, how much,
//! and the moment before which a feed entry cannot be this payment. The shared
//! code does the rest, identically, for both.
//!
//! # What is not shared
//!
//! The lock and the release. Base locks by `signalIntent` against a
//! `GlueDeposit` and releases by `fulfillIntent`; Zcash locks by a funding
//! transaction reaching depth and releases by broadcasting a decrypted
//! pre-signature. Those live behind [`Settlement`], and neither implementation
//! can see the other's types.

use std::fmt;

use alloy::primitives::{B256, U256};

use crate::auto::money::PaymentAmount;

/// Which settlement system a unit of work belongs to.
///
/// Deliberately a closed enum rather than an open trait object at the identity
/// level: a work item's rail is written into the journal, and a journal read
/// back by a daemon that does not recognise the rail must fail loudly rather
/// than default to one. Defaulting would mean a Zcash escrow evaluated by the
/// Base state machine, which is how a release gets skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rail {
    /// 1Click plus zk-p2p on Base: `GlueDeposit` in, `fulfillIntent` out.
    Base,
    /// Native Zcash escrow: a 2-of-2 P2SH released by an adaptor signature.
    Zec,
}

impl Rail {
    pub fn as_str(self) -> &'static str {
        match self {
            Rail::Base => "base",
            Rail::Zec => "zec",
        }
    }

    /// What this rail locks, for a prompt a human reads before approving.
    pub fn collateral(self) -> &'static str {
        match self {
            Rail::Base => "USDC stake in the zk-p2p StakeVault",
            Rail::Zec => "ZEC in a 2-of-2 escrow on Zcash mainnet",
        }
    }

    /// Every rail this build knows about, so a caller enumerating them cannot
    /// silently miss one added later.
    pub fn all() -> [Rail; 2] {
        [Rail::Base, Rail::Zec]
    }
}

impl fmt::Display for Rail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Rail {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "base" | "zkp2p" | "zk-p2p" => Ok(Rail::Base),
            "zec" | "zcash" | "escrow" | "native" => Ok(Rail::Zec),
            other => Err(format!(
                "unknown rail {other:?}; this build knows base and zec"
            )),
        }
    }
}

/// A work item's identity, unique across both rails.
///
/// The journal is keyed on this. Base numbers its deposits from a contract
/// counter and Zcash names its escrows by outpoint, so the two namespaces would
/// otherwise be free to collide on a small integer: deposit 0 and a funding
/// txid that renders as "0" are different work, and a journal that cannot tell
/// them apart is a journal that reports the wrong fill as in flight.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct WorkId {
    pub rail: Rail,
    /// Rail-local identity. `deposit_id` on Base, `txid:vout` on Zcash.
    pub local: String,
}

impl WorkId {
    pub fn base(deposit_id: U256) -> Self {
        Self {
            rail: Rail::Base,
            local: deposit_id.to_string(),
        }
    }

    /// `txid` here is the display order a block explorer prints, not the
    /// internal order the wire format uses, because this string is what a human
    /// pastes back into `paid_path`.
    pub fn zec(funding_txid_display: &str, vout: u32) -> Self {
        Self {
            rail: Rail::Zec,
            local: format!("{funding_txid_display}:{vout}"),
        }
    }
}

impl fmt::Display for WorkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.rail, self.local)
    }
}

/// The fiat side of one trade, which is the part both rails share.
///
/// A rail produces this and the shared Venmo code consumes it. Nothing on this
/// struct names a chain, a contract or a script, which is the property that
/// keeps one browser driver and one `locate_payment` serving both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiatLeg {
    /// Venmo username without the leading @, already checked for shape and
    /// already matched against whatever payee commitment the rail carries.
    pub recipient: String,
    /// What to send, rounded and capped by [`crate::auto::money::payment_cents`].
    pub payment: PaymentAmount,
    /// The earliest moment a feed entry could be this payment.
    ///
    /// The cut `locate_payment` needs. Both rails have one and they come from
    /// different clocks: Base uses the intent's on-chain signal time, Zcash uses
    /// the moment the escrow reached its confirmation depth. Either way a
    /// payment cannot predate the lock it settles, so an earlier entry of the
    /// same amount to the same handle is somebody else's.
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// A per-payment tag written into the Venmo note, and matched on when the
    /// feed is read.
    ///
    /// `locate_payment` otherwise discriminates on the rendered amount and the
    /// receiver's username alone, so two people sending the same amount to the
    /// same handle produce two entries it cannot tell apart - a refusal that
    /// arrives after the dollars have gone, needing an operator and an explicit
    /// index. The note is the only feed field the paying side controls.
    ///
    /// `None` on a rail that does not set one, which matches on amount and
    /// receiver exactly as before.
    pub tag: Option<String>,
    /// What the enclave is told to bind the attestation to.
    ///
    /// On Base this is the `IntentSignaled` hash; on Zcash it is
    /// `sha256("zecp2p-intent-v1" || canonical_terms)`. The enclave signs
    /// whatever 32 bytes it is handed and checks neither against any chain, so
    /// the rail owns the meaning and the shared code only carries it.
    pub intent_hash: B256,
    /// Release amount in 6-decimal USD units, as the enclave's `INTENT_AMOUNT`.
    pub intent_amount_6dec: U256,
    /// The rate the attestation is proved against, scaled by 1e18.
    ///
    /// Never defaulted on either rail. The prover's own default is 1e18 and it
    /// is wrong for every trade not priced at exactly 1.0; on Base that reverts
    /// at `UPV: Snapshot rate mismatch`, and on Zcash `payment_details` refuses
    /// the attestation with `RateMismatch`. The native escrow quotes exactly
    /// 1e18 today, which makes the two failures look alike and is precisely why
    /// this is carried rather than assumed.
    pub rate_18dec: U256,
    /// The enclave's `INTENT_TIMESTAMP_MS`.
    pub intent_timestamp_ms: u64,
    /// The curator's `hashedOnchainId` for the payee.
    pub payee_hash: B256,
}

/// Where a trade stands on its own rail, reduced to what the shared loop needs.
///
/// This is not a second copy of either rail's state machine. `auto::pipeline`
/// still decides the Base fill and `zecp2p_escrow::lp::evaluate` still decides
/// the escrow; this is the answer both give to the only three questions the
/// shared loop asks: may I pay, have I paid, and is it finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailState {
    /// The lock is not ready. Nothing to do but wait, with the reason.
    Waiting { why: String },
    /// Locked, verified, and inside every deadline. The fiat leg may run.
    ReadyToPay(FiatLeg),
    /// The fiat has left and the settlement has not completed.
    AwaitingSettlement(FiatLeg),
    /// Finished.
    Settled { reference: String },
    /// Stopped, and a human has to look. Never resolved automatically.
    NeedsOperator { why: String },
}

impl RailState {
    /// The fiat leg, when this state has one.
    pub fn fiat_leg(&self) -> Option<&FiatLeg> {
        match self {
            RailState::ReadyToPay(leg) | RailState::AwaitingSettlement(leg) => Some(leg),
            _ => None,
        }
    }

    /// Whether this state still occupies the daemon's one in-flight slot.
    pub fn is_open(&self) -> bool {
        !matches!(self, RailState::Settled { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The journal writes a rail and reads it back. An unrecognised one must
    /// fail rather than default: a Zcash escrow driven by the Base state
    /// machine never broadcasts its release.
    #[test]
    fn an_unknown_rail_refuses_rather_than_defaulting() {
        assert_eq!("base".parse::<Rail>(), Ok(Rail::Base));
        assert_eq!("zec".parse::<Rail>(), Ok(Rail::Zec));
        assert_eq!("Zcash".parse::<Rail>(), Ok(Rail::Zec));
        let err = "solana".parse::<Rail>().expect_err("must refuse");
        assert!(err.contains("base and zec"), "{err}");
    }

    #[test]
    fn a_rail_round_trips_through_json() {
        for rail in Rail::all() {
            let json = serde_json::to_string(&rail).unwrap();
            assert_eq!(serde_json::from_str::<Rail>(&json).unwrap(), rail);
        }
        assert_eq!(serde_json::to_string(&Rail::Zec).unwrap(), "\"zec\"");
    }

    /// The collision this key exists to prevent. Base deposit 0 and a Zcash
    /// escrow whose local identity renders as "0" are different work, and a
    /// journal that conflates them reports the wrong fill in flight.
    #[test]
    fn the_two_rails_cannot_collide_on_an_id() {
        let base = WorkId::base(U256::ZERO);
        let zec = WorkId {
            rail: Rail::Zec,
            local: "0".into(),
        };
        assert_ne!(base, zec);
        assert_eq!(base.local, zec.local, "the collision is real without the rail");
        assert_eq!(base.to_string(), "base/0");
        assert_eq!(zec.to_string(), "zec/0");
    }

    #[test]
    fn a_zec_work_id_names_the_outpoint() {
        let id = WorkId::zec("d599b8cd", 0);
        assert_eq!(id.rail, Rail::Zec);
        assert_eq!(id.local, "d599b8cd:0");
    }

    /// Both rails must be able to say who is at risk, because the prompt a
    /// human approves says it out loud and the two are not the same asset.
    #[test]
    fn each_rail_names_what_it_locks() {
        assert!(Rail::Base.collateral().contains("USDC"));
        assert!(Rail::Zec.collateral().contains("ZEC"));
    }

    #[test]
    fn only_the_paying_states_carry_a_fiat_leg() {
        let waiting = RailState::Waiting { why: "depth".into() };
        assert!(waiting.fiat_leg().is_none());
        assert!(waiting.is_open());
        assert!(!RailState::Settled {
            reference: "0xabc".into()
        }
        .is_open());
    }
}
