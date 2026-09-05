//! An order, and the stages it moves through.
//!
//! The stage names are the page's, not this crate's invention: the page
//! switches on them and renders a different screen for each, so they are part
//! of the API and `stage_name` is the one place they are written.
//!
//! Everything here is data and pure functions over it. Nothing in this module
//! talks to a node, an attestor or a browser; the driver does that, and it does
//! it against a state it can only reach through the transitions below.

use serde::{Deserialize, Serialize};

use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::EscrowTerms;

/// Where an order stands, as the page understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Nothing at the address yet.
    AwaitingZec,
    /// An output exists and is gaining confirmations.
    Confirming,
    /// Deep enough, announced, and waiting for the user's pre-signature.
    NeedsPresignature,
    /// Pre-signature verified. The LP may pay.
    Locked,
    /// The dollars have gone.
    Paid,
    /// The release is on chain.
    Released,
    /// The pay deadline passed with nothing sent.
    Unpaid,
    /// At or past `T`, and the user may refund.
    Refundable,
    /// The refund was broadcast.
    Refunded,
    /// Stopped, and a human has to look.
    Failed,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::AwaitingZec => "awaiting_zec",
            Stage::Confirming => "confirming",
            Stage::NeedsPresignature => "needs_presignature",
            Stage::Locked => "locked",
            Stage::Paid => "paid",
            Stage::Released => "released",
            Stage::Unpaid => "unpaid",
            Stage::Refundable => "refundable",
            Stage::Refunded => "refunded",
            Stage::Failed => "failed",
        }
    }

    /// Whether this order still holds the coordinator's one in-flight slot.
    ///
    /// The slot exists because two payments in flight means two feed entries of
    /// the same amount to the same handle, and `locate_payment` refuses to
    /// guess between them. That refusal is correct and it happens *after* both
    /// payments have left.
    pub fn is_open(self) -> bool {
        !matches!(
            self,
            Stage::Released | Stage::Refunded | Stage::Failed | Stage::Unpaid
        )
    }

    /// Whether money may have left for this order.
    ///
    /// `Locked` counts, because the journal entry is written before the click
    /// and a crash there cannot distinguish "about to pay" from "paid".
    pub fn fiat_may_have_left(self) -> bool {
        matches!(self, Stage::Paid | Stage::Released)
    }
}

/// A quote, held until it is spent on an order or expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub quote_id: String,
    pub amount_zat: u64,
    pub gross_cents: u64,
    pub net_cents: u64,
    pub usd_amount_6dec: u64,
    pub platform_fee_zat: u64,
    pub miner_fee_zat: u64,
    pub rate_usd_per_zec: f64,
    pub lines: Vec<QuoteLine>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteLine {
    pub label: String,
    pub cents: i64,
    pub is_zpay_fee: bool,
}

impl Quote {
    pub fn is_expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        now > self.expires_at
    }
}

/// The funding output, once one has been found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Funding {
    /// Internal byte order. The view reverses it for display.
    #[serde(with = "hex32")]
    pub txid: [u8; 32],
    pub vout: u32,
    pub confirmations: u32,
    pub required: u32,
}

/// What the attestor answered, kept so the page can be shown it again on a
/// reload and so a restart does not need a second announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub event_id: String,
    pub r: String,
    pub p: String,
    pub terms_hash: String,
}

/// One order, in full. This is what is written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub order_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub stage: Stage,
    /// Set when the stage is `Failed`, and shown to the user.
    #[serde(default)]
    pub reason: Option<String>,

    pub handle: String,
    pub quote: Quote,

    /// The height when the order opened, which bounds a rescan.
    pub opened_height: u32,
    /// The highest block already searched for this order's funding output.
    ///
    /// Without it every sweep re-walked the whole window from `opened_height`,
    /// which is one `getblock` per block per tick: at a 200-block lookback and
    /// a 20 s tick that is ~870k node calls a day for a single unfunded order,
    /// and it is what exhausted the provider's quota. With it a sweep reads
    /// only the blocks that arrived since the last one.
    ///
    /// Absent on orders written before this field existed, and on those the
    /// scan falls back to `opened_height` - the old behaviour, once, after
    /// which the cursor is set. It is only ever advanced to a height that has
    /// actually been searched, so a crash between the scan and the store loses
    /// progress rather than skipping blocks.
    #[serde(default)]
    pub scanned_through: Option<u32>,
    pub network: String,
    pub consensus_branch_id: u32,

    #[serde(with = "hex33")]
    pub u_pub: [u8; 33],
    #[serde(with = "hex33")]
    pub l_pub: [u8; 33],
    pub refund_height: u64,
    pub address: String,
    #[serde(with = "hexbytes")]
    pub redeem_script: Vec<u8>,
    #[serde(with = "hexbytes")]
    pub script_pubkey: Vec<u8>,
    #[serde(with = "hex32")]
    pub payee_hash: [u8; 32],
    #[serde(with = "hexbytes")]
    pub treasury_script: Vec<u8>,
    #[serde(with = "hexbytes")]
    pub lp_output_script: Vec<u8>,

    #[serde(default)]
    pub funding: Option<Funding>,
    /// Set when the funding reached depth. This is the terms' `lock_confirmed_ms`
    /// and the cut for the feed search, so it is recorded once and never
    /// recomputed from the clock.
    #[serde(default)]
    pub lock_confirmed_ms: Option<u64>,
    #[serde(default)]
    pub announcement: Option<Announcement>,
    /// The user's adaptor pre-signature, hex. 162 bytes.
    #[serde(default)]
    pub pre_signature: Option<String>,
    #[serde(default)]
    pub pre_signed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub payment: Option<Payment>,
    #[serde(default)]
    pub release_txid: Option<String>,
    #[serde(default)]
    pub refund_txid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub sent_at: chrono::DateTime<chrono::Utc>,
    pub cents: u64,
}

impl Order {
    /// The transaction-level terms.
    pub fn escrow_terms(&self, funding: &Funding) -> EscrowTerms {
        EscrowTerms {
            funding_txid: funding.txid,
            vout: funding.vout,
            amount_zat: self.quote.amount_zat,
            u_pub: self.u_pub,
            l_pub: self.l_pub,
            refund_height: self.refund_height,
            consensus_branch_id: self.consensus_branch_id,
        }
    }

    /// The full canonical terms, once the escrow has locked.
    ///
    /// Returns `None` before there is a funding outpoint or a lock time,
    /// because both are committed by `terms_hash` and a placeholder for either
    /// would produce a hash that binds nothing.
    pub fn canonical_terms(&self) -> Option<CanonicalTerms> {
        let funding = self.funding?;
        let lock_confirmed_ms = self.lock_confirmed_ms?;
        Some(CanonicalTerms {
            funding_txid: funding.txid,
            vout: funding.vout,
            amount_zat: self.quote.amount_zat,
            u_pub: self.u_pub,
            l_pub: self.l_pub,
            refund_height: self.refund_height,
            usd_amount_6dec: self.quote.usd_amount_6dec,
            rate_18dec: zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC,
            payee_hash: self.payee_hash,
            lock_confirmed_ms,
            platform_fee_zat: self.quote.platform_fee_zat,
            treasury_script: self.treasury_script.clone(),
        })
    }

    /// The release's output split.
    ///
    /// Built from the order rather than from today's configuration, so a fee or
    /// treasury change between the pre-signature and the release cannot alter
    /// the transaction the user signed.
    pub fn release_split(&self) -> zecp2p_escrow::tx::ReleaseSplit {
        zecp2p_escrow::tx::ReleaseSplit {
            payout_script: self.lp_output_script.clone(),
            miner_fee_zat: self.quote.miner_fee_zat,
            platform_fee_zat: self.quote.platform_fee_zat,
            treasury_script: self.treasury_script.clone(),
        }
    }

    /// The ZIP 244 digest the user pre-signed and the LP will complete.
    pub fn release_digest(&self) -> anyhow::Result<[u8; 32]> {
        let funding = self
            .funding
            .ok_or_else(|| anyhow::anyhow!("this order has no funding outpoint yet"))?;
        let terms = self.escrow_terms(&funding);
        let split = self.release_split();
        let tx = zecp2p_escrow::tx::build_release_split(&terms, &split)
            .map_err(|e| anyhow::anyhow!("could not build the release: {e}"))?;
        tx.sighash()
            .map_err(|e| anyhow::anyhow!("could not compute the release digest: {e}"))
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Moves to `Failed` with a reason the page shows.
    pub fn fail(&mut self, why: impl Into<String>) {
        self.stage = Stage::Failed;
        self.reason = Some(why.into());
        self.touch();
    }
}

/// Hex for the fixed-width fields. Serde has no array impls past 32, and an
/// order on disk should be readable anyway.
macro_rules! hex_array {
    ($name:ident, $len:expr) => {
        mod $name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $len], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $len], D::Error> {
                let s = String::deserialize(d)?;
                let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
                raw.try_into().map_err(|_| {
                    serde::de::Error::custom(concat!("expected ", stringify!($len), " bytes"))
                })
            }
        }
    };
}

hex_array!(hex32, 32);
hex_array!(hex33, 33);

/// Hex for byte vectors, so an order on disk is readable and diffable.
mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stage_names_are_the_ones_the_page_switches_on() {
        // The page renders a different screen per stage and falls through to a
        // bare label for anything it does not know. Renaming one here silently
        // degrades the UI, so the strings are pinned.
        assert_eq!(Stage::AwaitingZec.as_str(), "awaiting_zec");
        assert_eq!(Stage::Confirming.as_str(), "confirming");
        assert_eq!(Stage::NeedsPresignature.as_str(), "needs_presignature");
        assert_eq!(Stage::Locked.as_str(), "locked");
        assert_eq!(Stage::Paid.as_str(), "paid");
        assert_eq!(Stage::Released.as_str(), "released");
        assert_eq!(Stage::Unpaid.as_str(), "unpaid");
        assert_eq!(Stage::Refundable.as_str(), "refundable");
        assert_eq!(Stage::Refunded.as_str(), "refunded");
        assert_eq!(Stage::Failed.as_str(), "failed");
    }

    #[test]
    fn a_finished_order_releases_the_in_flight_slot() {
        for done in [Stage::Released, Stage::Refunded, Stage::Failed, Stage::Unpaid] {
            assert!(!done.is_open(), "{} should free the slot", done.as_str());
        }
        for open in [
            Stage::AwaitingZec,
            Stage::Confirming,
            Stage::NeedsPresignature,
            Stage::Locked,
            Stage::Paid,
            Stage::Refundable,
        ] {
            assert!(open.is_open(), "{} still holds the slot", open.as_str());
        }
    }

    #[test]
    fn only_the_stages_after_the_click_report_that_fiat_left() {
        assert!(Stage::Paid.fiat_may_have_left());
        assert!(Stage::Released.fiat_may_have_left());
        assert!(!Stage::Locked.fiat_may_have_left());
        assert!(!Stage::Unpaid.fiat_may_have_left());
    }
}
