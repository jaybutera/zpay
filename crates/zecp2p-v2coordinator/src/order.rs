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
    /// The outpoint an announcement was drawn against while it was still only
    /// in the mempool.
    ///
    /// Separate from `funding` on purpose. `funding` means "seen in a block by
    /// the scanner and re-read with `gettxout`", and it is what the payment
    /// decision is built on. This means only "a transaction paying this escrow
    /// was in the mempool, and the terms the user signed name it". If that
    /// transaction is replaced or never mined, this stays set, `funding` stays
    /// `None`, nothing is ever paid, and the escrow refunds at T.
    #[serde(default, with = "opt_hex32")]
    pub mempool_announced_txid: Option<[u8; 32]>,
    #[serde(default)]
    pub mempool_announced_vout: Option<u32>,
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

    /// The outpoint these terms are bound to.
    ///
    /// `funding` when the scanner has seen it in a block, and otherwise the one
    /// a mempool sighting announced against. They are the same outpoint in the
    /// ordinary case: the mempool entry is the transaction that later confirms.
    ///
    /// Preferring `funding` matters when they differ, which means the mempool
    /// transaction was replaced and a different one confirmed. The terms the
    /// user signed name the replaced outpoint, so the pre-signature will not
    /// decrypt onto the confirmed one - `verify_pre_signature` re-derives the
    /// digest and refuses. That is the correct outcome: nothing is paid and the
    /// escrow refunds at T.
    fn bound_outpoint(&self) -> Option<([u8; 32], u32)> {
        if let Some(f) = self.funding {
            return Some((f.txid, f.vout));
        }
        Some((self.mempool_announced_txid?, self.mempool_announced_vout?))
    }

    /// The full canonical terms, once the escrow has locked.
    ///
    /// Returns `None` before there is an outpoint or a lock time, because both
    /// are committed by `terms_hash` and a placeholder for either would produce
    /// a hash that binds nothing.
    pub fn canonical_terms(&self) -> Option<CanonicalTerms> {
        let (funding_txid, vout) = self.bound_outpoint()?;
        let lock_confirmed_ms = self.lock_confirmed_ms?;
        Some(CanonicalTerms {
            funding_txid,
            vout,
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
        // The same outpoint the announcement was drawn against, so what the
        // user signs and what `terms_hash` commits to cannot disagree.
        let (txid, vout) = self
            .bound_outpoint()
            .ok_or_else(|| anyhow::anyhow!("this order has no funding outpoint yet"))?;
        let terms = self.escrow_terms(&Funding {
            txid,
            vout,
            confirmations: 0,
            required: 0,
        });
        let split = self.release_split();
        let tx = zecp2p_escrow::tx::build_release_split(&terms, &split)
            .map_err(|e| anyhow::anyhow!("could not build the release: {e}"))?;
        tx.sighash()
            .map_err(|e| anyhow::anyhow!("could not compute the release digest: {e}"))
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    /// Whether this order still owes the user a look at the refund deadline.
    ///
    /// `Unpaid` and `Failed` are terminal for the *trade* - nothing more will
    /// be paid or released - but they are not terminal for the user's coin.
    /// The escrow is still funded and the timeout branch still pays out at `T`,
    /// while the page offers its refund form on `Refundable` alone. Left out of
    /// the sweep, an order in either stage never reaches `Refundable` and the
    /// user is told the trade is over with no way back to their ZEC.
    ///
    /// **Unless the dollars went.** `Failed` is also what `settle` writes when
    /// the Venmo leg errors after the journal claim, and what `finish_payment`
    /// writes when the payment left and the release did not broadcast. There
    /// the LP has paid and holds a valid release, and the loss on a race is the
    /// LP's (spec 4.5). Promoting those to `Refundable` would put a screen in
    /// front of the user telling them to take a coin the LP has already bought
    /// - this coordinator instructing its own counterparty to spend against it.
    /// A recorded payment is the cheap, local signal for that, and the refund
    /// endpoint independently refuses on the journal.
    ///
    /// `Refunded` and `Released` are excluded: the escrow output is spent, so
    /// there is nothing left to refund. `Refundable` is excluded because it is
    /// already the answer.
    pub fn still_owes_a_refund_check(&self) -> bool {
        matches!(self.stage, Stage::Unpaid | Stage::Failed)
            && self.payment.is_none()
            && !self.stage.fiat_may_have_left()
            // Something has to be at the address. An order nobody ever funded
            // has no escrow to refund: promoting it says "your ZEC is in the
            // escrow" over an empty one, hands the user a form the refund
            // builder cannot fill, and keeps the order in the sweep list for
            // good. A mempool sighting counts - the coin is on its way even if
            // no block holds it yet.
            && (self.funding.is_some() || self.mempool_announced_txid.is_some())
    }

    /// The tag written into the Venmo note, so this payment is distinguishable
    /// from any other in the feed.
    ///
    /// `locate_payment` matches a feed entry on the rendered amount and the
    /// receiver's username, and nothing else. Two entries that agree on both
    /// give the "many" refusal, which lands after the dollars have gone and
    /// needs an operator with an explicit index. Two people sending the same
    /// amount to the same handle is not a rare case; it is the normal one at
    /// any volume.
    ///
    /// The note is the only field the feed carries that this side controls.
    /// Checked against the live feed on 2026-09-05: every story returned a
    /// `note.content`, including our own past payments.
    ///
    /// Derived from the order id rather than drawn separately, so it needs no
    /// new state and cannot disagree with the order it belongs to. Hex, and
    /// short, because it goes in a field a person reads.
    pub fn payment_tag(&self) -> String {
        // The id is `esc_` and 24 hex characters of randomness; the last eight
        // are as unpredictable as the whole.
        let tail: String = self
            .order_id
            .chars()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        tail
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

/// The same, for a field that may be absent. `None` round-trips as JSON null,
/// so an order written before the field existed still loads.
mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        let Some(s) = s else { return Ok(None) };
        let raw = hex::decode(&s).map_err(serde::de::Error::custom)?;
        raw.try_into()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

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
