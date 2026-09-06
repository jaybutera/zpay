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
    /// Opened, never funded, and left long enough that it stopped counting.
    ///
    /// Finding 4. Opening an order is free - a quote id, a curve point and a
    /// served handle - and until this existed an unfunded one held capacity
    /// against every intake guard for the length of a refund window, about 23
    /// hours. Five of them locked a handle out for a day; two hundred closed
    /// intake entirely; one at a given amount blocked every real order for that
    /// amount to that handle. None of it cost the caller anything.
    ///
    /// Terminal and empty. Nothing was ever sent to the escrow - that is what
    /// makes it expirable, and the check is the chain rather than a clock alone
    /// - so there is nothing to refund and nothing to release. The record stays
    /// readable so a user who funded late is told what happened rather than
    /// getting a 404, and `still_owes_a_refund_check` keeps watching the
    /// address in case coin arrives after all.
    Expired,
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
            Stage::Expired => "expired",
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
            Stage::Released
                | Stage::Refunded
                | Stage::Failed
                | Stage::Unpaid
                | Stage::Expired
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
    /// Which client opened this order, for the per-client standing bound.
    ///
    /// Finding 4. An address, and a weak identity: it is what is available at
    /// this layer without asking users to hold an account. Never shown to
    /// anyone - it is absent from every view - and used only to count how many
    /// open orders one caller holds.
    ///
    /// Optional because orders written before this existed do not carry one,
    /// and because a coordinator may be reached over a socket with no address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_by: Option<String>,
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
    /// Set once the chain has been asked what became of the sighted funding and
    /// answered that nothing is there.
    ///
    /// R5-2. A sighting is admitted as evidence of funding because in the usual
    /// case the coin is on its way, and until `T` there is no way to tell a
    /// transaction still waiting for a block from one that will never get one.
    /// At `T` there is: `gettxout` on the sighted outpoint. A null answer means
    /// the transaction expired unmined and nothing ever reached the address, so
    /// there is no escrow to refund and nothing further to sweep for.
    ///
    /// Recorded rather than re-derived so the answer costs one chain read
    /// rather than one per sweep for the life of the store. Only written on a
    /// definite null - a node that will not answer leaves it unset and the
    /// question is asked again.
    ///
    /// Absent on orders written before this field existed, which read as "not
    /// asked yet" and are asked on their next sweep past `T`.
    #[serde(default)]
    pub sighting_never_confirmed: bool,
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
    /// The note the rail typed into this payment, as it typed it.
    ///
    /// The feed search happens on a later sweep than the payment, and possibly
    /// under a later binary. What the feed holds is what was typed at the time,
    /// so it is recorded rather than re-derived: an order paid with a bare
    /// configured note and attested after a deploy that appends tags would
    /// otherwise be looked for under a tag its entry does not carry, and every
    /// sweep would refuse - after the dollars had gone, with the one payment
    /// slot held.
    ///
    /// `None` on an order paid before this field existed, and on one paid by a
    /// rail that reports no note. Both mean the same thing to the search:
    /// nothing is known about the note, so match on amount and receiver, which
    /// is what those payments were matched on when they were made.
    #[serde(default)]
    pub note: Option<String>,
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
    /// The outpoint a mempool sighting named, if one was ever recorded.
    ///
    /// Distinct from `funding`, which only a block scan writes. This is what
    /// the sweep re-reads at `T` to tell a transaction that confirmed behind
    /// the scan cursor from one that expired unmined.
    pub fn mempool_outpoint(&self) -> Option<([u8; 32], u32)> {
        Some((self.mempool_announced_txid?, self.mempool_announced_vout?))
    }

    fn bound_outpoint(&self) -> Option<([u8; 32], u32)> {
        if let Some(f) = self.funding {
            return Some((f.txid, f.vout));
        }
        self.mempool_outpoint()
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
        // `Expired` is here for the case the expiry itself cannot rule out:
        // coin that arrives after the order stopped counting. Expiry is only
        // written over an order with no funding and no sighting, so the common
        // case leaves this false on the first evaluation and the order drops
        // out of the sweep - which is the whole saving. An expired order that
        // *does* acquire a funding outpoint later is a user owed their coin
        // back, and it stays in the sweep until `T` puts it in front of them.
        matches!(self.stage, Stage::Unpaid | Stage::Failed | Stage::Expired)
            && self.payment.is_none()
            && !self.stage.fiat_may_have_left()
            // Something has to be at the address. An order nobody ever funded
            // has no escrow to refund: promoting it says "your ZEC is in the
            // escrow" over an empty one, hands the user a form the refund
            // builder cannot fill, and keeps the order in the sweep list for
            // good. A mempool sighting counts - the coin is on its way even if
            // no block holds it yet.
            //
            // R5-2: unless the chain has since been asked and said the sighted
            // transaction never confirmed. Then the sighting is evidence of
            // nothing, and an order kept on the strength of it is the same
            // never-funded order R4-2 took off the list, reached by a different
            // route.
            && (self.funding.is_some()
                || (self.mempool_announced_txid.is_some() && !self.sighting_never_confirmed))
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
    /// Hex, and short, because it goes in a field a person reads.
    ///
    /// **Hashed, not sliced.** The order id is the only credential for
    /// `GET /escrow/orders/{id}`, which returns the handle, the escrow address,
    /// the funding txid and the amounts, and for the refund POST. Taking
    /// characters of the id straight would print a third of that bearer token
    /// into a note Venmo shows the payee, and - if the LP account's default
    /// audience is public - to anyone reading the LP's feed. Sixty-four bits
    /// would remain, so the id would not be enumerable over HTTP, but nothing
    /// about the tag requires leaking any of it.
    ///
    /// The hash keeps everything the derivation was chosen for. It is a pure
    /// function of the order, so it needs no new state, it cannot disagree with
    /// the order it belongs to, and it gives the same answer after a restart.
    /// It is domain-separated so this digest cannot be confused with any other
    /// the coordinator takes over an order id.
    pub fn payment_tag(&self) -> String {
        payment_tag_for(&self.order_id)
    }

    /// The tag the feed search should look for on this order, if any.
    ///
    /// Two callers, and they ask different questions.
    ///
    /// **Before the payment** there is no note yet, and this is the tag the
    /// rail is about to write. The order's own tag is the answer.
    ///
    /// **After the payment** the only tag that can be found is the one that was
    /// actually typed, and that was recorded when it was typed. Deriving it
    /// again here would be a guess about a past run. An order paid by a build
    /// that wrote the bare configured note, and attested after a deploy of a
    /// build that appends a tag, would be searched for under a tag its feed
    /// entry does not carry: `locate_payment` finds nothing, refuses, and the
    /// driver retries it on every sweep - with the dollars already gone and the
    /// one payment slot held. That order is by definition the one whose money
    /// has already left.
    ///
    /// So a paid order is matched on what its note actually says. A recorded
    /// note carrying this order's tag is matched on the tag. One that does not
    /// carry it - a bare `thanks` from before the deploy - and an order whose
    /// note was never recorded are matched on amount and receiver, exactly as
    /// they were when they were sent.
    pub fn tag_to_match(&self) -> Option<String> {
        let tag = self.payment_tag();
        match &self.payment {
            // Not paid yet: this is the tag the rail will write.
            None => Some(tag),
            // Paid, and the note that went out carries the tag.
            Some(payment)
                if payment
                    .note
                    .as_deref()
                    .is_some_and(|note| note_carries_tag(note, &tag)) =>
            {
                Some(tag)
            }
            // Paid with something else, or with a note nobody recorded.
            Some(_) => None,
        }
    }

    /// Moves to `Failed` with a reason the page shows.
    pub fn fail(&mut self, why: impl Into<String>) {
        self.stage = Stage::Failed;
        self.reason = Some(why.into());
        self.touch();
    }
}

/// Whether a note carries a tag, on the same terms the feed search uses.
///
/// Case-insensitive, because the note is read back out of somebody else's
/// system and nothing on this side guarantees the case it comes back in.
fn note_carries_tag(note: &str, tag: &str) -> bool {
    note.to_ascii_lowercase().contains(&tag.to_ascii_lowercase())
}

/// The tag for an order id: the first eight hex characters of a
/// domain-separated SHA-256 of it.
///
/// Free-standing so the note the rail typed can be checked against the order it
/// belongs to without an `Order` in hand.
pub fn payment_tag_for(order_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"zpay/payment-tag/v1");
    hasher.update(order_id.as_bytes());
    // 32 bits of a 256-bit digest. The tag has to fit a note a person reads,
    // and it only has to separate the payments in flight at one moment, which
    // the global slot holds at one.
    hex::encode(&hasher.finalize()[..4])
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

    /// A minimal order, enough for the pure functions over one.
    fn an_order(id: &str) -> Order {
        Order {
            order_id: id.into(),
            opened_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            stage: Stage::Locked,
            reason: None,
            handle: "jay-butera".into(),
            quote: Quote {
                quote_id: "q1".into(),
                amount_zat: 200_000,
                gross_cents: 100,
                net_cents: 90,
                usd_amount_6dec: 900_000,
                platform_fee_zat: 400,
                miner_fee_zat: 15_000,
                rate_usd_per_zec: 40.25,
                lines: vec![],
                expires_at: chrono::Utc::now(),
            },
            opened_height: 100,
            scanned_through: None,
            mempool_announced_txid: None,
            mempool_announced_vout: None,
            sighting_never_confirmed: false,
            network: "test".into(),
            consensus_branch_id: 0x37a5_165b,
            u_pub: [2u8; 33],
            l_pub: [3u8; 33],
            refund_height: 1252,
            address: "t2Address".into(),
            redeem_script: vec![1, 2, 3],
            script_pubkey: vec![0xa9, 0x14],
            payee_hash: [7u8; 32],
            treasury_script: vec![],
            lp_output_script: vec![0x76, 0xa9],
            funding: None,
            lock_confirmed_ms: None,
            announcement: None,
            pre_signature: None,
            pre_signed_at: None,
            payment: None,
            release_txid: None,
            refund_txid: None,
        }
    }

    fn paid_with(id: &str, note: Option<&str>) -> Order {
        let mut order = an_order(id);
        order.stage = Stage::Paid;
        order.payment = Some(Payment {
            sent_at: chrono::Utc::now(),
            cents: 90,
            note: note.map(Into::into),
        });
        order
    }

    /// The tag must not print any of the order id, which is the bearer
    /// credential for the order's own endpoint and for its refund.
    #[test]
    fn the_tag_leaks_no_part_of_the_order_id() {
        let id = "esc_1f2809bcb726cd630ff7932c";
        let tag = an_order(id).payment_tag();

        assert_eq!(tag.len(), 8, "a tag goes in a field a person reads: {tag:?}");
        assert!(
            tag.chars().all(|c| c.is_ascii_hexdigit()),
            "the note round-trips through Venmo, so the tag stays ASCII: {tag:?}"
        );
        // Not a slice of the id, from either end or anywhere in the middle.
        let body = id.trim_start_matches("esc_");
        assert!(
            !body.contains(&tag),
            "the tag is a substring of the order id, so the note publishes part \
             of the credential that reads and refunds this order: {tag} in {id}"
        );
    }

    /// It still has to be a function of the order alone: no new state, and the
    /// same answer after a restart.
    #[test]
    fn the_tag_is_the_same_every_time_and_different_per_order() {
        let one = an_order("esc_1f2809bcb726cd630ff7932c");
        let two = an_order("esc_0102030405060708090a0b0c");

        assert_eq!(one.payment_tag(), one.payment_tag());
        assert_ne!(
            one.payment_tag(),
            two.payment_tag(),
            "two orders sharing a tag discriminates nothing"
        );
    }

    /// An order paid before a deploy that appends tags, attested after it.
    ///
    /// The feed entry carries the bare configured note. Searching it for a tag
    /// finds nothing, and that refusal repeats on every sweep with the dollars
    /// gone and the payment slot held. What the note says is what decides.
    #[test]
    fn an_order_paid_with_a_bare_note_is_not_searched_for_under_a_tag() {
        let id = "esc_1f2809bcb726cd630ff7932c";
        assert_eq!(
            paid_with(id, Some("thanks")).tag_to_match(),
            None,
            "a payment whose note has no tag must be matched the way it was sent"
        );
        // Same for one paid before the note was recorded at all.
        assert_eq!(paid_with(id, None).tag_to_match(), None);
    }

    /// The ordinary case, both sides of the payment.
    #[test]
    fn an_order_is_matched_on_the_tag_it_was_actually_paid_with() {
        let id = "esc_1f2809bcb726cd630ff7932c";
        let tag = an_order(id).payment_tag();

        // Before the click: the tag the rail is about to write.
        assert_eq!(an_order(id).tag_to_match(), Some(tag.clone()));

        // After it, with the note the rail reports having typed.
        let paid = paid_with(id, Some(&format!("thanks {tag}")));
        assert_eq!(paid.tag_to_match(), Some(tag.clone()));

        // And a note that carries somebody else's tag is not this one's.
        let other = an_order("esc_0102030405060708090a0b0c").payment_tag();
        assert_eq!(paid_with(id, Some(&format!("thanks {other}"))).tag_to_match(), None);
    }

    /// The note comes back out of Venmo, which is free to change its case.
    #[test]
    fn a_recorded_note_matches_its_tag_whatever_case_it_comes_back_in() {
        let id = "esc_1f2809bcb726cd630ff7932c";
        let tag = an_order(id).payment_tag();
        let shouted = format!("THANKS {}", tag.to_ascii_uppercase());
        assert_eq!(paid_with(id, Some(&shouted)).tag_to_match(), Some(tag));
    }

    /// An order written before the note field existed still loads.
    #[test]
    fn a_payment_stored_without_a_note_still_deserialises() {
        let payment: Payment = serde_json::from_str(
            r#"{"sent_at":"2026-09-05T10:00:00Z","cents":90}"#,
        )
        .expect("an order written before the note field must still load");
        assert_eq!(payment.cents, 90);
        assert_eq!(payment.note, None);
    }

    #[test]
    fn only_the_stages_after_the_click_report_that_fiat_left() {
        assert!(Stage::Paid.fiat_may_have_left());
        assert!(Stage::Released.fiat_may_have_left());
        assert!(!Stage::Locked.fiat_may_have_left());
        assert!(!Stage::Unpaid.fiat_may_have_left());
    }
}
