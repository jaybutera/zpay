//! The user's side, spec 5.3 and 4.4.
//!
//! Two things matter here and nothing else really does. The user must store
//! `u_priv` and the redeem script *before* it broadcasts the funding
//! transaction, because losing them loses the refund path and the ZEC with it
//! (spec 8, "user loses u_priv"). And the user must verify the attestor's
//! announcement against a pinned identity before it encrypts a pre-signature
//! under it, because a pre-signature made under an attacker's outcome point is
//! a pre-signature the attacker can decrypt.

use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};

use crate::chain::{ChainClient, ChainError};
use crate::deadlines::EscrowPolicy;
use crate::dlc::{outcome_point, pre_sign, verify_pre_signature, DlcError};
use crate::tx::{build_release_split, EscrowTerms, ReleaseSplit, TxError};

/// What the user must have on disk before the funding transaction is
/// broadcast. Without every field the refund cannot be built.
///
/// `Debug` is written by hand rather than derived: criterion 14 requires that
/// nothing in any log match `u_priv`, and a derived `Debug` prints it in full
/// the first time this struct reaches a `tracing` field or a panic message.
#[derive(Clone, PartialEq, Eq)]
pub struct EscrowRecord {
    pub u_priv: [u8; 32],
    pub redeem_script: Vec<u8>,
    pub refund_height: u64,
    pub funding_txid: [u8; 32],
    pub vout: u32,
    pub amount_zat: u64,
    pub consensus_branch_id: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("the escrow record is incomplete: {0}")]
    IncompleteRecord(&'static str),
    #[error("the announced attestor key is not the pinned one")]
    UnpinnedAttestor,
    #[error(
        "the announcement is for event {announced}, but this escrow's outpoint is event \
         {expected}; a pre-signature encrypted under another event's outcome point can be \
         decrypted by whoever obtains that event's scalar"
    )]
    ForeignAnnouncement { announced: String, expected: String },
    #[error("the escrow record was not persisted before funding")]
    NotPersisted,
    #[error(
        "the stored redeem script's user slot is not this record's own key, so the escrow it \
         describes cannot be refunded"
    )]
    RecordKeyMismatch,
    #[error(
        "the LP's terms hash to {got}, but the terms this client accepted hash to {expected}"
    )]
    TermsNotAsAccepted { expected: String, got: String },
    #[error(
        "refund height {got} is outside the usable range; the maximum this client will accept \
         is {max}"
    )]
    RefundHeightOutOfRange { got: u64, max: u64 },
    #[error(
        "the LP's terms say {field} is {got}, but the user accepted {expected}; the fiat side \
         of an escrow is the user's to state, not the LP's"
    )]
    FiatTermsNotAsQuoted {
        field: &'static str,
        got: String,
        expected: String,
    },
    #[error("it is height {current}, the refund is not spendable until {refund_height}")]
    TooEarlyToRefund { current: u32, refund_height: u32 },
    #[error("dlc error: {0}")]
    Dlc(#[from] DlcError),
    #[error("transaction error: {0}")]
    Tx(String),
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("treasury error: {0}")]
    Treasury(String),
}

impl From<crate::treasury::TreasuryError> for ClientError {
    fn from(e: crate::treasury::TreasuryError) -> Self {
        ClientError::Treasury(e.to_string())
    }
}

impl From<TxError> for ClientError {
    fn from(e: TxError) -> Self {
        ClientError::Tx(e.to_string())
    }
}

impl core::fmt::Debug for EscrowRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EscrowRecord")
            // Redacted, not omitted: a reader can see the key is present.
            .field("u_priv", &"[redacted]")
            .field("redeem_script", &hex::encode(&self.redeem_script))
            .field("refund_height", &self.refund_height)
            .field("funding_txid", &hex::encode(self.funding_txid))
            .field("vout", &self.vout)
            .field("amount_zat", &self.amount_zat)
            .field("consensus_branch_id", &self.consensus_branch_id)
            .finish()
    }
}

impl EscrowRecord {
    /// Every field the refund path needs. A record that cannot build a refund
    /// must not be treated as saved.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.u_priv == [0u8; 32] {
            return Err(ClientError::IncompleteRecord("u_priv is unset"));
        }
        if self.redeem_script.is_empty() {
            return Err(ClientError::IncompleteRecord("redeem_script is empty"));
        }
        if self.refund_height == 0 || self.refund_height > MAX_REFUND_HEIGHT {
            return Err(ClientError::RefundHeightOutOfRange {
                got: self.refund_height,
                max: MAX_REFUND_HEIGHT,
            });
        }
        if self.amount_zat == 0 {
            return Err(ClientError::IncompleteRecord("amount_zat is zero"));
        }
        if self.consensus_branch_id == 0 {
            return Err(ClientError::IncompleteRecord("consensus_branch_id is unset"));
        }

        // The stored script's user slot must be the key this record carries.
        // `prepare_escrow` derives it so it cannot be otherwise, but a record
        // read back from disk has been outside this process, and a record whose
        // script does not answer to its own key is a record that cannot refund
        // (round 3 finding 1).
        let secp = secp256k1_zkp::Secp256k1::signing_only();
        let u_priv = SecretKey::from_slice(&self.u_priv)
            .map_err(|_| ClientError::IncompleteRecord("u_priv is not a valid key"))?;
        let expected = u_priv.public_key(&secp).serialize();
        if crate::client::u_pub_in_script(&self.redeem_script)? != expected {
            return Err(ClientError::RecordKeyMismatch);
        }
        Ok(())
    }
}

/// Somewhere durable to keep escrow records.
pub trait RecordStore {
    fn save(&mut self, record: &EscrowRecord) -> Result<(), ClientError>;
    fn load(&self, funding_txid: &[u8; 32]) -> Option<EscrowRecord>;
}

/// The largest refund height the client will accept.
///
/// Round 3 finding 2: `refund_height` was LP-chosen and unbounded, so terms
/// carrying `T = 2^62` locked the escrow for centuries, and any `T` above
/// `u32::MAX` produced a refund the client could never even build. Mainnet is
/// near 3.47M and gains roughly 420k blocks a year, so this is centuries of
/// headroom and still far below the CLTV threshold at which a locktime is read
/// as a Unix timestamp rather than a height.
pub const MAX_REFUND_HEIGHT: u64 = 500_000_000;

/// What the user accepted before it agreed to fund anything.
///
/// Round 2 finding 1 and round 3 findings 1 and 2: the LP returns `terms` in
/// step 1c of spec 5.3, and every field of them the user does not check is a
/// field the LP has written. Rather than accumulate one comparison per round,
/// the client now *derives* the whole canonical terms from this quote plus the
/// escrow's own chain facts - see [`CanonicalTerms`] construction in
/// [`prepare_escrow`]. Anything the LP sends is compared against what the
/// client built, so a field nobody thought to check cannot silently be the
/// LP's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedQuote {
    /// The dollars the user expects to receive, 6 decimals.
    pub usd_amount_6dec: u64,
    /// The user's own Venmo, as the zk-p2p curator's `hashedOnchainId`. This is
    /// the field that matters most: it is the user's identity, and the user is
    /// the only party that knows it.
    pub payee_hash: [u8; 32],
    /// The rate the escrow is priced at. For a ZEC escrow this must be the
    /// identity rate; see `payment_details::IDENTITY_RATE_18DEC`.
    pub rate_18dec: u128,
    /// The absolute height at which the user may reclaim the escrow.
    ///
    /// The user agrees to a timeout, not just a price. Without it here the LP
    /// picks how long the money is locked.
    pub refund_height: u64,
    /// The LP's key in the 2-of-2. The user has no way to verify this key is
    /// the LP's rather than a second key it also holds - that is inherent to
    /// the two-signer design - but it must be the key the user was quoted, so
    /// that the escrow address the user funds is the one both parties agreed.
    pub l_pub: [u8; 33],
    /// The escrow amount in zatoshis.
    pub amount_zat: u64,
    /// The platform cut, in zatoshis, paid as a third output on the release.
    ///
    /// Private, and it is worth saying why rather than leaving it to taste. The
    /// whole security argument for the fee is that the user *derives* it and
    /// never accepts it: [`AcceptedQuote::new`] computes it from `amount_zat`
    /// at [`crate::treasury::PLATFORM_FEE_BPS`], and pairs it with the pinned
    /// treasury script. A public field is a field a caller holding an LP's
    /// answer can assign, which is exactly the substitution the pin exists to
    /// prevent. Read it through [`AcceptedQuote::platform_fee_zat`].
    platform_fee_zat: u64,
    /// Where that cut is paid. Private for the same reason, and empty exactly
    /// when `platform_fee_zat` is zero.
    treasury_script: Vec<u8>,
}

/// Why a quote was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QuoteError {
    #[error("the escrow amount is zero")]
    ZeroAmount,
    #[error("the escrow holds {amount_zat} zat, below the {minimum} zat floor")]
    BelowMinimum { amount_zat: u64, minimum: u64 },
    #[error("the quote pays nothing")]
    ZeroPayout,
    #[error(
        "rate {got} is not the identity rate {expected}; for a ZEC escrow the enclave's \
         releaseAmount only means dollars at the identity rate (spec 16.3)"
    )]
    NonIdentityRate { got: u128, expected: u128 },
    #[error("refund height {got} is outside the usable range 1..={max}")]
    RefundHeightOutOfRange { got: u64, max: u64 },
    #[error("the LP public key is not a valid compressed secp256k1 point")]
    BadLpKey,
    #[error("the treasury is not usable: {0}")]
    Treasury(String),
    #[error(
        "a platform fee of {fee_zat} zat against a {amount_zat} zat escrow leaves the LP \
         nothing; the fee is a share of the trade, not the trade"
    )]
    FeeExceedsEscrow { amount_zat: u64, fee_zat: u64 },
}

/// The minimum escrow, spec section 3: "0.001 ZEC above fees".
///
/// R5-8: this was 100000 flat, which is 0.001 ZEC and not 0.001 ZEC *above
/// fees*. The larger of the two fees is the shielded refund at 20000 zat (spec
/// 12.3), so the floor is 0.001 ZEC plus that. Nothing broke at the old value -
/// an escrow there still released 85000 - but the constant now says what the
/// spec says.
pub const MINIMUM_ESCROW_ZAT: u64 = 100_000 + 20_000;

impl AcceptedQuote {
    /// Builds a quote, refusing anything the protocol cannot honour.
    ///
    /// Round 4 finding 4: a client builds these, and every field is one the
    /// user is committing to. A zero amount, a rate that is not the identity
    /// rate, or a timeout the client can never reach are all refusable here
    /// rather than several layers down, where the error would name a
    /// consequence instead of the cause.
    pub fn new(
        usd_amount_6dec: u64,
        payee_hash: [u8; 32],
        rate_18dec: u128,
        refund_height: u64,
        l_pub: [u8; 33],
        amount_zat: u64,
        network: crate::address::AddrNetwork,
    ) -> Result<Self, QuoteError> {
        let mut q = Self::checked(
            usd_amount_6dec,
            payee_hash,
            rate_18dec,
            refund_height,
            l_pub,
            amount_zat,
        )?;

        // The platform fee is derived here and nowhere else. This is the one
        // policy site: the rate is `treasury::PLATFORM_FEE_BPS`, the address is
        // the constant compiled into this binary for `network`, and neither is
        // a parameter - a parameter is something a caller relaying an LP's
        // answer could fill in, and a treasury address the LP supplies is one
        // it can point at itself.
        let fee = crate::treasury::default_platform_fee_zat(amount_zat);
        if fee == 0 {
            // Below the dust threshold there is no treasury output and so no
            // script to name. Leaving both fields cleared rather than filling
            // the script anyway keeps `canonical_json` from committing to an
            // address the transaction does not pay.
            return Ok(q);
        }

        // The fee comes out of the escrow before the LP's leg, and an escrow
        // that pays the platform everything pays the LP nothing.
        // `MINIMUM_ESCROW_ZAT` covers the miner fee; this catches a rate large
        // enough to swallow what is left.
        if fee >= amount_zat {
            return Err(QuoteError::FeeExceedsEscrow {
                amount_zat,
                fee_zat: fee,
            });
        }

        q.platform_fee_zat = fee;
        q.treasury_script = crate::treasury::treasury_script(network)
            .map_err(|e| QuoteError::Treasury(e.to_string()))?;
        Ok(q)
    }

    /// The same quote with no platform fee.
    ///
    /// Named rather than implied, and for one reason: a build that silently
    /// stops charging would show up as revenue going quietly to zero rather
    /// than as an error, so the fee-bearing constructor is the default and a
    /// caller that wants the two-output shape says so. Its uses are tests, and
    /// reproducing an escrow written before a treasury was pinned.
    pub fn without_platform_fee(
        usd_amount_6dec: u64,
        payee_hash: [u8; 32],
        rate_18dec: u128,
        refund_height: u64,
        l_pub: [u8; 33],
        amount_zat: u64,
    ) -> Result<Self, QuoteError> {
        Self::checked(
            usd_amount_6dec,
            payee_hash,
            rate_18dec,
            refund_height,
            l_pub,
            amount_zat,
        )
    }

    /// Everything both constructors refuse, and a quote carrying no fee yet.
    ///
    /// Private, so the fee-free shape is never something a caller reaches by
    /// accident: the two public constructors are the only ways in, and one of
    /// them says "without" in its name.
    fn checked(
        usd_amount_6dec: u64,
        payee_hash: [u8; 32],
        rate_18dec: u128,
        refund_height: u64,
        l_pub: [u8; 33],
        amount_zat: u64,
    ) -> Result<Self, QuoteError> {
        if amount_zat == 0 {
            return Err(QuoteError::ZeroAmount);
        }
        if amount_zat < MINIMUM_ESCROW_ZAT {
            return Err(QuoteError::BelowMinimum {
                amount_zat,
                minimum: MINIMUM_ESCROW_ZAT,
            });
        }
        if usd_amount_6dec == 0 {
            return Err(QuoteError::ZeroPayout);
        }
        if rate_18dec != crate::payment_details::IDENTITY_RATE_18DEC {
            return Err(QuoteError::NonIdentityRate {
                got: rate_18dec,
                expected: crate::payment_details::IDENTITY_RATE_18DEC,
            });
        }
        if refund_height == 0 || refund_height > MAX_REFUND_HEIGHT {
            return Err(QuoteError::RefundHeightOutOfRange {
                got: refund_height,
                max: MAX_REFUND_HEIGHT,
            });
        }
        // A key that is not a point makes an unspendable escrow, and the user
        // would discover it at `T` and not before.
        PublicKey::from_slice(&l_pub).map_err(|_| QuoteError::BadLpKey)?;

        Ok(Self {
            usd_amount_6dec,
            payee_hash,
            rate_18dec,
            refund_height,
            l_pub,
            amount_zat,
            platform_fee_zat: 0,
            treasury_script: Vec::new(),
        })
    }

    /// The platform cut this quote commits to, in zatoshis.
    pub fn platform_fee_zat(&self) -> u64 {
        self.platform_fee_zat
    }

    /// The treasury scriptPubKey this quote commits to. Empty exactly when
    /// [`AcceptedQuote::platform_fee_zat`] is zero.
    pub fn treasury_script(&self) -> &[u8] {
        &self.treasury_script
    }

    /// A quote at the identity rate, which is the only rate a ZEC escrow uses.
    pub fn at_identity_rate(
        usd_amount_6dec: u64,
        payee_hash: [u8; 32],
        refund_height: u64,
        l_pub: [u8; 33],
        amount_zat: u64,
        network: crate::address::AddrNetwork,
    ) -> Result<Self, QuoteError> {
        Self::new(
            usd_amount_6dec,
            payee_hash,
            crate::payment_details::IDENTITY_RATE_18DEC,
            refund_height,
            l_pub,
            amount_zat,
            network,
        )
    }

    /// A quote at the identity rate with no platform fee. See
    /// [`AcceptedQuote::without_platform_fee`].
    pub fn at_identity_rate_without_fee(
        usd_amount_6dec: u64,
        payee_hash: [u8; 32],
        refund_height: u64,
        l_pub: [u8; 33],
        amount_zat: u64,
    ) -> Result<Self, QuoteError> {
        Self::without_platform_fee(
            usd_amount_6dec,
            payee_hash,
            crate::payment_details::IDENTITY_RATE_18DEC,
            refund_height,
            l_pub,
            amount_zat,
        )
    }

    /// The release split this quote implies, given the miner fee.
    ///
    /// One place computes it, so the digest the user signs and the bytes the LP
    /// broadcasts cannot be assembled from different opinions about where the
    /// treasury output goes or whether there is one.
    pub fn release_split(&self, lp_output_script: &[u8], miner_fee_zat: u64) -> ReleaseSplit {
        ReleaseSplit {
            payout_script: lp_output_script.to_vec(),
            miner_fee_zat,
            platform_fee_zat: self.platform_fee_zat,
            treasury_script: self.treasury_script.clone(),
        }
    }
}

/// The attestor announcement the user receives (spec 5.1).
#[derive(Debug, Clone)]
pub struct Announcement {
    pub p: PublicKey,
    pub r: PublicKey,
    pub event_id: [u8; 32],
}

/// Checks the announcement against the attestor identity the user has pinned,
/// and against the escrow's own outpoint.
///
/// The event id check is not a formality. The LP relays the announcement, so it
/// can relay a *genuine* one issued for an escrow the LP itself controls. If
/// the user encrypts its pre-signature under that event's outcome point, then
/// the moment the LP pays itself for its own escrow the attestor hands over a
/// scalar that decrypts the victim's signature too. The user must therefore
/// recompute `event_id` from the outpoint it is about to fund, and refuse
/// anything else.
///
/// In Phase 1 the attestor pin is a configured key. In Phase 7 it is whatever
/// key the Nitro attestation document carries, which is the step that turns
/// "trust the operator" into "trust the measured code".
pub fn verify_announcement(
    announcement: &Announcement,
    pinned_attestor_key: &PublicKey,
    funding_txid: &[u8; 32],
    vout: u32,
) -> Result<(), ClientError> {
    if &announcement.p != pinned_attestor_key {
        return Err(ClientError::UnpinnedAttestor);
    }
    let expected = crate::dlc::event_id(funding_txid, vout);
    if announcement.event_id != expected {
        return Err(ClientError::ForeignAnnouncement {
            announced: hex::encode(announcement.event_id),
            expected: hex::encode(expected),
        });
    }
    Ok(())
}

/// Builds the pre-signature, but only after the record is on disk.
///
/// The argument list is long because every one of these is a thing the two
/// parties must agree on exactly; bundling them into a struct would hide that
/// the LP's output script and the fee are as much a part of what the user
/// signs as the escrow terms are.
#[allow(clippy::too_many_arguments)]
///
/// The ordering is the point. `store.save` happens before anything that could
/// lead to a funded escrow, so a crash between here and broadcast leaves the
/// user able to refund.
pub fn prepare_escrow(
    secp: &Secp256k1<secp256k1_zkp::All>,
    store: &mut impl RecordStore,
    funding_txid: [u8; 32],
    vout: u32,
    consensus_branch_id: u32,
    quote: &AcceptedQuote,
    lp_terms: &crate::terms::CanonicalTerms,
    u_priv: &SecretKey,
    announcement: &Announcement,
    pinned_attestor_key: &PublicKey,
    lp_output_script: &[u8],
    fee_zat: u64,
) -> Result<PreparedEscrow, ClientError> {
    // 1. The user's key is derived, never accepted.
    //
    //    Round 3 finding 1: nothing compared `terms.u_pub` to `u_priv`. An LP
    //    that returned a second key of its own in that slot got the user to
    //    fund a 2-of-2 the LP held both halves of - spendable at any height
    //    with no attestor and no payment - while the user's refund at `T`
    //    failed, because the script wanted a key the user does not have. That
    //    is the "timeout refund needs nobody" invariant of spec section 1,
    //    gone. Deriving it means the slot cannot be anything else.
    let u_pub = u_priv.public_key(secp).serialize();

    // 2. The timeout is the user's to accept, and must be usable.
    if quote.refund_height == 0 || quote.refund_height > MAX_REFUND_HEIGHT {
        return Err(ClientError::RefundHeightOutOfRange {
            got: quote.refund_height,
            max: MAX_REFUND_HEIGHT,
        });
    }

    // 3. Build the terms the user is willing to fund, from the quote it
    //    accepted and the chain facts it observed. Nothing here originates with
    //    the LP except `l_pub`, which is in the quote because the user agreed
    //    to it.
    let canonical = crate::terms::CanonicalTerms {
        funding_txid,
        vout,
        amount_zat: quote.amount_zat,
        u_pub,
        l_pub: quote.l_pub,
        refund_height: quote.refund_height,
        usd_amount_6dec: quote.usd_amount_6dec,
        rate_18dec: quote.rate_18dec,
        payee_hash: quote.payee_hash,
        lock_confirmed_ms: lp_terms.lock_confirmed_ms,
        // Both derived by the quote from a pinned constant and a published
        // rate, so an LP that names a different treasury or a different cut
        // hashes differently and is caught by the comparison below - before the
        // user has funded anything.
        platform_fee_zat: quote.platform_fee_zat(),
        treasury_script: quote.treasury_script().to_vec(),
    };

    // 4. Whatever the LP sent must be exactly that. One comparison over the
    //    whole structure, so a field added later is covered without anyone
    //    remembering to check it.
    if lp_terms != &canonical {
        return Err(ClientError::TermsNotAsAccepted {
            expected: hex::encode(canonical.terms_hash()),
            got: hex::encode(lp_terms.terms_hash()),
        });
    }

    let terms = EscrowTerms {
        funding_txid,
        vout,
        amount_zat: quote.amount_zat,
        u_pub,
        l_pub: quote.l_pub,
        refund_height: quote.refund_height,
        consensus_branch_id,
    };

    // 5. The announcement must be for this outpoint and from the pinned
    //    attestor (round 1 finding 2).
    verify_announcement(announcement, pinned_attestor_key, &funding_txid, vout)?;

    // 6. Persist before anything cryptographic exists, so a crash between here
    //    and broadcast still leaves a refundable escrow (spec 5.3).
    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().map_err(TxError::from)?,
        refund_height: quote.refund_height,
        funding_txid,
        vout,
        amount_zat: quote.amount_zat,
        consensus_branch_id,
    };
    record.validate()?;
    store.save(&record)?;

    // 7. Only now is a pre-signature produced.
    let y = outcome_point(
        secp,
        &announcement.r,
        &announcement.p,
        &announcement.event_id,
        &canonical.terms_hash(),
    )?;
    // The digest is over the *whole* output set, treasury output included. That
    // is what makes the fee cost no extra trust: SIGHASH_ALL commits to every
    // output's value, script and position, so the pre-signature the LP receives
    // decrypts to a signature over this transaction and no other. An LP that
    // wants the fee for itself would need a different signature from the user,
    // and it has no way to produce one.
    let split = quote.release_split(lp_output_script, fee_zat);
    let digest = build_release_split(&terms, &split)?.sighash()?;
    let pre_sig = pre_sign(secp, &digest, u_priv, &y);

    // The user verifies its own pre-signature before handing it over, so a
    // failure surfaces here rather than as an LP that will not pay.
    verify_pre_signature(secp, &pre_sig, &digest, &u_priv.public_key(secp), &y)?;

    Ok(PreparedEscrow {
        pre_signature: pre_sig,
        outcome_point: y,
        terms,
        canonical,
        split,
    })
}

/// What the client holds after a successful handshake.
///
/// The terms are returned rather than taken, so a caller cannot act on a
/// different set from the ones the pre-signature commits to.
pub struct PreparedEscrow {
    pub pre_signature: secp256k1_zkp::EcdsaAdaptorSignature,
    pub outcome_point: PublicKey,
    pub terms: EscrowTerms,
    pub canonical: crate::terms::CanonicalTerms,
    /// The exact output set the pre-signature was made over.
    ///
    /// Returned rather than left for the caller to rebuild, because a caller
    /// that rebuilt it and got one field wrong would produce a release the
    /// pre-signature does not authorise, and would find out only after the LP
    /// had paid the fiat.
    pub split: ReleaseSplit,
}

impl core::fmt::Debug for PreparedEscrow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedEscrow")
            .field("terms_hash", &hex::encode(self.canonical.terms_hash()))
            .field("refund_height", &self.terms.refund_height)
            .field("platform_fee_zat", &self.split.platform_fee_zat)
            .finish()
    }
}

/// The guard on broadcasting the funding transaction.
///
/// Spec 5.3: the client stores `(u_priv, redeem_script, T, funding_txid)`
/// durably before broadcasting. This is that rule as code.
pub fn may_broadcast_funding(
    store: &impl RecordStore,
    funding_txid: &[u8; 32],
) -> Result<(), ClientError> {
    match store.load(funding_txid) {
        Some(record) => record.validate(),
        None => Err(ClientError::NotPersisted),
    }
}

/// Whether the refund can be broadcast yet, and the transaction if so.
///
/// The height check is not decoration: a refund broadcast before `T` is
/// rejected, and repeated attempts are how a client leaks its intent to the
/// mempool for no gain.
pub fn refund_when_due(
    chain: &impl ChainClient,
    record: &EscrowRecord,
    policy: &EscrowPolicy,
    user_output_script: &[u8],
    fee_zat: u64,
) -> Result<crate::tx::UnsignedEscrowTx, ClientError> {
    record.validate()?;
    let current = chain.height()?;
    // The script's own `T`, not a policy-derived one. CLTV honours the number
    // in the redeem script and nothing else, so deriving the gate from a policy
    // and a lock height can only disagree with the chain.
    let refund_height = u32::try_from(record.refund_height)
        .map_err(|_| ClientError::IncompleteRecord("refund_height is not a block height"))?;

    if !policy.may_refund_at(refund_height, current) {
        return Err(ClientError::TooEarlyToRefund {
            current,
            refund_height,
        });
    }

    let terms = EscrowTerms {
        funding_txid: record.funding_txid,
        vout: record.vout,
        amount_zat: record.amount_zat,
        // The redeem script is what was stored; the keys are recovered from it
        // rather than re-derived, so a client that lost its LP contact can
        // still refund.
        u_pub: extract_u_pub(&record.redeem_script)?,
        l_pub: extract_l_pub(&record.redeem_script)?,
        refund_height: record.refund_height,
        consensus_branch_id: record.consensus_branch_id,
    };

    Ok(crate::tx::build_refund(&terms, user_output_script, fee_zat)?)
}

/// `u_pub` as it appears in a redeem script.
pub(crate) fn u_pub_in_script(redeem_script: &[u8]) -> Result<[u8; 33], ClientError> {
    extract_u_pub(redeem_script)
}

/// `u_pub` sits at a fixed offset in the redeem script of spec 4.1: after
/// OP_IF and OP_2 comes the 33-byte push.
fn extract_u_pub(redeem_script: &[u8]) -> Result<[u8; 33], ClientError> {
    if redeem_script.len() < 36 || redeem_script[2] != 33 {
        return Err(ClientError::IncompleteRecord("redeem_script is malformed"));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&redeem_script[3..36]);
    Ok(out)
}

/// `l_pub` follows immediately after `u_pub`.
fn extract_l_pub(redeem_script: &[u8]) -> Result<[u8; 33], ClientError> {
    if redeem_script.len() < 70 || redeem_script[36] != 33 {
        return Err(ClientError::IncompleteRecord("redeem_script is malformed"));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&redeem_script[37..70]);
    Ok(out)
}

/// An in-memory record store for tests. A real client writes to disk and
/// fsyncs before returning.
///
/// `Debug` reports how many records are held and nothing about them, so that
/// logging the store cannot print a key even indirectly.
#[derive(Default)]
pub struct MemoryRecordStore {
    records: std::collections::HashMap<[u8; 32], EscrowRecord>,
    /// Set to make `save` fail, so the ordering guarantee can be tested.
    pub fail_writes: bool,
}

impl core::fmt::Debug for MemoryRecordStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryRecordStore")
            .field("records", &self.records.len())
            .field("fail_writes", &self.fail_writes)
            .finish()
    }
}

impl MemoryRecordStore {
    /// Makes every `save` fail, so a caller's ordering guarantee can be tested.
    pub fn failing() -> Self {
        Self {
            fail_writes: true,
            ..Default::default()
        }
    }
}

impl RecordStore for MemoryRecordStore {
    fn save(&mut self, record: &EscrowRecord) -> Result<(), ClientError> {
        if self.fail_writes {
            return Err(ClientError::NotPersisted);
        }
        self.records.insert(record.funding_txid, record.clone());
        Ok(())
    }

    fn load(&self, funding_txid: &[u8; 32]) -> Option<EscrowRecord> {
        self.records.get(funding_txid).cloned()
    }
}
