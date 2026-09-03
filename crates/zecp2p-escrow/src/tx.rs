//! Deterministic construction of the release and refund transactions, and the
//! ZIP 244 digest both parties sign.
//!
//! This module carries the requirement from spec 4.6 that the user client and
//! the LP produce the *identical* 32-byte digest. They never exchange the
//! transaction; each builds it from the agreed terms. A disagreement is not a
//! visible error, it is a release the LP cannot broadcast and money it has
//! already paid out, so everything here is derived from `EscrowTerms` and
//! nothing is passed in loose.

use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zcash_script::script::Code;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{Bundle, OutPoint, TxOut};
use zcash_transparent::sighash::{
    SignableInput as TransparentSignableInput, SighashType, TransparentAuthorizingContext,
};

use crate::script::{p2sh_script_pubkey, redeem_script, CompressedPubkey, ScriptError};

/// `nSequence` for the release input. The release is not timelocked, so the
/// input is final (spec 4.3).
pub const RELEASE_SEQUENCE: u32 = 0xffff_ffff;

/// `nSequence` for the refund input. CLTV is disabled outright if every input
/// is final, so the refund must not be (spec 4.4).
pub const REFUND_SEQUENCE: u32 = 0xffff_fffe;

/// SIGHASH_ALL. The only hash type the escrow uses.
pub const SIGHASH_ALL: u8 = 0x01;

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("script error: {0}")]
    Script(#[from] ScriptError),
    #[error("the escrow holds {amount} zat, which does not cover the {fee} zat fee")]
    BelowFee { amount: u64, fee: u64 },
    #[error("the output script is empty")]
    EmptyOutputScript,
    #[error("a transaction with no outputs pays nobody")]
    NoOutputs,
    #[error(
        "output {index} pays {value} zat, below the {threshold} zat dust threshold; a node \
         will not relay the transaction, so the release would be unbroadcastable rather \
         than merely small"
    )]
    DustOutput {
        index: usize,
        value: u64,
        threshold: u64,
    },
    #[error(
        "the platform fee is {fee} zat and the treasury script is {script_len} bytes; both \
         must be set or both empty, since a fee with no destination cannot be paid and a \
         destination with no fee is an output the release does not carry"
    )]
    InconsistentFee { fee: u64, script_len: usize },
    #[error(
        "the outputs total {outputs} zat, which with the {fee} zat miner fee exceeds the \
         {amount} zat the escrow holds"
    )]
    OutputsExceedEscrow {
        amount: u64,
        fee: u64,
        outputs: u64,
    },
    #[error("the transparent input index is out of range")]
    BadInputIndex,
    #[error("could not serialize the transaction: {0}")]
    Serialize(String),
    #[error(
        "consensus branch id {0:#x} is not one this build knows; it is read from the node, so \
         an unknown value means a network upgrade this binary predates"
    )]
    UnknownBranchId(u32),
}

/// One output of an escrow spend: where it pays and how much.
///
/// A pair rather than two parallel slices, because the pairing is what the
/// sighash commits to. Two parties that agreed on the same scripts and the same
/// values but zipped them differently produce different digests, and the way
/// that failure shows up is a release the LP cannot broadcast after it has
/// already paid the fiat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutSpec {
    pub script: Vec<u8>,
    pub value_zat: u64,
}

impl TxOutSpec {
    pub fn new(script: impl Into<Vec<u8>>, value_zat: u64) -> Self {
        Self {
            script: script.into(),
            value_zat,
        }
    }
}

/// How a release divides the escrow: the miner takes `fee_zat`, the treasury
/// takes `platform_fee_zat`, and the counterparty output takes the rest.
///
/// The platform fee is a *third output* on the release, not a skim taken
/// somewhere off-chain. Its enforcement is the ZIP 244 SIGHASH_ALL digest: the
/// user's adaptor pre-signature is made over a transaction whose entire output
/// set is committed, so an LP holding that pre-signature can broadcast the
/// transaction that pays the treasury or it can broadcast nothing. There is no
/// third option in which it keeps the fee, because no signature it can produce
/// authorises one.
///
/// A `platform_fee_zat` of zero means a two-output release and is the shape
/// every escrow written before this field existed has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSplit {
    /// Where the counterparty leg of the trade is paid.
    pub payout_script: Vec<u8>,
    /// The ZIP 317 miner fee, subtracted from the escrow before anyone is paid.
    pub miner_fee_zat: u64,
    /// The platform cut, in zatoshis. Zero omits the treasury output entirely.
    pub platform_fee_zat: u64,
    /// The treasury scriptPubKey. Ignored when `platform_fee_zat` is zero.
    pub treasury_script: Vec<u8>,
}

impl ReleaseSplit {
    /// A release with no platform fee: the shape the escrow had before the
    /// treasury output existed.
    pub fn without_fee(payout_script: impl Into<Vec<u8>>, miner_fee_zat: u64) -> Self {
        Self {
            payout_script: payout_script.into(),
            miner_fee_zat,
            platform_fee_zat: 0,
            treasury_script: Vec::new(),
        }
    }

    /// The ordered output set for an escrow of `amount_zat`.
    ///
    /// **The order is part of the signature.** It is fixed here, once, as
    /// `[payout, treasury]` with the treasury always last, and nothing sorts
    /// it: not by value, not by script, and not by which party assembled it.
    /// Two implementations that ordered these differently would compute
    /// different digests from identical terms, and this module exists because
    /// that failure costs the LP money it has already paid out.
    ///
    /// The treasury output is omitted when the fee is zero, rather than
    /// written as a zero-value output, because a zero-value output is dust and
    /// makes the whole release non-standard.
    pub fn outputs(&self, amount_zat: u64) -> Result<Vec<TxOutSpec>, TxError> {
        // Both or neither. A fee with no destination cannot be paid, and a
        // destination with no fee is an output the release does not carry;
        // either half alone means the two parties are about to build different
        // transactions from what they believe are the same terms. Refuse here,
        // where the message names the cause, rather than at the sighash, where
        // the symptom is a release the LP cannot broadcast.
        if (self.platform_fee_zat == 0) != self.treasury_script.is_empty() {
            return Err(TxError::InconsistentFee {
                fee: self.platform_fee_zat,
                script_len: self.treasury_script.len(),
            });
        }

        let committed = self
            .miner_fee_zat
            .checked_add(self.platform_fee_zat)
            .ok_or(TxError::OutputsExceedEscrow {
                amount: amount_zat,
                fee: self.miner_fee_zat,
                outputs: self.platform_fee_zat,
            })?;
        let payout = amount_zat
            .checked_sub(committed)
            .ok_or(TxError::BelowFee {
                amount: amount_zat,
                fee: committed,
            })?;
        if payout == 0 {
            return Err(TxError::OutputsExceedEscrow {
                amount: amount_zat,
                fee: self.miner_fee_zat,
                outputs: self.platform_fee_zat,
            });
        }

        let mut outs = vec![TxOutSpec::new(self.payout_script.clone(), payout)];
        if self.platform_fee_zat > 0 {
            outs.push(TxOutSpec::new(
                self.treasury_script.clone(),
                self.platform_fee_zat,
            ));
        }

        // Every output must clear dust and name a script. The caller usually
        // gets this right - `treasury::platform_fee_zat` drops a sub-dust fee to
        // zero, and the payout leg is large by construction - but "usually" is
        // not the standard for a transaction nobody can re-sign. A dust output
        // anywhere makes the whole release non-standard, so a release that is
        // short by one zatoshi does not confirm at all.
        for (index, o) in outs.iter().enumerate() {
            if o.script.is_empty() {
                return Err(TxError::EmptyOutputScript);
            }
            if o.value_zat < crate::treasury::DUST_THRESHOLD_ZAT {
                return Err(TxError::DustOutput {
                    index,
                    value: o.value_zat,
                    threshold: crate::treasury::DUST_THRESHOLD_ZAT,
                });
            }
        }
        Ok(outs)
    }
}

/// Everything both parties need to rebuild the same transaction.
///
/// This is the subset of spec 5.2's canonical terms that determines the bytes
/// of the release; the rest of the terms bind the payment, not the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowTerms {
    pub funding_txid: [u8; 32],
    pub vout: u32,
    pub amount_zat: u64,
    pub u_pub: CompressedPubkey,
    pub l_pub: CompressedPubkey,
    pub refund_height: u64,
    /// The consensus branch id in force, read from the node and never
    /// hard-coded (spec 4.3).
    pub consensus_branch_id: u32,
}

impl EscrowTerms {
    pub fn redeem_script(&self) -> Result<Vec<u8>, ScriptError> {
        redeem_script(&self.u_pub, &self.l_pub, self.refund_height)
    }

    pub fn script_pubkey(&self) -> Result<Vec<u8>, ScriptError> {
        Ok(p2sh_script_pubkey(&self.redeem_script()?))
    }

    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.funding_txid, self.vout)
    }
}

/// Authorization carrying only the effects needed for a sighash: the value and
/// scriptPubKey of each input.
///
/// `zcash_transparent::bundle::EffectsOnly` holds exactly this, but its field
/// is crate-private, so the escrow supplies its own.
#[derive(Debug)]
pub struct EscrowEffects {
    inputs: Vec<TxOut>,
}

impl EscrowEffects {
    /// Builds the effects for a set of spent outputs. Used by the regtest
    /// funding helper, which signs a P2PKH input rather than the escrow.
    pub fn for_inputs(inputs: Vec<TxOut>) -> Self {
        Self { inputs }
    }
}

impl zcash_transparent::bundle::Authorization for EscrowEffects {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for EscrowEffects {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|i| i.value()).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs.iter().map(|i| i.script_pubkey().clone()).collect()
    }
}

/// The authorization marker for an escrow transaction that has effects but no
/// signatures. Shielded bundles are always absent here: the release and refund
/// spend a transparent input, and a shielded *output* is added by the client's
/// own wallet build, not by this digest path.
#[derive(Debug)]
pub struct EscrowUnauthorized;

impl Authorization for EscrowUnauthorized {
    type TransparentAuth = EscrowEffects;
    type SaplingAuth = ::sapling::bundle::Authorized;
    type OrchardAuth = ::orchard::bundle::Authorized;
}

/// A transaction the escrow has built but not yet signed, together with
/// everything needed to compute its sighash.
///
/// Every field is public chain data - scripts, an outpoint, an amount - so
/// `Debug` here cannot print a key.
#[derive(Debug)]
pub struct UnsignedEscrowTx {
    data: TransactionData<EscrowUnauthorized>,
    redeem_script: Vec<u8>,
    script_pubkey: Vec<u8>,
    amount_zat: u64,
}

impl UnsignedEscrowTx {
    /// The ZIP 244 digest for the escrow's single transparent input.
    ///
    /// BLAKE2b-256 personalized `ZcashSigHash` plus the consensus branch id,
    /// committing to the prevout, value, spent scriptPubKey and nSequence
    /// (spec 4.6).
    pub fn sighash(&self) -> Result<[u8; 32], TxError> {
        let bundle = self
            .data
            .transparent_bundle()
            .expect("an escrow transaction always has a transparent input");
        let script_code = Script(Code(self.redeem_script.clone()));
        let script_pubkey = Script(Code(self.script_pubkey.clone()));

        let input = TransparentSignableInput::from_parts(
            bundle,
            SighashType::ALL,
            0,
            &script_code,
            &script_pubkey,
            Zatoshis::const_from_u64(self.amount_zat),
        )
        .map_err(|_| TxError::BadInputIndex)?;

        let txid_parts = self.data.digest(TxIdDigester);
        let digest = signature_hash(&self.data, &SignableInput::Transparent(input), &txid_parts);
        Ok(*digest.as_ref())
    }

    pub fn lock_time(&self) -> u32 {
        self.data.lock_time()
    }

    pub fn version(&self) -> TxVersion {
        self.data.version()
    }

    pub fn redeem_script(&self) -> &[u8] {
        &self.redeem_script
    }
}

/// Turns the ordered output specs into the bundle's `vout`, refusing the
/// shapes a node would.
///
/// An empty script is refused rather than encoded: `OP_RETURN`-less empty
/// scriptPubKeys are anyone-can-spend, so an output built from a script the
/// caller forgot to set is money handed to the first miner who notices.
fn build_vout(outputs: &[TxOutSpec]) -> Result<Vec<TxOut>, TxError> {
    if outputs.is_empty() {
        return Err(TxError::NoOutputs);
    }
    let mut vout = Vec::with_capacity(outputs.len());
    for o in outputs {
        if o.script.is_empty() {
            return Err(TxError::EmptyOutputScript);
        }
        vout.push(TxOut::new(
            Zatoshis::const_from_u64(o.value_zat),
            Script(Code(o.script.clone())),
        ));
    }
    Ok(vout)
}

fn build(
    terms: &EscrowTerms,
    outputs: &[TxOutSpec],
    sequence: u32,
    lock_time: u32,
) -> Result<UnsignedEscrowTx, TxError> {
    let vout = build_vout(outputs)?;
    let redeem = terms.redeem_script()?;
    let script_pubkey = terms.script_pubkey()?;

    let prev_out = TxOut::new(
        Zatoshis::const_from_u64(terms.amount_zat),
        Script(Code(script_pubkey.clone())),
    );

    let bundle = Bundle::<EscrowEffects> {
        vin: vec![zcash_transparent::bundle::TxIn::from_parts(
            terms.outpoint(),
            (),
            sequence,
        )],
        vout,
        authorization: EscrowEffects {
            inputs: vec![prev_out],
        },
    };

    // The branch id is read from a node, so it is untrusted input: a hostile or
    // merely upgraded node can hand back a value this build does not know.
    // Refusing is right; panicking in a builder the daemons call on every poll
    // is not.
    let branch = BranchId::try_from(terms.consensus_branch_id)
        .map_err(|_| TxError::UnknownBranchId(terms.consensus_branch_id))?;

    let data = TransactionData::<EscrowUnauthorized>::from_parts(
        // Spec 4.3 mandates version 5. Under the NU6.3 branch the builder would
        // default to V6 (Phase 0 finding 12.2); pinning it here means the two
        // parties cannot disagree by taking different defaults.
        TxVersion::V5,
        branch,
        lock_time,
        // nExpiryHeight = 0: a release delayed by congestion stays minable
        // (spec 4.5), and Zcash has no RBF to bump it with.
        0.into(),
        Some(bundle),
        None,
        None,
        None,
    );

    Ok(UnsignedEscrowTx {
        data,
        redeem_script: redeem,
        script_pubkey,
        amount_zat: terms.amount_zat,
    })
}

/// A release over an output list given directly, bypassing [`ReleaseSplit`]'s
/// policy checks.
///
/// [`build_release_split`] is what production code calls: it derives the output
/// set from the split, and refuses a dust output, an empty script, or a fee
/// without a destination. This builds whatever it is handed.
///
/// It exists so the dust boundary can be probed against a real node. Checking
/// that our threshold matches the node's means broadcasting a transaction our
/// own gate refuses, and the alternative - a test-only hatch cut into the gate -
/// would weaken the thing being tested. So the primitive is public and honest
/// about what it does not check, rather than private with a hole in it.
///
/// Do not use it to build a release for a user. `build_vout` still refuses an
/// empty output set and an empty script, because those produce transactions
/// that lose money rather than merely fail.
pub fn build_release_from_outputs(
    terms: &EscrowTerms,
    outputs: &[TxOutSpec],
) -> Result<UnsignedEscrowTx, TxError> {
    build(terms, outputs, RELEASE_SEQUENCE, 0)
}

/// Serializes a signed release over an output list given directly. See
/// [`build_release_from_outputs`] for why this is public.
pub fn serialize_release_from_outputs(
    terms: &EscrowTerms,
    outputs: &[TxOutSpec],
    script_sig: &[u8],
) -> Result<Vec<u8>, TxError> {
    serialize_signed(terms, outputs, RELEASE_SEQUENCE, 0, script_sig)
}

/// The release transaction of spec 4.3: one escrow input, the split's outputs,
/// `nLockTime = 0`, final input.
pub fn build_release_split(
    terms: &EscrowTerms,
    split: &ReleaseSplit,
) -> Result<UnsignedEscrowTx, TxError> {
    build(
        terms,
        &split.outputs(terms.amount_zat)?,
        RELEASE_SEQUENCE,
        0,
    )
}

/// A release paying only the LP, with no platform fee.
pub fn build_release(
    terms: &EscrowTerms,
    lp_output_script: &[u8],
    fee_zat: u64,
) -> Result<UnsignedEscrowTx, TxError> {
    build_release_split(terms, &ReleaseSplit::without_fee(lp_output_script, fee_zat))
}

/// The refund transaction of spec 4.4: `nLockTime = T` and a non-final input,
/// without which CLTV does not run at all.
pub fn build_refund(
    terms: &EscrowTerms,
    user_output_script: &[u8],
    fee_zat: u64,
) -> Result<UnsignedEscrowTx, TxError> {
    let value = terms
        .amount_zat
        .checked_sub(fee_zat)
        .ok_or(TxError::BelowFee {
            amount: terms.amount_zat,
            fee: fee_zat,
        })?;
    build(
        terms,
        &[TxOutSpec::new(user_output_script.to_vec(), value)],
        REFUND_SEQUENCE,
        u32::try_from(terms.refund_height).map_err(|_| TxError::BadInputIndex)?,
    )
}

/// DER-encodes a signature with low-S normalisation and the SIGHASH_ALL byte
/// (spec 4.6).
///
/// Adaptor decryption can yield a high-S signature. Zcash enforces low-S as a
/// standardness rule, so an un-normalised signature is valid by consensus and
/// still refused by the mempool, which for a release means the LP's funds sit
/// unspendable.
pub fn encode_signature(sig: &secp256k1::ecdsa::Signature) -> Vec<u8> {
    let mut normalised = *sig;
    normalised.normalize_s();
    let mut der = normalised.serialize_der().to_vec();
    der.push(SIGHASH_ALL);
    der
}

/// Zatoshis balance helper kept next to the builders so the value type used for
/// fee arithmetic is the library's, not a bare integer.
pub fn zat(v: u64) -> ZatBalance {
    ZatBalance::const_from_i64(v as i64)
}

/// Serializes a fully signed escrow spend into the bytes a node accepts.
///
/// The escrow's two spending transactions have exactly one transparent input,
/// an ordered output set and no shielded bundle, so this rebuilds the same
/// `TransactionData` with an authorized transparent bundle and freezes it.
/// Going back through the library rather than hand-rolling the v5 format means
/// ZIP 225 field ordering, the version group id and the branch id come from the
/// same code that computed the sighash.
pub fn serialize_signed(
    terms: &EscrowTerms,
    outputs: &[TxOutSpec],
    sequence: u32,
    lock_time: u32,
    script_sig: &[u8],
) -> Result<Vec<u8>, TxError> {
    use zcash_primitives::transaction::Authorized as TxAuthorized;
    use zcash_transparent::bundle::Authorized as TransparentAuthorized;

    let bundle = Bundle::<TransparentAuthorized> {
        vin: vec![zcash_transparent::bundle::TxIn::from_parts(
            terms.outpoint(),
            Script(Code(script_sig.to_vec())),
            sequence,
        )],
        vout: build_vout(outputs)?,
        authorization: TransparentAuthorized,
    };

    let data = TransactionData::<TxAuthorized>::from_parts(
        TxVersion::V5,
        BranchId::try_from(terms.consensus_branch_id)
            .map_err(|_| TxError::UnknownBranchId(terms.consensus_branch_id))?,
        lock_time,
        0.into(),
        Some(bundle),
        None,
        None,
        None,
    );

    let tx = data.freeze().map_err(|e| TxError::Serialize(e.to_string()))?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| TxError::Serialize(e.to_string()))?;
    Ok(bytes)
}

/// Serializes a signed release (spec 4.3), platform fee included.
///
/// It rebuilds the output set from the same [`ReleaseSplit`] the digest was
/// computed from, so the bytes broadcast and the bytes signed cannot drift.
pub fn serialize_release_split(
    terms: &EscrowTerms,
    split: &ReleaseSplit,
    script_sig: &[u8],
) -> Result<Vec<u8>, TxError> {
    serialize_signed(
        terms,
        &split.outputs(terms.amount_zat)?,
        RELEASE_SEQUENCE,
        0,
        script_sig,
    )
}

/// Serializes a signed release paying only the LP.
pub fn serialize_release(
    terms: &EscrowTerms,
    lp_output_script: &[u8],
    fee_zat: u64,
    script_sig: &[u8],
) -> Result<Vec<u8>, TxError> {
    serialize_release_split(
        terms,
        &ReleaseSplit::without_fee(lp_output_script, fee_zat),
        script_sig,
    )
}

/// Serializes a signed refund (spec 4.4).
pub fn serialize_refund(
    terms: &EscrowTerms,
    user_output_script: &[u8],
    fee_zat: u64,
    script_sig: &[u8],
) -> Result<Vec<u8>, TxError> {
    let value = terms
        .amount_zat
        .checked_sub(fee_zat)
        .ok_or(TxError::BelowFee {
            amount: terms.amount_zat,
            fee: fee_zat,
        })?;
    serialize_signed(
        terms,
        &[TxOutSpec::new(user_output_script.to_vec(), value)],
        REFUND_SEQUENCE,
        u32::try_from(terms.refund_height).map_err(|_| TxError::BadInputIndex)?,
        script_sig,
    )
}

/// The txid of a transaction, computed before it is broadcast.
///
/// Spec 4.2 rests on this: ZIP 244 txids do not commit to signatures, so the
/// client knows the funding outpoint before the funding transaction is signed,
/// and the pre-signature can therefore commit to it. Round 7 noted that nothing
/// in the repo exercised it - every txid in the regtest run was read back from
/// the node afterwards.
///
/// The bytes returned are **internal order**. Every Zcash RPC and every
/// explorer prints the reverse; `rpc::txid_to_rpc_hex` converts.
pub fn txid_of_signed(raw_tx: &[u8]) -> Result<[u8; 32], TxError> {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    // The branch id only selects the parser; a v5 transaction carries its own.
    let tx = Transaction::read(raw_tx, BranchId::Nu5)
        .map_err(|e| TxError::Serialize(format!("could not parse the transaction: {e}")))?;
    Ok(*tx.txid().as_ref())
}

/// The txid a *signed* release will have, computed from the unsigned form plus
/// the signatures that will go into it.
///
/// Used to check the ZIP 244 property directly: sign the same transaction two
/// ways and the txid must not move.
pub fn release_txid(
    terms: &EscrowTerms,
    lp_output_script: &[u8],
    fee_zat: u64,
    script_sig: &[u8],
) -> Result<[u8; 32], TxError> {
    let raw = serialize_release(terms, lp_output_script, fee_zat, script_sig)?;
    txid_of_signed(&raw)
}

/// The txid a signed release with a platform-fee output will have.
pub fn release_split_txid(
    terms: &EscrowTerms,
    split: &ReleaseSplit,
    script_sig: &[u8],
) -> Result<[u8; 32], TxError> {
    txid_of_signed(&serialize_release_split(terms, split, script_sig)?)
}
