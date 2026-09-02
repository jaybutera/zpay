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
use crate::tx::{build_release, EscrowTerms, TxError};

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
    #[error("the escrow record was not persisted before funding")]
    NotPersisted,
    #[error("it is height {current}, the refund is not spendable until {refund_height}")]
    TooEarlyToRefund { current: u32, refund_height: u32 },
    #[error("dlc error: {0}")]
    Dlc(#[from] DlcError),
    #[error("transaction error: {0}")]
    Tx(String),
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
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
        if self.refund_height == 0 {
            return Err(ClientError::IncompleteRecord("refund_height is unset"));
        }
        if self.amount_zat == 0 {
            return Err(ClientError::IncompleteRecord("amount_zat is zero"));
        }
        if self.consensus_branch_id == 0 {
            return Err(ClientError::IncompleteRecord("consensus_branch_id is unset"));
        }
        Ok(())
    }
}

/// Somewhere durable to keep escrow records.
pub trait RecordStore {
    fn save(&mut self, record: &EscrowRecord) -> Result<(), ClientError>;
    fn load(&self, funding_txid: &[u8; 32]) -> Option<EscrowRecord>;
}

/// The attestor announcement the user receives (spec 5.1).
#[derive(Debug, Clone)]
pub struct Announcement {
    pub p: PublicKey,
    pub r: PublicKey,
    pub event_id: [u8; 32],
}

/// Checks the announcement against the attestor identity the user has pinned.
///
/// In Phase 1 that pin is a configured key. In Phase 7 it is whatever key the
/// Nitro attestation document carries, which is the step that turns "trust the
/// operator" into "trust the measured code".
pub fn verify_announcement(
    announcement: &Announcement,
    pinned_attestor_key: &PublicKey,
) -> Result<(), ClientError> {
    if &announcement.p != pinned_attestor_key {
        return Err(ClientError::UnpinnedAttestor);
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
    terms: &EscrowTerms,
    u_priv: &SecretKey,
    announcement: &Announcement,
    pinned_attestor_key: &PublicKey,
    lp_output_script: &[u8],
    fee_zat: u64,
) -> Result<(secp256k1_zkp::EcdsaAdaptorSignature, PublicKey), ClientError> {
    verify_announcement(announcement, pinned_attestor_key)?;

    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().map_err(TxError::from)?,
        refund_height: terms.refund_height,
        funding_txid: terms.funding_txid,
        vout: terms.vout,
        amount_zat: terms.amount_zat,
        consensus_branch_id: terms.consensus_branch_id,
    };
    record.validate()?;
    store.save(&record)?;

    // Only now is anything cryptographic produced.
    let y = outcome_point(secp, &announcement.r, &announcement.p, &announcement.event_id)?;
    let digest = build_release(terms, lp_output_script, fee_zat)?.sighash()?;
    let pre_sig = pre_sign(secp, &digest, u_priv, &y);

    // The user verifies its own pre-signature before handing it over, so a
    // failure surfaces here rather than as an LP that will not pay.
    let u_pub = u_priv.public_key(secp);
    verify_pre_signature(secp, &pre_sig, &digest, &u_pub, &y)?;

    Ok((pre_sig, y))
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
    lock_height: u32,
    user_output_script: &[u8],
    fee_zat: u64,
) -> Result<crate::tx::UnsignedEscrowTx, ClientError> {
    record.validate()?;
    let current = chain.height()?;
    let refund_height = policy.refund_height(lock_height);

    if !policy.may_refund(lock_height, current) {
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
