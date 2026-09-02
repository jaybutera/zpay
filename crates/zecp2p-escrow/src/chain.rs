//! The node interface, and an in-memory chain for tests.
//!
//! Everything the escrow needs from a Zcash node is here, and it is a small
//! surface on purpose: the height, the branch id, one output's status, and
//! broadcast. Keeping it a trait means the protocol logic in `client.rs` and
//! `lp.rs` is exercised against a chain whose reorgs and confirmation depths a
//! test controls, rather than against whatever a live node happened to be doing.
//!
//! The real adapter over zebrad's `getblockchaininfo`, `gettxout` and
//! `sendrawtransaction` is not written; nothing in this crate has ever spoken
//! to a node.

use std::collections::HashMap;

/// One transparent output as the node reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub script_pubkey: Vec<u8>,
    pub amount_zat: u64,
    /// Confirmations, counting the containing block as one. Zero means the
    /// output is in the mempool and in no block.
    pub confirmations: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("the node rejected the transaction: {0}")]
    Rejected(String),
    #[error("the node is unreachable: {0}")]
    Unreachable(String),
}

/// What the escrow asks of a Zcash node.
pub trait ChainClient {
    /// The current best-chain height.
    fn height(&self) -> Result<u32, ChainError>;

    /// The consensus branch id in force. Spec 4.3 requires this be read from
    /// the node rather than hard-coded, because it changes at every network
    /// upgrade and a stale value produces a sighash nobody will accept.
    fn consensus_branch_id(&self) -> Result<u32, ChainError>;

    /// The output at `txid:vout`, or `None` if it does not exist or is spent.
    fn utxo(&self, txid: &[u8; 32], vout: u32) -> Result<Option<Utxo>, ChainError>;

    /// Submits a raw transaction. The error carries the node's own reason,
    /// which for a bad signature is what criterion 12 wants to see.
    fn broadcast(&self, raw_tx: &[u8]) -> Result<[u8; 32], ChainError>;
}

/// An in-memory chain, so the protocol logic can be tested against reorgs,
/// confirmation depths and rejections that a live testnet will not produce on
/// demand.
#[derive(Debug, Default)]
pub struct FakeChain {
    pub height: u32,
    pub branch_id: u32,
    utxos: HashMap<([u8; 32], u32), Utxo>,
    /// Raw transactions the node should refuse, by the reason it gives.
    rejections: Vec<(Vec<u8>, String)>,
    /// Set when the node should behave as if it were down.
    pub offline: bool,
    accepted: std::cell::RefCell<Vec<Vec<u8>>>,
}

impl FakeChain {
    pub fn new(height: u32, branch_id: u32) -> Self {
        Self {
            height,
            branch_id,
            ..Default::default()
        }
    }

    pub fn add_utxo(&mut self, txid: [u8; 32], vout: u32, utxo: Utxo) {
        self.utxos.insert((txid, vout), utxo);
    }

    /// Sets the confirmation count of an existing output, so a test can walk an
    /// escrow up to depth or drop it back down in a reorg.
    pub fn set_confirmations(&mut self, txid: &[u8; 32], vout: u32, confirmations: u32) {
        if let Some(u) = self.utxos.get_mut(&(*txid, vout)) {
            u.confirmations = confirmations;
        }
    }

    /// Removes an output, standing in for a reorg that unwound the funding
    /// transaction or for the escrow having been spent.
    pub fn remove_utxo(&mut self, txid: &[u8; 32], vout: u32) {
        self.utxos.remove(&(*txid, vout));
    }

    /// Makes the node refuse any transaction containing `marker`.
    pub fn reject_containing(&mut self, marker: Vec<u8>, reason: &str) {
        self.rejections.push((marker, reason.to_string()));
    }

    pub fn accepted_transactions(&self) -> Vec<Vec<u8>> {
        self.accepted.borrow().clone()
    }
}

impl ChainClient for FakeChain {
    fn height(&self) -> Result<u32, ChainError> {
        if self.offline {
            return Err(ChainError::Unreachable("fake node is offline".into()));
        }
        Ok(self.height)
    }

    fn consensus_branch_id(&self) -> Result<u32, ChainError> {
        if self.offline {
            return Err(ChainError::Unreachable("fake node is offline".into()));
        }
        Ok(self.branch_id)
    }

    fn utxo(&self, txid: &[u8; 32], vout: u32) -> Result<Option<Utxo>, ChainError> {
        if self.offline {
            return Err(ChainError::Unreachable("fake node is offline".into()));
        }
        Ok(self.utxos.get(&(*txid, vout)).cloned())
    }

    fn broadcast(&self, raw_tx: &[u8]) -> Result<[u8; 32], ChainError> {
        if self.offline {
            return Err(ChainError::Unreachable("fake node is offline".into()));
        }
        for (marker, reason) in &self.rejections {
            if raw_tx.windows(marker.len()).any(|w| w == marker.as_slice()) {
                return Err(ChainError::Rejected(reason.clone()));
            }
        }
        self.accepted.borrow_mut().push(raw_tx.to_vec());
        let mut txid = [0u8; 32];
        let n = raw_tx.len().min(32);
        txid[..n].copy_from_slice(&raw_tx[..n]);
        Ok(txid)
    }
}
