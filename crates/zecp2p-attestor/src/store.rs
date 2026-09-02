//! The `events` table of spec section 6, and the two rules that make the
//! attestor safe to run: one announcement per event, and one signature per
//! event.
//!
//! Both rules exist for the same reason. The nonce `k` is used once; a second
//! signature under a different challenge would let anyone solve for `d` from
//! the two published scalars. The store is therefore the enforcement point, not
//! a cache.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub event_id: [u8; 32],
    pub terms_hash: [u8; 32],
    /// The announced nonce point, 33 bytes compressed.
    pub r: [u8; 33],
    /// The funding transaction, so a second announcement for the same escrow
    /// can be refused (spec 6, rate limits).
    pub funding_txid: [u8; 32],
    /// Present once the outcome has been signed. `k` is gone by then.
    pub signed_s: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("an announcement already exists for this event")]
    DuplicateEvent,
    #[error("an announcement already exists for this funding transaction")]
    DuplicateFundingTx,
    #[error("no announcement exists for this event")]
    UnknownEvent,
    #[error("this event has already been signed")]
    AlreadySigned,
}

/// An in-memory store with the same invariants as the SQLite table.
///
/// The persistent implementation must hold these too; the tests treat this as
/// the specification of the behaviour rather than as a stub.
#[derive(Debug, Default)]
pub struct EventStore {
    events: HashMap<[u8; 32], Event>,
    /// `k`, held apart from the event row so that "delete k on sign" is a
    /// single operation that cannot half-happen.
    nonces: HashMap<[u8; 32], [u8; 32]>,
    funding: HashMap<[u8; 32], [u8; 32]>,
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an announcement. Refuses a second one for the same event or the
    /// same funding transaction.
    pub fn announce(
        &mut self,
        event_id: [u8; 32],
        terms_hash: [u8; 32],
        r: [u8; 33],
        funding_txid: [u8; 32],
        k: [u8; 32],
    ) -> Result<(), StoreError> {
        if self.events.contains_key(&event_id) {
            return Err(StoreError::DuplicateEvent);
        }
        if self.funding.contains_key(&funding_txid) {
            return Err(StoreError::DuplicateFundingTx);
        }
        self.events.insert(
            event_id,
            Event {
                event_id,
                terms_hash,
                r,
                funding_txid,
                signed_s: None,
            },
        );
        self.nonces.insert(event_id, k);
        self.funding.insert(funding_txid, event_id);
        Ok(())
    }

    pub fn get(&self, event_id: &[u8; 32]) -> Option<&Event> {
        self.events.get(event_id)
    }

    /// Returns `k` for signing. Fails if the event is unknown or already
    /// signed, which is what stops a second signature under the same nonce.
    pub fn take_nonce_for_signing(
        &mut self,
        event_id: &[u8; 32],
    ) -> Result<[u8; 32], StoreError> {
        let event = self.events.get(event_id).ok_or(StoreError::UnknownEvent)?;
        if event.signed_s.is_some() {
            return Err(StoreError::AlreadySigned);
        }
        self.nonces
            .get(event_id)
            .copied()
            .ok_or(StoreError::AlreadySigned)
    }

    /// Records the signature and destroys `k`.
    pub fn mark_signed(&mut self, event_id: &[u8; 32], s: [u8; 32]) -> Result<(), StoreError> {
        let event = self
            .events
            .get_mut(event_id)
            .ok_or(StoreError::UnknownEvent)?;
        if event.signed_s.is_some() {
            return Err(StoreError::AlreadySigned);
        }
        event.signed_s = Some(s);
        // The nonce is gone from here on. A later signing attempt finds no `k`
        // and cannot proceed even if some other check were bypassed.
        self.nonces.remove(event_id);
        Ok(())
    }

    /// The already-signed scalar, so a repeated `/attest` is idempotent rather
    /// than a second signature.
    pub fn signed_outcome(&self, event_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.events.get(event_id).and_then(|e| e.signed_s)
    }

    pub fn holds_nonce(&self, event_id: &[u8; 32]) -> bool {
        self.nonces.contains_key(event_id)
    }
}
