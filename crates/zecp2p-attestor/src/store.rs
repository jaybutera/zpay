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
    /// When the attestor issued this announcement, in milliseconds.
    ///
    /// This is the attestor's own clock, and it is what bounds how old a
    /// payment may be. A payment for this escrow cannot predate the moment the
    /// attestor first heard of it, so `terms.lock_confirmed_ms` - which the LP
    /// writes - is never used for that (round 2 finding 2).
    pub announced_at_ms: u64,
    /// Present once the outcome has been signed. `k` is gone by then.
    pub signed_s: Option<[u8; 32]>,
    /// The payment that released this escrow, once it has been signed. One
    /// Venmo payment releases one escrow, and this is the record of which.
    pub payment_nullifier: Option<[u8; 32]>,
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
    #[error("this payment has already released another escrow")]
    PaymentAlreadyConsumed,
}

/// A nonce bound to the event it was drawn for.
///
/// Handing back a bare `[u8; 32]` let a caller sign event B with event A's
/// nonce, which is the one mistake that exposes `d`. Carrying the event id
/// alongside the scalar means the signing call can refuse a mismatch, and the
/// type cannot be constructed outside the store.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundNonce {
    event_id: [u8; 32],
    k: [u8; 32],
}

impl BoundNonce {
    /// The nonce, but only for the event it was issued against.
    pub fn secret_for(&self, event_id: &[u8; 32]) -> Option<&[u8; 32]> {
        (&self.event_id == event_id).then_some(&self.k)
    }

    pub fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }
}

impl core::fmt::Debug for BoundNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Criterion 14: `k` must not reach a log.
        f.debug_struct("BoundNonce")
            .field("event_id", &hex::encode(self.event_id))
            .field("k", &"[redacted]")
            .finish()
    }
}

/// An in-memory store with the same invariants as the SQLite table.
///
/// The persistent implementation must hold these too; the tests treat this as
/// the specification of the behaviour rather than as a stub.
///
/// `Debug` is written by hand. Criterion 14 bars `k` from any log, and of all
/// the secrets here it is the one whose exposure is unrecoverable: two
/// signatures under one nonce give up `d`.
#[derive(Default)]
pub struct EventStore {
    events: HashMap<[u8; 32], Event>,
    /// `k`, held apart from the event row so that "delete k on sign" is a
    /// single operation that cannot half-happen.
    nonces: HashMap<[u8; 32], [u8; 32]>,
    funding: HashMap<[u8; 32], [u8; 32]>,
    /// Payments that have already released an escrow. One Venmo payment
    /// releases one escrow, so this set is what stops an LP presenting a single
    /// attestation against several escrows for the same user.
    consumed_payments: HashMap<[u8; 32], [u8; 32]>,
}

impl core::fmt::Debug for EventStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventStore")
            .field("events", &self.events.len())
            // The count only. A nonce must not reach a log even as bytes.
            .field("nonces_held", &self.nonces.len())
            .field("consumed_payments", &self.consumed_payments.len())
            .finish()
    }
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an announcement. Refuses a second one for the same event or the
    /// same funding transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn announce(
        &mut self,
        event_id: [u8; 32],
        terms_hash: [u8; 32],
        r: [u8; 33],
        funding_txid: [u8; 32],
        k: [u8; 32],
        announced_at_ms: u64,
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
                announced_at_ms,
                signed_s: None,
                payment_nullifier: None,
            },
        );
        self.nonces.insert(event_id, k);
        self.funding.insert(funding_txid, event_id);
        Ok(())
    }

    pub fn get(&self, event_id: &[u8; 32]) -> Option<&Event> {
        self.events.get(event_id)
    }

    /// Removes `k` and returns it bound to its event.
    ///
    /// `take` is now literal (round 3 finding 5): the nonce leaves the store on
    /// the first call, so a second one finds nothing whatever the caller does
    /// next. That is a deliberate change of recovery semantics - a signing run
    /// that crashes after taking the nonce and before `mark_signed` cannot be
    /// retried, and the event is dead. That is the safe direction: the
    /// alternative is a window in which two signings under one nonce are
    /// possible, and two signatures under one nonce publish `d`.
    #[cfg(feature = "test-signer")]
    pub fn take_nonce_for_signing(
        &mut self,
        event_id: &[u8; 32],
    ) -> Result<BoundNonce, StoreError> {
        self.take_nonce_inner(event_id)
    }

    fn take_nonce_inner(
        &mut self,
        event_id: &[u8; 32],
    ) -> Result<BoundNonce, StoreError> {
        let event = self.events.get(event_id).ok_or(StoreError::UnknownEvent)?;
        if event.signed_s.is_some() {
            return Err(StoreError::AlreadySigned);
        }
        self.nonces
            .remove(event_id)
            .map(|k| BoundNonce {
                event_id: *event_id,
                k,
            })
            .ok_or(StoreError::AlreadySigned)
    }

    #[cfg(not(feature = "test-signer"))]
    pub(crate) fn take_nonce_for_signing(
        &mut self,
        event_id: &[u8; 32],
    ) -> Result<BoundNonce, StoreError> {
        self.take_nonce_inner(event_id)
    }

    /// Whether this payment has already released an escrow.
    pub fn payment_is_consumed(&self, nullifier: &[u8; 32]) -> bool {
        self.consumed_payments.contains_key(nullifier)
    }

    /// The event a payment was consumed by, for operators answering "why was
    /// this refused".
    pub fn payment_consumed_by(&self, nullifier: &[u8; 32]) -> Option<[u8; 32]> {
        self.consumed_payments.get(nullifier).copied()
    }

    /// Records the signature, consumes the payment, and destroys `k`.
    ///
    /// The three happen together on purpose: a crash between signing and
    /// recording the nullifier would let the same payment release a second
    /// escrow.
    pub fn mark_signed(
        &mut self,
        event_id: &[u8; 32],
        s: [u8; 32],
        payment_nullifier: [u8; 32],
    ) -> Result<(), StoreError> {
        if let Some(other) = self.consumed_payments.get(&payment_nullifier) {
            if other != event_id {
                return Err(StoreError::PaymentAlreadyConsumed);
            }
        }
        let event = self
            .events
            .get_mut(event_id)
            .ok_or(StoreError::UnknownEvent)?;
        if event.signed_s.is_some() {
            return Err(StoreError::AlreadySigned);
        }
        event.signed_s = Some(s);
        event.payment_nullifier = Some(payment_nullifier);
        self.consumed_payments.insert(payment_nullifier, *event_id);
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
