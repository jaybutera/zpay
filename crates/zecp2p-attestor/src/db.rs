//! SQLite persistence for the `events` table of spec section 6, as revised in
//! 16.5.
//!
//! ```text
//! events(event_id PRIMARY KEY, terms_hash, r, k_sealed, funding_txid,
//!        announced_at_ms, signed_at_ms, s, payment_nullifier)
//! ```
//!
//! The invariants are enforced by the schema rather than by the code that
//! writes to it, because a process restart between two escrows is exactly when
//! code-level bookkeeping is lost:
//!
//! - `event_id` is the primary key, so one announcement per event;
//! - `funding_txid` is UNIQUE, so one announcement per escrow;
//! - `r` is UNIQUE, so a nonce point cannot be announced twice - the failure
//!   that publishes `d` (round 4 finding 1);
//! - `payment_nullifier` is UNIQUE, so one Venmo payment releases one escrow
//!   even across a restart (round 2 finding 5).
//!
//! `k_sealed` is cleared on signing, in the same transaction that records `s`
//! and the nullifier. In Phase 7 it is sealed to the enclave; here it is stored
//! as raw bytes, and the database file is as sensitive as the attestor key.

use rusqlite::{params, Connection, OptionalExtension};

use crate::store::{Event, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("stored column {0} is not the expected width")]
    Corrupt(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e.to_string())
    }
}

/// The persistent event store.
pub struct SqliteEventStore {
    conn: Connection,
}

impl std::fmt::Debug for SqliteEventStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print rows: `k_sealed` is in them (criterion 14).
        f.debug_struct("SqliteEventStore").finish_non_exhaustive()
    }
}

fn bytes32(v: Vec<u8>, what: &'static str) -> Result<[u8; 32], DbError> {
    v.try_into().map_err(|_| DbError::Corrupt(what))
}

impl SqliteEventStore {
    pub fn open(path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn in_memory() -> Result<Self, DbError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, DbError> {
        // Durability matters here: an announcement that is lost after the user
        // has funded leaves an escrow the attestor will not sign for, and the
        // user waits until `T`.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                event_id          BLOB PRIMARY KEY NOT NULL,
                terms_hash        BLOB NOT NULL,
                r                 BLOB NOT NULL UNIQUE,
                k_sealed          BLOB,
                funding_txid      BLOB NOT NULL UNIQUE,
                announced_at_ms   INTEGER NOT NULL,
                signed_at_ms      INTEGER,
                s                 BLOB,
                payment_nullifier BLOB UNIQUE
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    /// Records an announcement. The UNIQUE constraints are what refuse a
    /// duplicate event, escrow or nonce point.
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
        if announced_at_ms == 0 {
            return Err(StoreError::UnknownEvent);
        }
        let res = self.conn.execute(
            "INSERT INTO events (event_id, terms_hash, r, k_sealed, funding_txid, announced_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &event_id[..],
                &terms_hash[..],
                &r[..],
                &k[..],
                &funding_txid[..],
                announced_at_ms as i64
            ],
        );
        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                // Distinguish which uniqueness rule was hit, so an operator can
                // tell a retry from a nonce collision.
                let text = e.to_string();
                Err(if text.contains("events.r") {
                    StoreError::DuplicateNoncePoint
                } else if text.contains("events.funding_txid") {
                    StoreError::DuplicateFundingTx
                } else {
                    StoreError::DuplicateEvent
                })
            }
        }
    }

    pub fn get(&self, event_id: &[u8; 32]) -> Result<Option<Event>, DbError> {
        let row = self
            .conn
            .query_row(
                "SELECT terms_hash, r, funding_txid, announced_at_ms, s, payment_nullifier
                 FROM events WHERE event_id = ?1",
                params![&event_id[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((terms_hash, r, funding_txid, announced_at_ms, s, nullifier)) = row else {
            return Ok(None);
        };
        let r: [u8; 33] = r.try_into().map_err(|_| DbError::Corrupt("r"))?;
        Ok(Some(Event {
            event_id: *event_id,
            terms_hash: bytes32(terms_hash, "terms_hash")?,
            r,
            funding_txid: bytes32(funding_txid, "funding_txid")?,
            announced_at_ms: announced_at_ms as u64,
            signed_s: s.map(|v| bytes32(v, "s")).transpose()?,
            payment_nullifier: nullifier.map(|v| bytes32(v, "nullifier")).transpose()?,
        }))
    }

    /// Whether this payment has already released an escrow, across restarts.
    pub fn payment_is_consumed(&self, nullifier: &[u8; 32]) -> Result<bool, DbError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM events WHERE payment_nullifier = ?1",
                params![&nullifier[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// The scalar already published for an event, if any.
    pub fn signed_outcome(&self, event_id: &[u8; 32]) -> Result<Option<[u8; 32]>, DbError> {
        let s: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT s FROM events WHERE event_id = ?1",
                params![&event_id[..]],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        s.map(|v| bytes32(v, "s")).transpose()
    }

    /// Takes the nonce and records the signature in one transaction.
    ///
    /// The whole sequence is atomic on purpose (round 2 finding 4): a crash
    /// between taking `k` and recording `s` would either leave a usable nonce
    /// beside a published scalar, or a consumed payment with no record of which
    /// escrow consumed it.
    pub fn sign_and_record<F>(
        &mut self,
        event_id: &[u8; 32],
        nullifier: [u8; 32],
        signed_at_ms: u64,
        sign: F,
    ) -> Result<[u8; 32], StoreError>
    where
        F: FnOnce(&[u8; 32]) -> Result<[u8; 32], StoreError>,
    {
        let tx = self
            .conn
            .transaction()
            .map_err(|_| StoreError::UnknownEvent)?;

        let (k, already): (Option<Vec<u8>>, Option<Vec<u8>>) = tx
            .query_row(
                "SELECT k_sealed, s FROM events WHERE event_id = ?1",
                params![&event_id[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| StoreError::UnknownEvent)?;

        if already.is_some() {
            return Err(StoreError::AlreadySigned);
        }
        let k: [u8; 32] = k
            .ok_or(StoreError::AlreadySigned)?
            .try_into()
            .map_err(|_| StoreError::AlreadySigned)?;

        let s = sign(&k)?;

        // Clearing `k_sealed` in the same statement that writes `s` means the
        // nonce cannot outlive its one use.
        let updated = tx
            .execute(
                "UPDATE events SET s = ?1, k_sealed = NULL, signed_at_ms = ?2,
                 payment_nullifier = ?3 WHERE event_id = ?4 AND s IS NULL",
                params![
                    &s[..],
                    signed_at_ms as i64,
                    &nullifier[..],
                    &event_id[..]
                ],
            )
            .map_err(|e| {
                if e.to_string().contains("payment_nullifier") {
                    StoreError::PaymentAlreadyConsumed
                } else {
                    StoreError::UnknownEvent
                }
            })?;

        if updated != 1 {
            return Err(StoreError::AlreadySigned);
        }
        tx.commit().map_err(|_| StoreError::UnknownEvent)?;
        Ok(s)
    }

    pub fn holds_nonce(&self, event_id: &[u8; 32]) -> Result<bool, DbError> {
        let k: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT k_sealed FROM events WHERE event_id = ?1",
                params![&event_id[..]],
                |row| row.get(0),
            )
            .optional()?;
        Ok(matches!(k, Some(Some(_))))
    }
}
