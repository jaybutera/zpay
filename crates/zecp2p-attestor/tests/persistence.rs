//! The SQLite events table, spec section 6 as revised in 16.5.
//!
//! The point of this layer is the restart. Every invariant the in-memory store
//! enforces has to survive a process boundary, because a process boundary
//! between two escrows is exactly when an attacker would like the bookkeeping
//! to be forgotten.

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::store::StoreError;

const NOW_MS: u64 = 1_788_315_013_000;

fn ev(n: u8) -> [u8; 32] {
    [n; 32]
}

fn r_point(n: u8) -> [u8; 33] {
    [n; 33]
}

#[test]
fn an_announcement_round_trips() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();

    let e = db.get(&ev(1)).unwrap().expect("the row is there");
    assert_eq!(e.terms_hash, ev(2));
    assert_eq!(e.r, r_point(3));
    assert_eq!(e.funding_txid, ev(4));
    assert_eq!(e.announced_at_ms, NOW_MS);
    assert!(e.signed_s.is_none());
    assert!(e.payment_nullifier.is_none());
    assert!(db.holds_nonce(&ev(1)).unwrap());
}

#[test]
fn the_schema_refuses_a_second_announcement_for_one_event() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();
    assert_eq!(
        db.announce(ev(1), ev(9), r_point(9), ev(9), ev(9), NOW_MS),
        Err(StoreError::DuplicateEvent)
    );
}

#[test]
fn the_schema_refuses_a_second_announcement_for_one_escrow() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();
    assert_eq!(
        db.announce(ev(9), ev(8), r_point(8), ev(4), ev(7), NOW_MS),
        Err(StoreError::DuplicateFundingTx)
    );
}

#[test]
fn the_schema_refuses_a_repeated_nonce_point() {
    // Round 4 finding 1, at the layer that survives a restart. Two signatures
    // under one nonce publish `d`, so this is a UNIQUE constraint and not a
    // code-level check that a fresh process would forget.
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();
    assert_eq!(
        db.announce(ev(9), ev(8), r_point(3), ev(7), ev(6), NOW_MS),
        Err(StoreError::DuplicateNoncePoint)
    );
}

#[test]
fn a_zero_announcement_time_is_refused() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    assert!(db
        .announce(ev(1), ev(2), r_point(3), ev(4), ev(5), 0)
        .is_err());
}

#[test]
fn signing_clears_the_nonce_and_records_the_payment() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();

    let s = db
        .sign_and_record(&ev(1), ev(0xaa), NOW_MS + 1000, |k| {
            assert_eq!(k, &ev(5), "the signer sees the nonce it announced");
            Ok(ev(0x77))
        })
        .unwrap();
    assert_eq!(s, ev(0x77));

    assert!(!db.holds_nonce(&ev(1)).unwrap(), "k must be cleared");
    assert_eq!(db.signed_outcome(&ev(1)).unwrap(), Some(ev(0x77)));
    assert!(db.payment_is_consumed(&ev(0xaa)).unwrap());
}

#[test]
fn a_second_signing_of_one_event_is_refused() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();
    db.sign_and_record(&ev(1), ev(0xaa), NOW_MS, |_| Ok(ev(0x77)))
        .unwrap();

    assert_eq!(
        db.sign_and_record(&ev(1), ev(0xbb), NOW_MS, |_| Ok(ev(0x88))),
        Err(StoreError::AlreadySigned)
    );
}

#[test]
fn one_payment_cannot_release_two_escrows() {
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();
    db.announce(ev(6), ev(7), r_point(8), ev(9), ev(10), NOW_MS)
        .unwrap();

    db.sign_and_record(&ev(1), ev(0xaa), NOW_MS, |_| Ok(ev(0x77)))
        .unwrap();
    assert_eq!(
        db.sign_and_record(&ev(6), ev(0xaa), NOW_MS, |_| Ok(ev(0x88))),
        Err(StoreError::PaymentAlreadyConsumed)
    );
    // And the second event is untouched, so nothing was half-done.
    assert!(db.holds_nonce(&ev(6)).unwrap());
    assert!(db.signed_outcome(&ev(6)).unwrap().is_none());
}

#[test]
fn a_signer_that_fails_leaves_the_nonce_intact() {
    // The transaction rolls back, so a signing error is retryable rather than
    // burning the event.
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
        .unwrap();

    assert_eq!(
        db.sign_and_record(&ev(1), ev(0xaa), NOW_MS, |_| Err(StoreError::UnknownEvent)),
        Err(StoreError::UnknownEvent)
    );
    assert!(db.holds_nonce(&ev(1)).unwrap());
    assert!(db.signed_outcome(&ev(1)).unwrap().is_none());
}

// --- The restart. This is what the table exists for. ---

#[test]
fn every_invariant_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attestor.sqlite");
    let path = path.to_str().unwrap();

    {
        let mut db = SqliteEventStore::open(path).unwrap();
        db.announce(ev(1), ev(2), r_point(3), ev(4), ev(5), NOW_MS)
            .unwrap();
        db.sign_and_record(&ev(1), ev(0xaa), NOW_MS, |_| Ok(ev(0x77)))
            .unwrap();
    }

    // A fresh process opening the same file.
    let mut db = SqliteEventStore::open(path).unwrap();

    assert_eq!(
        db.signed_outcome(&ev(1)).unwrap(),
        Some(ev(0x77)),
        "the published scalar must survive, so a repeated /attest is idempotent"
    );
    assert!(!db.holds_nonce(&ev(1)).unwrap(), "k must stay gone");
    assert!(
        db.payment_is_consumed(&ev(0xaa)).unwrap(),
        "the consumed payment must survive, or one payment releases two escrows"
    );

    assert_eq!(
        db.announce(ev(9), ev(8), r_point(3), ev(7), ev(6), NOW_MS),
        Err(StoreError::DuplicateNoncePoint),
        "a nonce point announced before the restart must still be refused"
    );
    assert_eq!(
        db.announce(ev(9), ev(8), r_point(9), ev(4), ev(6), NOW_MS),
        Err(StoreError::DuplicateFundingTx)
    );
    assert_eq!(
        db.sign_and_record(&ev(1), ev(0xbb), NOW_MS, |_| Ok(ev(0x88))),
        Err(StoreError::AlreadySigned)
    );

    // A second escrow with a fresh payment still works, so the constraints bite
    // only where they should.
    db.announce(ev(11), ev(12), r_point(13), ev(14), ev(15), NOW_MS)
        .unwrap();
    db.sign_and_record(&ev(11), ev(0xcc), NOW_MS, |_| Ok(ev(0x99)))
        .unwrap();
}

#[test]
fn the_debug_output_never_prints_a_nonce() {
    // Criterion 14. The database holds `k_sealed`, so its Debug must not walk
    // rows.
    let mut db = SqliteEventStore::in_memory().unwrap();
    db.announce(ev(1), ev(2), r_point(3), ev(4), [0xAB; 32], NOW_MS)
        .unwrap();
    let text = format!("{db:?}");
    assert!(!text.contains(&hex::encode([0xABu8; 32])));
    assert!(!text.contains("171, 171"));
}
