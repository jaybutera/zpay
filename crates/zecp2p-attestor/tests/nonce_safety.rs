//! Round 4 finding 1: the attestor draws its own nonce, and the store refuses a
//! repeated one.
//!
//! Nonce reuse is the one attestor failure with no recovery. Two outcome
//! signatures under one `k` let anyone solve for `d` from the two published
//! scalars - the escrow crate's `dlc` tests do exactly that arithmetic. So the
//! nonce is not a parameter any caller can supply, and a repeat is refused by
//! the store rather than merely made unlikely by the RNG.

use std::collections::HashSet;

use secp256k1_zkp::{Secp256k1, SecretKey};

use zecp2p_attestor::store::{EventStore, StoreError};
use zecp2p_attestor::{handle_announce, AttestorError, FixedClock};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;

fn terms_for(txid: [u8; 32]) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: txid,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: [0x02; 33],
        l_pub: [0x03; 33],
        refund_height: 3_500_000,
        usd_amount_6dec: 1_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: NOW_MS,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    }
}

#[test]
fn every_announcement_gets_a_distinct_nonce_point() {
    // The nonce comes from the OS RNG inside the handler, so a caller cannot
    // arrange a repeat even by asking for one.
    let secp = Secp256k1::new();
    let mut store = EventStore::new();
    let mut seen = HashSet::new();

    for i in 0..64u8 {
        let mut txid = [0u8; 32];
        txid[0] = i;
        let t = terms_for(txid);
        let ev = event_id(&txid, 0);
        let r = handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t).unwrap();
        assert!(
            seen.insert(r.serialize()),
            "announcement {i} reused a nonce point"
        );
    }
    assert_eq!(seen.len(), 64);
}

#[test]
fn the_store_refuses_a_repeated_nonce_point() {
    // The RNG makes a collision negligible. This makes it impossible, which is
    // the right posture for the one failure that publishes `d`.
    let secp = Secp256k1::new();
    let mut store = EventStore::new();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let r = k.public_key(&secp).serialize();

    store
        .announce([1; 32], [2; 32], r, [4; 32], k.secret_bytes(), NOW_MS)
        .unwrap();

    assert_eq!(
        store.announce([9; 32], [8; 32], r, [7; 32], k.secret_bytes(), NOW_MS),
        Err(StoreError::DuplicateNoncePoint),
        "a second event under one nonce point must be refused"
    );
}

#[test]
fn the_handler_surfaces_a_repeated_nonce_as_a_refused_announcement() {
    use zecp2p_attestor::handle_announce_with_nonce;

    let secp = Secp256k1::new();
    let mut store = EventStore::new();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let a = terms_for([0x7a; 32]);
    let b = terms_for([0x7b; 32]);
    handle_announce_with_nonce(
        &mut store,
        &secp,
        &FixedClock(NOW_MS),
        &event_id(&a.funding_txid, 0),
        &a,
        &k,
    )
    .unwrap();

    let err = handle_announce_with_nonce(
        &mut store,
        &secp,
        &FixedClock(NOW_MS),
        &event_id(&b.funding_txid, 0),
        &b,
        &k,
    )
    .expect_err("reusing the nonce across two events must be refused");
    assert_eq!(err, AttestorError::DuplicateAnnouncement);

    assert!(
        store.get(&event_id(&b.funding_txid, 0)).is_none(),
        "the refused announcement must leave no row"
    );
}

#[test]
fn a_nonce_is_never_taken_from_the_caller_on_the_production_path() {
    // `handle_announce` has no `k` parameter, which is the property this test
    // records: it is a compile-time fact rather than a runtime check, so the
    // test exists to make a later signature change visible.
    let secp = Secp256k1::new();
    let mut store = EventStore::new();
    let t = terms_for([0x7a; 32]);
    let ev = event_id(&t.funding_txid, 0);

    let r1 = handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t).unwrap();

    // A second announcement for the same event is refused for its own reason,
    // and the first nonce point stands.
    assert!(handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t).is_err());
    assert_eq!(store.get(&ev).unwrap().r, r1.serialize());
}
