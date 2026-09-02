//! Criterion 14, attestor side: nothing in any log matches `k` or `d`.
//!
//! The attestor's nonce is the one secret whose exposure is unrecoverable: two
//! signatures under one `k` give up `d`, and `d` is the key the whole service
//! rests on. So its `Debug` output is a test, not an assumption.

use zecp2p_attestor::store::{Event, EventStore};

const NONCE: [u8; 32] = [0xAB; 32];

fn leaks(text: &str, secret: &[u8; 32]) -> bool {
    text.contains(&hex::encode(secret))
        || text.contains(&hex::encode(secret).to_uppercase())
        || text.contains(&format!("{secret:?}"))
}

#[test]
fn the_event_store_never_prints_the_nonce() {
    let mut store = EventStore::new();
    store
        .announce([1; 32], [2; 32], [3; 33], [4; 32], NONCE)
        .unwrap();

    let text = format!("{store:?}");
    assert!(
        !leaks(&text, &NONCE),
        "the event store's Debug exposed k: {text}"
    );
}

#[test]
fn an_event_row_carries_no_nonce_at_all() {
    // The row and the nonce are stored apart precisely so that logging an
    // event cannot print `k`. This checks the type has no field for it.
    let event = Event {
        event_id: [1; 32],
        terms_hash: [2; 32],
        r: [3; 33],
        funding_txid: [4; 32],
        signed_s: Some([5; 32]),
    };
    let text = format!("{event:?}");
    assert!(!leaks(&text, &NONCE));
    // `R` and `s` are public: R is announced, and s becomes public the moment
    // the release is broadcast. Logging them is what section 6 asks for.
    assert!(text.contains("signed_s"));
}

#[test]
fn the_nonce_is_not_recoverable_from_the_store_after_signing() {
    let mut store = EventStore::new();
    store
        .announce([1; 32], [2; 32], [3; 33], [4; 32], NONCE)
        .unwrap();
    store.mark_signed(&[1; 32], [7; 32], [0x9a; 32]).unwrap();

    assert!(!store.holds_nonce(&[1; 32]));
    let text = format!("{store:?}");
    assert!(!leaks(&text, &NONCE), "k survived signing: {text}");
}
