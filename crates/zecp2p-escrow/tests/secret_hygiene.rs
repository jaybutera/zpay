//! Criterion 14: nothing in any log matches `u_priv`, `k`, or `d`.
//!
//! `Debug` is how secrets reach logs in practice - a `tracing` field, an
//! `unwrap` on an error carrying the struct, a panic message. These types hold
//! key material, so their `Debug` output is checked rather than assumed.

use zecp2p_escrow::client::{EscrowRecord, MemoryRecordStore, RecordStore};

const SECRET: [u8; 32] = [0xAB; 32];

fn record() -> EscrowRecord {
    EscrowRecord {
        u_priv: SECRET,
        redeem_script: vec![0x63, 0x52, 33],
        refund_height: 3_401_152,
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: 0x37a5_165b,
    }
}

/// The ways a 32-byte secret shows up in text: as hex, and as the decimal byte
/// list a derived `Debug` prints.
fn leaks(text: &str, secret: &[u8; 32]) -> bool {
    let hex_lower = hex::encode(secret);
    let hex_upper = hex_lower.to_uppercase();
    let debug_list = format!("{secret:?}");
    // The distinctive run of repeated bytes, which is what a derived Debug of
    // [0xAB; 32] actually emits.
    text.contains(&hex_lower) || text.contains(&hex_upper) || text.contains(&debug_list)
}

#[test]
fn the_escrow_record_does_not_print_the_user_key() {
    let text = format!("{:?}", record());
    assert!(
        !leaks(&text, &SECRET),
        "EscrowRecord's Debug exposed u_priv: {text}"
    );
    // It should still be useful for debugging: the outpoint identifies which
    // escrow this is.
    assert!(
        text.contains("7a7a7a") || text.contains("122"),
        "Debug should still identify the escrow: {text}"
    );
}

#[test]
fn the_record_store_does_not_print_stored_keys() {
    let mut store = MemoryRecordStore::default();
    store.save(&record()).unwrap();
    let text = format!("{store:?}");
    assert!(
        !leaks(&text, &SECRET),
        "MemoryRecordStore's Debug exposed a stored u_priv: {text}"
    );
}

#[test]
fn the_error_types_do_not_carry_key_material() {
    // Errors are the most likely thing to be logged verbatim.
    use zecp2p_escrow::client::ClientError;
    for e in [
        ClientError::NotPersisted,
        ClientError::UnpinnedAttestor,
        ClientError::IncompleteRecord("u_priv is unset"),
        ClientError::TooEarlyToRefund {
            current: 1,
            refund_height: 2,
        },
    ] {
        let text = format!("{e:?} {e}");
        assert!(!leaks(&text, &SECRET), "error leaked key material: {text}");
    }
}
