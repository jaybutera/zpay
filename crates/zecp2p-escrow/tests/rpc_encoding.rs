//! The conversions in the RPC adapter, which are where a hosted node's answers
//! turn into protocol values. These run offline.
//!
//! Both of the bugs guarded here are silent: a reversed txid makes the escrow
//! look permanently unmined, and a truncated amount makes a correctly funded
//! escrow fail its amount check. Neither produces an error message that points
//! at the cause.

use zecp2p_escrow::rpc::{rpc_hex_to_txid, txid_to_rpc_hex, zec_to_zat, Network};

#[test]
fn txids_are_reversed_for_the_rpc_and_back_again() {
    // Zcash RPC renders a txid big-endian, the reverse of the byte order used
    // inside a transaction.
    let internal: [u8; 32] = {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        b
    };

    let rpc = txid_to_rpc_hex(&internal);
    assert!(
        rpc.starts_with("1f1e1d"),
        "the rpc form must be the reverse: {rpc}"
    );
    assert!(rpc.ends_with("020100"));
    assert_eq!(rpc_hex_to_txid(&rpc).unwrap(), internal, "round trip");
}

#[test]
fn a_real_testnet_txid_round_trips() {
    // Taken from testnet block 4319772. If the adapter asked about the
    // un-reversed form, the node would answer "no such output" forever and the
    // LP would wait out the whole refund window.
    let rpc = "deab26c42c09764c2830b0b9f421b3da7c302404d2097af132242bc6f57d6613";
    let internal = rpc_hex_to_txid(rpc).unwrap();
    assert_ne!(hex::encode(internal), rpc, "the two forms must differ");
    assert_eq!(txid_to_rpc_hex(&internal), rpc);
}

#[test]
fn a_malformed_txid_from_the_node_is_an_error_not_a_panic() {
    assert!(rpc_hex_to_txid("not hex").is_err());
    assert!(rpc_hex_to_txid("abcd").is_err(), "a short txid must be refused");
}

#[test]
fn zec_amounts_round_to_the_nearest_zatoshi() {
    // 1.25 ZEC is not exactly representable in binary floating point. The float
    // is a lossy rendering of an integer number of zatoshis, so rounding
    // recovers the integer and truncation would not.
    assert_eq!(zec_to_zat(1.25).unwrap(), 125_000_000);
    assert_eq!(zec_to_zat(0.0).unwrap(), 0);
    assert_eq!(zec_to_zat(0.00000001).unwrap(), 1, "one zatoshi");
    assert_eq!(zec_to_zat(0.05).unwrap(), 5_000_000);

    // The case that motivates rounding: a value whose float representation
    // sits just below the integer it stands for.
    assert_eq!(zec_to_zat(0.1 + 0.2).unwrap(), 30_000_000);
}

#[test]
fn the_escrow_sized_amounts_convert_exactly() {
    // The amounts this protocol actually uses, including the $1 mainnet test.
    for zat in [10_000u64, 15_000, 20_000, 100_000, 5_000_000, 125_000_000] {
        let as_zec = zat as f64 / 1e8;
        assert_eq!(
            zec_to_zat(as_zec).unwrap(),
            zat,
            "{zat} zat did not survive the round trip through ZEC"
        );
    }
}

#[test]
fn a_nonsensical_amount_is_refused() {
    // A provider returning garbage must not become a zero-value escrow that
    // quietly fails an amount check somewhere further along.
    assert!(zec_to_zat(-1.0).is_err());
    assert!(zec_to_zat(f64::NAN).is_err());
    assert!(zec_to_zat(f64::INFINITY).is_err());
}

#[test]
fn the_network_chain_field_matches_what_a_node_reports() {
    // getblockchaininfo reports "main" or "test"; the client refuses an
    // endpoint whose chain does not match its configuration, because pointing
    // a testnet config at a mainnet URL spends real money.
    assert_eq!(Network::Main.chain_field(), "main");
    assert_eq!(Network::Test.chain_field(), "test");
}
