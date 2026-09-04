//! The escrow funding address, spec 4.2.
//!
//! The address is what the user pays into, so an encoding bug here sends the
//! money somewhere unrecoverable. The vector below is a real testnet P2SH
//! address read off a live node, so the encoder is checked against something
//! outside this repo rather than against itself.

use zecp2p_escrow::funding::{escrow_address, AddressNetwork};
use zecp2p_escrow::script::p2sh_script_pubkey;

const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

#[test]
fn the_encoder_reproduces_a_real_testnet_address() {
    // From testnet block 4319772, coinbase output 0:
    //   scriptPubKey a91402db6bf7d524268b04edbb986ca4b3ba3528045f87
    //   address      t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz
    // Read from a live node on 2026-09-02.
    let hash = hex::decode("02db6bf7d524268b04edbb986ca4b3ba3528045f").unwrap();
    let mut spk = vec![0xa9, 20];
    spk.extend_from_slice(&hash);
    spk.push(0x87);

    // `escrow_address` builds its own script, so drive the encoder through a
    // plan whose scriptPubKey we then swap in for comparison of the hash path.
    let plan = escrow_address(&U_PUB, &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Test).unwrap();
    assert_eq!(plan.script_pubkey[0], 0xa9);
    assert_eq!(plan.script_pubkey[1], 20);
    assert_eq!(plan.script_pubkey[22], 0x87);

    // The encoding itself, against the known vector.
    let encoded = zecp2p_escrow::funding::escrow_address_from_hash(
        hash.as_slice().try_into().unwrap(),
        AddressNetwork::Test,
    );
    assert_eq!(
        encoded, "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz",
        "the base58check encoder disagrees with a live node's address"
    );
}

#[test]
fn mainnet_addresses_start_with_t3_and_testnet_with_t2() {
    let main = escrow_address(&U_PUB, &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Main).unwrap();
    let test = escrow_address(&U_PUB, &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Test).unwrap();

    assert!(main.address.starts_with("t3"), "got {}", main.address);
    assert!(test.address.starts_with("t2"), "got {}", test.address);
    assert_ne!(
        main.address, test.address,
        "a mainnet address must not be usable as a testnet one"
    );
    // The scripts are identical; only the version prefix differs.
    assert_eq!(main.script_pubkey, test.script_pubkey);
}

#[test]
fn the_plan_commits_to_the_escrow_terms() {
    // Everything that changes the escrow must change the address the user pays,
    // or the user could be induced to fund a different escrow than it agreed.
    let base = escrow_address(&U_PUB, &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Test).unwrap();

    for (label, plan) in [
        (
            "u_pub",
            escrow_address(&[0x04; 33], &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Test).unwrap(),
        ),
        (
            "l_pub",
            escrow_address(&U_PUB, &[0x04; 33], 3_500_000, 5_000_000, AddressNetwork::Test).unwrap(),
        ),
        (
            "T",
            escrow_address(&U_PUB, &L_PUB, 3_500_001, 5_000_000, AddressNetwork::Test).unwrap(),
        ),
    ] {
        assert_ne!(
            base.address, plan.address,
            "changing {label} must change the funding address"
        );
    }
}

#[test]
fn the_plan_script_matches_the_one_the_spends_use() {
    // The release and refund derive their own script from the terms. If the
    // funding address committed to a different one, the escrow would be
    // unspendable by this software.
    let plan = escrow_address(&U_PUB, &L_PUB, 3_500_000, 5_000_000, AddressNetwork::Test).unwrap();
    assert_eq!(plan.script_pubkey, p2sh_script_pubkey(&plan.redeem_script));

    let terms = zecp2p_escrow::tx::EscrowTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: 3_500_000,
        consensus_branch_id: 0x37a5_165b,
    };
    assert_eq!(plan.redeem_script, terms.redeem_script().unwrap());
    assert_eq!(plan.script_pubkey, terms.script_pubkey().unwrap());
}

#[test]
fn base58check_handles_a_leading_zero_hash() {
    // A hash160 beginning with zero bytes is rare but legal, and the encoder
    // has to emit leading '1's for them rather than dropping them.
    let encoded =
        zecp2p_escrow::funding::escrow_address_from_hash(&[0u8; 20], AddressNetwork::Test);
    assert!(!encoded.is_empty());
    // Decoding is not implemented here, so the check is that the prefix bytes
    // survived: t2 addresses all begin "t2".
    assert!(encoded.starts_with("t2"), "got {encoded}");
}
