//! Mints the payout and refund keys for a run and prints their addresses.
//!
//! These are the two addresses the ask asks Casper for: `ZECP2P_LP_ADDRESS`,
//! where the released ZEC lands, and the refund destination, which is the exit
//! from every failure after the coin is locked. They must be different, so a
//! single lost key cannot take both exits at once.
//!
//! The keys are ordinary keystore entries, minted under their own labels and
//! written 0600 by `Keystore::create`, which refuses to overwrite. They are
//! test keys for this run and hold nothing until a release or a refund pays
//! them; they are deliberately not any wallet Casper already uses.
//!
//! The address is encoded here and then decoded again by
//! `address::script_pubkey_for`, the same function the refund uses on whatever
//! string it is handed. So the printed address is not merely encoded correctly
//! by this file's own arithmetic: it is accepted by the code that will spend to
//! it, on the network the run is configured for, and its hash160 is checked
//! against the key's own. An address that fails any of those does not print.
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zecp2p_escrow::address::{script_pubkey_for, AddrNetwork};
use zecp2p_escrow::keystore::Keystore;

/// base58check over a two-byte version prefix and a 20-byte hash.
fn base58check(prefix: [u8; 2], hash: &[u8; 20]) -> String {
    let mut payload = prefix.to_vec();
    payload.extend_from_slice(hash);
    let ck = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&ck[..4]);

    const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for b in &payload {
        let mut carry = *b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = payload.iter().take_while(|b| **b == 0).count();
    let mut out = "1".repeat(zeros);
    for d in digits.iter().rev() {
        out.push(A[*d as usize] as char);
    }
    out
}

fn hash160(pk: &[u8; 33]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(pk)).into()
}

fn main() {
    let dir = std::env::var("ZECP2P_KEYSTORE").expect("set ZECP2P_KEYSTORE");
    let label = std::env::var("ZECP2P_ESCROW_LABEL").expect("set ZECP2P_ESCROW_LABEL");
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => AddrNetwork::Main,
        _ => AddrNetwork::Test,
    };
    // t1 on mainnet, tm on test: P2PKH either way, because these are plain
    // single-key destinations and not another escrow.
    let prefix = match network {
        AddrNetwork::Main => [0x1c, 0xb8],
        AddrNetwork::Test => [0x1d, 0x25],
    };

    let ks = Keystore::new(&dir);
    let secp = Secp256k1::new();

    println!("keystore           : {dir}");
    println!("network            : {network:?}");
    println!();

    for (role, suffix) in [("payout", "payout"), ("refund", "refund")] {
        let name = format!("{label}-{suffix}");
        // load_or_create so re-running prints the same address rather than
        // refusing: these keys are minted by this tool and by nothing else.
        let existed = ks.exists(&name);
        let sk: SecretKey = ks.load_or_create(&name).expect("keystore");
        let pk: [u8; 33] = PublicKey::from_secret_key(&secp, &sk).serialize();
        let h = hash160(&pk);
        let addr = base58check(prefix, &h);

        // Decode it back with the crate's own parser, on this network, and
        // check the script it yields pays exactly this key's hash160.
        let spk = script_pubkey_for(&addr, network)
            .expect("the address we just encoded must decode on this network");
        let mut want = vec![0x76, 0xa9, 20];
        want.extend_from_slice(&h);
        want.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(spk, want, "{role} address does not pay its own key");

        println!("{role:7} key file  : {}", ks.path_of(&name).display());
        println!("{role:7} origin    : {}", if existed { "Loaded" } else { "Created" });
        println!("{role:7} pubkey    : {}", hex::encode(pk));
        println!("{role:7} address   : {addr}");
        println!("{role:7} scriptPubKey: {}", hex::encode(&spk));
        println!();
    }
}
