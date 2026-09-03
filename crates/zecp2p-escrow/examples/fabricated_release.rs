//! Criterion 12 against a real funded escrow: a release assembled with a
//! fabricated `s` must be rejected by the node.
//!
//! The escrow crate's tests show this at the script and cryptographic layers.
//! This shows it where the criterion asks: a node's mempool, on an outpoint
//! that really holds coin, so "rejected" cannot be an artefact of the input not
//! existing.
//!
//! ```text
//! ZECP2P_RPC_URL=http://127.0.0.1:18232 \
//!   cargo run -p zecp2p-escrow --example fabricated_release -- <txid> <vout> <T> <lp_t_addr>
//! ```

use std::time::Duration;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::rpc::{rpc_hex_to_txid, Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::tx::{build_release, encode_signature, serialize_release, EscrowTerms};

const DEV_U: [u8; 32] = [0x11; 32];
const DEV_L: [u8; 32] = [0x22; 32];

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let txid = rpc_hex_to_txid(a[1].trim()).expect("txid");
    let vout: u32 = a[2].parse().expect("vout");
    let refund_height: u64 = a[3].parse().expect("T");

    let url = std::env::var("ZECP2P_RPC_URL").expect("set ZECP2P_RPC_URL");
    // A hosted endpoint needs a longer broadcast budget than a local node; see
    // `RpcConfig::hosted`.
    let mut cfg = RpcConfig::public(url, Network::Test);
    cfg.timeout = Duration::from_secs(45);
    let chain = RpcChainClient::new(cfg).expect("rpc");
    let branch = chain.consensus_branch_id().expect("branch");

    let utxo = chain
        .utxo(&txid, vout)
        .expect("utxo query")
        .expect("the escrow must be funded for this test to mean anything");

    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&DEV_U).unwrap();
    let l_priv = SecretKey::from_slice(&DEV_L).unwrap();
    let terms = EscrowTerms {
        funding_txid: txid,
        vout,
        amount_zat: utxo.amount_zat,
        u_pub: PublicKey::from_secret_key(&secp, &u_priv).serialize(),
        l_pub: PublicKey::from_secret_key(&secp, &l_priv).serialize(),
        refund_height,
        consensus_branch_id: branch,
    };
    let redeem = terms.redeem_script().expect("redeem");
    assert_eq!(
        utxo.script_pubkey,
        terms.script_pubkey().unwrap(),
        "the outpoint does not pay this escrow"
    );

    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp_script = p2pkh([0x09; 20]);
    let digest = build_release(&terms, &lp_script, fee)
        .unwrap()
        .sighash()
        .unwrap();

    // The LP holds its own key and invents the user's. This is exactly what
    // decrypting a pre-signature under a fabricated `s` yields: a well-formed
    // signature by the wrong key.
    let fabricated = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let sig_fake = secp.sign_ecdsa(&Message::from_digest(digest), &fabricated);
    let sig_l = secp.sign_ecdsa(&Message::from_digest(digest), &l_priv);
    let script_sig = release_script_sig(
        &encode_signature(&sig_fake),
        &encode_signature(&sig_l),
        &redeem,
    );
    let raw = serialize_release(&terms, &lp_script, fee, &script_sig).expect("serialize");

    println!("escrow          : {}:{vout}", a[1].trim());
    println!("escrow value    : {} zat", utxo.amount_zat);
    println!("confirmations   : {}", utxo.confirmations);
    println!("fabricated s    : 3333..33");
    println!("raw release     : {}", hex::encode(&raw));

    match chain.broadcast(&raw) {
        Ok(id) => println!("ACCEPTED (BAD!) : {}", hex::encode(id)),
        Err(e) => println!("node rejected   : {e}"),
    }

    // And the honest release, for contrast: the same transaction with the
    // user's real signature is the one that would spend.
    let sig_u = secp.sign_ecdsa(&Message::from_digest(digest), &u_priv);
    let honest = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &redeem,
    );
    let honest_raw = serialize_release(&terms, &lp_script, fee, &honest).expect("serialize");
    println!("honest release  : {}", hex::encode(&honest_raw));
}
