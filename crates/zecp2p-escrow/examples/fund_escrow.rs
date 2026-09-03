//! Funds an escrow on regtest by spending a P2PKH outpoint into its P2SH
//! address, and prints the funding txid.
//!
//! This stands in for the shielded funding leg of spec 4.2, which needs the
//! wallet tooling `funding.rs` describes. Nothing in the protocol reads the
//! funding transaction's inputs, so a transparent funder changes no spend-side
//! property: the release and the refund spend a transparent P2SH outpoint
//! either way.
//!
//! ```text
//! ZECP2P_RPC_URL=http://127.0.0.1:18232 \
//!   cargo run -p zecp2p-escrow --example fund_escrow -- <txid> <vout> <value_zat> <escrow_spk_hex> <amount_zat>
//! ```

use std::time::Duration;

use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_script::script::Code;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{Authorized as TAuthorized, Bundle, OutPoint, TxIn, TxOut};

use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::rpc::{rpc_hex_to_txid, Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::tx::encode_signature;

/// The regtest miner key, from `miner_addr.rs`. Regtest coin, worth nothing.
const MINER_KEY: [u8; 32] = [0x5e; 32];

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let txid = rpc_hex_to_txid(a[1].trim()).expect("txid");
    let vout: u32 = a[2].parse().expect("vout");
    let value_zat: u64 = a[3].parse().expect("input value in zat");
    let escrow_spk = hex::decode(a[4].trim()).expect("escrow scriptPubKey hex");
    let amount_zat: u64 = a[5].parse().expect("escrow amount in zat");

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&MINER_KEY).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(pk)).into();

    // The P2PKH scriptPubKey the coinbase paid, which is also the script_code
    // for signing this input.
    let mut p2pkh = vec![0x76, 0xa9, 20];
    p2pkh.extend_from_slice(&hash);
    p2pkh.extend_from_slice(&[0x88, 0xac]);

    let url = std::env::var("ZECP2P_RPC_URL").expect("set ZECP2P_RPC_URL");
    // A hosted endpoint needs a longer broadcast budget than a local node; see
    // `RpcConfig::hosted`.
    let mut cfg = RpcConfig::public(url, Network::Test);
    cfg.timeout = Duration::from_secs(45);
    let chain = RpcChainClient::new(cfg).expect("rpc");
    let branch = chain.consensus_branch_id().expect("branch id");

    // 1-in 2-out P2PKH-ish spend: ZIP 317 charges the grace minimum here.
    let fee = 10_000u64;
    let change = value_zat
        .checked_sub(amount_zat + fee)
        .expect("input does not cover the escrow plus fee");

    let mut vout_list = vec![TxOut::new(
        Zatoshis::const_from_u64(amount_zat),
        Script(Code(escrow_spk.clone())),
    )];
    if change > 0 {
        vout_list.push(TxOut::new(
            Zatoshis::const_from_u64(change),
            Script(Code(p2pkh.clone())),
        ));
    }

    // Sighash over the unsigned form, then rebuild with the scriptSig.
    let unsigned = zecp2p_escrow::funding::p2pkh_sighash(
        branch,
        &OutPoint::new(txid, vout),
        &p2pkh,
        value_zat,
        &vout_list,
    )
    .expect("sighash");

    let sig = secp.sign_ecdsa(&Message::from_digest(unsigned), &sk);
    let der = encode_signature(&sig);

    // scriptSig for P2PKH: <sig> <pubkey>
    let mut script_sig = Vec::new();
    script_sig.push(der.len() as u8);
    script_sig.extend_from_slice(&der);
    script_sig.push(pk.len() as u8);
    script_sig.extend_from_slice(&pk);

    let bundle = Bundle::<TAuthorized> {
        vin: vec![TxIn::from_parts(
            OutPoint::new(txid, vout),
            Script(Code(script_sig)),
            0xffff_ffff,
        )],
        vout: vout_list,
        authorization: TAuthorized,
    };
    let data = TransactionData::<Authorized>::from_parts(
        TxVersion::V5,
        BranchId::try_from(branch).expect("known branch"),
        0,
        0.into(),
        Some(bundle),
        None,
        None,
        None,
    );
    let tx = data.freeze().expect("freeze");
    let mut raw = Vec::new();
    tx.write(&mut raw).expect("serialize");

    println!("funding raw : {}", hex::encode(&raw));
    match chain.broadcast(&raw) {
        Ok(id) => println!("FUNDING TXID: {}", hex::encode(id)),
        Err(e) => println!("node said   : {e}"),
    }
}
