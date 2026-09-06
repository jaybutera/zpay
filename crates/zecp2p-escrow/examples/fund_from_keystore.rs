//! Funds an escrow from a keystore key, on whatever network the RPC is for.
//!
//! `fund_escrow.rs` spends the regtest miner's hardcoded key on `Network::Test`
//! and is only useful on a local node. This one takes its key from the keystore
//! by label and its network from `ZECP2P_RPC_NETWORK`, which is what a funding
//! run against a hosted mainnet endpoint needs. It exists so a browser-driven
//! end-to-end test can send the ZEC itself instead of asking a person to open a
//! wallet.
//!
//! It spends P2PKH outpoints into the escrow's scriptPubKey and returns the
//! change to the same P2PKH. Nothing in the escrow protocol reads the funding
//! transaction's inputs, so a transparent funder changes no spend-side
//! property; the release and the refund spend a P2SH outpoint either way.
//!
//! ```text
//! ZECP2P_RPC_URL=https://zec.nownodes.io \
//! ZECP2P_RPC_NETWORK=main \
//! ZECP2P_RPC_API_KEY_HEADER=api-key ZECP2P_RPC_API_KEY=... \
//! ZECP2P_KEYSTORE=$HOME/.zecp2p/mainnet-v2coord \
//!   cargo run -p zecp2p-escrow --example fund_from_keystore -- \
//!     <label> <txid> <vout> <value_zat> <escrow_address> <amount_zat> \
//!     <u_pub_hex> <l_pub_hex> <refund_height>
//! ```
//!
//! One key funds the escrow, but its coin need not sit in a single output. A
//! run that has been paying escrows holds its balance as change from each
//! release, so the largest single output shrinks below the next escrow long
//! before the balance does. The txid, vout and value arguments therefore each
//! accept a comma-separated list of the same length, and every listed outpoint
//! must pay the funding key:
//!
//! ```text
//!   ... <label> <txid_a>,<txid_b> <vout_a>,<vout_b> <value_a>,<value_b> ...
//! ```
//!
//! The fee is ZIP 317's floor for the resulting shape rather than a constant,
//! since a spend of several inputs is a larger transaction than a spend of one.
//!
//! The escrow is named by the address the page shows, not by a scriptPubKey
//! hex: `script_pubkey_for` decodes it against the configured network, so an
//! address from the wrong network is refused here rather than paid. The txid is
//! given the way an explorer prints it. Nothing is broadcast until every
//! argument has been echoed back, so a mistyped amount is visible before it
//! costs anything.
//!
//! The last three arguments are the escrow's own parameters, and giving them
//! turns the address from something trusted into something checked: the redeem
//! script is rebuilt here from `u_pub`, `l_pub` and the refund height, hashed,
//! and the resulting P2SH address compared against the address being paid. A
//! coordinator that returns an address it cannot open, or a page that displays
//! one it did not derive, stops here with nothing signed. They are optional
//! only so a regtest funding with no order behind it still works; a run against
//! a live coordinator should always pass them.

use std::time::Duration;

use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_script::script::Code;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{Authorized as TAuthorized, Bundle, OutPoint, TxIn, TxOut};

use zecp2p_escrow::address::{script_pubkey_for, AddrNetwork};
use zecp2p_escrow::script::CompressedPubkey;
use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::funding::AddressNetwork;
use zecp2p_escrow::keystore::Keystore;
use zecp2p_escrow::rpc::{txid_from_display, Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::tx::encode_signature;

/// ZIP 317's marginal fee, and the grace number of logical actions it does not
/// charge for. A transparent spend's logical action count is the greater of its
/// input and output counts, so a 1-in 2-out funding sits inside the grace and
/// costs the 10,000 zat floor, while a 3-in 2-out funding costs one marginal
/// fee more.
const MARGINAL_FEE_ZAT: u64 = 5_000;
const GRACE_ACTIONS: u64 = 2;

fn zip317_fee(inputs: usize, outputs: usize) -> u64 {
    let actions = std::cmp::max(inputs as u64, outputs as u64);
    MARGINAL_FEE_ZAT * std::cmp::max(GRACE_ACTIONS, actions)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 7 && a.len() != 10 {
        eprintln!(
            "usage: fund_from_keystore <label> <txid> <vout> <value_zat> <escrow_address> <amount_zat> \
             [<u_pub_hex> <l_pub_hex> <refund_height>]"
        );
        std::process::exit(2);
    }
    let label = a[1].trim().to_string();
    // Each of the three is a list, and a single outpoint is the one-element
    // case, so the old command line still means what it did.
    let txids: Vec<_> = a[2].split(',').map(str::trim).collect();
    let vouts: Vec<_> = a[3].split(',').map(str::trim).collect();
    let values: Vec<_> = a[4].split(',').map(str::trim).collect();
    if txids.len() != vouts.len() || txids.len() != values.len() {
        eprintln!(
            "REFUSING: {} txids, {} vouts and {} values. They name one outpoint each \
             and must be the same length. Nothing was signed.",
            txids.len(),
            vouts.len(),
            values.len()
        );
        std::process::exit(2);
    }
    let inputs: Vec<(OutPoint, u64)> = txids
        .iter()
        .zip(vouts.iter())
        .zip(values.iter())
        .map(|((t, v), val)| {
            (
                OutPoint::new(
                    txid_from_display(t).expect("txid, as an explorer prints it"),
                    v.parse().expect("vout"),
                ),
                val.parse::<u64>().expect("input value in zat"),
            )
        })
        .collect();
    // Spending the same outpoint twice would build a transaction the network
    // rejects, and the arithmetic below would have counted its value twice.
    for i in 0..inputs.len() {
        for j in (i + 1)..inputs.len() {
            if inputs[i].0 == inputs[j].0 {
                eprintln!(
                    "REFUSING: outpoint {}:{} is listed twice. Nothing was signed.",
                    txids[i], vouts[i]
                );
                std::process::exit(2);
            }
        }
    }
    let value_zat: u64 = inputs.iter().map(|(_, v)| *v).sum();
    let escrow_address = a[5].trim().to_string();
    let amount_zat: u64 = a[6].parse().expect("escrow amount in zat");

    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        Ok("test") | Err(_) => Network::Test,
        Ok(other) => panic!("ZECP2P_RPC_NETWORK is {other}; expected main or test"),
    };
    let addr_network = match network {
        Network::Main => AddrNetwork::Main,
        _ => AddrNetwork::Test,
    };
    // Decoded against the network this run is for, so a testnet address in a
    // mainnet run stops here instead of sending coin to an unspendable script.
    let escrow_spk = script_pubkey_for(&escrow_address, addr_network)
        .expect("the escrow address, on this network");

    // The address is checked, not believed. Rebuilding the redeem script from
    // the order's own parameters and hashing it reproduces the address without
    // asking whoever supplied it, so an address that belongs to some other
    // script - a coordinator bug, a tampered response, a wrong order pasted in
    // - is caught before anything is signed.
    if a.len() == 10 {
        let u_pub: CompressedPubkey = hex::decode(a[7].trim())
            .expect("u_pub as hex")
            .try_into()
            .expect("u_pub is 33 bytes");
        let l_pub: CompressedPubkey = hex::decode(a[8].trim())
            .expect("l_pub as hex")
            .try_into()
            .expect("l_pub is 33 bytes");
        let refund_height: u64 = a[9].parse().expect("refund height");
        let plan = zecp2p_escrow::funding::escrow_address(
            &u_pub,
            &l_pub,
            refund_height,
            amount_zat,
            match network {
                Network::Main => AddressNetwork::Main,
                _ => AddressNetwork::Test,
            },
        )
        .expect("the escrow parameters build a redeem script");
        println!("derived     : {} (from u_pub, l_pub, height {refund_height})", plan.address);
        if plan.address != escrow_address {
            eprintln!(
                "REFUSING: the address given is {escrow_address} but these parameters derive \
                 {}. Nothing was signed.",
                plan.address
            );
            std::process::exit(3);
        }
        if plan.script_pubkey != escrow_spk {
            eprintln!("REFUSING: the derived scriptPubKey does not match. Nothing was signed.");
            std::process::exit(3);
        }
    } else {
        println!("derived     : not checked (no escrow parameters given)");
    }
    let keystore_dir = std::env::var("ZECP2P_KEYSTORE").expect("set ZECP2P_KEYSTORE");
    // `load`, never `load_or_create`: a fresh key here would sign for an
    // address that holds nothing, and the failure would look like a node fault.
    let sk = Keystore::new(&keystore_dir)
        .load(&label)
        .expect("the funding key, by label");

    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(pk)).into();

    // The P2PKH scriptPubKey the input paid, which is also its script_code.
    let mut p2pkh = vec![0x76, 0xa9, 20];
    p2pkh.extend_from_slice(&hash);
    p2pkh.extend_from_slice(&[0x88, 0xac]);

    // The fee depends on the output count and the output count depends on
    // whether there is change, so the two-output shape is priced first and the
    // no-change shape only considered if that does not fit.
    let fee_zat = zip317_fee(inputs.len(), 2);
    let (fee_zat, change) = match value_zat.checked_sub(amount_zat + fee_zat) {
        Some(change) => (fee_zat, change),
        None => {
            // No room for change. A one-output spend is cheaper, so try it
            // before giving up: the remainder over the escrow becomes fee.
            let bare = zip317_fee(inputs.len(), 1);
            match value_zat.checked_sub(amount_zat + bare) {
                Some(_) => (value_zat - amount_zat, 0),
                None => {
                    eprintln!(
                        "REFUSING: {} input zat across {} outpoint(s) does not cover {amount_zat} \
                         zat to the escrow plus a {bare} zat fee. Nothing was signed.",
                        value_zat,
                        inputs.len()
                    );
                    std::process::exit(2);
                }
            }
        }
    };

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

    // Everything the spend commits to, before it is signed. A wrong amount or a
    // wrong escrow script is cheaper to see here than on the chain.
    println!("network     : {network:?}");
    for (i, (op, value)) in inputs.iter().enumerate() {
        println!(
            "input {i}     : {}:{} worth {value} zat",
            zecp2p_escrow::rpc::txid_to_rpc_hex(op.hash()),
            op.n()
        );
    }
    println!("input total : {value_zat} zat");
    println!("funding key : {label} -> hash160 {}", hex::encode(hash));
    println!("escrow      : {escrow_address}");
    println!("escrow spk  : {}", hex::encode(&escrow_spk));
    println!("to escrow   : {amount_zat} zat");
    println!("fee         : {fee_zat} zat");
    println!("change      : {change} zat");

    let url = std::env::var("ZECP2P_RPC_URL").expect("set ZECP2P_RPC_URL");
    let mut cfg = RpcConfig::hosted(url, network);
    cfg.timeout = Duration::from_secs(45);
    // A hosted endpoint authenticates by header; a local node does not, so the
    // pair is optional and only set when both halves are present.
    if let (Ok(name), Ok(value)) = (
        std::env::var("ZECP2P_RPC_API_KEY_HEADER"),
        std::env::var("ZECP2P_RPC_API_KEY"),
    ) {
        cfg.api_key_header = Some((name, value));
    }
    let chain = RpcChainClient::new(cfg).expect("rpc");
    let branch = chain.consensus_branch_id().expect("branch id");

    // Every input pays the same key, so each carries the same scriptPubKey. The
    // digest still differs per input: ZIP 244 commits to the whole input set
    // and to which member of it is being signed.
    let sighash_inputs: Vec<(OutPoint, Vec<u8>, u64)> = inputs
        .iter()
        .map(|(op, value)| (op.clone(), p2pkh.clone(), *value))
        .collect();

    let mut vin = Vec::with_capacity(inputs.len());
    for (index, (op, _)) in inputs.iter().enumerate() {
        let unsigned = zecp2p_escrow::funding::p2pkh_sighash_multi(
            branch,
            &sighash_inputs,
            index,
            &vout_list,
        )
        .expect("sighash");

        let sig = secp.sign_ecdsa(&Message::from_digest(unsigned), &sk);
        let der = encode_signature(&sig);

        let mut script_sig = Vec::new();
        script_sig.push(der.len() as u8);
        script_sig.extend_from_slice(&der);
        script_sig.push(pk.len() as u8);
        script_sig.extend_from_slice(&pk);

        vin.push(TxIn::from_parts(
            op.clone(),
            Script(Code(script_sig)),
            0xffff_ffff,
        ));
    }

    let bundle = Bundle::<TAuthorized> {
        vin,
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
        // Display order, so the next command can take this line as it stands.
        Ok(id) => println!("FUNDING TXID: {}", zecp2p_escrow::rpc::txid_to_rpc_hex(&id)),
        Err(e) => {
            println!("node said   : {e}");
            std::process::exit(1);
        }
    }
}
