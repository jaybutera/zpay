//! Drives a real escrow end to end against a live node.
//!
//! This is the runner for the testnet run and then the mainnet $1 acceptance
//! test. It does the parts that need no Venmo payment and no attestor service,
//! and stops with an explicit instruction wherever a human or another service
//! must act.
//!
//! ```text
//! # 1. Print the address to fund, and the terms both sides must agree.
//! ZECP2P_RPC_URL=<endpoint> cargo run -p zecp2p-escrow --example escrow_e2e -- plan
//!
//! # 2. Once the address is funded, watch it reach the depth for its size.
//! ZECP2P_RPC_URL=<endpoint> cargo run -p zecp2p-escrow --example escrow_e2e -- watch <txid> <vout>
//!
//! # 3. After T, sweep it back with the user key alone. This is the refund
//! #    path of the acceptance criteria, and it needs nobody else.
//! ZECP2P_RPC_URL=<endpoint> cargo run -p zecp2p-escrow --example escrow_e2e -- refund <txid> <vout> <t-addr>
//! ```
//!
//! Keys come from `ZECP2P_U_PRIV` and `ZECP2P_L_PRIV` as 64 hex characters. If
//! unset, deterministic development keys are used and the run is testnet-only;
//! the tool refuses to touch mainnet with them.

use std::time::Duration;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use zecp2p_escrow::chain::{ChainClient, ChainError};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::depth::required_depth;
use zecp2p_escrow::fees::refund_fee_to_shielded_zat;
use zecp2p_escrow::funding::{escrow_address, AddressNetwork};
use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::script::refund_script_sig;
use zecp2p_escrow::tx::{build_refund, encode_signature, serialize_refund, EscrowTerms};

/// Development keys. Deterministic so a run is reproducible, and refused on
/// mainnet.
///
/// R5-7 is right that these are public: an escrow funded at the address `plan`
/// prints with them is spendable by anyone through the 2-of-2 branch, at any
/// height. That is acceptable for watching a refund confirm on testnet and is
/// **not** acceptable for criterion 12, where the point is that a fabricated
/// `s` fails - with both keys public there is nothing to fabricate. The tool
/// warns on every run that uses them.
const DEV_U: [u8; 32] = [0x11; 32];
const DEV_L: [u8; 32] = [0x22; 32];

fn key(var: &str, fallback: [u8; 32]) -> (SecretKey, bool) {
    match std::env::var(var) {
        Ok(h) => {
            let bytes = hex::decode(h.trim()).expect("key must be 64 hex characters");
            (
                SecretKey::from_slice(&bytes).expect("key must be a valid secp256k1 scalar"),
                false,
            )
        }
        Err(_) => (SecretKey::from_slice(&fallback).unwrap(), true),
    }
}

fn client() -> (RpcChainClient, Network) {
    let url = std::env::var("ZECP2P_RPC_URL").expect("set ZECP2P_RPC_URL");
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    let mut cfg = RpcConfig::public(url, network);
    cfg.timeout = Duration::from_secs(45);
    (RpcChainClient::new(cfg).expect("rpc client"), network)
}

/// Retries through a hosted provider's rate limit. A real node needs none of
/// this.
fn retry<T>(label: &str, mut f: impl FnMut() -> Result<T, ChainError>) -> T {
    for attempt in 0..8 {
        match f() {
            Ok(v) => return v,
            Err(e) => {
                let text = format!("{e}");
                if !text.contains("429") {
                    panic!("{label}: {e}");
                }
                std::thread::sleep(Duration::from_secs(15 * (attempt + 1)));
            }
        }
    }
    panic!("{label}: still rate limited");
}

fn p2pkh_from_t_addr(addr: &str) -> Vec<u8> {
    // Minimal base58check decode for a t1/t3 address, enough to build an output.
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = Vec::new();
    for c in addr.bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|a| *a == c)
            .expect("address is not base58") as u32;
        for d in num.iter_mut() {
            carry += (*d as u32) * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = addr.bytes().take_while(|b| *b == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend(num.iter().rev());
    assert!(full.len() >= 26, "address too short: {addr}");

    // R5-7: check the trailing four bytes against the double-SHA256 of the
    // payload. Without this a single mistyped character sends the refund to a
    // hash nobody holds - TAZ on the testnet run, the escrow on the mainnet one.
    let (payload, checksum) = full.split_at(full.len() - 4);
    let expected = {
        use sha2::{Digest, Sha256};
        Sha256::digest(Sha256::digest(payload))
    };
    assert_eq!(
        checksum,
        &expected[..4],
        "address checksum does not match; {addr} is mistyped"
    );

    let hash = &full[2..22];

    // t1/tm are P2PKH; t3/t2 are P2SH.
    let is_p2sh = addr.starts_with("t3") || addr.starts_with("t2");
    if is_p2sh {
        let mut s = vec![0xa9, 20];
        s.extend_from_slice(hash);
        s.push(0x87);
        s
    } else {
        let mut s = vec![0x76, 0xa9, 20];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("plan");

    let (u_priv, u_dev) = key("ZECP2P_U_PRIV", DEV_U);
    let (l_priv, l_dev) = key("ZECP2P_L_PRIV", DEV_L);
    let secp = Secp256k1::new();
    let u_pub = PublicKey::from_secret_key(&secp, &u_priv).serialize();
    let l_pub = PublicKey::from_secret_key(&secp, &l_priv).serialize();

    let (chain, network) = client();
    if network == Network::Main && (u_dev || l_dev) {
        eprintln!(
            "refusing to run on mainnet with development keys; set ZECP2P_U_PRIV and \
             ZECP2P_L_PRIV"
        );
        std::process::exit(2);
    }
    let addr_network = match network {
        Network::Main => AddressNetwork::Main,
        Network::Test => AddressNetwork::Test,
    };

    if u_dev || l_dev {
        eprintln!(
            "WARNING: using public development keys. Anyone can spend an escrow funded at \
             this address through the 2-of-2 branch. Fine for watching a refund confirm; \
             not valid for criterion 12, which needs a secret to fabricate against."
        );
    }

    let height = retry("height", || chain.height());
    let branch = retry("branch", || chain.consensus_branch_id());
    let policy = EscrowPolicy::mainnet_default();

    match cmd {
        "plan" => {
            let amount_zat: u64 = std::env::var("ZECP2P_AMOUNT_ZAT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(200_000);
            // ZECP2P_REFUND_DELAY lets a regtest run reach T by mining a few
            // blocks instead of 1152. Criterion 13 asks that every height be
            // derived from config, and this is that config.
            let refund_height = match std::env::var("ZECP2P_REFUND_DELAY") {
                Ok(d) => height + d.parse::<u32>().expect("ZECP2P_REFUND_DELAY"),
                Err(_) => policy.proposed_refund_height(height),
            };
            let plan =
                escrow_address(&u_pub, &l_pub, refund_height as u64, amount_zat, addr_network)
                    .expect("escrow address");

            println!("network            : {:?}", network);
            println!("chain height       : {height}");
            println!("consensus branch   : {branch:#010x}");
            println!("u_pub              : {}", hex::encode(u_pub));
            println!("l_pub              : {}", hex::encode(l_pub));
            println!("refund height T    : {refund_height}");
            println!("redeem script      : {}", hex::encode(&plan.redeem_script));
            println!("scriptPubKey       : {}", hex::encode(&plan.script_pubkey));
            println!("amount             : {amount_zat} zat");
            println!("required depth     : {}", required_depth(1_000_000));
            println!();
            println!("FUND THIS ADDRESS  : {}", plan.address);
            println!();
            println!(
                "Send exactly {amount_zat} zat to that address, then run:\n  \
                 escrow_e2e watch <txid> <vout>"
            );
        }

        "watch" => {
            let txid = parse_txid(&args[2]);
            let vout: u32 = args[3].parse().expect("vout");
            let amount_zat: u64 = std::env::var("ZECP2P_AMOUNT_ZAT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(200_000);
            let refund_height: u64 = std::env::var("ZECP2P_REFUND_HEIGHT")
                .expect("set ZECP2P_REFUND_HEIGHT to the T from `plan`")
                .parse()
                .expect("T");

            match retry("utxo", || chain.utxo(&txid, vout)) {
                None => println!("no output at that outpoint yet; the lock is not mined"),
                Some(u) => {
                    let plan = escrow_address(
                        &u_pub,
                        &l_pub,
                        refund_height,
                        amount_zat,
                        addr_network,
                    )
                    .unwrap();
                    println!("confirmations      : {}", u.confirmations);
                    println!("amount             : {} zat", u.amount_zat);
                    println!(
                        "pays our escrow    : {}",
                        u.script_pubkey == plan.script_pubkey
                    );
                    let need = required_depth(1_000_000);
                    println!("depth required     : {need}");
                    println!(
                        "LP may pay         : {}",
                        u.confirmations >= need
                            && policy.may_pay_before(refund_height as u32, height)
                    );
                    println!("refund available at: {refund_height} (now {height})");
                }
            }
        }

        "refund" => {
            let txid = parse_txid(&args[2]);
            let vout: u32 = args[3].parse().expect("vout");
            let dest = &args[4];
            let refund_height: u64 = std::env::var("ZECP2P_REFUND_HEIGHT")
                .expect("set ZECP2P_REFUND_HEIGHT")
                .parse()
                .expect("T");

            let utxo = retry("utxo", || chain.utxo(&txid, vout))
                .expect("the escrow output must exist to refund it");

            let terms = EscrowTerms {
                funding_txid: txid,
                vout,
                amount_zat: utxo.amount_zat,
                u_pub,
                l_pub,
                refund_height,
                consensus_branch_id: branch,
            };
            let redeem = terms.redeem_script().expect("redeem script");
            assert_eq!(
                utxo.script_pubkey,
                terms.script_pubkey().unwrap(),
                "the outpoint does not pay this escrow"
            );

            // A transparent destination, because the shielded output of spec
            // 4.4 needs the wallet tooling described in funding.rs.
            let fee = refund_fee_to_shielded_zat(redeem.len());
            let out_script = p2pkh_from_t_addr(dest);
            let unsigned = build_refund(&terms, &out_script, fee).expect("build refund");
            let digest = unsigned.sighash().expect("sighash");

            let sig = secp.sign_ecdsa(&Message::from_digest(digest), &u_priv);
            let script_sig = refund_script_sig(&encode_signature(&sig), &redeem);
            let raw = serialize_refund(&terms, &out_script, fee, &script_sig).expect("serialize");

            println!("refund nLockTime   : {}", unsigned.lock_time());
            println!("fee                : {fee} zat");
            println!("paying             : {} zat to {dest}", utxo.amount_zat - fee);
            println!("raw                : {}", hex::encode(&raw));

            if height < refund_height as u32 {
                println!();
                println!(
                    "height {height} is before T={refund_height}; the node will refuse this \
                     until T. Broadcasting anyway to record the verdict."
                );
            }
            match chain.broadcast(&raw) {
                Ok(id) => println!("BROADCAST OK, txid : {}", hex::encode(id)),
                Err(e) => println!("node said          : {e}"),
            }
        }

        "release" => {
            eprintln!(
                "the release needs the attestor's scalar; run the attestor service and the LP \
                 daemon. This tool covers the parts that need no Venmo payment."
            );
            std::process::exit(2);
        }

        other => {
            eprintln!("unknown command {other}; try plan, watch or refund");
            std::process::exit(2);
        }
    }
}

fn parse_txid(s: &str) -> [u8; 32] {
    zecp2p_escrow::rpc::rpc_hex_to_txid(s.trim()).expect("txid must be 64 hex characters")
}
