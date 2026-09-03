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
use zecp2p_escrow::fees::refund_fee_to_transparent_zat;
use zecp2p_escrow::address::{script_pubkey_for, AddrNetwork, AddressError};
use zecp2p_escrow::keystore::{self, KeyOrigin};
use zecp2p_escrow::funding::{escrow_address, AddressNetwork};
use zecp2p_escrow::rpc::{txid_to_display, Network, RpcChainClient, RpcConfig};
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

/// Resolves a key through the shared keystore.
///
/// Spec section 2 wants an ephemeral key per escrow. `ZECP2P_KEYSTORE` plus
/// `ZECP2P_ESCROW_LABEL` gives that: a fresh key the first time a label is
/// seen, the same key on every resume, written 0600 before it is returned.
///
/// `allow_create` is false for every command that spends an existing escrow.
/// Creating a key there would silently derive a *different* address from the
/// one holding the coin, and the refund would sign for an escrow that does not
/// exist. `KeystoreError::WouldCreate` says which file was missing instead.
fn key(
    var: &str,
    label_suffix: &str,
    fallback: [u8; 32],
    allow_create: bool,
    minting_command: bool,
) -> (SecretKey, KeyOrigin) {
    match keystore::from_env(var, label_suffix, fallback, allow_create) {
        Ok(pair) => pair,
        Err(keystore::KeystoreError::WouldCreate { path }) => {
            eprintln!("refusing to create a key.");
            eprintln!("  missing: {path}");
            eprintln!();
            if minting_command {
                // `plan` under a mainnet configuration.
                eprintln!("  On mainnet `plan` only ever loads an existing pair. Creating one");
                eprintln!("  here would print a different, equally confident-looking address");
                eprintln!("  from the one that was funded, so a mistyped ZECP2P_ESCROW_LABEL");
                eprintln!("  cannot silently reprint the ask's address.");
            } else {
                eprintln!("  This escrow was funded against a key that already exists. Creating a");
                eprintln!("  new one would derive a different address and sign for the wrong");
                eprintln!("  escrow.");
            }
            eprintln!();
            eprintln!("  Point ZECP2P_KEYSTORE/ZECP2P_ESCROW_LABEL at the original keystore,");
            eprintln!("  or set {var} to the original key.");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("keystore: {e}");
            std::process::exit(2);
        }
    }
}

fn client() -> (RpcChainClient, Network) {
    let url = std::env::var("ZECP2P_RPC_URL").expect("set ZECP2P_RPC_URL");
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    // A hosted endpoint needs a longer broadcast budget than a local node; see
    // `RpcConfig::hosted`.
    let mut cfg = if url.contains("127.0.0.1") || url.contains("localhost") {
        RpcConfig::public(url, network)
    } else {
        RpcConfig::hosted(url, network)
    };
    cfg.timeout = cfg.timeout.max(Duration::from_secs(45));
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

/// Decodes a spend destination, refusing anything the library's address
/// rules reject. The rules live in `zecp2p_escrow::address` so they can be
/// unit-tested without a mainnet node.
fn p2pkh_from_t_addr(addr: &str, network: Network) -> Vec<u8> {
    let want = match network {
        Network::Main => AddrNetwork::Main,
        Network::Test => AddrNetwork::Test,
    };
    match script_pubkey_for(addr, want) {
        Ok(spk) => spk,
        Err(e) => {
            eprintln!("refusing to build a transaction paying {addr}:");
            eprintln!("  {e}");
            if matches!(e, AddressError::WrongNetwork { .. }) {
                eprintln!();
                eprintln!("  It would confirm and pay a hash nobody holds a key for.");
            }
            std::process::exit(2);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("plan");

    // `plan` is the only command that may mint keys; everything else spends an
    // escrow that already exists.
    // R11-4: `plan` may mint a pair on testnet, where a fresh escrow is the
    // point. On mainnet the pair already exists and a mistyped
    // ZECP2P_ESCROW_LABEL would otherwise print a *different* t3 address with
    // the same confidence as the real one, which is the address the ask asks
    // Casper to fund. Read the configured network straight from the
    // environment: this decision must not depend on reaching a node.
    let configured_main = matches!(std::env::var("ZECP2P_RPC_NETWORK").as_deref(), Ok("main"));
    let allow_create = cmd == "plan" && !configured_main;
    let minting_command = cmd == "plan";
    let (u_priv, u_from) = key("ZECP2P_U_PRIV", "u", DEV_U, allow_create, minting_command);

    // R11-8: the refund signs only with `u`, but needs `l_pub` to rebuild the
    // redeem script. Deriving it from the LP *secret* made the user's exit
    // depend on a key the user does not control losing nothing. ZECP2P_L_PUB
    // supplies the public half directly, so a lost or withheld LP key file
    // cannot strand the escrow.
    let l_pub_override = std::env::var("ZECP2P_L_PUB").ok().map(|h| {
        let b = hex::decode(h.trim()).expect("ZECP2P_L_PUB must be 66 hex characters");
        let arr: [u8; 33] = b
            .try_into()
            .expect("ZECP2P_L_PUB must be a 33-byte compressed public key");
        PublicKey::from_slice(&arr).expect("ZECP2P_L_PUB must be a valid secp256k1 point");
        arr
    });
    let refund_only = cmd == "refund";
    let (l_priv, l_from) = if refund_only && l_pub_override.is_some() {
        // Never used to sign on this path; the refund's scriptSig carries only
        // the user's signature.
        (SecretKey::from_slice(&DEV_L).unwrap(), KeyOrigin::Development)
    } else {
        key("ZECP2P_L_PRIV", "l", DEV_L, allow_create, minting_command)
    };
    let u_dev = u_from == KeyOrigin::Development;
    let l_dev = l_from == KeyOrigin::Development && l_pub_override.is_none();
    println!("keys               : u: {u_from:?}, l: {l_from:?}");
    let secp = Secp256k1::new();
    let u_pub = PublicKey::from_secret_key(&secp, &u_priv).serialize();
    let l_pub = l_pub_override.unwrap_or_else(|| PublicKey::from_secret_key(&secp, &l_priv).serialize());

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
            // `ZECP2P_REFUND_HEIGHT` pins T outright. Without it T moves with
            // every block, and so does the escrow address - which is no use for
            // a funding instruction someone has to act on later.
            let refund_height = match (
                std::env::var("ZECP2P_REFUND_HEIGHT"),
                std::env::var("ZECP2P_REFUND_DELAY"),
            ) {
                (Ok(t), _) => t.parse::<u32>().expect("ZECP2P_REFUND_HEIGHT"),
                (Err(_), Ok(d)) => height + d.parse::<u32>().expect("ZECP2P_REFUND_DELAY"),
                _ => policy.proposed_refund_height(height),
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
            // 4.4 needs the wallet tooling described in funding.rs - so the
            // fee is the transparent one. Paying the shielded number here
            // overpays for actions the transaction does not have (R7-2).
            let fee = refund_fee_to_transparent_zat(redeem.len());
            let out_script = p2pkh_from_t_addr(dest, network);
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
                Ok(id) => println!("BROADCAST OK, txid : {}", txid_to_display(&id)),
                Err(e) => println!("node said          : {e}"),
            }
        }

        "release" => {
            // R8-1: do not add direct signing here, however convenient it looks
            // as a recovery path. A release signed with `u_priv` is
            // indistinguishable on chain from one signed by decrypting the
            // pre-signature, so a mainnet criterion 6 run that fell back to it
            // would look successful and prove nothing. Recovery belongs in
            // `paid_path resume`, which replays from the run record and can
            // only produce the decrypted signature.
            eprintln!(
                "the release needs the attestor's scalar. Run `paid_path`, and `paid_path \
                 resume` if it failed partway. This tool deliberately cannot sign a release \
                 with u_priv: that would produce a transaction the chain cannot tell from a \
                 decrypted one, and criterion 6 would be unfalsifiable."
            );
            std::process::exit(2);
        }

        other => {
            eprintln!("unknown command {other}; try plan, watch or refund");
            std::process::exit(2);
        }
    }
}

/// Display order, the same as every other tool (round 10 finding 2).
fn parse_txid(s: &str) -> [u8; 32] {
    zecp2p_escrow::rpc::txid_from_display(s.trim())
        .expect("txid must be 64 hex characters, as an explorer prints it")
}
