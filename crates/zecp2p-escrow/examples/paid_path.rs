//! The paid path end to end, spec 5.3 through 5.6.
//!
//! This is the leg the regtest run has never exercised: the user pre-signs, the
//! attestor publishes a scalar, the LP decrypts the pre-signature with it, and
//! the resulting signature goes into a release that a node accepts. Until now
//! every release was signed with `u_priv` directly, so the seam between
//! `decrypt_pre_signature`, low-S normalisation and the script interpreter had
//! never been crossed on a real chain.
//!
//! ```text
//! ZECP2P_RPC_URL=http://127.0.0.1:18232 \
//! ZECP2P_ATTESTOR_URL=http://127.0.0.1:8480 \
//! ZECP2P_ATTESTOR_TOKEN=... \
//! ZECP2P_U_PRIV=<64 hex> ZECP2P_L_PRIV=<64 hex> \
//!   cargo run -p zecp2p-escrow --example paid_path -- <funding_txid_internal> <vout> <T> <payee_hash>
//! ```
//!
//! The attestation itself still needs a real Venmo payment through the pinned
//! prover, which is the mainnet leg. For a regtest run the attestor is built
//! with `test-signer` and this tool signs the attestation with the same test
//! key, which proves the plumbing and nothing about the enclave.

use std::time::Duration;

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::ChainClient;
use zecp2p_escrow::dlc::{
    decrypt_pre_signature, outcome_point, pre_sign, recover_outcome_secret,
    verify_outcome_secret, verify_pre_signature,
};
use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::lp_client::{AttestorClient, WireAttestation};
use zecp2p_escrow::payment_details::{
    IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::rpc::{rpc_hex_to_txid, txid_to_rpc_hex, Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::{
    build_release, encode_signature, release_txid, serialize_release, EscrowTerms,
};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

fn key(k: &str) -> SecretKey {
    SecretKey::from_slice(&hex::decode(env(k).trim()).expect("64 hex characters"))
        .expect("a valid secp256k1 scalar")
}

/// Everything a run needs to be resumed.
///
/// R8-1: the runner kept the pre-signature, `s` and the signed release in
/// memory and wrote none of them, so a failure after `/attest` - including the
/// R7-6 case where the node is a block behind at broadcast - lost the only
/// signed release and it could not be rebuilt. The recovery that existed was to
/// sign with `u_priv`, which produces a transaction the chain cannot tell from
/// a decrypted one; on a mainnet criterion 6 run that would look like success
/// and prove nothing.
#[derive(Debug, Serialize, Deserialize)]
struct RunRecord {
    lock_confirmed_ms: u64,
    terms_hash: String,
    event_id: String,
    r: String,
    p: String,
    y: String,
    release_digest: String,
    /// The adaptor pre-signature, so a resumed run decrypts rather than signs.
    pre_signature: String,
    /// Set once the attestor has published it.
    s: Option<String>,
    /// Set once the release is assembled; this is what a resumed run broadcasts.
    raw_release: Option<String>,
    txid: Option<String>,
}

impl RunRecord {
    fn load(path: &str) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn save(&self, path: &str) {
        let text = serde_json::to_string_pretty(self).expect("serialize the run record");
        std::fs::write(path, text).expect("write the run record");
    }
}

/// Base58Check decode of a `t` address, with the checksum enforced.
fn decode_t_address(addr: &str) -> Vec<u8> {
    const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = Vec::new();
    for c in addr.bytes() {
        let mut carry = A.iter().position(|x| *x == c).expect("not base58") as u32;
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
    let (payload, checksum) = full.split_at(full.len() - 4);
    let expected = Sha256::digest(Sha256::digest(payload));
    assert_eq!(checksum, &expected[..4], "address checksum failed: {addr}");

    let hash = &full[2..22];
    if addr.starts_with("t3") || addr.starts_with("t2") {
        let mut v = vec![0xa9, 20];
        v.extend_from_slice(hash);
        v.push(0x87);
        v
    } else {
        p2pkh(hash.try_into().unwrap())
    }
}

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn word_u(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The enclave's 14-word blob for a payment that satisfies these terms.
///
/// On mainnet this comes from `prove_payment_pinned.mjs` after a real Venmo
/// payment, signed by the enclave. Here it is built and signed with the test
/// key, which the attestor must be running `test-signer` to accept.
fn attestation_for(t: &CanonicalTerms, payment_ms: u64) -> (PaymentAttestation, Vec<u8>, Vec<u8>) {
    let details: Vec<u8> = [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(484),
        USD_FIAT_CURRENCY,
        word_u(payment_ms as u128),
        [0x55; 32],
        t.intent_hash(),
        word_u(t.usd_amount_6dec as u128),
        VENMO_PAYMENT_METHOD,
        USD_FIAT_CURRENCY,
        t.payee_hash,
        word_u(t.rate_18dec),
        word_u((t.lock_confirmed_ms / 1000) as u128),
        word_u(1_209_600),
    ]
    .concat();

    let att = PaymentAttestation {
        intent_hash: t.intent_hash(),
        release_amount: t.usd_amount_6dec as u128,
        data_hash: Keccak256::digest(&details).into(),
    };

    let enclave = Sk1::from_slice(&[0xe1; 32]).unwrap();
    let sig = Secp1::new()
        .sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &enclave);
    let (rec_id, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(i32::from(rec_id) as u8 + 27);

    (att, sig_bytes, details)
}

/// The address the test enclave key recovers to, so the attestor can be told to
/// trust it for a regtest run.
fn test_enclave_address() -> [u8; 20] {
    let secp = Secp1::new();
    let key = Sk1::from_slice(&[0xe1; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let h: [u8; 32] = Keccak256::digest(&pubkey.serialize_uncompressed()[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    addr
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() > 1 && a[1] == "enclave-address" {
        println!("{}", hex::encode(test_enclave_address()));
        return;
    }
    let funding_txid = rpc_hex_to_txid(&txid_to_rpc_hex(
        &hex::decode(a[1].trim())
            .expect("txid hex")
            .try_into()
            .expect("32 bytes"),
    ))
    .unwrap();
    let vout: u32 = a[2].parse().expect("vout");
    let refund_height: u64 = a[3].parse().expect("T");
    let payee_hash: [u8; 32] = hex::decode(a[4].trim())
        .expect("payee hash hex")
        .try_into()
        .expect("32 bytes");

    let secp = Secp256k1::new();
    let u_priv = key("ZECP2P_U_PRIV");
    let l_priv = key("ZECP2P_L_PRIV");
    let u_pub = u_priv.public_key(&secp).serialize();
    let l_pub = l_priv.public_key(&secp).serialize();

    // R8-2: the network is read, not assumed, so `check_network` can refuse a
    // mainnet endpoint given a testnet config and vice versa.
    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    let mut cfg = RpcConfig::public(env("ZECP2P_RPC_URL"), network);
    cfg.timeout = Duration::from_secs(45);
    let chain = RpcChainClient::new(cfg).expect("rpc");
    let branch = chain.consensus_branch_id().expect("branch");
    let height = chain.height().expect("height");

    let utxo = chain
        .utxo(&funding_txid, vout)
        .expect("utxo")
        .expect("the escrow must be funded");

    // --- The terms both sides agree, and the transaction they describe.
    // R8-1: `now` here meant a second invocation produced different terms and a
    // 409 from the attestor, so a run that failed after /attest could not be
    // resumed. The record carries it; the environment can pin it.
    let record_path = std::env::var("ZECP2P_RUN_RECORD")
        .unwrap_or_else(|_| "paid-path-run.json".to_string());
    let prior = RunRecord::load(&record_path);
    let now_ms = prior
        .as_ref()
        .map(|r| r.lock_confirmed_ms)
        .or_else(|| {
            std::env::var("ZECP2P_LOCK_CONFIRMED_MS")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        });
    if prior.is_some() {
        println!("resuming from {record_path}");
    }
    let canonical = CanonicalTerms {
        funding_txid,
        vout,
        amount_zat: utxo.amount_zat,
        u_pub,
        l_pub,
        refund_height,
        usd_amount_6dec: std::env::var("ZECP2P_USD_6DEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000),
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash,
        lock_confirmed_ms: now_ms,
    };
    let terms = EscrowTerms {
        funding_txid,
        vout,
        amount_zat: utxo.amount_zat,
        u_pub,
        l_pub,
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

    // R8-2: the payout script was `p2pkh([0x09; 20])`, a hash nobody holds a
    // key for. On mainnet that pays the release to nowhere.
    let lp_script = match std::env::var("ZECP2P_LP_ADDRESS") {
        Ok(addr) => decode_t_address(addr.trim()),
        Err(_) => {
            if network == Network::Main {
                panic!("set ZECP2P_LP_ADDRESS: a mainnet release must pay a real address");
            }
            eprintln!(
                "WARNING: no ZECP2P_LP_ADDRESS; paying a burn script. Testnet only."
            );
            p2pkh([0x09; 20])
        }
    };

    println!("== escrow ==");
    println!("  outpoint     {}:{vout}", txid_to_rpc_hex(&funding_txid));
    println!("  value        {} zat, {} confirmations", utxo.amount_zat, utxo.confirmations);
    println!("  T            {refund_height}   (tip {height})");
    println!("  terms hash   {}", hex::encode(canonical.terms_hash()));
    println!("  intent hash  {}", hex::encode(canonical.intent_hash()));

    // --- 5.1: the LP asks the attestor to announce.
    let attestor = AttestorClient::new(env("ZECP2P_ATTESTOR_URL"), env("ZECP2P_ATTESTOR_TOKEN"))
        .expect("attestor client");
    let (p_hex, build) = attestor.identity().expect("identity");
    println!("== attestor ==");
    println!("  P            {p_hex}");
    println!("  build        {build}");

    let ann = attestor.announce(&canonical).expect("announce");

    // R8-4: the runner computed `Y` from whatever `P` the announcement carried.
    // The client refuses an unpinned key; the runner should exercise that, since
    // it is what stops an LP relaying an announcement from an attestor of its
    // own. `ZECP2P_ATTESTOR_P` is required on mainnet.
    match std::env::var("ZECP2P_ATTESTOR_P") {
        Ok(pinned) => {
            assert_eq!(
                ann.p,
                pinned.trim(),
                "the announcement is from an attestor this run does not trust"
            );
            println!("  P pinned     yes");
        }
        Err(_) => {
            if network == Network::Main {
                panic!("set ZECP2P_ATTESTOR_P: a mainnet run must pin the attestor key");
            }
            println!("  P pinned     NO (testnet only)");
        }
    }
    println!("  event id     {}", ann.event_id);
    println!("  R            {}", ann.r);
    assert_eq!(
        ann.terms_hash,
        hex::encode(canonical.terms_hash()),
        "the attestor pinned different terms than we sent"
    );

    // --- 5.3: the user checks the announcement and pre-signs.
    let r_point = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&ann.r).unwrap()).unwrap();
    let p_point = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&ann.p).unwrap()).unwrap();
    let event_id = zecp2p_escrow::dlc::event_id(&funding_txid, vout);
    assert_eq!(
        hex::encode(event_id),
        ann.event_id,
        "the announcement is for another escrow"
    );

    let y = outcome_point(&secp, &r_point, &p_point, &event_id, &canonical.terms_hash())
        .expect("outcome point");
    let digest = build_release(&terms, &lp_script, fee)
        .unwrap()
        .sighash()
        .unwrap();
    let pre_sig = pre_sign(&secp, &digest, &u_priv, &y);
    verify_pre_signature(&secp, &pre_sig, &digest, &u_priv.public_key(&secp), &y)
        .expect("the LP must be able to verify the pre-signature before it pays");
    println!("== handshake ==");
    println!("  release digest {}", hex::encode(digest));
    println!("  Y              {}", hex::encode(y.serialize()));
    println!("  pre-signature verified against u_pub and Y");

    // Written before the LP pays anything. From here a failure is resumable.
    let mut record = prior.unwrap_or(RunRecord {
        lock_confirmed_ms: now_ms,
        terms_hash: hex::encode(canonical.terms_hash()),
        event_id: ann.event_id.clone(),
        r: ann.r.clone(),
        p: ann.p.clone(),
        y: hex::encode(y.serialize()),
        release_digest: hex::encode(digest),
        pre_signature: hex::encode(pre_sig.as_ref()),
        s: None,
        raw_release: None,
        txid: None,
    });
    record.save(&record_path);
    println!("  run record   {record_path}");

    // R8-5: confirm the announcement still stands immediately before paying. If
    // the attestor lost its store in between, the user has pre-signed under an
    // `R` it no longer holds, and an LP that pays first gets a 404 that is not
    // retryable - out the fiat, with the user refunding at `T`. A repeat
    // announce with the same terms costs nothing and returns the stored `R`.
    let recheck = attestor
        .announce(&canonical)
        .expect("the attestor must still hold this announcement");
    assert_eq!(
        recheck.r, record.r,
        "the attestor no longer holds the R this pre-signature was made against; do not pay"
    );
    println!("  R confirmed before paying");

    // --- 5.4: the LP pays and proves it. On mainnet this is a real Venmo
    //     payment through the pinned prover.
    let (att, att_sig, details) = attestation_for(&canonical, now_ms + 60_000);

    // --- 5.5: the attestor checks and publishes s.
    let s_bytes = attestor
        .attest(
            &ann.event_id,
            &canonical,
            WireAttestation::from_parts(&att, &att_sig, &details),
        )
        .expect("attest");
    let s = SecretKey::from_slice(&s_bytes).expect("s");
    record.s = Some(hex::encode(s_bytes));
    record.save(&record_path);
    println!("== attestation ==");
    println!("  s              {}", hex::encode(s_bytes));

    // --- 5.6: the LP checks s*G == Y, decrypts, and assembles the release.
    verify_outcome_secret(&secp, &s, &y).expect("s*G must equal Y");
    let sig_u_zkp = decrypt_pre_signature(&pre_sig, &s).expect("decrypt");

    // Criterion 6: recover(sig_u, pre_sig, Y) reproduces s.
    let recovered =
        recover_outcome_secret(&secp, &pre_sig, &sig_u_zkp, &y).expect("recover");
    assert_eq!(recovered.secret_bytes(), s_bytes, "recover must reproduce s");
    println!("  s*G == Y       yes");
    println!("  recover(sig_u, pre_sig, Y) reproduces s: yes");

    let sig_u = secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
    let secp1 = Secp1::new();
    let sig_l = secp1.sign_ecdsa(
        &Message::from_digest(digest),
        &Sk1::from_slice(&l_priv.secret_bytes()).unwrap(),
    );
    let script_sig = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &redeem,
    );

    // The pre-broadcast txid, spec 4.2's property.
    let expected = release_txid(&terms, &lp_script, fee, &script_sig).expect("txid");
    let raw = serialize_release(&terms, &lp_script, fee, &script_sig).expect("serialize");
    record.raw_release = Some(hex::encode(&raw));
    record.txid = Some(txid_to_rpc_hex(&expected));
    record.save(&record_path);
    println!("== release ==");
    println!("  fee            {fee} zat");
    println!("  pays           {} zat", utxo.amount_zat - fee);
    println!("  txid before broadcast {}", txid_to_rpc_hex(&expected));

    // R8-3: retry the answers that mean "not yet". The raw transaction is in the
    // record either way, so a give-up here is resumable.
    let policy = zecp2p_escrow::deadlines::EscrowPolicy::mainnet_default();
    match zecp2p_escrow::lp::broadcast_release_until_deadline(
        &chain,
        &policy,
        refund_height as u32,
        &raw,
        || std::thread::sleep(Duration::from_secs(5)),
    ) {
        Ok(id) => {
            println!("  node accepted  {}", txid_to_rpc_hex(&id));
            assert_eq!(
                id, expected,
                "the node's txid must match the one computed before broadcast"
            );
            println!("  txid matched the pre-broadcast computation");
        }
        Err(e) => {
            println!("  node said      {e}");
            println!("  the signed release is in {record_path}; rerun to resume");
        }
    }
}
