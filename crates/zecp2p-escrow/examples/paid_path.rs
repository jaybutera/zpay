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
use zecp2p_escrow::keystore;
use zecp2p_escrow::lp_client::{AttestorClient, WireAttestation};
use zecp2p_escrow::payment_details::{
    IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::rpc::{txid_to_display, Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::{
    build_release, encode_signature, release_txid, serialize_release, EscrowTerms,
};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

/// Everything a run needs to be resumed.
///
/// R8-1: the runner kept the pre-signature, `s` and the signed release in
/// memory and wrote none of them. R9-1: worse, the resume then re-derived the
/// pre-signature instead of reading it back, and `encrypt` draws fresh
/// randomness - so the record and the mined release disagreed and criterion 6
/// became uncheckable. Everything a resume needs is written here, and a resume
/// reads rather than recomputes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunRecord {
    lock_confirmed_ms: u64,
    terms_hash: String,
    event_id: String,
    r: String,
    p: String,
    y: String,
    release_digest: String,
    /// The adaptor pre-signature. Never regenerated (R9-1).
    pre_signature: String,
    /// The LP payout script, so a resume rebuilds the same transaction rather
    /// than whatever the environment says today.
    lp_script: String,
    /// The escrow amount and fee at the time of the first run.
    amount_zat: u64,
    fee_zat: u64,
    /// The outpoint this release must spend, so `verify` can check that the
    /// transaction it read is this escrow's release and not some other
    /// transaction with a two-signature scriptSig (R12-5). Optional so a
    /// record written before this field still loads.
    #[serde(default)]
    funding_txid: Option<String>,
    #[serde(default)]
    funding_vout: Option<u32>,
    /// Set once the attestor has published it.
    s: Option<String>,
    /// Set once the release is assembled; this is what a resumed run broadcasts.
    raw_release: Option<String>,
    txid: Option<String>,
}

impl RunRecord {
    /// Loads a run record, distinguishing "no run yet" from "the run's record
    /// is damaged".
    ///
    /// Round 10: both used to return `None`, so a corrupt record read as a
    /// fresh start. A resume would then draw a new nonce and re-sign, which is
    /// precisely the R9-1 failure the record exists to prevent. A damaged
    /// record stops the run instead.
    fn load(path: &str) -> Option<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                eprintln!("cannot read the run record at {path}: {e}");
                eprintln!("  Refusing to treat an unreadable record as a fresh run.");
                std::process::exit(2);
            }
        };
        match serde_json::from_str(&text) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("the run record at {path} is corrupt: {e}");
                eprintln!();
                eprintln!("  Refusing to start over: this escrow may already have a");
                eprintln!("  pre-signature outstanding, and re-signing with a fresh nonce");
                eprintln!("  would leak the user key if the first signature is also seen.");
                eprintln!("  Restore the record, or refund the escrow at T.");
                std::process::exit(2);
            }
        }
    }

    fn save(&self, path: &str) {
        let text = serde_json::to_string_pretty(self).expect("serialize the run record");
        std::fs::write(path, text).expect("write the run record");
    }
}

fn decode_t_address(addr: &str, network: Network) -> Vec<u8> {
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

    let prefix = [full[0], full[1]];
    let hash: [u8; 20] = full[2..22].try_into().unwrap();

    // Mainnet: t1 = 1cb8 (P2PKH), t3 = 1cbd (P2SH).
    // Testnet: tm = 1d25 (P2PKH), t2 = 1cba (P2SH).
    let (p2pkh_prefix, p2sh_prefix) = match network {
        Network::Main => ([0x1c, 0xb8], [0x1c, 0xbd]),
        Network::Test => ([0x1d, 0x25], [0x1c, 0xba]),
    };

    if prefix == p2pkh_prefix {
        p2pkh(hash)
    } else if prefix == p2sh_prefix {
        let mut v = vec![0xa9, 20];
        v.extend_from_slice(&hash);
        v.push(0x87);
        v
    } else {
        panic!(
            "{addr} has prefix {prefix:02x?}, which is not a {network:?} address. Paying it \
             would send the release somewhere unspendable."
        );
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


/// Loads the prover's export into the shape `/attest` wants.
///
/// R9-3: `paid_path` always built the attestation with the test key, so a
/// production attestor answered 400 and the run stopped *after* the dollar was
/// sent. `prove_payment_pinned.mjs` writes exactly these fields; the fixture at
/// `tests/fixtures/attestation_1000000.json` has the same shape.
fn attestation_from_prover(path: &str) -> WireAttestation {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read the prover's export at {path}: {e}");
        eprintln!();
        eprintln!("  This is the file step 4 writes. If the prover failed, no");
        eprintln!("  attestation exists yet and nothing here can proceed: the release");
        eprintln!("  needs the attestor's scalar, and the attestor needs this file.");
        eprintln!("  Rerun the prover with OUT set to this path.");
        eprintln!();
        eprintln!("  The escrow is untouched and still refunds at T.");
        std::process::exit(2);
    });
    let j: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    let att = &j["attestation"];
    let tv = &att["typedDataValue"];

    let field = |v: &serde_json::Value, name: &str| -> String {
        v[name]
            .as_str()
            .unwrap_or_else(|| panic!("{path} has no attestation.{name}"))
            .trim_start_matches("0x")
            .to_string()
    };

    println!("  prover export  {path}");
    println!("  signer         {}", field(att, "signer"));
    println!("  intent hash    {}", field(tv, "intentHash"));
    println!("  releaseAmount  {}", field(tv, "releaseAmount"));

    WireAttestation {
        intent_hash: field(tv, "intentHash"),
        release_amount: tv["releaseAmount"]
            .as_str()
            .expect("releaseAmount is a decimal string")
            .to_string(),
        data_hash: field(tv, "dataHash"),
        signature: field(att, "signature"),
        encoded_payment_details: field(att, "encodedPaymentDetails"),
    }
}

struct Setup {
    chain: RpcChainClient,
    network: Network,
    secp: Secp256k1<secp256k1_zkp::All>,
    u_priv: SecretKey,
    l_priv: SecretKey,
    terms: EscrowTerms,
    canonical: CanonicalTerms,
    redeem: Vec<u8>,
    fee: u64,
    lp_script: Vec<u8>,
    digest: [u8; 32],
    event_id: [u8; 32],
    record_path: String,
    prior: Option<RunRecord>,
}

/// Everything both subcommands need, derived once so they cannot disagree.
fn setup(args: &[String], allow_create: bool) -> Setup {
    // Round 10 finding 2: every tool now takes the txid in display order - what
    // an explorer, `getblock` and `fund_escrow`'s own output show - and
    // converts internally. This one used to take the reverse, so the same
    // escrow needed two different strings depending on the command.
    let funding_txid = zecp2p_escrow::rpc::txid_from_display(args[2].trim())
        .expect("txid must be 64 hex characters, as an explorer prints it");
    let vout: u32 = args[3].parse().expect("vout");
    let refund_height: u64 = args[4].parse().expect("T");
    let payee_hash: [u8; 32] = hex::decode(args[5].trim())
        .expect("payee hash hex")
        .try_into()
        .expect("32 bytes");

    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    let url = env("ZECP2P_RPC_URL");
    let mut cfg = if url.contains("127.0.0.1") || url.contains("localhost") {
        RpcConfig::public(url, network)
    } else {
        RpcConfig::hosted(url, network)
    };
    cfg.timeout = cfg.timeout.max(Duration::from_secs(45));
    let chain = RpcChainClient::new(cfg).expect("rpc");
    // R13-2: this is the first chain read of every command, and on `attest` it
    // happens after the fiat has been sent. A node outage here used to be a raw
    // panic one call before the resume path, so the operator saw a backtrace
    // rather than the two commands that matter.
    let branch = chain.consensus_branch_id().unwrap_or_else(|e| {
        let shown = args[2].trim();
        eprintln!("cannot reach the node: {e}");
        eprintln!();
        eprintln!("  Nothing has been signed or broadcast by this command, and no");
        eprintln!("  coin has moved. This is the node or the provider, not the escrow.");
        eprintln!();
        eprintln!("  Retry the same command when it answers again:");
        eprintln!("    paid_path attest {shown} {vout} {refund_height} <payee_hash> <attestation.json>");
        eprintln!();
        eprintln!("  The escrow refunds at block {refund_height} with the user key alone:");
        eprintln!("    escrow_e2e refund {shown} {vout} <t1 refund address>");
        std::process::exit(4);
    });

    // R9-2: from the keystore the runbook creates, not only ZECP2P_U_PRIV.
    // R9-7: a mainnet run will not silently create a second pair.
    let create = allow_create && network != Network::Main;
    let (u_priv1, u_from) =
        keystore::from_env("ZECP2P_U_PRIV", "u", [0x11; 32], create).expect("user key");
    let (l_priv1, l_from) =
        keystore::from_env("ZECP2P_L_PRIV", "l", [0x22; 32], create).expect("LP key");
    let u_priv = SecretKey::from_slice(&u_priv1.secret_bytes()).unwrap();
    let l_priv = SecretKey::from_slice(&l_priv1.secret_bytes()).unwrap();
    if network == Network::Main
        && (u_from == keystore::KeyOrigin::Development
            || l_from == keystore::KeyOrigin::Development)
    {
        panic!("refusing to run on mainnet with the public development keys");
    }
    println!("  keys           u: {u_from:?}, l: {l_from:?}");

    let secp = Secp256k1::new();
    let u_pub = u_priv.public_key(&secp).serialize();
    let l_pub = l_priv.public_key(&secp).serialize();

    let record_path = std::env::var("ZECP2P_RUN_RECORD")
        .unwrap_or_else(|_| "paid-path-run.json".to_string());
    let prior = RunRecord::load(&record_path);

    // R9-4: a resume that already holds a signed release must not need the
    // escrow to still be unspent. `gettxout` answers null once the release is
    // mined, and requiring it here made the one path that exists to re-broadcast
    // a held release unreachable - which is the R7-6 case the retry loop was
    // built for. The record carries the amount, so fall back to it.
    let utxo_amount = match chain.utxo(&funding_txid, vout).expect("utxo") {
        Some(u) => {
            assert_eq!(
                u.script_pubkey,
                {
                    let (u_pub2, l_pub2) = (u_pub, l_pub);
                    let t = EscrowTerms {
                        funding_txid,
                        vout,
                        amount_zat: u.amount_zat,
                        u_pub: u_pub2,
                        l_pub: l_pub2,
                        refund_height,
                        consensus_branch_id: branch,
                    };
                    t.script_pubkey().unwrap()
                },
                "the outpoint does not pay this escrow"
            );
            u.amount_zat
        }
        None => match prior.as_ref().map(|r| r.amount_zat) {
            Some(a) => {
                println!("  escrow         already spent; using the recorded amount");
                a
            }
            None => panic!("the escrow must be funded"),
        },
    };

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

    let canonical = CanonicalTerms {
        funding_txid,
        vout,
        amount_zat: utxo_amount,
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
        amount_zat: utxo_amount,
        u_pub,
        l_pub,
        refund_height,
        consensus_branch_id: branch,
    };
    let redeem = terms.redeem_script().expect("redeem");

    // A resume rebuilds the transaction the record describes, not whatever the
    // environment says now (R9-1).
    let fee = prior
        .as_ref()
        .map(|r| r.fee_zat)
        .unwrap_or_else(|| release_fee_to_transparent_zat(redeem.len()));
    let lp_script = match prior.as_ref() {
        Some(r) => hex::decode(&r.lp_script).expect("recorded payout script"),
        None => match std::env::var("ZECP2P_LP_ADDRESS") {
            Ok(addr) => decode_t_address(addr.trim(), network),
            Err(_) => {
                if network == Network::Main {
                    panic!("set ZECP2P_LP_ADDRESS: a mainnet release must pay a real address");
                }
                eprintln!("WARNING: no ZECP2P_LP_ADDRESS; paying a burn script. Testnet only.");
                p2pkh([0x09; 20])
            }
        },
    };

    let digest = build_release(&terms, &lp_script, fee)
        .unwrap()
        .sighash()
        .unwrap();
    let event_id = zecp2p_escrow::dlc::event_id(&funding_txid, vout);

    Setup {
        chain,
        network,
        secp,
        u_priv,
        l_priv,
        terms,
        canonical,
        redeem,
        fee,
        lp_script,
        digest,
        event_id,
        record_path,
        prior,
    }
}

/// Refuses to proceed once the escrow is too close to `T`.
///
/// Round 10 finding 3: an escrow funded 35 blocks before `T` still printed
/// "SEND THE DOLLAR", and a release was accepted 15 blocks past
/// `BROADCAST_DEADLINE`. The runbook had a cutoff; nothing enforced it. Past
/// these heights the run cannot finish, and the money would go out for an
/// escrow that ends in a refund.
fn enforce_deadlines(s: &Setup, stage: &str) {
    let policy = zecp2p_escrow::deadlines::EscrowPolicy::mainnet_default();
    let t = s.terms.refund_height as u32;
    let height = s.chain.height().expect("height");

    let (limit, what) = match stage {
        // `announce` is followed by a Venmo payment, so it is gated on the
        // deadline for paying.
        "announce" => (
            policy.pay_deadline_for_refund_height(t),
            "PAY_DEADLINE: the LP must not send Venmo at or after this height",
        ),
        // `attest` ends in a broadcast.
        _ => (
            policy.broadcast_deadline_for_refund_height(t),
            "BROADCAST_DEADLINE: a release broadcast after this races the refund",
        ),
    };

    println!("  height         {height}  (T {t}, limit {limit})");
    if height >= limit {
        eprintln!();
        eprintln!("REFUSING TO PROCEED.");
        eprintln!("  height {height} is at or past {limit}");
        eprintln!("  {what}");
        eprintln!();
        eprintln!(
            "  The escrow is safe: at height {t} the user key alone refunds it. Run:"
        );
        eprintln!("    escrow_e2e refund <txid> <vout> <t1 refund address>");
        std::process::exit(3);
    }
}

/// Warns, without refusing, that a resumed broadcast now races the refund.
///
/// Spec 4.5: past `BROADCAST_DEADLINE` the user may sweep at `T`, and whichever
/// transaction is mined first wins. Refusing here would strand an LP who has
/// already paid, so this says what is happening instead.
fn warn_if_past_broadcast_deadline(s: &Setup) {
    let policy = zecp2p_escrow::deadlines::EscrowPolicy::mainnet_default();
    let t = s.terms.refund_height as u32;
    let limit = policy.broadcast_deadline_for_refund_height(t);
    let height = match s.chain.height() {
        Ok(h) => h,
        // A resume must still broadcast if the height cannot be read; the
        // release is the LP's only claim on a dollar already sent.
        Err(e) => {
            println!("  height         unknown ({e}); broadcasting anyway");
            return;
        }
    };
    println!("  height         {height}  (T {t}, limit {limit})");
    if height >= limit {
        println!();
        println!("  WARNING: past BROADCAST_DEADLINE {limit}. This release now races the");
        println!("  user's refund, which becomes spendable at {t}. Whichever is mined");
        println!("  first wins. Broadcasting anyway: the payment has already been sent,");
        println!("  and this release is the only claim on it.");
        println!();
    }
}

fn attestor_client() -> AttestorClient {
    AttestorClient::new(env("ZECP2P_ATTESTOR_URL"), env("ZECP2P_ATTESTOR_TOKEN"))
        .expect("attestor client")
}

/// Announces, pre-signs and stops. Nothing is paid.
///
/// R9-3: the operator needs the intent hash *before* sending the dollar, since
/// the prover takes it and an attestation for the wrong intent is refused after
/// the money is gone.
fn cmd_announce(args: &[String]) {
    let s = setup(args, true);
    if let Some(prior) = &s.prior {
        println!("a record already exists at {}", s.record_path);
        println!("  intent hash    {}", prior_intent(prior, &s));
        println!("  event id       {}", prior.event_id);
        println!("nothing to do; run `attest` next");
        return;
    }

    println!("== escrow ==");
    println!("  outpoint       {}:{}", args[2].trim(), s.canonical.vout);
    println!("  value          {} zat", s.canonical.amount_zat);
    println!("  T              {}", s.canonical.refund_height);
    println!("  terms hash     {}", hex::encode(s.canonical.terms_hash()));
    enforce_deadlines(&s, "announce");

    let attestor = attestor_client();
    let (p_hex, build) = attestor.identity().expect("identity");
    println!("== attestor ==");
    println!("  P              {p_hex}");
    println!("  build          {build}");
    if s.network == Network::Main && build.contains("test-signer") {
        panic!("refusing to run on mainnet against a test-signer attestor");
    }
    match std::env::var("ZECP2P_ATTESTOR_P") {
        Ok(pinned) => {
            assert_eq!(p_hex, pinned.trim(), "the attestor is not the pinned one");
            println!("  P pinned       yes");
        }
        Err(_) => {
            if s.network == Network::Main {
                panic!("set ZECP2P_ATTESTOR_P: a mainnet run must pin the attestor key");
            }
            println!("  P pinned       NO (testnet only)");
        }
    }

    let ann = attestor.announce(&s.canonical).expect("announce");
    assert_eq!(
        ann.event_id,
        hex::encode(s.event_id),
        "the announcement is for another escrow"
    );
    assert_eq!(
        ann.terms_hash,
        hex::encode(s.canonical.terms_hash()),
        "the attestor pinned different terms"
    );

    let r_point = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&ann.r).unwrap()).unwrap();
    let p_point = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&ann.p).unwrap()).unwrap();
    let y = outcome_point(
        &s.secp,
        &r_point,
        &p_point,
        &s.event_id,
        &s.canonical.terms_hash(),
    )
    .expect("outcome point");

    let pre_sig = pre_sign(&s.secp, &s.digest, &s.u_priv, &y);
    verify_pre_signature(&s.secp, &pre_sig, &s.digest, &s.u_priv.public_key(&s.secp), &y)
        .expect("the LP must be able to verify the pre-signature before it pays");

    // Written before anything else, and never regenerated (R9-1).
    let record = RunRecord {
        lock_confirmed_ms: s.canonical.lock_confirmed_ms,
        terms_hash: hex::encode(s.canonical.terms_hash()),
        event_id: ann.event_id.clone(),
        r: ann.r.clone(),
        p: ann.p.clone(),
        y: hex::encode(y.serialize()),
        release_digest: hex::encode(s.digest),
        pre_signature: hex::encode(pre_sig.as_ref()),
        lp_script: hex::encode(&s.lp_script),
        amount_zat: s.canonical.amount_zat,
        fee_zat: s.fee,
        funding_txid: Some(txid_to_display(&s.terms.funding_txid)),
        funding_vout: Some(s.canonical.vout),
        s: None,
        raw_release: None,
        txid: None,
    };
    record.save(&s.record_path);

    println!("== handshake ==");
    println!("  R              {}", ann.r);
    println!("  Y              {}", hex::encode(y.serialize()));
    println!("  pre-signature verified and recorded");
    println!("  run record     {}", s.record_path);
    println!();
    println!("== SEND THE DOLLAR, THEN RUN THE PROVER WITH ==");
    println!("  INTENT_HASH          0x{}", hex::encode(s.canonical.intent_hash()));
    println!("  INTENT_AMOUNT        {}", s.canonical.usd_amount_6dec);
    println!("  PAYEE_HASH           0x{}", hex::encode(s.canonical.payee_hash));
    println!("  INTENT_TIMESTAMP_MS  {}", s.canonical.lock_confirmed_ms);
    println!("  INTENT_RATE          {}", s.canonical.rate_18dec);
    println!();
    println!("then: paid_path attest <txid> <vout> <T> <payee_hash> <attestation.json>");
}

fn prior_intent(_prior: &RunRecord, s: &Setup) -> String {
    hex::encode(s.canonical.intent_hash())
}

/// Attests, decrypts and broadcasts. Replays whatever the record already holds.
fn cmd_attest(args: &[String]) {
    let s = setup(args, false);
    let mut record = s
        .prior
        .clone()
        .unwrap_or_else(|| panic!("no run record at {}; run `announce` first", s.record_path));

    // R9-1 step 1 / R9-4: a release already built is broadcast as it stands.
    // The attestor is not needed, which is the point: this is the path the
    // retry loop was built for.
    if let Some(raw_hex) = record.raw_release.clone() {
        let raw = hex::decode(&raw_hex).expect("recorded release");
        println!("== resuming with the release already built ==");
        println!("  txid           {}", record.txid.clone().unwrap_or_default());
        // R11-5: a resume must not refuse - the dollar is already gone, and
        // this release is the only way to be paid for it. But past
        // BROADCAST_DEADLINE it is racing the refund, and the LP should know
        // that before waiting on a confirmation that may never come.
        warn_if_past_broadcast_deadline(&s);
        broadcast(&s, &raw, &record);
        return;
    }

    enforce_deadlines(&s, "attest");

    let y = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&record.y).unwrap())
        .expect("recorded Y");
    let pre_sig =
        secp256k1_zkp::EcdsaAdaptorSignature::from_slice(&hex::decode(&record.pre_signature).unwrap())
            .expect("recorded pre-signature");

    // The recorded pre-signature must still be the one for this release, or the
    // record and the transaction have diverged and criterion 6 is meaningless.
    assert_eq!(
        record.release_digest,
        hex::encode(s.digest),
        "the release digest changed since the record was written"
    );
    verify_pre_signature(
        &s.secp,
        &pre_sig,
        &s.digest,
        &s.u_priv.public_key(&s.secp),
        &y,
    )
    .expect("the recorded pre-signature must verify against the recorded Y");
    println!("  pre-signature  replayed from the record and verified");

    // R9-1 step 2/3: use the recorded scalar if there is one.
    let s_bytes: [u8; 32] = match record.s.clone() {
        Some(hexs) => {
            println!("  s              replayed from the record");
            hex::decode(hexs).unwrap().try_into().unwrap()
        }
        None => {
            // R11-8 / R12-2: read the attestation before touching the network.
            // The check is free and local, while the identity and re-announce
            // calls each spend one of five requests in the hosted endpoint's
            // minute. Discovering a missing file *after* them wasted two calls
            // and, on the staged run, put the rate limit between the operator
            // and a scalar they had already paid for.
            let wire = match args.get(6) {
                Some(path) => Some(attestation_from_prover(path)),
                None => {
                    if s.network == Network::Main {
                        eprintln!(
                            "a mainnet run needs the prover's export: \
                             paid_path attest <txid> <vout> <T> <payee_hash> <attestation.json>"
                        );
                        std::process::exit(2);
                    }
                    None
                }
            };

            let attestor = attestor_client();
            let (p_hex, build) = attestor.identity().expect("identity");
            if s.network == Network::Main && build.contains("test-signer") {
                panic!("refusing to run on mainnet against a test-signer attestor");
            }
            assert_eq!(p_hex, record.p, "the attestor is not the one that announced");

            // R8-5: the announcement must still stand before the scalar is asked for.
            let recheck = attestor.announce(&s.canonical).expect("re-announce");
            assert_eq!(recheck.r, record.r, "the attestor no longer holds this R");

            // R9-3: a real attestation from the prover, or the test key off mainnet.
            let wire = match wire {
                Some(w) => w,
                None => {
                    eprintln!("WARNING: signing the attestation with the test key. Testnet only.");
                    let (att, sig, det) =
                        attestation_for(&s.canonical, s.canonical.lock_confirmed_ms + 60_000);
                    WireAttestation::from_parts(&att, &sig, &det)
                }
            };

            // R12-3: by this point the fiat has been sent. A refusal here must
            // say what to do next, not print a Rust panic and leave the
            // operator to guess whether the money is gone.
            let got = attestor
                .attest(&record.event_id, &s.canonical, wire)
                .unwrap_or_else(|e| {
                    let txid = zecp2p_escrow::rpc::txid_to_display(&s.terms.funding_txid);
                    let vout = s.canonical.vout;
                    let t = s.terms.refund_height;

                    // R13-1: a timeout is not a refusal. The attestor reads the
                    // chain through the same rate-limited endpoint and can be
                    // asleep inside the request; telling the operator to re-run
                    // the prover here sent them to fix something that was not
                    // broken, with the fiat already sent.
                    if matches!(e, zecp2p_escrow::lp_client::LpClientError::TimedOut(_)) {
                        eprintln!("the attestor did not answer in time:");
                        eprintln!("  {e}");
                        eprintln!();
                        eprintln!("  Nothing is wrong with the attestation. The attestor reads the");
                        eprintln!("  chain through the same rate-limited endpoint, so it may still");
                        eprintln!("  be waiting out a limit, and dropping this connection may have");
                        eprintln!("  cancelled its work.");
                        eprintln!();
                        eprintln!("  Do NOT re-run the prover. Wait a minute and run exactly this");
                        eprintln!("  again; the pre-signature in {} is reused.", s.record_path);
                        eprintln!(
                            "    paid_path attest {txid} {vout} {t} <payee_hash> <attestation.json>"
                        );
                        eprintln!();
                        eprintln!("  The escrow has NOT been released and no coin has moved.");
                        eprintln!("  If it still will not complete before block {t}, refund:");
                        eprintln!("    escrow_e2e refund {txid} {vout} <t1 refund address>");
                        std::process::exit(4);
                    }

                    if e.is_retryable() {
                        eprintln!("the attestor could not answer:");
                        eprintln!("  {e}");
                        eprintln!();
                        eprintln!("  This is an availability problem, not a verdict on the");
                        eprintln!("  attestation. Do NOT re-run the prover. Retry the same command:");
                        eprintln!(
                            "    paid_path attest {txid} {vout} {t} <payee_hash> <attestation.json>"
                        );
                        eprintln!();
                        eprintln!("  The escrow has NOT been released. It refunds at block {t}:");
                        eprintln!("    escrow_e2e refund {txid} {vout} <t1 refund address>");
                        std::process::exit(4);
                    }

                    eprintln!("the attestor refused to publish the scalar:");
                    eprintln!("  {e}");
                    eprintln!();
                    eprintln!("  The escrow has NOT been released and no coin has moved.");
                    eprintln!("  The pre-signature and this run's state are saved in");
                    eprintln!("  {}.", s.record_path);
                    eprintln!();
                    eprintln!("  A 4xx means the attestation did not match these terms: usually");
                    eprintln!("  the prover ran with a different INTENT_HASH, amount or payee");
                    eprintln!("  than `announce` printed, or against a different payment. Rerun");
                    eprintln!("  the prover with the values `announce` printed, then:");
                    eprintln!(
                        "    paid_path attest {txid} {vout} {t} <payee_hash> <attestation.json>"
                    );
                    eprintln!();
                    eprintln!("  If it cannot be resolved before block {t}, take the refund:");
                    eprintln!("    escrow_e2e refund {txid} {vout} <t1 refund address>");
                    std::process::exit(3);
                });
            record.s = Some(hex::encode(got));
            record.save(&s.record_path);
            got
        }
    };

    let scalar = SecretKey::from_slice(&s_bytes).expect("s");
    verify_outcome_secret(&s.secp, &scalar, &y).expect("s*G must equal Y");
    let sig_u_zkp = decrypt_pre_signature(&pre_sig, &scalar).expect("decrypt");
    let recovered = recover_outcome_secret(&s.secp, &pre_sig, &sig_u_zkp, &y).expect("recover");
    assert_eq!(recovered.secret_bytes(), s_bytes, "recover must reproduce s");
    println!("== attestation ==");
    println!("  s              {}", hex::encode(s_bytes));
    println!("  s*G == Y       yes");
    println!("  recover(sig_u, pre_sig, Y) reproduces s: yes");

    let sig_u = secp256k1::ecdsa::Signature::from_der(&sig_u_zkp.serialize_der()).unwrap();
    let secp1 = Secp1::new();
    let sig_l = secp1.sign_ecdsa(
        &Message::from_digest(s.digest),
        &Sk1::from_slice(&s.l_priv.secret_bytes()).unwrap(),
    );
    let script_sig = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &s.redeem,
    );
    let expected = release_txid(&s.terms, &s.lp_script, s.fee, &script_sig).expect("txid");
    let raw = serialize_release(&s.terms, &s.lp_script, s.fee, &script_sig).expect("serialize");

    record.raw_release = Some(hex::encode(&raw));
    record.txid = Some(txid_to_display(&expected));
    record.save(&s.record_path);

    println!("== release ==");
    println!("  fee            {} zat", s.fee);
    println!("  pays           {} zat", s.canonical.amount_zat - s.fee);
    println!("  txid           {}", txid_to_display(&expected));
    broadcast(&s, &raw, &record);
}

fn broadcast(s: &Setup, raw: &[u8], record: &RunRecord) {
    let policy = zecp2p_escrow::deadlines::EscrowPolicy::mainnet_default();
    match zecp2p_escrow::lp::broadcast_release_until_deadline(
        &s.chain,
        &policy,
        s.terms.refund_height as u32,
        raw,
        || std::thread::sleep(Duration::from_secs(15)),
    ) {
        Ok(id) => {
            println!("  node accepted  {}", txid_to_display(&id));
            println!();
            println!("verify criterion 6 once it is mined:");
            println!(
                "  paid_path verify {} {}",
                s.record_path,
                txid_to_display(&id)
            );
        }
        Err(e) => {
            println!("  node said      {e}");
            let retryable = matches!(&e, zecp2p_escrow::lp::LpError::Chain(c) if c.is_retryable());
            if retryable {
                println!("  This is not a verdict: the node cannot judge it yet, or could not");
                println!("  be reached. The signed release is in {}.", s.record_path);
                println!("  Rerun `attest` to resend; it replays the same bytes.");
            } else {
                println!("  The chain refused this release. The signed bytes are in {}.", s.record_path);
                println!("  Rerunning `attest` will resend the same transaction and get the");
                println!("  same answer; the escrow refunds at T={}.", s.terms.refund_height);
            }
            let _ = record;
        }
    }
}

/// Criterion 6 against the mined transaction, not the runner's own assertion.
///
/// R9-1 step 5: takes `sig_u` out of the scriptSig of the transaction the chain
/// actually holds, recovers with the recorded pre-signature and `Y`, and
/// compares to the recorded `s`. A release signed directly with `u_priv` fails
/// this; that is the whole point.
fn cmd_verify(args: &[String]) {
    let record = RunRecord::load(&args[2])
        .unwrap_or_else(|| panic!("no run record at {}", args[2]));
    let txid_rpc = args[3].trim();

    let network = match std::env::var("ZECP2P_RPC_NETWORK").as_deref() {
        Ok("main") => Network::Main,
        _ => Network::Test,
    };
    let url = env("ZECP2P_RPC_URL");
    let cfg = if url.contains("127.0.0.1") || url.contains("localhost") {
        RpcConfig::public(url, network)
    } else {
        RpcConfig::hosted(url, network)
    };
    let chain = RpcChainClient::new(cfg).expect("rpc");

    let details = chain.release_details(txid_rpc).unwrap_or_else(|e| {
        eprintln!("cannot read the release {txid_rpc}: {e}");
        eprintln!();
        eprintln!("  `verify` reads the transaction the chain holds, so it only works");
        eprintln!("  once the release is mined. Give it the txid `attest` printed, in");
        eprintln!("  the order shown, and wait for a confirmation.");
        std::process::exit(2);
    });
    let script_sig = details.script_sig.clone();

    // R11-8 / R12-5: criterion 6 is about *this* escrow's release. Without
    // these, any transaction whose first input carried a two-signature
    // scriptSig would satisfy the recovery below, and a green
    // `CRITERION 6 HOLDS` would prove nothing about where the coin went.
    let mut checked = Vec::new();
    if let Some(want_txid) = record.funding_txid.as_deref() {
        let got = details.spends_txid.as_deref().unwrap_or("");
        if !got.eq_ignore_ascii_case(want_txid) {
            eprintln!("this transaction does not spend the escrow.");
            eprintln!("  it spends  {got}");
            eprintln!("  escrow is  {want_txid}");
            std::process::exit(2);
        }
        if let (Some(want_vout), Some(got_vout)) = (record.funding_vout, details.spends_vout) {
            if want_vout != got_vout {
                eprintln!("this transaction spends vout {got_vout}, the escrow is vout {want_vout}.");
                std::process::exit(2);
            }
        }
        checked.push("spends the escrow outpoint");
    }

    let want_script = hex::decode(&record.lp_script).unwrap_or_default();
    if !want_script.is_empty() {
        if details.pays_script_pubkey != want_script {
            eprintln!("this transaction does not pay the agreed LP script.");
            eprintln!("  pays       {}", hex::encode(&details.pays_script_pubkey));
            eprintln!("  agreed     {}", hex::encode(&want_script));
            std::process::exit(2);
        }
        checked.push("pays the agreed LP script");
    }

    let want_zat = record.amount_zat.saturating_sub(record.fee_zat);
    if details.pays_zat != want_zat {
        eprintln!("this transaction pays {} zat, the terms say {want_zat}.", details.pays_zat);
        std::process::exit(2);
    }
    checked.push("pays the agreed amount");

    // scriptSig is OP_0 <sig_u> <sig_l> OP_1 <redeem>; sig_u is the first push.
    let len = script_sig[1] as usize;
    let der = &script_sig[2..2 + len - 1]; // drop the sighash byte
    let sig_u = secp256k1_zkp::ecdsa::Signature::from_der(der).expect("sig_u from the chain");

    let secp = Secp256k1::new();
    let y = secp256k1_zkp::PublicKey::from_slice(&hex::decode(&record.y).unwrap()).unwrap();
    let pre_sig = secp256k1_zkp::EcdsaAdaptorSignature::from_slice(
        &hex::decode(&record.pre_signature).unwrap(),
    )
    .expect("recorded pre-signature");

    println!("mined txid     {txid_rpc}");
    for c in &checked {
        println!("  checked      {c}");
    }
    println!("record         {}", args[2]);
    match recover_outcome_secret(&secp, &pre_sig, &sig_u, &y) {
        Ok(rec) => {
            let expected = record.s.clone().expect("the record has no s");
            let got = hex::encode(rec.secret_bytes());
            println!("recovered s    {got}");
            println!("recorded  s    {expected}");
            if got == expected {
                println!();
                println!("CRITERION 6 HOLDS: the mined signature is the decrypted pre-signature.");
            } else {
                println!();
                println!("MISMATCH: recovery gave a different scalar.");
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!();
            println!("CRITERION 6 FAILS: recovery from the mined signature did not work ({e}).");
            println!("The release was not produced by decrypting the recorded pre-signature.");
            std::process::exit(1);
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("enclave-address") => println!("{}", hex::encode(test_enclave_address())),
        Some("announce") => cmd_announce(&a),
        Some("attest") => cmd_attest(&a),
        Some("verify") => cmd_verify(&a),
        _ => {
            eprintln!("usage:");
            eprintln!("  paid_path announce <txid> <vout> <T> <payee_hash>");
            eprintln!("  paid_path attest   <txid> <vout> <T> <payee_hash> [attestation.json]");
            eprintln!("  paid_path verify   <record.json> <mined_txid>");
            std::process::exit(2);
        }
    }
}
