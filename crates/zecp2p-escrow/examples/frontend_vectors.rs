//! Vectors for the page's hand-written escrow crypto, and the check of what
//! the page produced.
//!
//! `frontend/app/escrow.js` re-implements, in the browser, the user's half of
//! the protocol: the redeem script, the t3 address, the ZIP 244 digest, the
//! canonical terms, the outcome point, the adaptor pre-signature and the
//! refund. Each of those fails silently when it is wrong. A digest one byte
//! off yields a pre-signature the LP verifies happily against the wrong
//! message, and the LP discovers the mismatch after it has paid the dollars.
//!
//! So this example is the referee. `emit` prints, from fixed inputs, every
//! intermediate value this crate computes. The node test recomputes them and
//! compares. `check` takes what the page then produced - a pre-signature, a
//! signed refund, a completed release - and runs it through the same
//! functions the LP and the attestor run: `verify_pre_signature`, adaptor
//! decryption with a real outcome scalar, `txid_of_signed`, and the consensus
//! script interpreter zebrad links.
//!
//! ```text
//! cargo run -p zecp2p-escrow --example frontend_vectors -- emit > /tmp/vectors.json
//! node frontend/app/test/escrow-vectors.js /tmp/vectors.json /tmp/js-out.json
//! cargo run -p zecp2p-escrow --example frontend_vectors -- check /tmp/vectors.json /tmp/js-out.json
//! ```

use secp256k1_zkp::{EcdsaAdaptorSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use zcash_script::interpreter::{CallbackTransactionSignatureChecker, Flags, SignatureChecker};
use zcash_script::script::{self, Code};
use zcash_script::Script;

use zecp2p_escrow::address::{script_pubkey_for, AddrNetwork};
use zecp2p_escrow::dlc::{
    decrypt_pre_signature, event_id, outcome_point, recover_outcome_secret, sign_outcome,
    verify_outcome_secret, verify_pre_signature,
};
use zecp2p_escrow::fees::{refund_fee_to_transparent_zat, release_fee_zat};
use zecp2p_escrow::funding::{escrow_address, AddressNetwork};
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::treasury::platform_fee_zat;
use zecp2p_escrow::tx::{
    build_refund, build_release_split, serialize_refund, serialize_release_split, txid_of_signed,
    EscrowTerms, ReleaseSplit,
};

const LP_ADDRESS: &str = "t1JmKjw3HJKgx9BY18BGC6MYqPSbqfCrRPU";
const TREASURY_ADDRESS: &str = "t1dSuQrrrSUbeQsbzH9LmVqT8BZibPagj4B";
const REFUND_TO: &str = "t1JmKjw3HJKgx9BY18BGC6MYqPSbqfCrRPU";

#[derive(Serialize, Deserialize)]
struct Inputs {
    u_priv: String,
    l_priv: String,
    attestor_d: String,
    attestor_k: String,
    funding_txid: String,
    vout: u32,
    amount_zat: u64,
    refund_height: u64,
    consensus_branch_id: u32,
    usd_amount_6dec: u64,
    payee_hash: String,
    lock_confirmed_ms: u64,
    lp_address: String,
    treasury_address: String,
    refund_to: String,
    network: String,
}

#[derive(Serialize, Deserialize)]
struct Expected {
    u_pub: String,
    l_pub: String,
    redeem_script: String,
    script_pubkey: String,
    address: String,
    lp_script: String,
    treasury_script: String,
    refund_script: String,
    platform_fee_zat: u64,
    miner_fee_zat: u64,
    refund_fee_zat: u64,
    canonical_json: String,
    terms_hash: String,
    intent_hash: String,
    event_id: String,
    attestor_p: String,
    attestor_r: String,
    outcome_point: String,
    outcome_secret: String,
    release_digest: String,
    refund_digest: String,
    release_txid: String,
    refund_txid: String,
    /// Serialized with a one-byte placeholder scriptSig, so the page's byte
    /// layout can be compared before any signature exists.
    release_raw_placeholder: String,
    refund_raw_placeholder: String,
}

#[derive(Serialize, Deserialize)]
struct Vectors {
    inputs: Inputs,
    expected: Expected,
}

/// What the page produced from the same inputs.
#[derive(Deserialize)]
struct JsOutput {
    pre_signature: String,
    release_script_sig: String,
    release_raw: String,
    release_txid: String,
    refund_script_sig: String,
    refund_raw: String,
    refund_txid: String,
}

fn sk(hex: &str) -> SecretKey {
    SecretKey::from_slice(&hex::decode(hex).unwrap()).unwrap()
}

fn h32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn inputs() -> Inputs {
    use sha2::{Digest, Sha256};
    Inputs {
        u_priv: "11".repeat(32),
        l_priv: "22".repeat(32),
        attestor_d: "d1".repeat(32),
        attestor_k: "4b".repeat(32),
        funding_txid: hex::encode(Sha256::digest(b"zpay frontend vector funding")),
        vout: 0,
        amount_zat: 200_000,
        refund_height: 3_472_000,
        consensus_branch_id: 0x37a5_165b,
        usd_amount_6dec: 1_500_000,
        payee_hash: "85".repeat(32),
        lock_confirmed_ms: 1_756_919_460_000,
        lp_address: LP_ADDRESS.into(),
        treasury_address: TREASURY_ADDRESS.into(),
        refund_to: REFUND_TO.into(),
        network: "main".into(),
    }
}

struct Built {
    secp: Secp256k1<secp256k1_zkp::All>,
    u_pub: PublicKey,
    terms: EscrowTerms,
    canonical: CanonicalTerms,
    split: ReleaseSplit,
    refund_script: Vec<u8>,
    refund_fee: u64,
    event: [u8; 32],
    r: PublicKey,
    p: PublicKey,
    y: PublicKey,
    s: SecretKey,
    release_digest: [u8; 32],
    refund_digest: [u8; 32],
}

fn build(i: &Inputs) -> Built {
    let secp = Secp256k1::new();
    let u_priv = sk(&i.u_priv);
    let l_priv = sk(&i.l_priv);
    let d = sk(&i.attestor_d);
    let k = sk(&i.attestor_k);
    let u_pub = PublicKey::from_secret_key(&secp, &u_priv);
    let l_pub = PublicKey::from_secret_key(&secp, &l_priv);

    let funding_txid = h32(&i.funding_txid);
    let lp_script = script_pubkey_for(&i.lp_address, AddrNetwork::Main).unwrap();
    let treasury_script = script_pubkey_for(&i.treasury_address, AddrNetwork::Main).unwrap();
    let refund_script = script_pubkey_for(&i.refund_to, AddrNetwork::Main).unwrap();
    let fee = platform_fee_zat(i.amount_zat, zecp2p_escrow::treasury::PLATFORM_FEE_BPS);

    let terms = EscrowTerms {
        funding_txid,
        vout: i.vout,
        amount_zat: i.amount_zat,
        u_pub: u_pub.serialize(),
        l_pub: l_pub.serialize(),
        refund_height: i.refund_height,
        consensus_branch_id: i.consensus_branch_id,
    };
    let redeem = terms.redeem_script().unwrap();
    let n_outputs = if fee > 0 { 2 } else { 1 };
    let miner_fee = release_fee_zat(redeem.len(), n_outputs);
    let refund_fee = refund_fee_to_transparent_zat(redeem.len());

    let canonical = CanonicalTerms {
        funding_txid,
        vout: i.vout,
        amount_zat: i.amount_zat,
        u_pub: u_pub.serialize(),
        l_pub: l_pub.serialize(),
        refund_height: i.refund_height,
        usd_amount_6dec: i.usd_amount_6dec,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: h32(&i.payee_hash),
        lock_confirmed_ms: i.lock_confirmed_ms,
        platform_fee_zat: fee,
        treasury_script: if fee > 0 { treasury_script } else { Vec::new() },
    };
    let split = ReleaseSplit {
        payout_script: lp_script,
        miner_fee_zat: miner_fee,
        platform_fee_zat: fee,
        treasury_script: canonical.treasury_script.clone(),
    };

    let event = event_id(&funding_txid, i.vout);
    let r = PublicKey::from_secret_key(&secp, &k);
    let p = PublicKey::from_secret_key(&secp, &d);
    let th = canonical.terms_hash();
    let y = outcome_point(&secp, &r, &p, &event, &th).unwrap();
    let s = sign_outcome(&secp, &k, &d, &event, &th).unwrap();
    verify_outcome_secret(&secp, &s, &y).unwrap();

    let release_digest = build_release_split(&terms, &split).unwrap().sighash().unwrap();
    let refund_digest = build_refund(&terms, &refund_script, refund_fee)
        .unwrap()
        .sighash()
        .unwrap();

    Built {
        secp,
        u_pub,
        terms,
        canonical,
        split,
        refund_script,
        refund_fee,
        event,
        r,
        p,
        y,
        s,
        release_digest,
        refund_digest,
    }
}

fn emit() {
    let i = inputs();
    let b = build(&i);
    let redeem = b.terms.redeem_script().unwrap();
    let plan = escrow_address(
        &b.terms.u_pub,
        &b.terms.l_pub,
        b.terms.refund_height,
        b.terms.amount_zat,
        AddressNetwork::Main,
    )
    .unwrap();
    assert_eq!(plan.script_pubkey, p2sh_script_pubkey(&redeem_script(&b.terms.u_pub, &b.terms.l_pub, b.terms.refund_height).unwrap()));

    let placeholder = [0x00u8];
    let release_raw = serialize_release_split(&b.terms, &b.split, &placeholder).unwrap();
    let refund_raw = serialize_refund(&b.terms, &b.refund_script, b.refund_fee, &placeholder).unwrap();

    let expected = Expected {
        u_pub: hex::encode(b.terms.u_pub),
        l_pub: hex::encode(b.terms.l_pub),
        redeem_script: hex::encode(&redeem),
        script_pubkey: hex::encode(&plan.script_pubkey),
        address: plan.address,
        lp_script: hex::encode(&b.split.payout_script),
        treasury_script: hex::encode(&b.split.treasury_script),
        refund_script: hex::encode(&b.refund_script),
        platform_fee_zat: b.split.platform_fee_zat,
        miner_fee_zat: b.split.miner_fee_zat,
        refund_fee_zat: b.refund_fee,
        canonical_json: b.canonical.canonical_json(),
        terms_hash: hex::encode(b.canonical.terms_hash()),
        intent_hash: hex::encode(b.canonical.intent_hash()),
        event_id: hex::encode(b.event),
        attestor_p: hex::encode(b.p.serialize()),
        attestor_r: hex::encode(b.r.serialize()),
        outcome_point: hex::encode(b.y.serialize()),
        outcome_secret: hex::encode(b.s.secret_bytes()),
        release_digest: hex::encode(b.release_digest),
        refund_digest: hex::encode(b.refund_digest),
        release_txid: hex::encode(txid_of_signed(&release_raw).unwrap()),
        refund_txid: hex::encode(txid_of_signed(&refund_raw).unwrap()),
        release_raw_placeholder: hex::encode(&release_raw),
        refund_raw_placeholder: hex::encode(&refund_raw),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&Vectors { inputs: i, expected }).unwrap()
    );
}

fn consensus_flags() -> Flags {
    Flags::P2SH
        | Flags::StrictEnc
        | Flags::LowS
        | Flags::NullDummy
        | Flags::SigPushOnly
        | Flags::MinimalData
        | Flags::CleanStack
        | Flags::CHECKLOCKTIMEVERIFY
}

fn checker(digest: [u8; 32], lock_time: i64) -> CallbackTransactionSignatureChecker<'static> {
    let cb: &'static dyn Fn(&Code, &zcash_script::signature::HashType) -> Option<[u8; 32]> =
        Box::leak(Box::new(move |_: &Code, _: &zcash_script::signature::HashType| Some(digest)));
    CallbackTransactionSignatureChecker {
        sighash: cb,
        lock_time,
        is_final: false,
    }
}

fn eval(script_sig: &[u8], script_pubkey: &[u8], checker: &dyn SignatureChecker) -> bool {
    let sig = script::Component::parse(&Code(script_sig.to_vec()));
    let pk = script::Component::parse(&Code(script_pubkey.to_vec()));
    let (sig, pk) = match (sig, pk) {
        (Ok(s), Ok(p)) => (s, p),
        _ => return false,
    };
    let s: Script<zcash_script::opcode::PossiblyBad, zcash_script::opcode::PossiblyBad> =
        Script { sig, pub_key: pk };
    s.eval(consensus_flags(), checker).unwrap_or(false)
}

fn check(vectors_path: &str, js_path: &str) {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(vectors_path).unwrap()).unwrap();
    let js: JsOutput = serde_json::from_str(&std::fs::read_to_string(js_path).unwrap()).unwrap();
    let b = build(&v.inputs);
    let spk = b.terms.script_pubkey().unwrap();
    let mut failures = 0;
    let mut report = |name: &str, ok: bool| {
        println!("{} {}", if ok { "ok  " } else { "FAIL" }, name);
        if !ok {
            failures += 1;
        }
    };

    // 1. The pre-signature, through the LP's own check.
    let pre = EcdsaAdaptorSignature::from_slice(&hex::decode(&js.pre_signature).unwrap())
        .expect("the page's pre-signature parses as libsecp256k1-zkp's format");
    report(
        "verify_pre_signature accepts the page's pre-signature",
        verify_pre_signature(&b.secp, &pre, &b.release_digest, &b.u_pub, &b.y).is_ok(),
    );
    let mut wrong = b.release_digest;
    wrong[0] ^= 1;
    report(
        "verify_pre_signature rejects it over a changed digest",
        verify_pre_signature(&b.secp, &pre, &wrong, &b.u_pub, &b.y).is_err(),
    );

    // 2. Decrypting with the real outcome scalar yields the user's signature.
    let sig_u = decrypt_pre_signature(&pre, &b.s).expect("decrypts");
    let mut norm = sig_u;
    norm.normalize_s();
    report(
        "the decrypted signature verifies under u_pub over the release digest",
        b.secp
            .verify_ecdsa(&Message::from_digest(b.release_digest), &norm, &b.u_pub)
            .is_ok(),
    );
    let recovered = recover_outcome_secret(&b.secp, &pre, &sig_u, &b.y).expect("recovers");
    report(
        "recover_outcome_secret gives back the attestor's scalar",
        recovered.secret_bytes() == b.s.secret_bytes(),
    );

    // 3. The release the page's LP-side (the mock) assembled.
    let release_raw = hex::decode(&js.release_raw).unwrap();
    let txid = txid_of_signed(&release_raw).expect("the page's release parses as a v5 transaction");
    report("the release txid matches the page's", hex::encode(txid) == js.release_txid);
    report(
        "the release txid matches this crate's",
        hex::encode(txid) == v.expected.release_txid,
    );
    let ss = hex::decode(&js.release_script_sig).unwrap();
    report(
        "the interpreter accepts the release scriptSig (2-of-2 branch)",
        eval(&ss, &spk, &checker(b.release_digest, 0)),
    );

    // 4. The refund the page signed alone.
    let refund_raw = hex::decode(&js.refund_raw).unwrap();
    let rtxid = txid_of_signed(&refund_raw).expect("the page's refund parses as a v5 transaction");
    report("the refund txid matches the page's", hex::encode(rtxid) == js.refund_txid);
    report(
        "the refund txid matches this crate's",
        hex::encode(rtxid) == v.expected.refund_txid,
    );
    let rss = hex::decode(&js.refund_script_sig).unwrap();
    let t = b.terms.refund_height as i64;
    report(
        "the interpreter accepts the refund scriptSig at T",
        eval(&rss, &spk, &checker(b.refund_digest, t)),
    );
    report(
        "the interpreter rejects the refund scriptSig at T - 1",
        !eval(&rss, &spk, &checker(b.refund_digest, t - 1)),
    );

    let _ = &b.canonical;
    if failures > 0 {
        eprintln!("{failures} check(s) failed");
        std::process::exit(1);
    }
    println!("all checks passed");
}

/// A release the browser and the mock LP assembled between them, with keys
/// the page drew at random.
///
/// Unlike `check`, nothing here is a fixed vector: the digest is recomputed
/// from the terms alone, so the page's own digest is not trusted, and then the
/// scriptSig the two JavaScript halves produced is run through the consensus
/// interpreter against that digest. It is how a run of the mock is promoted
/// from "JavaScript agrees with JavaScript" to "the crate agrees".
#[derive(Deserialize)]
struct ReleaseRun {
    funding_txid: String,
    vout: u32,
    amount_zat: u64,
    u_pub: String,
    l_pub: String,
    refund_height: u64,
    consensus_branch_id: u32,
    lp_output_script: String,
    miner_fee_zat: u64,
    platform_fee_zat: u64,
    treasury_script: String,
    pre_signature: String,
    outcome_point: String,
    outcome_secret: String,
    release_script_sig: String,
    release_raw: String,
    release_txid: String,
}

fn check_release(path: &str) {
    let r: ReleaseRun = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let terms = EscrowTerms {
        funding_txid: h32(&r.funding_txid),
        vout: r.vout,
        amount_zat: r.amount_zat,
        u_pub: hex::decode(&r.u_pub).unwrap().try_into().unwrap(),
        l_pub: hex::decode(&r.l_pub).unwrap().try_into().unwrap(),
        refund_height: r.refund_height,
        consensus_branch_id: r.consensus_branch_id,
    };
    let split = ReleaseSplit {
        payout_script: hex::decode(&r.lp_output_script).unwrap(),
        miner_fee_zat: r.miner_fee_zat,
        platform_fee_zat: r.platform_fee_zat,
        treasury_script: hex::decode(&r.treasury_script).unwrap(),
    };
    let redeem = terms.redeem_script().unwrap();
    let spk = terms.script_pubkey().unwrap();
    let digest = build_release_split(&terms, &split).unwrap().sighash().unwrap();
    let u_pub = PublicKey::from_slice(&terms.u_pub).unwrap();
    let y = PublicKey::from_slice(&hex::decode(&r.outcome_point).unwrap()).unwrap();
    let s = sk(&r.outcome_secret);

    let mut failures = 0;
    let mut report = |name: &str, ok: bool| {
        println!("{} {}", if ok { "ok  " } else { "FAIL" }, name);
        if !ok {
            failures += 1;
        }
    };

    report(
        "the miner fee is the conventional fee for this release",
        r.miner_fee_zat == release_fee_zat(redeem.len(), if r.platform_fee_zat > 0 { 2 } else { 1 }),
    );
    report("s*G == Y for the mock attestor's scalar", verify_outcome_secret(&secp, &s, &y).is_ok());
    let pre = EcdsaAdaptorSignature::from_slice(&hex::decode(&r.pre_signature).unwrap()).unwrap();
    report(
        "the browser's pre-signature verifies over the crate's digest",
        verify_pre_signature(&secp, &pre, &digest, &u_pub, &y).is_ok(),
    );
    let raw = hex::decode(&r.release_raw).unwrap();
    let txid = txid_of_signed(&raw).expect("the release parses as a v5 transaction");
    report("the release txid matches", hex::encode(txid) == r.release_txid);
    let ss = hex::decode(&r.release_script_sig).unwrap();
    report(
        "the interpreter accepts the release against the crate's digest",
        eval(&ss, &spk, &checker(digest, 0)),
    );
    if failures > 0 {
        eprintln!("{failures} check(s) failed");
        std::process::exit(1);
    }
    println!("release run checks passed");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("emit") => emit(),
        Some("check") => check(&args[2], &args[3]),
        Some("check-release") => check_release(&args[2]),
        _ => {
            eprintln!(
                "usage: frontend_vectors emit | check <vectors.json> <js-out.json> | check-release <run.json>"
            );
            std::process::exit(2);
        }
    }
}
