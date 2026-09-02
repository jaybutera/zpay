//! The success path of `attest_over_db`, which had never been exercised.
//!
//! Round 5's closing note: `attest_over_db` had never returned `Ok` in any
//! test, because the pinned enclave key cannot sign for terms a test invents
//! and the service has no test-signer path by design. So every `/attest` in the
//! suite stopped at the signer check, before the chain call and before the
//! SQLite write. R5-4 - a panic in the chain call that poisoned the store lock
//! - lived in exactly that gap.
//!
//! These drive the whole path to a scalar, through the same gated affordance
//! the in-memory handler already had.

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use zecp2p_attestor::db::SqliteEventStore;
use zecp2p_attestor::{
    attest_over_db_against_signer, AttestorError, FixedClock,
};
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::{FakeChain, Utxo};
use zecp2p_escrow::dlc::{event_id, outcome_point, verify_outcome_secret};
use zecp2p_escrow::payment_details::{
    RatePolicy, IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];

fn test_enclave() -> (Sk1, [u8; 20]) {
    let secp = Secp1::new();
    let key = Sk1::from_slice(&[0xe1; 32]).unwrap();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let h: [u8; 32] = Keccak256::digest(&pubkey.serialize_uncompressed()[1..]).into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    (key, addr)
}

fn attest_for(intent: [u8; 32], amount: u128, details: &[u8]) -> (PaymentAttestation, Vec<u8>) {
    let (key, _) = test_enclave();
    let att = PaymentAttestation {
        intent_hash: intent,
        release_amount: amount,
        data_hash: Keccak256::digest(details).into(),
    };
    let sig = Secp1::new().sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
    let (rec_id, compact) = sig.serialize_compact();
    let mut b = compact.to_vec();
    b.push(i32::from(rec_id) as u8 + 27);
    (att, b)
}

fn word_u(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn terms() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: NOW_MS,
    }
}

fn details(t: &CanonicalTerms) -> Vec<u8> {
    [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(484),
        USD_FIAT_CURRENCY,
        word_u((t.lock_confirmed_ms + 60_000) as u128),
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
    .concat()
}

fn spk() -> Vec<u8> {
    p2sh_script_pubkey(&redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap())
}

fn funded_chain(confirmations: u32) -> FakeChain {
    let mut c = FakeChain::new(3_400_000, NU6_3);
    c.add_utxo(
        [0x7a; 32],
        0,
        Utxo {
            script_pubkey: spk(),
            amount_zat: 5_000_000,
            confirmations,
        },
    );
    c
}

/// Announces over the persistent store with a known nonce, so the test can
/// check the scalar against the outcome point the user would have used.
fn announce(db: &mut SqliteEventStore, t: &CanonicalTerms, k: &SecretKey) -> [u8; 32] {
    let secp = Secp256k1::new();
    let ev = event_id(&t.funding_txid, t.vout);
    db.announce(
        ev,
        t.terms_hash(),
        k.public_key(&secp).serialize(),
        t.funding_txid,
        k.secret_bytes(),
        NOW_MS,
    )
    .unwrap();
    ev
}

#[test]
fn the_sqlite_path_produces_a_scalar_that_opens_the_outcome_point() {
    // The whole point: a scalar that satisfies `s*G == Y` for the announced R,
    // computed through the SQLite transaction rather than the in-memory store.
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let mut db = SqliteEventStore::in_memory().unwrap();
    let t = terms();
    let ev = announce(&mut db, &t, &k);

    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let s = attest_over_db_against_signer(
        &mut db,
        &funded_chain(30),
        &secp,
        &d,
        &FixedClock(NOW_MS),
        &ev,
        &t,
        &att,
        &sig,
        &det,
        &RatePolicy::production(),
        &signer,
    )
    .expect("a genuine, confirmed, paid escrow must yield a scalar");

    let y = outcome_point(
        &secp,
        &k.public_key(&secp),
        &d.public_key(&secp),
        &ev,
        &t.terms_hash(),
    )
    .unwrap();
    verify_outcome_secret(&secp, &s, &y)
        .expect("the scalar must be the discrete log of the announced outcome point");

    // And the store recorded the consequences.
    assert!(!db.holds_nonce(&ev).unwrap(), "k is cleared on signing");
    assert_eq!(db.signed_outcome(&ev).unwrap(), Some(s.secret_bytes()));
}

/// R6-2 changed this: an identical repeat now returns the same scalar, because
/// refusing it left an LP who had paid Venmo with no way to collect. A repeat
/// that is *not* identical is still refused, which is what criterion 8 is for.
/// See `lost_response_recovery.rs` for the full set.
#[test]
fn a_second_attest_over_sqlite_replays_only_for_an_identical_request() {
    // Criterion 8, on the persistent path (R5-3, amended by R6-2).
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let mut db = SqliteEventStore::in_memory().unwrap();
    let t = terms();
    let ev = announce(&mut db, &t, &k);
    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let run = |db: &mut SqliteEventStore| {
        attest_over_db_against_signer(
            db,
            &funded_chain(30),
            &secp,
            &d,
            &FixedClock(NOW_MS),
            &ev,
            &t,
            &att,
            &sig,
            &det,
            &RatePolicy::production(),
            &signer,
        )
    };

    let first = run(&mut db).expect("the first attest signs");
    let replay = run(&mut db).expect("an identical repeat returns the same scalar");
    assert_eq!(first.secret_bytes(), replay.secret_bytes());

    // A repeat under different terms is refused.
    let mut other = t.clone();
    other.usd_amount_6dec = 1;
    let err = attest_over_db_against_signer(
        &mut db,
        &funded_chain(30),
        &secp,
        &d,
        &FixedClock(NOW_MS),
        &ev,
        &other,
        &att,
        &sig,
        &det,
        &RatePolicy::production(),
        &signer,
    )
    .expect_err("different terms must not replay");
    assert!(
        matches!(err, AttestorError::TermsChanged | AttestorError::AlreadySigned),
        "got {err}"
    );
}

#[test]
fn one_payment_cannot_release_two_escrows_over_sqlite() {
    // Round 2 finding 5, on the path that survives a restart. This is the first
    // test to reach it with a real signature rather than a dummy closure.
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let (_, signer) = test_enclave();
    let mut db = SqliteEventStore::in_memory().unwrap();

    let mut signed = 0usize;
    for (i, txid) in [[0x7a; 32], [0x7bu8; 32]].into_iter().enumerate() {
        let mut t = terms();
        t.funding_txid = txid;
        let k = SecretKey::from_slice(&[0x40 + i as u8; 32]).unwrap();
        let ev = announce(&mut db, &t, &k);

        // The same payment index and digest: one Venmo payment.
        let det = details(&t);
        let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

        let mut chain = FakeChain::new(3_400_000, NU6_3);
        chain.add_utxo(
            txid,
            0,
            Utxo {
                script_pubkey: spk(),
                amount_zat: 5_000_000,
                confirmations: 30,
            },
        );

        if attest_over_db_against_signer(
            &mut db,
            &chain,
            &secp,
            &d,
            &FixedClock(NOW_MS),
            &ev,
            &t,
            &att,
            &sig,
            &det,
            &RatePolicy::production(),
            &signer,
        )
        .is_ok()
        {
            signed += 1;
        }
    }

    assert_eq!(
        signed, 1,
        "one payment must release exactly one escrow, even over SQLite"
    );
}

#[test]
fn a_shallow_escrow_is_refused_and_leaves_the_nonce_intact() {
    // Reaching the depth check needs a signature the decision path accepts,
    // which is only possible on this gated route - so this is the first test
    // that gets there over SQLite.
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let mut db = SqliteEventStore::in_memory().unwrap();
    let t = terms();
    let ev = announce(&mut db, &t, &k);
    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let err = attest_over_db_against_signer(
        &mut db,
        &funded_chain(9),
        &secp,
        &d,
        &FixedClock(NOW_MS),
        &ev,
        &t,
        &att,
        &sig,
        &det,
        &RatePolicy::production(),
        &signer,
    )
    .expect_err("nine confirmations is not ten");
    assert!(
        matches!(err, AttestorError::InsufficientDepth { .. }),
        "got {err}"
    );
    assert!(
        db.holds_nonce(&ev).unwrap(),
        "a refused attestation must not consume the nonce"
    );
}

#[test]
fn an_unreachable_node_is_an_outage_and_not_a_verdict() {
    // The LP has already paid Venmo when it calls this. A node it cannot read
    // must not read as "refused" (R5-1).
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let mut db = SqliteEventStore::in_memory().unwrap();
    let t = terms();
    let ev = announce(&mut db, &t, &k);
    let det = details(&t);
    let (att, sig) = attest_for(t.intent_hash(), t.usd_amount_6dec as u128, &det);

    let mut chain = funded_chain(30);
    chain.offline = true;

    let err = attest_over_db_against_signer(
        &mut db, &chain, &secp, &d, &FixedClock(NOW_MS), &ev, &t, &att, &sig, &det,
        &RatePolicy::production(), &signer,
    )
    .expect_err("an unreachable node must not produce a scalar");
    assert!(matches!(err, AttestorError::Chain(_)), "got {err}");
    assert!(db.holds_nonce(&ev).unwrap());
}
