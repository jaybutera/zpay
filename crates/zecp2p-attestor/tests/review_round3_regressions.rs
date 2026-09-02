//! Round 3 PoCs 3, 4 and 5, ported to the fixed API.

use secp256k1::{Message, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use zecp2p_attestor::store::EventStore;
use zecp2p_attestor::{
    handle_announce, handle_attest_against_signer, handle_attest_with_chain, AttestorError,
    ChainObservation, FixedClock,
};
use zecp2p_escrow::attestation::{eip712_digest, PaymentAttestation};
use zecp2p_escrow::chain::{FakeChain, Utxo};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::payment_details::{
    PaymentDetailsError, RatePolicy, IDENTITY_RATE_18DEC, USD_FIAT_CURRENCY, VENMO_PAYMENT_METHOD,
};
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};
use zecp2p_escrow::terms::CanonicalTerms;

const NOW_MS: u64 = 1_788_315_013_000;
const MONTH_MS: u64 = 30 * 24 * 3600 * 1000;
const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;

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
    let sig =
        Secp1::new().sign_ecdsa_recoverable(&Message::from_digest(eip712_digest(&att)), &key);
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

fn details(t: &CanonicalTerms, amount: u128, payment_ms: u64, index: u128, rate: u128) -> Vec<u8> {
    [
        VENMO_PAYMENT_METHOD,
        t.payee_hash,
        word_u(index),
        USD_FIAT_CURRENCY,
        word_u(payment_ms as u128),
        [0x55; 32],
        t.intent_hash(),
        word_u(amount),
        VENMO_PAYMENT_METHOD,
        USD_FIAT_CURRENCY,
        t.payee_hash,
        word_u(rate),
        word_u((t.lock_confirmed_ms / 1000) as u128),
        word_u(1_209_600),
    ]
    .concat()
}

fn terms_for(txid: [u8; 32], lock_confirmed_ms: u64) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: txid,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: [0x02; 33],
        l_pub: [0x03; 33],
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 100_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms,
    }
}

fn spk() -> Vec<u8> {
    p2sh_script_pubkey(&redeem_script(&[0x02; 33], &[0x03; 33], REFUND_HEIGHT).unwrap())
}

/// R3-3: `announced_at_ms` had no attestor-side writer.
///
/// Round 2 moved the recency bound to a store field, but nothing ever stamped
/// it, so a row announced with `0` narrowed nothing and the month-old payment
/// of round 2's PoC came straight back. `handle_announce` stamps it from a
/// clock the handler owns and refuses a zero stamp.
#[test]
fn r3_3_announce_stamps_the_attestors_own_clock_and_refuses_zero() {
    let secp = Secp256k1::new();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let t = terms_for([0x7a; 32], NOW_MS - MONTH_MS);
    let ev = event_id(&t.funding_txid, 0);

    // A clock that returns zero is refused rather than producing a row that
    // bounds nothing.
    let mut store = EventStore::new();
    assert_eq!(
        handle_announce(&mut store, &secp, &FixedClock(0), &ev, &t, &k).unwrap_err(),
        AttestorError::ZeroClock
    );
    assert!(store.get(&ev).is_none());

    // A real clock stamps the row, whatever the LP claims about the lock time.
    let mut store = EventStore::new();
    handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();
    assert_eq!(store.get(&ev).unwrap().announced_at_ms, NOW_MS);
    assert_ne!(
        store.get(&ev).unwrap().announced_at_ms,
        t.lock_confirmed_ms,
        "the stamp must be the attestor's clock, not the LP's claim"
    );
}

#[test]
fn r3_3b_the_month_old_payment_is_refused_once_the_row_is_stamped() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms_for([0x7a; 32], NOW_MS - MONTH_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();

    let blob = details(&t, 100_000_000, NOW_MS - MONTH_MS + 60_000, 77, IDENTITY_RATE_18DEC);
    let (att, sig) = attest_for(t.intent_hash(), 100_000_000, &blob);
    // Even with the caller handing over the LP's own generous bound.
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: t.lock_confirmed_ms,
    };

    let err = handle_attest_against_signer(
        &mut store,
        &secp,
        &d,
        &ev,
        &t,
        &att,
        &sig,
        &blob,
        &obs,
        &RatePolicy::production(),
        &signer,
    )
    .expect_err("a month-old payment must be refused");
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::PaymentPredatesLock { .. })
        ),
        "got {err}"
    );
}

/// An announcement whose event id is not the one its outpoint produces is
/// refused, so the store cannot hold a row whose later checks compare against
/// the wrong escrow.
#[test]
fn r3_3c_announce_checks_the_event_id_against_the_outpoint() {
    let secp = Secp256k1::new();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let t = terms_for([0x7a; 32], NOW_MS);
    let foreign = event_id(&[0xa7; 32], 0);

    let mut store = EventStore::new();
    let err = handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &foreign, &t, &k)
        .expect_err("an event id for another outpoint must be refused");
    assert!(matches!(err, AttestorError::EventIdMismatch { .. }), "got {err}");
}

/// R3-4: `RatePolicy::Exact(u128)` took any value in a default build, and
/// `Exact(1)` reproduces the round-1 theft: at `conversionRate = 1` the
/// enclave's `min(fiat * 1e18 / rate, intent)` saturates at the intent for a
/// one-cent payment.
///
/// The variants now carry no caller-chosen payload outside the feature.
#[test]
fn r3_4_a_rate_of_one_is_refused_by_the_only_constructible_policy() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms_for([0x7a; 32], NOW_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();

    let blob = details(&t, 100_000_000, NOW_MS + 60_000, 77, 1);
    let (att, sig) = attest_for(t.intent_hash(), 100_000_000, &blob);
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    let err = handle_attest_against_signer(
        &mut store, &secp, &d, &ev, &t, &att, &sig, &blob, &obs,
        &RatePolicy::production(), &signer,
    )
    .expect_err("rate 1 must be refused");
    assert!(
        matches!(
            err,
            AttestorError::PaymentDetails(PaymentDetailsError::RateMismatch { .. })
        ),
        "got {err}"
    );

    // `Identity` is the only variant a production build can name, and it is
    // what `production()` returns.
    assert_eq!(RatePolicy::production(), RatePolicy::Identity);
}

/// R3-5: the pre-finding-4 signing path was public, so an in-process caller
/// could obtain a scalar for a consumed payment before any store check ran.
///
/// `decide`, `sign_decided_outcome` and `take_nonce_for_signing` are no longer
/// reachable from outside without the test feature, and the nonce now actually
/// leaves the store on the first take. This test counts signings rather than
/// inspecting the store, so it proves the property directly.
#[test]
fn r3_5_one_payment_yields_exactly_one_scalar() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let (_, signer) = test_enclave();
    let mut store = EventStore::new();

    let mut evs = Vec::new();
    for (i, txid) in [[0x7a; 32], [0x7bu8; 32]].into_iter().enumerate() {
        let t = terms_for(txid, NOW_MS);
        let k = SecretKey::from_slice(&[0x40 + i as u8; 32]).unwrap();
        let ev = event_id(&txid, 0);
        handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();
        evs.push((t, ev));
    }

    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    let mut scalars = 0usize;
    for (t, ev) in &evs {
        let blob = details(t, 100_000_000, NOW_MS + 60_000, 484, IDENTITY_RATE_18DEC);
        let (att, sig) = attest_for(t.intent_hash(), 100_000_000, &blob);
        if handle_attest_against_signer(
            &mut store, &secp, &d, ev, t, &att, &sig, &blob, &obs,
            &RatePolicy::production(), &signer,
        )
        .is_ok()
        {
            scalars += 1;
        }
    }

    assert_eq!(
        scalars, 1,
        "one Venmo payment must yield exactly one outcome scalar"
    );
    assert!(
        store.holds_nonce(&evs[1].1),
        "the refused event's nonce was never taken"
    );
}

/// The nonce leaves the store on the first take, so a second signing finds
/// nothing whatever else changes. Round 3 finding 5.
#[test]
fn r3_5b_the_nonce_is_gone_after_one_signing() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let (_, signer) = test_enclave();

    let t = terms_for([0x7a; 32], NOW_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();

    let blob = details(&t, 100_000_000, NOW_MS + 60_000, 484, IDENTITY_RATE_18DEC);
    let (att, sig) = attest_for(t.intent_hash(), 100_000_000, &blob);
    let obs = ChainObservation {
        script_pubkey: spk(),
        amount_zat: 5_000_000,
        confirmations: 30,
        earliest_acceptable_payment_ms: NOW_MS,
    };

    handle_attest_against_signer(
        &mut store, &secp, &d, &ev, &t, &att, &sig, &blob, &obs,
        &RatePolicy::production(), &signer,
    )
    .unwrap();

    assert!(!store.holds_nonce(&ev), "k must be gone after signing");
    assert!(store.take_nonce_for_signing(&ev).is_err());
}

/// R3-4's other half: `handle_attest_with_chain` reads the escrow from the
/// attestor's own node instead of trusting a caller's observation.
#[test]
fn the_handler_reads_the_escrow_from_its_own_node() {
    let secp = Secp256k1::new();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let t = terms_for([0x7a; 32], NOW_MS);
    let ev = event_id(&t.funding_txid, 0);
    let mut store = EventStore::new();
    handle_announce(&mut store, &secp, &FixedClock(NOW_MS), &ev, &t, &k).unwrap();

    let blob = details(&t, 100_000_000, NOW_MS + 60_000, 484, IDENTITY_RATE_18DEC);
    let (att, sig) = attest_for(t.intent_hash(), 100_000_000, &blob);

    // A node that does not have the escrow: no observation a caller could pass
    // makes this succeed.
    let empty = FakeChain::new(3_400_000, NU6_3);
    assert_eq!(
        handle_attest_with_chain(
            &mut store, &empty, &secp, &d, &ev, &t, &att, &sig, &blob
        )
        .unwrap_err(),
        AttestorError::EscrowNotFound
    );

    // With the escrow present, the chain facts come from the node and the
    // attestation is checked against the *pinned* enclave key - so a
    // test-signed attestation is refused here even though the same attestation
    // passes `handle_attest_against_signer`. That is the production path
    // pinning its signer, which is what round 3 finding 7 asked for.
    let mut node = FakeChain::new(3_400_000, NU6_3);
    node.add_utxo(
        t.funding_txid,
        0,
        Utxo {
            script_pubkey: spk(),
            amount_zat: 5_000_000,
            confirmations: 30,
        },
    );
    let err = handle_attest_with_chain(
        &mut store, &node, &secp, &d, &ev, &t, &att, &sig, &blob,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            AttestorError::Attestation(
                zecp2p_escrow::attestation::AttestationError::WrongSigner { .. }
            )
        ),
        "the chain-reading handler must pin the real enclave signer, got {err}"
    );
    assert!(store.holds_nonce(&ev), "nothing was signed");

    // And the depth the node reports is the one that governs: an escrow the
    // node says is shallow is refused before the signature is even considered
    // is not the ordering here, but the depth check is reachable and uses the
    // node's number, which `observe_escrow` proves directly.
    let mut shallow = FakeChain::new(3_400_000, NU6_3);
    shallow.add_utxo(
        t.funding_txid,
        0,
        Utxo {
            script_pubkey: spk(),
            amount_zat: 5_000_000,
            confirmations: 5,
        },
    );
    let observed =
        zecp2p_attestor::observe_escrow(&shallow, &t, NOW_MS).expect("the node has the escrow");
    assert_eq!(
        observed.confirmations, 5,
        "the depth must come from the node, not from a caller"
    );
    assert_eq!(observed.script_pubkey, spk());
    assert_eq!(observed.amount_zat, 5_000_000);
}
