//! The review round 2 proofs of concept, ported to the fixed API.
//!
//! Round 1 closed two ways to steal an escrow. Round 2 found the same theft
//! class one layer up: the LP no longer forges the *payment*, it writes the
//! *terms* that the payment is checked against. These are kept as the standing
//! regression.

use secp256k1_zkp::{Message, Secp256k1, SecretKey};

use zecp2p_escrow::client::{
    prepare_escrow, AcceptedQuote, Announcement, ClientError, MemoryRecordStore,
};
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::EscrowTerms;

const NU6_3: u32 = 0x37a5_165b;
const REFUND_HEIGHT: u64 = 3_500_000;
const VICTIM_TXID: [u8; 32] = [0x7a; 32];
const USER_VENMO_HASH: [u8; 32] = [0x85; 32];
const LP_VENMO_HASH: [u8; 32] = [0x11; 32];

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// PoC 1: the LP authored the fiat side of the terms.
///
/// The chain fields were honest; `payee_hash` was the LP's own Venmo and
/// `usd_amount_6dec` was one micro-dollar. Nothing in the client compared
/// either to anything the user held, so every check downstream honestly
/// verified the LP paying itself, and the scalar released 0.05 ZEC.
///
/// The user now states its own fiat terms and the client compares all three.
#[test]
fn poc1_the_client_refuses_lp_authored_fiat_terms() {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let tx_terms = EscrowTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: u_priv.public_key(&secp).serialize(),
        l_pub: l_priv.public_key(&secp).serialize(),
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: NU6_3,
    };

    // What the user actually accepted: 100 USD, to its own Venmo.
    let accepted = AcceptedQuote {
        usd_amount_6dec: 100_000_000,
        payee_hash: USER_VENMO_HASH,
        rate_18dec: IDENTITY_RATE_18DEC,
        refund_height: REFUND_HEIGHT,
        l_pub: tx_terms.l_pub,
        amount_zat: 5_000_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };

    // What the LP returns in step 1c: chain fields honest, fiat fields its own.
    let lp_terms = CanonicalTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: tx_terms.u_pub,
        l_pub: tx_terms.l_pub,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: LP_VENMO_HASH,
        lock_confirmed_ms: 1_788_315_013_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };

    let ann = Announcement {
        p: d.public_key(&secp),
        r: k.public_key(&secp),
        event_id: event_id(&VICTIM_TXID, 0),
    };
    let fee = release_fee_to_transparent_zat(tx_terms.redeem_script().unwrap().len());
    let mut store = MemoryRecordStore::default();

    let err = prepare_escrow(
        &secp,
        &mut store,
        VICTIM_TXID,
        0,
        NU6_3,
        &accepted,
        &lp_terms,
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect_err("the client must refuse terms whose fiat side it did not agree to");

    // The amount is checked first; the payee is checked too.
    assert!(
        matches!(err, ClientError::TermsNotAsAccepted { .. }),
        "got {err}"
    );

    // With the amount honest and only the payee swapped, that is caught as well.
    let payee_only = CanonicalTerms {
        usd_amount_6dec: 100_000_000,
        ..lp_terms.clone()
    };
    let err = prepare_escrow(
        &secp,
        &mut store,
        VICTIM_TXID,
        0,
        NU6_3,
        &accepted,
        &payee_only,
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect_err("the payee is the user's identity and only the user knows it");
    assert!(
        matches!(err, ClientError::TermsNotAsAccepted { .. }),
        "got {err}"
    );

    // Nothing was persisted and no pre-signature was produced for either.
    use zecp2p_escrow::client::RecordStore;
    assert!(store.load(&VICTIM_TXID).is_none());

    // And the honest case still works.
    let honest = CanonicalTerms {
        usd_amount_6dec: 100_000_000,
        payee_hash: USER_VENMO_HASH,
        ..lp_terms
    };
    let prepared = prepare_escrow(
        &secp,
        &mut store,
        VICTIM_TXID,
        0,
        NU6_3,
        &accepted,
        &honest,
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect("terms matching the accepted quote are fine");

    let digest = zecp2p_escrow::tx::build_release(&tx_terms, &p2pkh([0x09; 20]), fee)
        .unwrap()
        .sighash()
        .unwrap();
    zecp2p_escrow::dlc::verify_pre_signature(
        &secp,
        &prepared.pre_signature,
        &digest,
        &u_priv.public_key(&secp),
        &prepared.outcome_point,
    )
    .unwrap();
    let _ = Message::from_digest(digest);
}

/// The rate is part of what the user accepted too, and for a ZEC escrow it must
/// be the identity rate (round 2 finding 3).
#[test]
fn poc1b_a_rate_the_user_did_not_accept_is_refused() {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let tx_terms = EscrowTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: u_priv.public_key(&secp).serialize(),
        l_pub: SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key(&secp)
            .serialize(),
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: NU6_3,
    };
    let accepted = AcceptedQuote {
        usd_amount_6dec: 100_000_000,
        payee_hash: USER_VENMO_HASH,
        rate_18dec: IDENTITY_RATE_18DEC,
        refund_height: REFUND_HEIGHT,
        l_pub: tx_terms.l_pub,
        amount_zat: 5_000_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };
    let bent = CanonicalTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: tx_terms.u_pub,
        l_pub: tx_terms.l_pub,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 100_000_000,
        rate_18dec: 990_881_148_896_019_200,
        payee_hash: USER_VENMO_HASH,
        lock_confirmed_ms: 1_788_315_013_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };

    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(tx_terms.redeem_script().unwrap().len());
    let err = prepare_escrow(
        &secp,
        &mut store,
        VICTIM_TXID,
        0,
        NU6_3,
        &accepted,
        &bent,
        &u_priv,
        &Announcement {
            p: d.public_key(&secp),
            r: k.public_key(&secp),
            event_id: event_id(&VICTIM_TXID, 0),
        },
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect_err("a rate the user did not accept must be refused");
    assert!(
        matches!(err, ClientError::TermsNotAsAccepted { .. }),
        "got {err}"
    );
}
