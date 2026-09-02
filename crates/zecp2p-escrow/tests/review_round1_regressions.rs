//! The review round 1 proofs-of-concept, ported to the fixed API.
//!
//! Each of these reproduced a real attack before the fix. They are kept as the
//! standing regression: if a later change reopens one, the corresponding test
//! here goes red rather than the hole reappearing quietly. The PoC letters match
//! the reviewer's file.

use secp256k1_zkp::{Message, Secp256k1, SecretKey};

use zecp2p_escrow::chain::{FakeChain, Utxo};
use zecp2p_escrow::client::{
    prepare_escrow, AcceptedQuote, refund_when_due, Announcement, ClientError, EscrowRecord, MemoryRecordStore,
    RecordStore,
};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::dlc::{decrypt_pre_signature, event_id, sign_outcome};
use zecp2p_escrow::fees::release_fee_to_transparent_zat;
use zecp2p_escrow::lp::{evaluate, may_send_payment, LpError, LpProgress, LpState};
use zecp2p_escrow::script::redeem_script;
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::{build_release, EscrowTerms, TxError};

const NU6_3: u32 = 0x37a5_165b;
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];
const REFUND_HEIGHT: u64 = 3_401_152;
const VICTIM_TXID: [u8; 32] = [0x7a; 32];

fn canonical_terms() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_000_000,
        rate_18dec: 990_881_148_896_019_200,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
    }
}

/// What the user accepted before funding. Round 2 finding 1: the client must
/// hold its own view of the fiat side, or the LP writes it.
fn quote(c: &CanonicalTerms) -> AcceptedQuote {
    AcceptedQuote {
        usd_amount_6dec: c.usd_amount_6dec,
        payee_hash: c.payee_hash,
        rate_18dec: c.rate_18dec,
    }
}

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// PoC B: the LP relays a genuine announcement issued for its own escrow.
///
/// Before the fix the client encrypted under that event's outcome point, so the
/// scalar the attestor legitimately published when the LP paid *itself* also
/// completed the victim's release. Now the client recomputes the event id from
/// the outpoint it is funding and refuses.
#[test]
fn poc_b_a_foreign_announcement_no_longer_reaches_a_pre_signature() {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let attacker_txid = [0xa7u8; 32];

    let terms = EscrowTerms {
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
    let mut canonical = canonical_terms();
    canonical.u_pub = terms.u_pub;
    canonical.l_pub = terms.l_pub;

    let foreign = Announcement {
        p: d.public_key(&secp),
        r: k.public_key(&secp),
        event_id: event_id(&attacker_txid, 0),
    };

    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    let err = prepare_escrow(
        &secp,
        &mut store,
        &terms,
        &canonical,
        &quote(&canonical),
        &u_priv,
        &foreign,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect_err("the client must refuse an announcement for another escrow");
    assert!(matches!(err, ClientError::ForeignAnnouncement { .. }), "got {err}");
    assert!(store.load(&VICTIM_TXID).is_none(), "nothing was persisted");

    // And the deeper property: even had a pre-signature been produced, the
    // scalar for the attacker's event no longer completes it, because Y commits
    // to the terms as well as the event.
    let honest = Announcement {
        p: d.public_key(&secp),
        r: k.public_key(&secp),
        event_id: event_id(&VICTIM_TXID, 0),
    };
    let (pre_sig, _) = prepare_escrow(
        &secp,
        &mut store,
        &terms,
        &canonical,
        &quote(&canonical),
        &u_priv,
        &honest,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .unwrap();

    let attacker_scalar = sign_outcome(
        &secp,
        &k,
        &d,
        &event_id(&attacker_txid, 0),
        &canonical.terms_hash(),
    )
    .unwrap();
    let sig = decrypt_pre_signature(&pre_sig, &attacker_scalar).unwrap();
    let digest = build_release(&terms, &p2pkh([0x09; 20]), fee)
        .unwrap()
        .sighash()
        .unwrap();
    assert!(
        secp.verify_ecdsa(&Message::from_digest(digest), &sig, &u_priv.public_key(&secp))
            .is_err(),
        "another event's scalar must not complete this escrow's pre-signature"
    );
}

/// PoC C: the LP was `ReadyToPay` at the exact height the user could refund,
/// because deadlines came from an observed lock height rather than the `T` in
/// the redeem script.
#[test]
fn poc_c_the_lp_is_not_ready_to_pay_at_the_refund_height() {
    let tx = EscrowTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: NU6_3,
    };
    let policy = EscrowPolicy::mainnet_default();

    let mut chain = FakeChain::new(REFUND_HEIGHT as u32, NU6_3);
    chain.add_utxo(
        VICTIM_TXID,
        0,
        Utxo {
            script_pubkey: tx.script_pubkey().unwrap(),
            amount_zat: 5_000_000,
            confirmations: 100,
        },
    );

    let state = evaluate(
        &chain,
        &tx,
        &canonical_terms(),
        &policy,
        LpProgress {
            pre_signature_verified: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(state, LpState::AbandonedUnpaid);
    assert!(matches!(
        may_send_payment(&state),
        Err(LpError::NotPayable(_))
    ));
    assert!(
        policy.may_refund_at(REFUND_HEIGHT as u32, REFUND_HEIGHT as u32),
        "the user can refund at exactly this height, which is why the LP must not pay"
    );
}

/// PoC F: the refund gate refused a refund the chain would accept, because it
/// derived `T` from policy instead of reading the stored redeem script.
#[test]
fn poc_f_the_refund_gate_uses_the_stored_t() {
    let record = EscrowRecord {
        u_priv: [0x11; 32],
        redeem_script: redeem_script(&U_PUB, &L_PUB, REFUND_HEIGHT).unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };
    let policy = EscrowPolicy::mainnet_default();
    let chain = FakeChain::new(REFUND_HEIGHT as u32 + 500, NU6_3);

    let refund = refund_when_due(&chain, &record, &policy, &p2pkh([0x0b; 20]), 20_000)
        .expect("500 blocks past the script's T the refund must build");
    assert_eq!(refund.lock_time(), REFUND_HEIGHT as u32);
}

/// PoC G: an unknown branch id panicked the builder. It is read from a node, so
/// it is untrusted input, and the daemons call this on every poll.
#[test]
fn poc_g_an_unknown_branch_id_is_an_error() {
    let tx = EscrowTerms {
        funding_txid: VICTIM_TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: 0xdead_beef,
    };
    match build_release(&tx, &p2pkh([0x09; 20]), 15_000) {
        Err(TxError::UnknownBranchId(0xdead_beef)) => {}
        other => panic!("expected UnknownBranchId, got {other:?}"),
    }
}
