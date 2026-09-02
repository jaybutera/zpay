//! The user's side, spec 5.3 and 4.4.
//!
//! The user's exposure is narrow and total: it locks ZEC and then, if the LP
//! never pays, needs nothing but its own key to get it back. These tests are
//! about the two ways that goes wrong - the key not being on disk when the
//! funding transaction goes out, and the pre-signature being made under
//! someone else's outcome point.

use secp256k1_zkp::{Secp256k1, SecretKey};

use zecp2p_escrow::chain::FakeChain;
use zecp2p_escrow::client::{
    AcceptedQuote,
    may_broadcast_funding, prepare_escrow, refund_when_due, verify_announcement, Announcement,
    ClientError, EscrowRecord, MemoryRecordStore, RecordStore,
};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::script::redeem_script;
use zecp2p_escrow::fees::{refund_fee_to_shielded_zat, release_fee_to_transparent_zat};
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::EscrowTerms;

const NU6_3: u32 = 0x37a5_165b;
const TXID: [u8; 32] = [0x7a; 32];
const REFUND_HEIGHT: u64 = 3_401_152;

fn setup() -> (
    Secp256k1<secp256k1_zkp::All>,
    SecretKey,
    SecretKey,
    EscrowTerms,
    Announcement,
) {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();

    let terms = EscrowTerms {
        funding_txid: TXID,
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

    let announcement = Announcement {
        p: d.public_key(&secp),
        r: k.public_key(&secp),
        event_id: event_id(&TXID, 0),
    };

    (secp, u_priv, d, terms, announcement)
}

fn canonical(t: &EscrowTerms) -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: t.funding_txid,
        vout: t.vout,
        amount_zat: t.amount_zat,
        u_pub: t.u_pub,
        l_pub: t.l_pub,
        refund_height: t.refund_height,
        usd_amount_6dec: 1_000_000,
        rate_18dec: 1_000_000_000_000_000_000,
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
        refund_height: c.refund_height,
        l_pub: c.l_pub,
        amount_zat: c.amount_zat,
    }
}

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

#[test]
fn the_record_is_on_disk_before_any_pre_signature_exists() {
    // Spec 5.3: the client stores u_priv and the redeem script durably before
    // it broadcasts. A crash after this call must still leave a refundable
    // escrow.
    let (secp, u_priv, d, terms, ann) = setup();
    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    assert!(store.load(&TXID).is_none());

    prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote(&canonical(&terms)),
        &canonical(&terms),
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .unwrap();

    let record = store.load(&TXID).expect("the record must be saved");
    assert_eq!(record.u_priv, u_priv.secret_bytes());
    assert_eq!(record.refund_height, REFUND_HEIGHT);
    record.validate().unwrap();
}

#[test]
fn a_failed_write_stops_the_handshake_before_a_pre_signature_is_produced() {
    // The dangerous ordering is a pre-signature handed to the LP with no key on
    // disk: the LP can release, and the user cannot refund. So a storage
    // failure must abort, not warn.
    let (secp, u_priv, d, terms, ann) = setup();
    let mut store = MemoryRecordStore::failing();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    let err = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote(&canonical(&terms)),
        &canonical(&terms),
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .unwrap_err();
    assert_eq!(err, ClientError::NotPersisted);
}

#[test]
fn funding_is_refused_until_the_record_is_persisted() {
    let store = MemoryRecordStore::default();
    assert_eq!(
        may_broadcast_funding(&store, &TXID),
        Err(ClientError::NotPersisted)
    );
}

#[test]
fn funding_is_refused_when_the_stored_record_is_incomplete() {
    // A record missing u_priv would pass a naive "is it saved" check and still
    // leave the escrow unrefundable.
    let mut store = MemoryRecordStore::default();
    store
        .save(&EscrowRecord {
            u_priv: [0u8; 32],
            redeem_script: vec![0x63, 0x52, 33],
            refund_height: REFUND_HEIGHT,
            funding_txid: TXID,
            vout: 0,
            amount_zat: 5_000_000,
            consensus_branch_id: NU6_3,
        })
        .unwrap();

    assert_eq!(
        may_broadcast_funding(&store, &TXID),
        Err(ClientError::IncompleteRecord("u_priv is unset"))
    );
}

#[test]
fn an_announcement_from_an_unpinned_attestor_is_refused() {
    // If the user encrypted its pre-signature under an attacker's outcome
    // point, the attacker could decrypt it and release the escrow without any
    // payment. This check is the only thing standing between those two facts.
    let (secp, _, d, _, ann) = setup();
    let impostor = SecretKey::from_slice(&[0xaa; 32]).unwrap().public_key(&secp);

    assert_eq!(
        verify_announcement(&ann, &impostor, &TXID, 0),
        Err(ClientError::UnpinnedAttestor)
    );
    verify_announcement(&ann, &d.public_key(&secp), &TXID, 0).unwrap();
}

#[test]
fn the_handshake_refuses_an_unpinned_attestor_before_saving_anything() {
    let (secp, u_priv, _, terms, ann) = setup();
    let impostor = SecretKey::from_slice(&[0xaa; 32]).unwrap().public_key(&secp);
    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    assert_eq!(
        prepare_escrow(
            &secp,
            &mut store,
            TXID,
            0,
            NU6_3,
            &quote(&canonical(&terms)),
            &canonical(&terms),
            &u_priv,
            &ann,
            &impostor,
            &p2pkh([0x09; 20]),
            fee,
        )
        .unwrap_err(),
        ClientError::UnpinnedAttestor
    );
}

#[test]
fn the_refund_is_refused_before_t_and_built_at_t() {
    // Property 1, from the client's side. Before T the transaction would be
    // rejected anyway; refusing here keeps the client from broadcasting into a
    // rejection repeatedly.
    let (secp, u_priv, _, terms, _) = setup();
    let policy = EscrowPolicy::mainnet_default();
    let fee = refund_fee_to_shielded_zat(terms.redeem_script().unwrap().len());

    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };
    let _ = &secp;

    let early = FakeChain::new(REFUND_HEIGHT as u32 - 1, NU6_3);
    assert_eq!(
        refund_when_due(&early, &record, &policy, &p2pkh([0x0b; 20]), fee)
            .unwrap_err(),
        ClientError::TooEarlyToRefund {
            current: REFUND_HEIGHT as u32 - 1,
            refund_height: REFUND_HEIGHT as u32
        }
    );

    let due = FakeChain::new(REFUND_HEIGHT as u32, NU6_3);
    let refund = refund_when_due(&due, &record, &policy, &p2pkh([0x0b; 20]), fee)
        .expect("the refund must build at exactly T");
    assert_eq!(refund.lock_time(), REFUND_HEIGHT as u32);
}

#[test]
fn the_refund_is_rebuilt_from_the_stored_record_alone() {
    // Section 8's "user loses u_priv" row is the failure this guards against.
    // The mirror property is that with the record, the user needs nothing else
    // - no LP, no attestor, no saved terms object.
    let (secp, u_priv, _, terms, _) = setup();
    let policy = EscrowPolicy::mainnet_default();
    let fee = refund_fee_to_shielded_zat(terms.redeem_script().unwrap().len());

    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };

    let chain = FakeChain::new(REFUND_HEIGHT as u32 + 10, NU6_3);
    let from_record =
        refund_when_due(&chain, &record, &policy, &p2pkh([0x0b; 20]), fee)
            .unwrap()
            .sighash()
            .unwrap();

    // The same refund built from the full terms must be byte-identical, which
    // is what "recovered from the record alone" has to mean.
    let from_terms = zecp2p_escrow::tx::build_refund(&terms, &p2pkh([0x0b; 20]), fee)
        .unwrap()
        .sighash()
        .unwrap();

    assert_eq!(
        from_record, from_terms,
        "the record must reconstruct exactly the refund the terms describe"
    );
    let _ = secp;
}

#[test]
fn a_malformed_redeem_script_is_refused_rather_than_producing_a_wrong_refund() {
    let (_, u_priv, _, _, _) = setup();
    let policy = EscrowPolicy::mainnet_default();
    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: vec![0x63, 0x52, 0x01, 0xff],
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };

    let chain = FakeChain::new(REFUND_HEIGHT as u32, NU6_3);
    assert_eq!(
        refund_when_due(&chain, &record, &policy, &p2pkh([0x0b; 20]), 20_000)
            .unwrap_err(),
        ClientError::IncompleteRecord("redeem_script is malformed")
    );
}

#[test]
fn the_user_verifies_its_own_pre_signature_before_handing_it_over() {
    // A pre-signature the LP cannot verify means the LP will not pay, and the
    // user waits until T for nothing. Catching it here is cheaper.
    let (secp, u_priv, d, terms, ann) = setup();
    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    let prepared = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote(&canonical(&terms)),
        &canonical(&terms),
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .unwrap();

    // The LP's own check, spec 5.3 step 5, must pass on what the user produced.
    let digest = zecp2p_escrow::tx::build_release(&terms, &p2pkh([0x09; 20]), fee)
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
    .expect("the LP must accept the pre-signature the client produced");
}

/// Review finding 2, critical: the client must recompute `event_id` from the
/// outpoint it is about to fund.
///
/// The attack the reviewer demonstrated: the LP relays a *genuine* announcement
/// -- correctly signed, from the pinned attestor -- issued for an escrow the LP
/// itself controls. The user encrypts its pre-signature under that event's
/// outcome point. The LP then pays itself for its own escrow, the attestor
/// legitimately publishes that event's scalar, and the same scalar completes
/// the victim's release. No payment to the victim ever happens.
///
/// The fix is one comparison, and this is the test that it is being made.
#[test]
fn an_announcement_for_another_escrow_is_refused() {
    let (secp, _, d, _, _) = setup();
    let attacker_txid = [0xa7u8; 32];
    let foreign = Announcement {
        p: d.public_key(&secp),
        r: SecretKey::from_slice(&[0x4b; 32]).unwrap().public_key(&secp),
        event_id: event_id(&attacker_txid, 0),
    };

    match verify_announcement(&foreign, &d.public_key(&secp), &TXID, 0) {
        Err(ClientError::ForeignAnnouncement { .. }) => {}
        other => panic!("a foreign event id must be refused, got {other:?}"),
    }

    // The same announcement is fine for the escrow it was actually issued for.
    verify_announcement(&foreign, &d.public_key(&secp), &attacker_txid, 0).unwrap();
}

#[test]
fn the_handshake_refuses_a_foreign_announcement_before_saving_or_signing() {
    let (secp, u_priv, d, terms, _) = setup();
    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    let foreign = Announcement {
        p: d.public_key(&secp),
        r: SecretKey::from_slice(&[0x4b; 32]).unwrap().public_key(&secp),
        event_id: event_id(&[0xa7; 32], 0),
    };

    let err = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote(&canonical(&terms)),
        &canonical(&terms),
        &u_priv,
        &foreign,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .unwrap_err();
    assert!(
        matches!(err, ClientError::ForeignAnnouncement { .. }),
        "got {err}"
    );
    assert!(
        store.load(&TXID).is_none(),
        "nothing should be persisted for an escrow the client refused to prepare"
    );
}

/// An announcement for the right transaction but the wrong output index is
/// still a different escrow.
#[test]
fn an_announcement_for_a_different_vout_is_refused() {
    let (secp, _, d, _, _) = setup();
    let wrong_vout = Announcement {
        p: d.public_key(&secp),
        r: SecretKey::from_slice(&[0x4b; 32]).unwrap().public_key(&secp),
        event_id: event_id(&TXID, 1),
    };
    assert!(matches!(
        verify_announcement(&wrong_vout, &d.public_key(&secp), &TXID, 0),
        Err(ClientError::ForeignAnnouncement { .. })
    ));
}

/// Review finding 7: the refund gate must use the `T` in the stored redeem
/// script, not a height derived from policy and a caller-supplied lock height.
///
/// The PoC passed a lock height that was off by the refund delay, and the gate
/// refused a refund the chain would have accepted 500 blocks earlier. The user
/// would have sat on a spendable escrow believing it was not yet due.
#[test]
fn the_refund_gate_follows_the_stored_t_not_a_policy_derived_height() {
    let (_, u_priv, _, terms, _) = setup();
    let policy = EscrowPolicy::mainnet_default();
    let fee = refund_fee_to_shielded_zat(terms.redeem_script().unwrap().len());

    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };

    // 500 blocks past the script's T. Whatever any policy would compute from a
    // lock height, CLTV says this is spendable.
    let chain = FakeChain::new(REFUND_HEIGHT as u32 + 500, NU6_3);
    let refund = refund_when_due(&chain, &record, &policy, &p2pkh([0x0b; 20]), fee)
        .expect("past the script's T the refund must build");
    assert_eq!(refund.lock_time(), REFUND_HEIGHT as u32);

    // And one block before T it is still refused, from the same source of truth.
    let early = FakeChain::new(REFUND_HEIGHT as u32 - 1, NU6_3);
    assert!(matches!(
        refund_when_due(&early, &record, &policy, &p2pkh([0x0b; 20]), fee),
        Err(ClientError::TooEarlyToRefund { .. })
    ));

    // A record whose stored T differs from the policy's view still governs.
    let mut later = record.clone();
    later.refund_height = REFUND_HEIGHT + 1_000;
    later.redeem_script =
        redeem_script(&terms.u_pub, &terms.l_pub, REFUND_HEIGHT + 1_000).unwrap();
    assert!(
        matches!(
            refund_when_due(&chain, &later, &policy, &p2pkh([0x0b; 20]), fee),
            Err(ClientError::TooEarlyToRefund { .. })
        ),
        "an escrow whose script says T+1000 is not refundable at T+500"
    );
}

/// The reviewer's closing note: if the wallet rebuilds the funding transaction
/// after `prepare_escrow` saved the record, the stored txid is stale and the
/// record points at an escrow that will never exist.
#[test]
fn a_record_that_does_not_match_the_funding_tx_is_detectable_before_broadcast() {
    let (_, u_priv, _, terms, _) = setup();
    let mut store = MemoryRecordStore::default();
    let record = EscrowRecord {
        u_priv: u_priv.secret_bytes(),
        redeem_script: terms.redeem_script().unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };
    store.save(&record).unwrap();

    // The wallet rebuilt the funding transaction, so the txid moved.
    let rebuilt_txid = [0xbb; 32];
    assert!(
        matches!(
            may_broadcast_funding(&store, &rebuilt_txid),
            Err(ClientError::NotPersisted)
        ),
        "broadcasting a funding tx the record does not describe must be refused"
    );

    // The record for the txid it does describe is still fine.
    may_broadcast_funding(&store, &TXID).unwrap();
}
