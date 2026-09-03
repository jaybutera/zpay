//! Both settlement rails driven through their whole decision path, against the
//! numbers the two live runs actually used.
//!
//! The unit tests in `auto::rail`, `auto::zec` and `auto::journal` each check
//! one piece. This checks the property the work exists for: that one daemon can
//! hold both systems at once without either changing the other's behaviour, and
//! that the fiat leg they share produces the same answer whichever asks.
//!
//! The two runs these numbers come from:
//!
//! - **Base, 2026-09-01.** Deposit 4499, 4,875,437 units at rate
//!   0.990881148896019200, paid $4.84, attested and fulfilled.
//! - **Zcash, 2026-09-03.** Funding `d599b8cd…c6d2:0`, 200,000 zat, $1.50 to
//!   jay-butera, released by `50f69c04…4c55` with criterion 6 holding.
//!
//! The escrow's real `intentHash` is asserted here against the value the
//! mainnet run recorded, because that hash is the entire binding between a
//! Venmo payment and an escrow: if this code computes a different one, the
//! attestation it obtains releases nothing.

use alloy::primitives::{B256, U256};

use zecp2p_escrow::{
    chain::{ChainClient, FakeChain, Utxo},
    deadlines::EscrowPolicy,
    tx::EscrowTerms,
};
use zecp2p_taker::auto::{
    fiat::prover_environment,
    journal::{FillRecord, FillState, Journal},
    money::payment_cents,
    rail::{FiatLeg, Rail, RailState, WorkId},
    zec::{canonical_terms, state_of, WatchedEscrow},
};

/// The mainnet escrow's own redeem-script keys, read out of the scriptSig of
/// the release transaction `50f69c04…4c55`. `u_pub` appears twice in the script
/// (the multisig branch and the CLTV branch) and `l_pub` once; the ordering was
/// confirmed by rebuilding the P2SH and matching it against the scriptPubKey
/// the funding output actually paid, `a9140254c1ae…87`, which is
/// `t3JmwpFaDiWhUtwTNRpEfknN2ZJD3h4gBUZ`.
const U_PUB: &str = "0336952f98c6a4c39bfb9cfcb9d2b44f926b7c9169e86307829132415a29bbe73c";
const L_PUB: &str = "02f65f068412941876f07ad23c7903bd799d5aea74856f7856b5a8338e05f4614f";

/// The refund height burned into that escrow's script, parsed from the same
/// redeem script (`OP_ELSE 0380fa34 OP_CLTV`).
const REFUND_HEIGHT: u64 = 3_472_000;

/// The moment the escrow reached its confirmation depth, from the run record.
const LOCK_CONFIRMED_MS: u64 = 1_788_455_397_380;

/// jay-butera's `hashedOnchainId`, as the curator answers it.
const PAYEE_HASH: &str = "853410f0416f12611961e72ee5397ec6839a3f6475467f8a557bbdb3fc8555db";

/// The `INTENT_HASH` the 2026-09-03 mainnet `announce` printed, and the one the
/// enclave signed over. This is the number that must not move.
const MAINNET_INTENT_HASH: &str =
    "a37aad5be02179be763bf03547ad4e0a359896b2f6acb8f2dc278536137eec5d";

/// The consensus branch in force on Zcash mainnet when the release was mined.
const BRANCH: u32 = 0x37a5_165b;

fn key(hex_text: &str) -> [u8; 33] {
    hex::decode(hex_text).unwrap().as_slice().try_into().unwrap()
}

fn bytes32(hex_text: &str) -> [u8; 32] {
    hex::decode(hex_text).unwrap().as_slice().try_into().unwrap()
}

/// The funding txid in internal order, which is the reverse of what an explorer
/// prints. The wire format uses this order and every RPC prints the other, so
/// getting it backwards is the classic way to ask a node about an outpoint that
/// does not exist.
fn funding_txid() -> [u8; 32] {
    let mut b = bytes32("d599b8cd1a7f6ba8eae98c7782e5eec4687c3fef17eaf57f3a3f27a8cf68c6d2");
    b.reverse();
    b
}

fn mainnet_escrow() -> WatchedEscrow {
    let terms = EscrowTerms {
        funding_txid: funding_txid(),
        vout: 0,
        amount_zat: 200_000,
        u_pub: key(U_PUB),
        l_pub: key(L_PUB),
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: BRANCH,
    };
    let canonical = canonical_terms(
        &terms,
        1_500_000,
        1_000_000_000_000_000_000,
        bytes32(PAYEE_HASH),
        LOCK_CONFIRMED_MS,
        0,
        Vec::new(),
    )
    .expect("the mainnet terms must build");

    WatchedEscrow {
        terms,
        canonical,
        recipient: "jay-butera".into(),
        pre_signature_verified: true,
        venmo_paid: false,
        outcome_secret_held: false,
    }
}

/// A chain holding that escrow unspent at `confirmations`, at `height`.
fn chain(height: u32, confirmations: u32) -> FakeChain {
    let escrow = mainnet_escrow();
    let mut chain = FakeChain::new(height, BRANCH);
    chain.add_utxo(
        escrow.terms.funding_txid,
        0,
        Utxo {
            script_pubkey: escrow.terms.script_pubkey().unwrap(),
            amount_zat: 200_000,
            confirmations,
        },
    );
    chain
}

/// The binding, checked against the value the mainnet run recorded.
///
/// If this ever fails, the daemon computes a different `intentHash` from the
/// one `paid_path` does, and an attestation obtained under it releases nothing
/// while the fiat has already left.
#[test]
fn the_rail_reproduces_the_mainnet_intent_hash() {
    let leg = mainnet_escrow().fiat_leg(10_000).unwrap();
    assert_eq!(
        hex::encode(leg.intent_hash.as_slice()),
        MAINNET_INTENT_HASH,
        "the rail's intent hash must be the one the enclave signed on 2026-09-03"
    );
}

/// And the whole fiat leg, not just the hash: the amount that was typed into
/// Venmo, the account it went to, and the snapshot the enclave was given.
#[test]
fn the_rail_reproduces_the_whole_mainnet_fiat_leg() {
    let leg = mainnet_escrow().fiat_leg(10_000).unwrap();
    assert_eq!(leg.payment.to_venmo_string(), "1.50");
    assert_eq!(leg.recipient, "jay-butera");
    assert_eq!(leg.intent_amount_6dec, U256::from(1_500_000u64));
    assert_eq!(leg.intent_timestamp_ms, LOCK_CONFIRMED_MS);
    assert_eq!(hex::encode(leg.payee_hash.as_slice()), PAYEE_HASH);

    // The prover environment the escrow's own `announce` printed that day.
    let env = prover_environment(&leg);
    let get = |k: &str| {
        env.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(get("INTENT_HASH"), format!("0x{MAINNET_INTENT_HASH}"));
    assert_eq!(get("INTENT_AMOUNT"), "1500000");
    assert_eq!(get("INTENT_TIMESTAMP_MS"), LOCK_CONFIRMED_MS.to_string());
    assert_eq!(get("INTENT_RATE"), "1000000000000000000");
}

/// The escrow rail's full path: under-confirmed, then payable, then paid.
#[test]
fn the_escrow_rail_walks_from_depth_to_payable() {
    let policy = EscrowPolicy::mainnet_default();
    let escrow = mainnet_escrow();

    // One confirmation is not enough for 200,000 zat.
    match state_of(&chain(3_470_690, 1), &escrow, &policy, 10_000).unwrap() {
        RailState::Waiting { why } => assert!(why.contains("confirmations"), "{why}"),
        other => panic!("expected a wait, got {other:?}"),
    }

    // Eleven confirmations is what the live `watch` reported before paying.
    match state_of(&chain(3_470_700, 11), &escrow, &policy, 10_000).unwrap() {
        RailState::ReadyToPay(leg) => {
            assert_eq!(leg.payment.to_venmo_string(), "1.50");
            assert_eq!(
                hex::encode(leg.intent_hash.as_slice()),
                MAINNET_INTENT_HASH
            );
        }
        other => panic!("expected ReadyToPay, got {other:?}"),
    }

    // Once paid, it is awaiting settlement rather than payable again. Paying a
    // second time against one escrow sends the fiat twice.
    let mut paid = mainnet_escrow();
    paid.venmo_paid = true;
    match state_of(&chain(3_470_700, 11), &paid, &policy, 10_000).unwrap() {
        RailState::AwaitingSettlement(_) => {}
        other => panic!("expected AwaitingSettlement, got {other:?}"),
    }
}

/// The two rails price their own trades and neither reaches into the other's
/// arithmetic, but both go through the one sizing function.
#[test]
fn both_rails_size_their_payments_through_the_same_function() {
    // Base, deposit 4499: 4,875,437 units at 0.990881148896019200 is $4.84.
    let base = payment_cents(
        U256::from(4_875_437u64),
        U256::from(990_881_148_896_019_200u128),
        10_000,
    )
    .unwrap();
    assert_eq!(base.to_venmo_string(), "4.84");

    // Zcash: $1.50 at a rate of exactly 1.0.
    let zec = mainnet_escrow().fiat_leg(10_000).unwrap().payment;
    assert_eq!(zec.to_venmo_string(), "1.50");

    // The same constructor produced both, so an unchecked amount cannot reach
    // the send button on either rail.
    assert_ne!(base, zec);
}

/// One operator cap governs both. A daemon told it may send $5 must refuse a
/// $50 trade whichever system settles it.
#[test]
fn the_payment_cap_binds_both_rails_alike() {
    let cap = 500;

    let base = payment_cents(
        U256::from(50_000_000u64),
        U256::from(1_000_000_000_000_000_000u128),
        cap,
    );
    assert!(base.is_err(), "the Base rail must refuse an oversized fill");

    let mut big = mainnet_escrow();
    big.canonical.usd_amount_6dec = 50_000_000;
    assert!(
        big.fiat_leg(cap).is_err(),
        "the escrow rail must refuse an oversized trade too"
    );
}

/// Two live trades, one on each rail, held in one journal at once. This is the
/// side-by-side property, stated directly.
#[test]
fn one_journal_holds_a_live_trade_on_each_rail() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(dir.path().join("both.jsonl")).unwrap();

    // The Base fill, mid-flight.
    let mut base = FillRecord::new(
        U256::from(4499),
        B256::repeat_byte(0xaa),
        U256::from(4_875_437u64),
        U256::from(990_881_148_896_019_200u128),
        "jay-butera".into(),
    );
    base.state = FillState::Signalled;
    base.intent_hash = Some(B256::repeat_byte(0xbb));
    journal.record(&base).unwrap();

    // The escrow fill, further along.
    let leg = mainnet_escrow().fiat_leg(10_000).unwrap();
    let mut zec = FillRecord::new_zec(
        mainnet_escrow().work_id().local,
        leg.intent_amount_6dec,
        leg.rate_18dec,
        leg.recipient.clone(),
    );
    zec.state = FillState::Paid;
    zec.intent_hash = Some(leg.intent_hash);
    zec.paid = Some(leg.payment.to_venmo_string());
    journal.record(&zec).unwrap();

    let latest = journal.latest().unwrap();
    assert_eq!(latest.len(), 2, "both rails must survive in one journal");

    let on_base = journal.in_flight_on(Rail::Base).unwrap().unwrap();
    assert_eq!(on_base.state, FillState::Signalled);
    assert_eq!(on_base.deposit_id, U256::from(4499));

    let on_zec = journal.in_flight_on(Rail::Zec).unwrap().unwrap();
    assert_eq!(on_zec.state, FillState::Paid);
    assert_eq!(on_zec.paid.as_deref(), Some("1.50"));
    assert_eq!(on_zec.intent_hash, Some(leg.intent_hash));

    // The escrow's fiat may have left, so a restart hands it to a human. The
    // Base fill is only signalled, which is recoverable without one.
    let stuck = journal.needs_operator().unwrap();
    assert_eq!(stuck.len(), 1);
    assert_eq!(stuck[0].rail, Rail::Zec);
}

/// The work ids of two live trades never collide, even when their rail-local
/// names would.
#[test]
fn the_two_live_trades_have_distinct_identities() {
    let base = WorkId::base(U256::from(4499));
    let zec = mainnet_escrow().work_id();
    assert_ne!(base, zec);
    assert_eq!(base.rail, Rail::Base);
    assert_eq!(zec.rail, Rail::Zec);
    assert!(zec.to_string().starts_with("zec/"));
}

/// A fiat leg carries nothing that names a chain, which is the property that
/// lets one browser driver and one feed search serve both rails.
#[test]
fn a_fiat_leg_is_rail_agnostic() {
    let leg: FiatLeg = mainnet_escrow().fiat_leg(10_000).unwrap();
    // Everything the shared code needs, and nothing about Zcash or Base.
    assert!(!leg.recipient.is_empty());
    assert!(leg.payment.cents() > 0);
    assert!(leg.intent_timestamp_ms > 0);
    assert_eq!(leg.not_before.timestamp_millis() as u64, LOCK_CONFIRMED_MS);
}

/// The escrow crate reads the branch from the node and the terms carry what the
/// pre-signature was made for. A mismatch stops the rail before it pays,
/// because the release the user pre-signed would not verify.
#[test]
fn a_branch_change_stops_the_escrow_rail() {
    let mut moved = chain(3_470_700, 11);
    moved.branch_id = 0xc8e7_1055;
    match state_of(&moved, &mainnet_escrow(), &EscrowPolicy::mainnet_default(), 10_000).unwrap() {
        RailState::NeedsOperator { why } => assert!(why.contains("Do not pay"), "{why}"),
        other => panic!("expected NeedsOperator, got {other:?}"),
    }
}

/// The chain fixture is the real escrow: the script it pays is the one the
/// mainnet funding output actually paid.
#[test]
fn the_fixture_pays_the_real_mainnet_script() {
    let escrow = mainnet_escrow();
    let spk = escrow.terms.script_pubkey().unwrap();
    assert_eq!(
        hex::encode(&spk),
        "a9140254c1aebb6ec6136cbe133b704782ef506ed17087",
        "this must be the scriptPubKey of t3JmwpFaDiWhUtwTNRpEfknN2ZJD3h4gBUZ"
    );
    // And the chain the tests drive really holds it.
    let utxo = ChainClient::utxo(&chain(3_470_700, 11), &escrow.terms.funding_txid, 0)
        .unwrap()
        .expect("the fixture must hold the escrow");
    assert_eq!(utxo.script_pubkey, spk);
    assert_eq!(utxo.amount_zat, 200_000);
}
