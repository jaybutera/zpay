//! Round 3 PoCs, ported to the fixed API.
//!
//! Round 1 stopped the LP forging the payment. Round 2 stopped it writing the
//! fiat terms. Round 3 found it writing `u_pub` - the user's own key slot - and
//! `refund_height`. The pattern was that every field the client did not check
//! belonged to the LP, so the fix is structural: the client now *derives* the
//! terms from the quote it accepted and compares the LP's copy against them
//! whole, rather than field by field.

use secp256k1::{Message, PublicKey as Pk1, Secp256k1 as Secp1, SecretKey as Sk1};
use secp256k1_zkp::{Secp256k1, SecretKey};
use zcash_script::interpreter::{CallbackTransactionSignatureChecker, Flags, SignatureChecker};
use zcash_script::script::{self, Code};
use zcash_script::Script;

use zecp2p_escrow::chain::FakeChain;
use zecp2p_escrow::client::{
    prepare_escrow, refund_when_due, AcceptedQuote, Announcement, ClientError, EscrowRecord,
    MemoryRecordStore, RecordStore, MAX_REFUND_HEIGHT,
};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::dlc::event_id;
use zecp2p_escrow::fees::{refund_fee_to_shielded_zat, release_fee_to_transparent_zat};
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script, refund_script_sig, release_script_sig};
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::build_release;

const NU6_3: u32 = 0x37a5_165b;
const TXID: [u8; 32] = [0x7a; 32];
const REFUND_HEIGHT: u64 = 3_500_000;

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
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

fn sign1(secp: &Secp1<secp256k1::All>, digest: &[u8; 32], key: &Sk1) -> Vec<u8> {
    let mut sig = secp.sign_ecdsa(&Message::from_digest(*digest), key);
    sig.normalize_s();
    let mut der = sig.serialize_der().to_vec();
    der.push(0x01);
    der
}

fn eval(script_sig: &[u8], script_pubkey: &[u8], digest: [u8; 32], height: i64) -> bool {
    let cb: &'static dyn Fn(&Code, &zcash_script::signature::HashType) -> Option<[u8; 32]> =
        Box::leak(Box::new(move |_: &Code, _: &zcash_script::signature::HashType| {
            Some(digest)
        }));
    let checker = CallbackTransactionSignatureChecker {
        sighash: cb,
        lock_time: height,
        is_final: false,
    };
    let (Ok(sig), Ok(pk)) = (
        script::Component::parse(&Code(script_sig.to_vec())),
        script::Component::parse(&Code(script_pubkey.to_vec())),
    ) else {
        return false;
    };
    let s: Script<zcash_script::opcode::PossiblyBad, zcash_script::opcode::PossiblyBad> =
        Script { sig, pub_key: pk };
    s.eval(consensus_flags(), &checker as &dyn SignatureChecker)
        .unwrap_or(false)
}

/// Runs the handshake with an LP that returns `lp_u_pub` in the user's slot and
/// `refund_height` as the timeout.
fn run_prepare(
    lp_u_pub: [u8; 33],
    refund_height: u64,
    quote_refund_height: u64,
) -> (Result<(), ClientError>, MemoryRecordStore) {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let l_pub = SecretKey::from_slice(&[0x22; 32])
        .unwrap()
        .public_key(&secp)
        .serialize();

    // Built at a height the constructor accepts, then set to the one under
    // test. R3-2 exercises `prepare_escrow`'s cap, and several of its cases are
    // heights `AcceptedQuote` itself refuses - so building the quote with them
    // directly would panic in this helper before the test could assert
    // anything, which is what happened between rounds 2 and 3.
    //
    // Overriding the field afterwards is the honest reproduction of the case:
    // a caller holding a quote whose timeout is unusable, which `prepare_escrow`
    // must refuse on its own rather than trusting the quote to have done it.
    let mut quote = AcceptedQuote::without_platform_fee(
        100_000_000,
        [0x85; 32],
        IDENTITY_RATE_18DEC,
        REFUND_HEIGHT,
        l_pub,
        5_000_000,
    )
    .expect("the fixture quote must build");
    quote.refund_height = quote_refund_height;
    let lp_terms = CanonicalTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: lp_u_pub,
        l_pub,
        refund_height,
        usd_amount_6dec: 100_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };
    let ann = Announcement {
        p: d.public_key(&secp),
        r: k.public_key(&secp),
        event_id: event_id(&TXID, 0),
    };
    let rs = redeem_script(&lp_u_pub, &l_pub, refund_height.max(1)).unwrap_or_default();
    let fee = release_fee_to_transparent_zat(rs.len().max(115));
    let mut store = MemoryRecordStore::default();
    let r = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote,
        &lp_terms,
        &u_priv,
        &ann,
        &d.public_key(&secp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .map(|_| ());
    (r, store)
}

/// R3-1: the LP returned a second key of its own in the user's slot.
///
/// The escrow the user funded was then a 2-of-2 the LP held both halves of:
/// spendable at any height with no attestor and no payment, while the user's
/// refund at `T` failed because the script wanted a key the user does not have.
/// That is spec section 1's first property - "timeout refund needs nobody" -
/// destroyed.
///
/// `prepare_escrow` now derives `u_pub` from `u_priv`, so the slot cannot be
/// anything else.
#[test]
fn r3_1_the_client_refuses_terms_whose_user_key_is_not_its_own() {
    let secp = Secp1::new();
    let lp_second = Sk1::from_slice(&[0x33; 32]).unwrap();
    let lp_second_pub = Pk1::from_secret_key(&secp, &lp_second).serialize();

    let (res, store) = run_prepare(lp_second_pub, REFUND_HEIGHT, REFUND_HEIGHT);
    let err = res.expect_err("a u_pub that is not the user's key must be refused");
    assert!(
        matches!(err, ClientError::TermsNotAsAccepted { .. }),
        "got {err}"
    );
    assert!(
        store.load(&TXID).is_none(),
        "nothing may be persisted for an escrow the client refused"
    );
}

/// The escrow the client *does* build always answers to the user's own key, so
/// the refund works and the LP cannot spend the release branch alone. Run
/// through the consensus interpreter, as the reviewer's PoC was.
#[test]
fn r3_1b_the_derived_escrow_always_refunds_to_the_user() {
    let secp = Secp1::new();
    let zkp = Secp256k1::new();
    let u_priv_zkp = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let u_priv = Sk1::from_slice(&[0x11; 32]).unwrap();
    let l_priv = Sk1::from_slice(&[0x22; 32]).unwrap();
    let l_pub = Pk1::from_secret_key(&secp, &l_priv).serialize();
    let u_pub = u_priv_zkp.public_key(&zkp).serialize();

    let canonical = CanonicalTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub,
        l_pub,
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 100_000_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
        platform_fee_zat: 0,
        treasury_script: Vec::new(),
    };
    let quote = AcceptedQuote::without_platform_fee(
        100_000_000,
        [0x85; 32],
        IDENTITY_RATE_18DEC,
        REFUND_HEIGHT,
        l_pub,
        5_000_000,
    )
    .expect("the fixture quote must build");
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    let ann = Announcement {
        p: d.public_key(&zkp),
        r: k.public_key(&zkp),
        event_id: event_id(&TXID, 0),
    };
    let mut store = MemoryRecordStore::default();
    let fee = release_fee_to_transparent_zat(
        redeem_script(&u_pub, &l_pub, REFUND_HEIGHT).unwrap().len(),
    );

    let prepared = prepare_escrow(
        &zkp,
        &mut store,
        TXID,
        0,
        NU6_3,
        &quote,
        &canonical,
        &u_priv_zkp,
        &ann,
        &d.public_key(&zkp),
        &p2pkh([0x09; 20]),
        fee,
    )
    .expect("terms matching the accepted quote are fine");

    let rs = prepared.terms.redeem_script().unwrap();
    let spk = p2sh_script_pubkey(&rs);
    let digest = build_release(&prepared.terms, &p2pkh([0x09; 20]), fee)
        .unwrap()
        .sighash()
        .unwrap();

    // The user's own key satisfies the refund branch at T.
    let ss_refund = refund_script_sig(&sign1(&secp, &digest, &u_priv), &rs);
    assert!(
        eval(&ss_refund, &spk, digest, REFUND_HEIGHT as i64),
        "the user must always be able to refund at T"
    );

    // And the LP's two keys do not: the second slot is the user's, and the LP
    // does not have it.
    let lp_second = Sk1::from_slice(&[0x33; 32]).unwrap();
    let ss_lp = release_script_sig(
        &sign1(&secp, &digest, &lp_second),
        &sign1(&secp, &digest, &l_priv),
        &rs,
    );
    assert!(
        !eval(&ss_lp, &spk, digest, 3_000_000),
        "the LP must not be able to spend the release branch with keys of its own"
    );
}

/// R3-2: `refund_height` was LP-chosen and unbounded.
///
/// Above `u32::MAX` the client could never build the refund at all; at `2^62`
/// the escrow was locked for centuries. The user now states the timeout it
/// accepted, and the client caps it.
#[test]
fn r3_2_an_unusable_refund_height_is_refused() {
    let secp = Secp256k1::new();
    let u_pub = SecretKey::from_slice(&[0x11; 32])
        .unwrap()
        .public_key(&secp)
        .serialize();

    for (t, label) in [
        (1u64 << 32, "above u32"),
        (600_000_000u64, "CLTV timestamp range"),
        (1u64 << 62, "2^62"),
    ] {
        // Even when the LP and the quote agree on the absurd value, the cap
        // refuses it: the user cannot accept a timeout it can never use.
        let (res, store) = run_prepare(u_pub, t, t);
        let err = res.expect_err(&format!("T={t} ({label}) must be refused"));
        assert!(
            matches!(err, ClientError::RefundHeightOutOfRange { .. }),
            "T={t} ({label}) gave {err}"
        );
        assert!(store.load(&TXID).is_none());
    }

    // And a timeout the LP raised above what the user accepted is caught as a
    // terms mismatch.
    let (res, _) = run_prepare(u_pub, REFUND_HEIGHT + 1_000, REFUND_HEIGHT);
    assert!(matches!(
        res.unwrap_err(),
        ClientError::TermsNotAsAccepted { .. }
    ));
}

#[test]
fn the_refund_height_cap_leaves_centuries_of_headroom() {
    // Mainnet was near 3.47M when this was written and gains roughly 420k
    // blocks a year, so the cap is not a limit anyone will meet, and it is far
    // below the 500,000,000 threshold at which a locktime is read as a Unix
    // timestamp rather than a height.
    assert_eq!(MAX_REFUND_HEIGHT, 500_000_000);
    assert!(MAX_REFUND_HEIGHT < u32::MAX as u64);
    let years = (MAX_REFUND_HEIGHT - 3_470_000) / 420_000;
    assert!(years > 1_000, "only {years} years of headroom");
}

/// A record whose stored script does not answer to its own key cannot refund,
/// so it is refused when read back rather than at `T`.
#[test]
fn a_record_whose_script_does_not_match_its_key_is_refused() {
    let secp = Secp1::new();
    let lp_second = Pk1::from_secret_key(&secp, &Sk1::from_slice(&[0x33; 32]).unwrap()).serialize();
    let l_pub = Pk1::from_secret_key(&secp, &Sk1::from_slice(&[0x22; 32]).unwrap()).serialize();

    let record = EscrowRecord {
        u_priv: [0x11; 32],
        redeem_script: redeem_script(&lp_second, &l_pub, REFUND_HEIGHT).unwrap(),
        refund_height: REFUND_HEIGHT,
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        consensus_branch_id: NU6_3,
    };

    assert_eq!(record.validate(), Err(ClientError::RecordKeyMismatch));

    let chain = FakeChain::new(REFUND_HEIGHT as u32 + 10, NU6_3);
    let fee = refund_fee_to_shielded_zat(record.redeem_script.len());
    assert_eq!(
        refund_when_due(
            &chain,
            &record,
            &EscrowPolicy::mainnet_default(),
            &p2pkh([0x0b; 20]),
            fee
        )
        .unwrap_err(),
        ClientError::RecordKeyMismatch
    );
}
