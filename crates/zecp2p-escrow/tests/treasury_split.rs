//! The platform fee as a third output on the release.
//!
//! The claim this feature rests on is that the fee needs no new trust, because
//! the user's adaptor pre-signature is over a ZIP 244 SIGHASH_ALL digest that
//! commits to the whole output set. These tests take that claim apart into the
//! four properties it actually needs:
//!
//! 1. the split arithmetic is exact and the outputs are in a fixed order;
//! 2. the treasury address is inside `terms_hash`, so an LP that rewrites it
//!    produces terms the user refuses before funding;
//! 3. the refund path has no treasury output at all, so a failed trade is free;
//! 4. the fee is bound by the same attestation that releases the escrow -
//!    change it and the outcome point moves, so the attestor's scalar decrypts
//!    nothing.
//!
//! Property 4 is the one worth reading closely. It is what makes the fee
//! enforced rather than merely requested.

use secp256k1_zkp::{Secp256k1, SecretKey};

use zecp2p_escrow::client::{
    prepare_escrow, AcceptedQuote, Announcement, ClientError, MemoryRecordStore,
};
use zecp2p_escrow::dlc::{
    decrypt_pre_signature, event_id, outcome_point, pre_sign, recover_outcome_secret,
    sign_outcome, verify_outcome_secret, verify_pre_signature,
};
use zecp2p_escrow::fees::{release_fee_to_transparent_zat, release_fee_zat};
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::treasury::{
    default_platform_fee_zat, platform_fee_zat, DUST_THRESHOLD_ZAT, PLATFORM_FEE_BPS,
};
use zecp2p_escrow::tx::{build_refund, build_release, build_release_split, EscrowTerms, ReleaseSplit, TxError};

const TXID: [u8; 32] = [0xd5; 32];
const PAYEE: [u8; 32] = [0x85; 32];
const REFUND_HEIGHT: u64 = 3_471_833;
const BRANCH: u32 = 0xc8e7_1055;
const LOCK_MS: u64 = 1_756_000_000_000;
/// 200,000 zat is the size the mainnet run actually escrowed.
const AMOUNT: u64 = 200_000;

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn lp_script() -> Vec<u8> {
    p2pkh([0x09; 20])
}

/// The platform's treasury: the actual pinned testnet constant, not a stand-in.
///
/// Using the real one means these tests exercise the same bytes a testnet
/// live-fire run puts on chain, so a constant that decoded wrongly would fail
/// here rather than at the node.
fn treasury_script() -> Vec<u8> {
    zecp2p_escrow::treasury::treasury_script(zecp2p_escrow::address::AddrNetwork::Test)
        .expect("the testnet treasury is pinned")
}

/// An address an LP might substitute for the treasury: its own.
fn lp_own_script() -> Vec<u8> {
    p2pkh([0xba; 20])
}

fn keys() -> (SecretKey, SecretKey) {
    (
        SecretKey::from_slice(&[0x11; 32]).unwrap(),
        SecretKey::from_slice(&[0x22; 32]).unwrap(),
    )
}

fn escrow_terms(secp: &Secp256k1<secp256k1_zkp::All>) -> EscrowTerms {
    let (u, l) = keys();
    EscrowTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: AMOUNT,
        u_pub: u.public_key(secp).serialize(),
        l_pub: l.public_key(secp).serialize(),
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: BRANCH,
    }
}

// ---------------------------------------------------------------------------
// 1. Split correctness
// ---------------------------------------------------------------------------

#[test]
fn the_three_way_split_adds_up_to_the_escrow_exactly() {
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let miner = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());
    let fee = default_platform_fee_zat(AMOUNT);
    assert_eq!(fee, 400, "20 bps of 200000 zat");

    let split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: miner,
        platform_fee_zat: fee,
        treasury_script: treasury_script(),
    };
    let outs = split.outputs(AMOUNT).expect("the split must build");

    assert_eq!(outs.len(), 2, "an LP leg and a treasury leg");
    // Nothing is created and nothing is lost: what the miner does not take, the
    // two outputs do. A rounding error here is ZEC that vanishes into the fee.
    assert_eq!(outs[0].value_zat + outs[1].value_zat + miner, AMOUNT);
    assert_eq!(outs[0].value_zat, AMOUNT - miner - fee);
    assert_eq!(outs[1].value_zat, fee);
}

#[test]
fn the_treasury_output_is_always_last() {
    // The order is inside the sighash, so it is not a stylistic choice. Two
    // parties that ordered these differently would compute different digests
    // from identical terms, and the LP would find out after paying the fiat.
    let split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 400,
        treasury_script: treasury_script(),
    };
    let outs = split.outputs(AMOUNT).unwrap();
    assert_eq!(outs[0].script, lp_script());
    assert_eq!(outs[1].script, treasury_script());

    // And it stays last even when the treasury output is the larger of the two,
    // which is what a sort-by-value would get wrong.
    let lopsided = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 150_000,
        treasury_script: treasury_script(),
    };
    let outs = lopsided.outputs(AMOUNT).unwrap();
    assert!(outs[1].value_zat > outs[0].value_zat);
    assert_eq!(outs[1].script, treasury_script(), "value must not reorder outputs");
}

#[test]
fn a_zero_fee_produces_the_two_output_release_it_always_had() {
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let miner = release_fee_to_transparent_zat(terms.redeem_script().unwrap().len());

    // The regression the design asked for: with the fee omitted, the new
    // multi-output builder must reproduce the digest the old single-output
    // builder produced, byte for byte. Anything else is a format change to
    // every escrow already in the wild.
    let old = build_release(&terms, &lp_script(), miner).unwrap().sighash().unwrap();
    let new = build_release_split(&terms, &ReleaseSplit::without_fee(lp_script(), miner))
        .unwrap()
        .sighash()
        .unwrap();
    assert_eq!(old, new);

    let outs = ReleaseSplit::without_fee(lp_script(), miner)
        .outputs(AMOUNT)
        .unwrap();
    assert_eq!(outs.len(), 1, "no fee means no treasury output, not a zero one");
}

#[test]
fn a_split_that_leaves_the_lp_nothing_is_refused() {
    // A fee that swallows the escrow would build a zero-value first output,
    // which is dust and makes the release unbroadcastable. Refusing here means
    // the failure is a message rather than a transaction no node will relay.
    let split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: AMOUNT - 15_000,
        treasury_script: treasury_script(),
    };
    assert!(matches!(
        split.outputs(AMOUNT),
        Err(TxError::OutputsExceedEscrow { .. })
    ));

    // And one that exceeds it outright.
    let over = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: AMOUNT,
        treasury_script: treasury_script(),
    };
    assert!(over.outputs(AMOUNT).is_err());
}

#[test]
fn an_empty_output_script_is_refused_rather_than_burned() {
    // An empty scriptPubKey is anyone-can-spend. An output paid to one is money
    // handed to whichever miner notices first, and it would confirm silently.
    //
    // A fee with an empty treasury is caught earlier still, by the both-or-
    // neither check, so the case this exercises is the payout leg.
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let split = ReleaseSplit {
        payout_script: Vec::new(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 400,
        treasury_script: treasury_script(),
    };
    assert!(matches!(
        build_release_split(&terms, &split),
        Err(TxError::EmptyOutputScript)
    ));
}

#[test]
fn changing_the_treasury_output_changes_the_digest() {
    // This is the enforcement, stated at the level of the transaction: the
    // sighash covers the treasury output's script and its value, so an LP that
    // wants either of them different needs a different signature from the user.
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let base = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 400,
        treasury_script: treasury_script(),
    };
    let d = |s: &ReleaseSplit| build_release_split(&terms, s).unwrap().sighash().unwrap();

    let mut redirected = base.clone();
    redirected.treasury_script = lp_own_script();
    assert_ne!(d(&base), d(&redirected), "the treasury script is signed over");

    let mut shrunk = base.clone();
    // Above dust, so this tests the digest rather than the dust gate.
    shrunk.platform_fee_zat = 100;
    assert_ne!(d(&base), d(&shrunk), "the fee amount is signed over");

    let dropped = ReleaseSplit::without_fee(lp_script(), 15_000);
    assert_ne!(d(&base), d(&dropped), "dropping the output is signed over");
}

// ---------------------------------------------------------------------------
// 2. Terms-hash binding
// ---------------------------------------------------------------------------

fn canonical_with(fee: u64, treasury: Vec<u8>, secp: &Secp256k1<secp256k1_zkp::All>) -> CanonicalTerms {
    let (u, l) = keys();
    CanonicalTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: AMOUNT,
        u_pub: u.public_key(secp).serialize(),
        l_pub: l.public_key(secp).serialize(),
        refund_height: REFUND_HEIGHT,
        usd_amount_6dec: 1_500_000,
        rate_18dec: IDENTITY_RATE_18DEC,
        payee_hash: PAYEE,
        lock_confirmed_ms: LOCK_MS,
        platform_fee_zat: fee,
        treasury_script: treasury,
    }
}

/// The quote the user's client actually builds for this escrow, fee and all.
///
/// It goes through `AcceptedQuote::at_identity_rate`, the single policy site, so
/// the fee and the treasury script here are derived exactly as a real client
/// derives them. A test that assigned them directly would be testing its own
/// arithmetic rather than the client's - which is why the fields are private.
fn honest_quote(secp: &Secp256k1<secp256k1_zkp::All>) -> AcceptedQuote {
    let (_, l) = keys();
    AcceptedQuote::at_identity_rate(
        1_500_000,
        PAYEE,
        REFUND_HEIGHT,
        l.public_key(secp).serialize(),
        AMOUNT,
        zecp2p_escrow::address::AddrNetwork::Test,
    )
    .expect("the quote must build against the pinned testnet treasury")
}

fn announcement_for(secp: &Secp256k1<secp256k1_zkp::All>) -> (Announcement, SecretKey, SecretKey) {
    let d = SecretKey::from_slice(&[0xd1; 32]).unwrap();
    let k = SecretKey::from_slice(&[0x4b; 32]).unwrap();
    (
        Announcement {
            p: d.public_key(secp),
            r: k.public_key(secp),
            event_id: event_id(&TXID, 0),
        },
        d,
        k,
    )
}

#[test]
fn an_lp_that_rewrites_the_treasury_address_is_refused_before_funding() {
    // The attack: the LP relays terms identical to the ones quoted except that
    // the treasury script is its own address. Without the field in
    // `CanonicalTerms` the user would sign a release paying the LP twice.
    let secp = Secp256k1::new();
    let (u_priv, _) = keys();
    let (ann, _, _) = announcement_for(&secp);
    let mut store = MemoryRecordStore::default();

    let quote = honest_quote(&secp);
    assert_eq!(quote.platform_fee_zat(), 400, "20 bps of 200000 zat");
    let lp_terms = canonical_with(quote.platform_fee_zat(), lp_own_script(), &secp);

    let err = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        BRANCH,
        &quote,
        &lp_terms,
        &u_priv,
        &ann,
        &ann.p,
        &lp_script(),
        15_000,
    )
    .expect_err("a rewritten treasury must not reach a pre-signature");

    assert!(
        matches!(err, ClientError::TermsNotAsAccepted { .. }),
        "got {err:?}"
    );

    // And nothing was persisted, so the user has not committed to an escrow it
    // would then have to wait out to `T`.
    assert!(
        zecp2p_escrow::client::may_broadcast_funding(&store, &TXID).is_err(),
        "a refused handshake must leave no record to broadcast against"
    );
}

#[test]
fn an_lp_that_shrinks_the_platform_fee_is_refused_too() {
    // The mirror case: an LP that keeps the treasury address but pays it less
    // than the terms say, pocketing the difference.
    let secp = Secp256k1::new();
    let (u_priv, _) = keys();
    let (ann, _, _) = announcement_for(&secp);
    let mut store = MemoryRecordStore::default();

    let err = prepare_escrow(
        &secp,
        &mut store,
        TXID,
        0,
        BRANCH,
        &honest_quote(&secp),
        &canonical_with(1, treasury_script(), &secp),
        &u_priv,
        &ann,
        &ann.p,
        &lp_script(),
        15_000,
    )
    .expect_err("a shrunken fee must not reach a pre-signature");
    assert!(matches!(err, ClientError::TermsNotAsAccepted { .. }));
}

#[test]
fn the_treasury_address_is_in_the_terms_hash_and_therefore_in_the_outcome_point() {
    // The load-bearing property, checked directly rather than through the
    // client: `terms_hash` feeds `outcome_challenge`, which produces `Y`. Two
    // sets of terms differing only in the treasury address must produce
    // different outcome points, or a scalar released for one would decrypt a
    // pre-signature made under the other.
    let secp = Secp256k1::new();
    let (ann, _, _) = announcement_for(&secp);

    let honest = canonical_with(400, treasury_script(), &secp);
    let rewritten = canonical_with(400, lp_own_script(), &secp);
    assert_ne!(honest.terms_hash(), rewritten.terms_hash());

    let y = |t: &CanonicalTerms| {
        outcome_point(&secp, &ann.r, &ann.p, &ann.event_id, &t.terms_hash()).unwrap()
    };
    assert_ne!(y(&honest), y(&rewritten));

    let cheaper = canonical_with(1, treasury_script(), &secp);
    assert_ne!(y(&honest), y(&cheaper), "the fee amount must move Y too");
}

// ---------------------------------------------------------------------------
// 3. The refund path charges nothing
// ---------------------------------------------------------------------------

#[test]
fn the_refund_pays_the_user_everything_and_the_treasury_nothing() {
    // A trade that failed was not served, so it is not billed. A fee on failure
    // would give the operator a reason to prefer failure, which is the whole
    // argument for keeping the refund branch untouched.
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let miner = zecp2p_escrow::fees::refund_fee_to_transparent_zat(
        terms.redeem_script().unwrap().len(),
    );
    let user = p2pkh([0x0b; 20]);

    let refund = build_refund(&terms, &user, miner).expect("the refund must build");

    // The refund's digest is the one-output shape, which the release with a
    // treasury output is not. There is no path by which the refund grows a
    // third output, because `build_refund` does not take a split.
    let release = build_release_split(
        &terms,
        &ReleaseSplit {
            payout_script: lp_script(),
            miner_fee_zat: 15_000,
            platform_fee_zat: 400,
            treasury_script: treasury_script(),
        },
    )
    .unwrap();
    assert_ne!(refund.sighash().unwrap(), release.sighash().unwrap());

    // And the value: everything but the miner fee goes back to the user.
    let raw = zecp2p_escrow::tx::serialize_refund(&terms, &user, miner, &[0x51]).unwrap();
    let outputs = transparent_outputs(&raw);
    assert_eq!(outputs.len(), 1, "the refund has exactly one output");
    assert_eq!(outputs[0].0, AMOUNT - miner);
    assert_eq!(outputs[0].1, user);
}

#[test]
fn a_refund_is_never_charged_even_when_the_terms_carry_a_fee() {
    // The terms the user signed do carry `platform_fee_zat`, because the
    // release pays it. The refund is built from `EscrowTerms`, which does not
    // carry it at all, so there is no way for the fee to leak onto the refund
    // even by mistake. This pins that the two structures stay separate.
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let user = p2pkh([0x0b; 20]);
    let miner = 10_000;

    let with_fee_in_terms = canonical_with(400, treasury_script(), &secp);
    assert_eq!(with_fee_in_terms.platform_fee_zat, 400);

    let raw = zecp2p_escrow::tx::serialize_refund(&terms, &user, miner, &[0x51]).unwrap();
    let outputs = transparent_outputs(&raw);
    assert_eq!(outputs.len(), 1);
    assert_eq!(
        outputs[0].0,
        AMOUNT - miner,
        "the refund returns the whole escrow less the miner fee"
    );
    assert!(
        !outputs.iter().any(|(_, script)| *script == treasury_script()),
        "no output of a refund may pay the treasury"
    );
}

// ---------------------------------------------------------------------------
// 4. The attestation enforces the fee amount
// ---------------------------------------------------------------------------

/// Verifies `sig` against `digest` under `u_pub`, the way a node's
/// CHECKMULTISIG would.
///
/// The signature is moved between the two secp crate versions by its DER bytes,
/// which is what `end_to_end.rs` does for the same reason.
fn signature_covers(
    sig: &secp256k1_zkp::ecdsa::Signature,
    digest: &[u8; 32],
    u_pub: &secp256k1_zkp::PublicKey,
) -> bool {
    let verifier = secp256k1::Secp256k1::verification_only();
    let sig = match secp256k1::ecdsa::Signature::from_der(&sig.serialize_der()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = secp256k1::PublicKey::from_slice(&u_pub.serialize()).unwrap();
    verifier
        .verify_ecdsa(&secp256k1::Message::from_digest(*digest), &sig, &pk)
        .is_ok()
}

#[test]
fn the_attestors_scalar_only_decrypts_the_release_that_pays_the_agreed_fee() {
    // The end-to-end statement of the enforcement claim, run through the real
    // adaptor path rather than asserted.
    //
    // The user pre-signs a release that pays the treasury 400 zat, under an
    // outcome point derived from terms carrying that fee. The attestor later
    // publishes a scalar for those terms. The scalar decrypts the
    // pre-signature, and the signature it yields covers the digest of the
    // three-output transaction and no other - including the two-output
    // transaction an LP would rather broadcast.
    let secp = Secp256k1::new();
    let (u_priv, _) = keys();
    let u_pub = u_priv.public_key(&secp);
    let terms = escrow_terms(&secp);
    let (ann, d, k) = announcement_for(&secp);

    let agreed = canonical_with(400, treasury_script(), &secp);
    let y = outcome_point(&secp, &ann.r, &ann.p, &ann.event_id, &agreed.terms_hash()).unwrap();

    let honest_split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 400,
        treasury_script: treasury_script(),
    };
    let honest_digest = build_release_split(&terms, &honest_split)
        .unwrap()
        .sighash()
        .unwrap();

    let pre_sig = pre_sign(&secp, &honest_digest, &u_priv, &y);
    verify_pre_signature(&secp, &pre_sig, &honest_digest, &u_pub, &y)
        .expect("the user verifies its own pre-signature before handing it over");

    // The attestor signs the outcome for the terms it announced.
    let s = sign_outcome(&secp, &k, &d, &ann.event_id, &agreed.terms_hash()).unwrap();
    verify_outcome_secret(&secp, &s, &y).expect("the scalar must be the discrete log of Y");
    let sig = decrypt_pre_signature(&pre_sig, &s).expect("the scalar decrypts the pre-signature");

    assert!(
        signature_covers(&sig, &honest_digest, &u_pub),
        "the released signature must sign the agreed release"
    );

    // The two transactions the LP would rather have: one with no treasury
    // output, and one paying the treasury slot to the LP's own address. The
    // decrypted signature authorises neither, and there is no other signature
    // from the user to fall back on.
    let skimmed = build_release_split(&terms, &ReleaseSplit::without_fee(lp_script(), 15_000))
        .unwrap()
        .sighash()
        .unwrap();
    assert_ne!(skimmed, honest_digest);
    assert!(
        !signature_covers(&sig, &skimmed, &u_pub),
        "a release that drops the fee must not be authorised"
    );

    let mut redirect = honest_split.clone();
    redirect.treasury_script = lp_own_script();
    let redirected = build_release_split(&terms, &redirect).unwrap().sighash().unwrap();
    assert!(
        !signature_covers(&sig, &redirected, &u_pub),
        "a release that redirects the fee must not be authorised"
    );

    // And the scalar recovered from the released signature is the attestor's,
    // which is criterion 6's check applied to the three-output release.
    assert_eq!(
        recover_outcome_secret(&secp, &pre_sig, &sig, &y).unwrap(),
        s
    );
}

#[test]
fn a_scalar_for_a_different_fee_does_not_open_the_pre_signature() {
    // The complementary half: not even the attestor can substitute a fee. A
    // scalar released against terms carrying a different `platform_fee_zat` is
    // the discrete log of a different `Y`, so the signature it yields does not
    // verify under `u_pub`.
    //
    // Decryption is structurally possible with any scalar - `end_to_end.rs`
    // makes the same point - so the assertion is on the resulting signature and
    // not on decryption failing.
    let secp = Secp256k1::new();
    let (u_priv, _) = keys();
    let u_pub = u_priv.public_key(&secp);
    let terms = escrow_terms(&secp);
    let (ann, d, k) = announcement_for(&secp);

    let agreed = canonical_with(400, treasury_script(), &secp);
    let y = outcome_point(&secp, &ann.r, &ann.p, &ann.event_id, &agreed.terms_hash()).unwrap();
    let digest = build_release_split(
        &terms,
        &ReleaseSplit {
            payout_script: lp_script(),
            miner_fee_zat: 15_000,
            platform_fee_zat: 400,
            treasury_script: treasury_script(),
        },
    )
    .unwrap()
    .sighash()
    .unwrap();
    let pre_sig = pre_sign(&secp, &digest, &u_priv, &y);

    // The attestor signs a different fee, and a different treasury, in turn.
    for other in [
        canonical_with(1, treasury_script(), &secp),
        canonical_with(400, lp_own_script(), &secp),
    ] {
        assert_ne!(other.terms_hash(), agreed.terms_hash());
        let wrong = sign_outcome(&secp, &k, &d, &ann.event_id, &other.terms_hash()).unwrap();
        assert!(
            verify_outcome_secret(&secp, &wrong, &y).is_err(),
            "a scalar for other terms is not the discrete log of this Y"
        );
        let sig = decrypt_pre_signature(&pre_sig, &wrong)
            .expect("decryption is structurally possible with any scalar");
        assert!(
            !signature_covers(&sig, &digest, &u_pub),
            "a scalar for other terms must not yield a usable signature"
        );
    }

    // The honest scalar still does, so the test is not passing by accident.
    let right = sign_outcome(&secp, &k, &d, &ann.event_id, &agreed.terms_hash()).unwrap();
    let sig = decrypt_pre_signature(&pre_sig, &right).unwrap();
    assert!(signature_covers(&sig, &digest, &u_pub));
}

// ---------------------------------------------------------------------------
// The fee is free, and the dust gate
// ---------------------------------------------------------------------------

#[test]
fn the_third_output_costs_no_extra_miner_fee() {
    // The design's arithmetic, checked against `fees.rs` rather than assumed.
    // The release input is 3 ZIP 317 actions, so the output side does not
    // become the binding constraint until there are four outputs.
    let secp = Secp256k1::new();
    let rs_len = escrow_terms(&secp).redeem_script().unwrap().len();

    assert_eq!(release_fee_zat(rs_len, 1), 15_000);
    assert_eq!(release_fee_zat(rs_len, 2), 15_000);
    assert_eq!(release_fee_zat(rs_len, 3), 15_000, "the treasury output is free");
    assert_eq!(release_fee_zat(rs_len, 4), 20_000, "the cliff is the fourth output");

    // And the one-output helper the rest of the crate uses is the same number.
    assert_eq!(release_fee_zat(rs_len, 1), release_fee_to_transparent_zat(rs_len));
}

#[test]
fn a_fee_below_dust_is_dropped_rather_than_written() {
    // A treasury output below the dust threshold makes the whole release
    // non-standard, so the trade would fail rather than merely go unbilled.
    // Both sides of the boundary, one zatoshi of escrow apart.
    assert_eq!(DUST_THRESHOLD_ZAT, 54);
    assert_eq!(platform_fee_zat(27_000, PLATFORM_FEE_BPS), 54);
    assert_eq!(platform_fee_zat(26_999, PLATFORM_FEE_BPS), 0);

    // At 20 bps the gate never fires on an escrow this protocol would quote:
    // `MINIMUM_ESCROW_ZAT` is 120,000 zat and the boundary is 27,000. That is
    // worth pinning rather than leaving implicit, because it means the
    // two-output path below is reached only through a lower rate.
    // A const assertion: lowering `MINIMUM_ESCROW_ZAT` past the dust boundary
    // should break the build here, so that whoever lowers it reads this note.
    const _: () = assert!(zecp2p_escrow::client::MINIMUM_ESCROW_ZAT > 27_000);

    // At 1 bp a 120,000 zat escrow yields 12 zat, which is dust. The split then
    // has one output, not a 12 zat one the node would refuse to relay.
    let small = 120_000u64;
    assert_eq!(platform_fee_zat(small, 1), 0);
    let split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: platform_fee_zat(small, 1),
        treasury_script: Vec::new(),
    };
    let outs = split.outputs(small).unwrap();
    assert_eq!(outs.len(), 1, "a dusted fee produces a two-output release");
    assert_eq!(outs[0].value_zat, small - 15_000);
}

#[test]
fn the_default_quote_derives_the_fee_and_the_pinned_treasury() {
    // The policy is applied by the default constructor, not opted into. A build
    // that quietly stopped charging would look like revenue going to zero
    // rather than like an error, so the fee-bearing shape is what a caller gets
    // without asking.
    let secp = Secp256k1::new();
    let q = honest_quote(&secp);

    assert_eq!(q.platform_fee_zat(), default_platform_fee_zat(AMOUNT));
    assert_eq!(
        q.treasury_script(),
        zecp2p_escrow::treasury::treasury_script(zecp2p_escrow::address::AddrNetwork::Test)
            .unwrap(),
        "the quote must name the pinned constant and nothing else"
    );
}

#[test]
fn the_fee_free_constructor_says_so_in_its_name() {
    // The escape hatch exists for tests and for reproducing an escrow announced
    // before a treasury was pinned. It is not reachable by omission.
    let secp = Secp256k1::new();
    let (_, l) = keys();
    let q = AcceptedQuote::at_identity_rate_without_fee(
        1_500_000,
        PAYEE,
        REFUND_HEIGHT,
        l.public_key(&secp).serialize(),
        AMOUNT,
    )
    .unwrap();
    assert_eq!(q.platform_fee_zat(), 0);
    assert!(q.treasury_script().is_empty());
}

#[test]
fn quoting_a_fee_against_the_unpinned_mainnet_treasury_refuses() {
    // Fail closed. Mainnet has no address yet, and a build that would charge a
    // fee there has nowhere to put it; quoting one anyway would burn every
    // zatoshi it collected. This is what keeps the mainnet constant honest
    // until a funded-and-spent txid is recorded.
    use zecp2p_escrow::address::AddrNetwork;
    use zecp2p_escrow::client::QuoteError;

    let secp = Secp256k1::new();
    let (_, l) = keys();
    let err = AcceptedQuote::at_identity_rate(
        1_500_000,
        PAYEE,
        REFUND_HEIGHT,
        l.public_key(&secp).serialize(),
        AMOUNT,
        AddrNetwork::Main,
    )
    .expect_err("no mainnet treasury is pinned yet");
    assert!(matches!(err, QuoteError::Treasury(_)), "got {err:?}");
}

#[test]
fn a_split_with_only_half_the_fee_set_is_refused() {
    // Round-1 review F6: a fee with no destination cannot be paid, and a
    // destination with no fee is an output the release does not carry. Either
    // half alone means the two parties are building different transactions from
    // what they believe are the same terms.
    let fee_no_script = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 400,
        treasury_script: Vec::new(),
    };
    assert!(matches!(
        fee_no_script.outputs(AMOUNT),
        Err(TxError::InconsistentFee { fee: 400, .. })
    ));

    let script_no_fee = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: 15_000,
        platform_fee_zat: 0,
        treasury_script: treasury_script(),
    };
    assert!(matches!(
        script_no_fee.outputs(AMOUNT),
        Err(TxError::InconsistentFee { fee: 0, .. })
    ));
}

#[test]
fn a_dust_payout_leg_is_refused_as_well_as_a_dust_fee() {
    // The dust rule applies to every output, not only the treasury one. A
    // release whose LP leg is 53 zat is as non-standard as one whose fee is,
    // and it would be the LP that discovered it, after paying the fiat.
    let split = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: AMOUNT - 500,
        platform_fee_zat: 447,
        treasury_script: treasury_script(),
    };
    assert!(
        matches!(
            split.outputs(AMOUNT),
            Err(TxError::DustOutput { index: 0, value: 53, .. })
        ),
        "a 53 zat payout leg must be refused"
    );

    // 54 zat is the threshold, so one zatoshi more is accepted.
    let ok = ReleaseSplit {
        payout_script: lp_script(),
        miner_fee_zat: AMOUNT - 500,
        platform_fee_zat: 446,
        treasury_script: treasury_script(),
    };
    let outs = ok.outputs(AMOUNT).expect("54 zat clears the threshold");
    assert_eq!(outs[0].value_zat, 54);
}

#[test]
fn the_taker_refuses_half_a_fee_when_it_rebuilds_terms() {
    // The taker rebuilds `CanonicalTerms` from what it was told, so it is a
    // third place the both-or-neither invariant has to hold. Checked here
    // through the escrow's own terms because the taker crate is downstream;
    // `zecp2p-taker`'s `canonical_terms` carries the matching refusal and its
    // own test.
    //
    // What makes this worth a test at all: a fee with no destination and a
    // destination with no fee both hash to terms that look plausible, and the
    // disagreement only becomes visible as a release nobody can broadcast.
    let secp = Secp256k1::new();
    let fee_only = canonical_with(400, Vec::new(), &secp);
    let script_only = canonical_with(0, treasury_script(), &secp);
    let honest = canonical_with(400, treasury_script(), &secp);

    // They are distinguishable at the hash, which is what lets any party that
    // checks refuse them.
    assert_ne!(fee_only.terms_hash(), honest.terms_hash());
    assert_ne!(script_only.terms_hash(), honest.terms_hash());

    // And the transaction builder refuses both outright.
    let terms = escrow_terms(&secp);
    for bad in [
        ReleaseSplit {
            payout_script: lp_script(),
            miner_fee_zat: 15_000,
            platform_fee_zat: fee_only.platform_fee_zat,
            treasury_script: fee_only.treasury_script.clone(),
        },
        ReleaseSplit {
            payout_script: lp_script(),
            miner_fee_zat: 15_000,
            platform_fee_zat: script_only.platform_fee_zat,
            treasury_script: script_only.treasury_script.clone(),
        },
    ] {
        assert!(matches!(
            build_release_split(&terms, &bad),
            Err(TxError::InconsistentFee { .. })
        ));
    }
}

/// The failure round 1 called out as the danger of a half-wired feature: a
/// runner that signs one output set and broadcasts another.
///
/// It is worth stating why this is the worst shape rather than merely a bug. By
/// the time the mismatch matters the LP has already paid the Venmo, the
/// attestor has already released its scalar, and the transaction the LP holds
/// carries a signature over a transaction it is not. There is no retry: the
/// pre-signature cannot be redrawn, and the escrow sits until `T`.
///
/// So the shape the code must have is that the digest and the bytes come from
/// *one* object, and this test is what says so.
#[test]
fn the_digest_and_the_broadcast_bytes_come_from_the_same_split() {
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let quote = honest_quote(&secp);
    let miner = release_fee_zat(terms.redeem_script().unwrap().len(), 2);

    // The one object. Everything downstream is derived from it.
    let split = quote.release_split(&lp_script(), miner);

    let digest = build_release_split(&terms, &split).unwrap().sighash().unwrap();
    let raw = zecp2p_escrow::tx::serialize_release_split(&terms, &split, &[0x51]).unwrap();

    // The serialized transaction must carry exactly the outputs the digest
    // committed to: same count, same order, same values, same scripts.
    let outs = transparent_outputs(&raw);
    let expected = split.outputs(terms.amount_zat).unwrap();
    assert_eq!(outs.len(), expected.len(), "output count must match");
    for (i, (got, want)) in outs.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got.0, want.value_zat, "output {i} value");
        assert_eq!(got.1, want.script, "output {i} script");
    }
    assert_eq!(outs.len(), 2, "a fee-bearing release pays the LP and the treasury");
    assert_eq!(outs[1].1, treasury_script(), "and the treasury output is last");

    // The half-wired shape, stated as the thing that must NOT happen: a runner
    // that signed this digest and then serialized the fee-free transaction
    // would produce bytes the signature does not cover.
    let skimmed = zecp2p_escrow::tx::serialize_release(&terms, &lp_script(), miner, &[0x51])
        .unwrap();
    assert_ne!(
        raw, skimmed,
        "the two-output and one-output releases must not serialize alike"
    );
    let skimmed_digest = build_release(&terms, &lp_script(), miner).unwrap().sighash().unwrap();
    assert_ne!(
        digest, skimmed_digest,
        "and their digests must differ, which is what makes the mismatch fatal"
    );
}

/// Round-2 review finding 1: what `paid_path verify` must compute.
///
/// The bug it fixes was arithmetic, not cryptography: verify subtracted only
/// the miner fee from the escrow and compared that to the first output, so
/// every fee-bearing release failed a check that was itself wrong. The testnet
/// live-fire would have ended there.
///
/// The example binary holds the real check; this pins the arithmetic it has to
/// use, against a transaction actually serialized by the escrow, so a future
/// edit that reintroduces the subtraction has somewhere to fail.
#[test]
fn a_verify_must_subtract_both_fees_and_look_at_the_treasury_output() {
    let secp = Secp256k1::new();
    let terms = escrow_terms(&secp);
    let quote = honest_quote(&secp);
    let miner = release_fee_zat(terms.redeem_script().unwrap().len(), 2);
    let split = quote.release_split(&lp_script(), miner);

    let raw = zecp2p_escrow::tx::serialize_release_split(&terms, &split, &[0x51]).unwrap();
    let outs = transparent_outputs(&raw);

    // What the old arithmetic expected, and what the transaction actually pays.
    let miner_only = AMOUNT - miner;
    let both_fees = AMOUNT - miner - split.platform_fee_zat;
    assert_ne!(
        miner_only, both_fees,
        "if these were equal the bug would be invisible and this test worthless"
    );
    assert_eq!(
        outs[0].0, both_fees,
        "the LP's leg is the escrow less the miner fee AND the platform fee"
    );

    // The treasury leg, which the old verify never looked at. It is the one
    // output no other party checks: the LP watches its own, and the user has
    // either been paid or refunded.
    assert_eq!(outs.len(), 2);
    assert_eq!(outs[1].1, split.treasury_script);
    assert_eq!(outs[1].0, split.platform_fee_zat);

    // And the fee-free shape, which must verify against a single output rather
    // than be reported as missing a treasury leg it never had.
    let no_fee = zecp2p_escrow::tx::serialize_release(
        &terms,
        &lp_script(),
        release_fee_zat(terms.redeem_script().unwrap().len(), 1),
        &[0x51],
    )
    .unwrap();
    assert_eq!(transparent_outputs(&no_fee).len(), 1);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Reads the transparent outputs back out of a serialized v5 transaction, as
/// `(value, scriptPubKey)`.
///
/// Parsed with the library rather than by hand so the test reads the same bytes
/// a node would, and so a change to ZIP 225 field order shows up here.
fn transparent_outputs(raw: &[u8]) -> Vec<(u64, Vec<u8>)> {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    let tx = Transaction::read(raw, BranchId::Nu5).expect("the transaction must parse");
    tx.transparent_bundle()
        .expect("an escrow spend always has a transparent bundle")
        .vout
        .iter()
        .map(|o| (u64::from(o.value()), o.script_pubkey().0 .0.clone()))
        .collect()
}
