//! The multi-input funding sighash, which exists so a funding run can spend
//! several small outputs into one escrow.
//!
//! ZIP 244 commits to every input's outpoint, value and scriptPubKey, so these
//! tests pin the two properties that make signing a multi-input funding safe:
//! the single-input case is unchanged by the generalisation, and each input of
//! a multi-input spend gets its own distinct digest.

use zcash_protocol::value::Zatoshis;
use zcash_script::script::Code;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{OutPoint, TxOut};

use zecp2p_escrow::funding::{p2pkh_sighash, p2pkh_sighash_multi};

/// Mainnet's branch id at the height these tests pretend to be at. Any known
/// id would do; the digests are compared against each other, not a vector.
const BRANCH: u32 = 0xc8e7_1055;

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn outpoint(byte: u8, n: u32) -> OutPoint {
    OutPoint::new([byte; 32], n)
}

fn outputs() -> Vec<TxOut> {
    vec![
        TxOut::new(
            Zatoshis::const_from_u64(180_814),
            Script(Code(vec![0xa9, 20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                             0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
                             0x87])),
        ),
        TxOut::new(
            Zatoshis::const_from_u64(5_000),
            Script(Code(p2pkh([0x07; 20]))),
        ),
    ]
}

#[test]
fn the_single_input_wrapper_is_the_one_input_case_of_the_multi_input_digest() {
    let op = outpoint(0xa1, 0);
    let spk = p2pkh([0x03; 20]);
    let vout = outputs();

    let single = p2pkh_sighash(BRANCH, &op, &spk, 127_736, &vout).unwrap();
    let multi = p2pkh_sighash_multi(BRANCH, &[(op, spk, 127_736)], 0, &vout).unwrap();

    assert_eq!(
        single, multi,
        "the wrapper must produce exactly the digest it produced before the \
         generalisation, or every existing single-input funder silently changes"
    );
}

#[test]
fn each_input_of_a_multi_input_spend_gets_its_own_digest() {
    let spk = p2pkh([0x03; 20]);
    let inputs = vec![
        (outpoint(0xa1, 0), spk.clone(), 127_736),
        (outpoint(0xb2, 0), spk.clone(), 124_031),
        (outpoint(0xc3, 1), spk, 45_764),
    ];
    let vout = outputs();

    let d0 = p2pkh_sighash_multi(BRANCH, &inputs, 0, &vout).unwrap();
    let d1 = p2pkh_sighash_multi(BRANCH, &inputs, 1, &vout).unwrap();
    let d2 = p2pkh_sighash_multi(BRANCH, &inputs, 2, &vout).unwrap();

    assert_ne!(d0, d1);
    assert_ne!(d1, d2);
    assert_ne!(d0, d2);
}

#[test]
fn a_multi_input_digest_is_not_the_digest_of_spending_that_input_alone() {
    let spk = p2pkh([0x03; 20]);
    let op = outpoint(0xa1, 0);
    let vout = outputs();

    let alone = p2pkh_sighash_multi(BRANCH, &[(op.clone(), spk.clone(), 127_736)], 0, &vout)
        .unwrap();
    let together = p2pkh_sighash_multi(
        BRANCH,
        &[
            (op, spk.clone(), 127_736),
            (outpoint(0xb2, 0), spk, 124_031),
        ],
        0,
        &vout,
    )
    .unwrap();

    assert_ne!(
        alone, together,
        "ZIP 244 commits to the whole input set, so signing input 0 as though \
         it were the only input would produce a signature the network rejects"
    );
}

#[test]
fn the_set_of_inputs_is_committed_to_by_value_and_by_outpoint() {
    let spk = p2pkh([0x03; 20]);
    let vout = outputs();
    let base = vec![
        (outpoint(0xa1, 0), spk.clone(), 127_736),
        (outpoint(0xb2, 0), spk.clone(), 124_031),
    ];
    let base_digest = p2pkh_sighash_multi(BRANCH, &base, 0, &vout).unwrap();

    let other_value = vec![
        (outpoint(0xa1, 0), spk.clone(), 127_736),
        (outpoint(0xb2, 0), spk.clone(), 124_030),
    ];
    assert_ne!(
        base_digest,
        p2pkh_sighash_multi(BRANCH, &other_value, 0, &vout).unwrap(),
        "a wrong value for another input must change this input's digest"
    );

    let other_outpoint = vec![
        (outpoint(0xa1, 0), spk.clone(), 127_736),
        (outpoint(0xb2, 1), spk, 124_031),
    ];
    assert_ne!(
        base_digest,
        p2pkh_sighash_multi(BRANCH, &other_outpoint, 0, &vout).unwrap(),
        "a different second outpoint must change this input's digest"
    );
}

#[test]
fn an_index_past_the_end_is_refused_rather_than_signing_the_wrong_input() {
    let spk = p2pkh([0x03; 20]);
    let inputs = vec![(outpoint(0xa1, 0), spk, 127_736)];
    assert!(p2pkh_sighash_multi(BRANCH, &inputs, 1, &outputs()).is_err());
    assert!(p2pkh_sighash_multi(BRANCH, &[], 0, &outputs()).is_err());
}
