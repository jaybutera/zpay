//! Canonical terms and `intentHash`, spec 5.2.
//!
//! The enclave signs whatever 32 bytes the LP hands it, so `intentHash` is the
//! only thing tying a Venmo payment to a particular escrow. If two escrows
//! could hash alike, one attestation would release both.

use zecp2p_escrow::terms::CanonicalTerms;

fn base() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: [0x7a; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: [0x02; 33],
        l_pub: [0x03; 33],
        refund_height: 3_500_000,
        usd_amount_6dec: 1_000_000,
        rate_18dec: 990_881_148_896_019_200,
        payee_hash: [0x85; 32],
        lock_confirmed_ms: 1_788_315_013_000,
        // 20 bps of 5_000_000 zat, the rate `treasury::PLATFORM_FEE_BPS` sets.
        platform_fee_zat: 10_000,
        treasury_script: TREASURY.to_vec(),
    }
}

/// A P2PKH scriptPubKey standing in for the treasury. Any 25 bytes serve; what
/// the tests below check is that the bytes reach the hash, not which bytes.
const TREASURY: &[u8] = &[
    0x76, 0xa9, 20, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
    0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0x88, 0xac,
];

#[test]
fn the_canonical_json_has_sorted_keys_and_no_whitespace() {
    let j = base().canonical_json();
    assert!(!j.contains(' '), "canonical json must not contain whitespace");
    assert!(!j.contains('\n'));

    // Keys in ascending order, as spec 5.2 requires. A different order in
    // another implementation would produce a different hash for the same terms.
    let keys: Vec<&str> = j
        .split(',')
        .map(|kv| kv.split(':').next().unwrap().trim_matches(|c| c == '{' || c == '"'))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "keys are not sorted: {keys:?}");
    assert_eq!(keys.len(), 12, "all twelve fields must be serialized");
}

#[test]
fn integers_are_serialized_as_decimal_strings() {
    // rate_18dec exceeds what a JSON number holds exactly. A parser that read
    // it as a float would round it and hash something else, so it is a string.
    let j = base().canonical_json();
    assert!(
        j.contains("\"rate_18dec\":\"990881148896019200\""),
        "got {j}"
    );
    assert!(j.contains("\"usd_amount_6dec\":\"1000000\""));
    assert!(j.contains("\"vout\":\"0\""));
}

#[test]
fn every_field_changes_the_intent_hash() {
    // Each of these is a term someone could try to restate after the fact.
    let base_hash = base().intent_hash();

    type Mutation = (&'static str, Box<dyn Fn(&mut CanonicalTerms)>);
    let mutations: Vec<Mutation> = vec![
        ("funding_txid", Box::new(|t: &mut CanonicalTerms| t.funding_txid = [0x7b; 32])),
        ("vout", Box::new(|t: &mut CanonicalTerms| t.vout = 1)),
        ("amount_zat", Box::new(|t: &mut CanonicalTerms| t.amount_zat += 1)),
        ("u_pub", Box::new(|t: &mut CanonicalTerms| t.u_pub = [0x04; 33])),
        ("l_pub", Box::new(|t: &mut CanonicalTerms| t.l_pub = [0x04; 33])),
        ("refund_height", Box::new(|t: &mut CanonicalTerms| t.refund_height += 1)),
        ("usd_amount_6dec", Box::new(|t: &mut CanonicalTerms| t.usd_amount_6dec += 1)),
        ("rate_18dec", Box::new(|t: &mut CanonicalTerms| t.rate_18dec += 1)),
        ("payee_hash", Box::new(|t: &mut CanonicalTerms| t.payee_hash = [0x86; 32])),
        ("lock_confirmed_ms", Box::new(|t: &mut CanonicalTerms| t.lock_confirmed_ms += 1)),
        ("platform_fee_zat", Box::new(|t: &mut CanonicalTerms| t.platform_fee_zat += 1)),
        ("treasury_script", Box::new(|t: &mut CanonicalTerms| t.treasury_script[3] ^= 0xff)),
    ];

    for (name, mutate) in mutations {
        let mut t = base();
        mutate(&mut t);
        assert_ne!(
            base_hash,
            t.intent_hash(),
            "changing {name} must change the intent hash"
        );
    }
}

#[test]
fn the_intent_hash_is_domain_separated_from_the_terms_hash() {
    // The announcement pins terms_hash and the enclave signs intent_hash. If
    // they were the same value, a signature over one would be a signature over
    // the other.
    let t = base();
    assert_ne!(t.intent_hash(), t.terms_hash());
}

#[test]
fn the_hashes_are_stable_across_calls() {
    let t = base();
    assert_eq!(t.intent_hash(), t.intent_hash());
    assert_eq!(t.terms_hash(), t.terms_hash());
    // And a second, separately constructed copy of the same terms agrees, which
    // is what lets the user and the LP compute it independently.
    assert_eq!(base().intent_hash(), t.intent_hash());
}

#[test]
fn the_canonical_json_is_a_fixed_vector() {
    // Pins the exact bytes another implementation would have to reproduce.
    assert_eq!(
        base().canonical_json(),
        concat!(
            "{\"amount_zat\":\"5000000\",",
            "\"funding_txid\":\"7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a\",",
            "\"l_pub\":\"030303030303030303030303030303030303030303030303030303030303030303\",",
            "\"lock_confirmed_ms\":\"1788315013000\",",
            "\"payee_hash\":\"8585858585858585858585858585858585858585858585858585858585858585\",",
            "\"platform_fee_zat\":\"10000\",",
            "\"rate_18dec\":\"990881148896019200\",",
            "\"refund_height\":\"3500000\",",
            "\"treasury_script\":\"76a914c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d388ac\",",
            "\"u_pub\":\"020202020202020202020202020202020202020202020202020202020202020202\",",
            "\"usd_amount_6dec\":\"1000000\",",
            "\"vout\":\"0\"}"
        )
    );
}
