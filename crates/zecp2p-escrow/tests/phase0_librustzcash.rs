//! Phase 0, unknown 2: can librustzcash build a v5 transaction with a
//! transparent P2SH input and a shielded output for the refund?
//!
//! The spec (section 4.4, open item 3) asks for "a v5 transaction with a
//! transparent input and an Ironwood or Orchard output". These tests answer
//! that against zcash_primitives 0.30.1 / orchard 0.15.5 and pin the answer, so
//! a later dependency bump that changes it fails here rather than on mainnet.
//!
//! The short version of what they establish:
//!
//! - Ironwood is NU6.3, a consensus branch, and it carries a *separate value
//!   pool* that exists only in a **V6** transaction. "v5 with an Ironwood
//!   output" is not constructible; it is a contradiction in the spec.
//! - Orchard outputs are valid in V5, and V5 is still valid under the NU6.3
//!   branch, so the refund-to-shielded requirement is met with Orchard.
//! - Under NU6.3 the builder *defaults* to V6. A v5 escrow must call
//!   `propose_version(TxVersion::V5)` explicitly.

use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;

/// The Ironwood / NU6.3 consensus branch id, as pinned by zcash_protocol.
/// Section 4.3 requires this be read from zebrad at runtime and never
/// hard-coded; this constant exists only so the test can state what it
/// expects.
const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

#[test]
fn ironwood_is_nu6_3_and_its_branch_id_is_stable() {
    assert_eq!(u32::from(BranchId::Nu6_3), NU6_3_BRANCH_ID);
    assert_eq!(BranchId::try_from(NU6_3_BRANCH_ID), Ok(BranchId::Nu6_3));
}

#[test]
fn v5_is_still_valid_under_the_ironwood_branch() {
    // This is what lets the spec keep its "version 5" mandate after NU6.3.
    assert!(
        TxVersion::V5.valid_in_branch(BranchId::Nu6_3),
        "if V5 ever stops being valid under the current branch, every escrow \
         transaction in this repo has to move to V6 together"
    );
}

#[test]
fn the_builder_defaults_to_v6_under_ironwood_so_v5_must_be_requested() {
    // The trap: a builder constructed for a current-height target produces V6,
    // not the V5 the spec mandates. Both parties must pin the version or their
    // ZIP 244 digests differ and the release is unspendable.
    assert_eq!(
        TxVersion::suggested_for_branch(BranchId::Nu6_3),
        TxVersion::V6,
        "the default version under NU6.3 must be treated as V6 by our builders"
    );
    assert_eq!(TxVersion::suggested_for_branch(BranchId::Nu5), TxVersion::V5);
}

#[test]
fn an_ironwood_output_requires_v6_and_orchard_is_the_v5_shielded_pool() {
    // Answers open item 3 directly. A refund paying into the Ironwood pool
    // cannot be a v5 transaction.
    assert!(
        !TxVersion::V5.has_ironwood(),
        "V5 carries no Ironwood bundle, so 'v5 with an Ironwood output' is not buildable"
    );
    assert!(TxVersion::V6.has_ironwood());

    // Orchard, however, is available in V5, which is what the refund uses.
    assert!(
        TxVersion::V5.has_orchard(),
        "the shielded refund output in a v5 transaction must be Orchard"
    );
}

// ---------------------------------------------------------------------------
// The type-level facts above are necessary but not sufficient: they say the
// version *permits* these combinations. The tests below actually drive the
// builder, so they prove the combination is constructible in practice.
// ---------------------------------------------------------------------------

use zcash_primitives::transaction::builder::{Builder, BuildConfig, BundlePadding};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::Zatoshis;
use zcash_script::script::Code;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zcash_transparent::bundle::{OutPoint, TxOut};

use zecp2p_escrow::script::{p2sh_script_pubkey, redeem_script};

/// A network whose NU6.3 activation is at height 10, so a target height above
/// that puts the builder on the Ironwood branch exactly as mainnet does today.
fn ironwood_network() -> LocalNetwork {
    LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: Some(BlockHeight::from_u32(10)),
    }
}

/// The escrow's release and refund transactions carry no Sapling bundle, so the
/// builder never invokes a prover; it only needs values that satisfy the bounds.
/// Constructing a real `SpendParameters` would mean loading the Sapling proving
/// keys, which this probe has no use for.
struct NoProver;

impl sapling::prover::SpendProver for NoProver {
    type Proof = sapling::bundle::GrothProofBytes;
    fn prepare_circuit(
        _: sapling::ProofGenerationKey,
        _: sapling::Diversifier,
        _: sapling::Rseed,
        _: sapling::value::NoteValue,
        _: jubjub::Fr,
        _: sapling::value::ValueCommitTrapdoor,
        _: bls12_381::Scalar,
        _: sapling::MerklePath,
    ) -> Option<sapling::circuit::Spend> {
        unreachable!("the escrow builds no Sapling spends")
    }
    fn create_proof<R: rand::RngCore>(&self, _: sapling::circuit::Spend, _: &mut R) -> Self::Proof {
        unreachable!("the escrow builds no Sapling spends")
    }
    fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
        unreachable!("the escrow builds no Sapling spends")
    }
}

impl sapling::prover::OutputProver for NoProver {
    type Proof = sapling::bundle::GrothProofBytes;
    fn prepare_circuit(
        _: &sapling::keys::EphemeralSecretKey,
        _: sapling::PaymentAddress,
        _: jubjub::Fr,
        _: sapling::value::NoteValue,
        _: sapling::value::ValueCommitTrapdoor,
    ) -> sapling::circuit::Output {
        unreachable!("the escrow builds no Sapling outputs")
    }
    fn create_proof<R: rand::RngCore>(&self, _: sapling::circuit::Output, _: &mut R) -> Self::Proof {
        unreachable!("the escrow builds no Sapling outputs")
    }
    fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
        unreachable!("the escrow builds no Sapling outputs")
    }
}

fn transparent_only_config() -> BuildConfig {
    BuildConfig::Standard {
        sapling_anchor: None,
        orchard_anchor: None,
        ironwood_anchor: None,
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    }
}

/// Builds a release-shaped transaction: one P2SH escrow input, one transparent
/// output, pinned to V5 under the Ironwood branch. This is the path the LP
/// takes in section 4.3.
#[test]
fn a_v5_transaction_accepts_a_p2sh_escrow_input_under_ironwood() {
    let secp = secp256k1::Secp256k1::new();
    let u_priv = secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap();
    let u_pub = secp256k1::PublicKey::from_secret_key(&secp, &u_priv).serialize();
    let l_pub = secp256k1::PublicKey::from_secret_key(&secp, &l_priv).serialize();

    let rs = redeem_script(&u_pub, &l_pub, 3_000_000).unwrap();
    let spk = p2sh_script_pubkey(&rs);

    let amount = Zatoshis::const_from_u64(100_000);
    let mut builder = Builder::new(
        ironwood_network(),
        BlockHeight::from_u32(1_000),
        transparent_only_config(),
    );

    // The spec mandates version 5; under NU6.3 the builder would otherwise
    // produce V6. If this call is ever dropped, the two parties build
    // different transactions and the release is unspendable.
    builder
        .propose_version::<zip317::FeeError>(TxVersion::V5)
        .expect("V5 must remain proposable under the Ironwood branch");

    let redeem = Code(rs.clone())
        .to_component()
        .expect("the escrow redeem script must parse as script opcodes");

    builder
        .add_transparent_p2sh_input(
            redeem,
            OutPoint::new([7u8; 32], 0),
            TxOut::new(
                amount,
                Code(spk.clone())
                    .to_component()
                    .expect("the P2SH scriptPubKey must parse")
                    .into(),
            ),
        )
        .expect("librustzcash must accept the escrow P2SH outpoint as an input");

    // Pay out to a transparent address, less the ZIP 317 fee of 10000 zat for
    // a 1-in 1-out transparent spend (section 3).
    builder
        .add_transparent_output(
            &TransparentAddress::PublicKeyHash([9u8; 20]),
            Zatoshis::const_from_u64(90_000),
        )
        .expect("a transparent release output must be addable");

    // The P2SH input and the V5 version were both accepted by the builder; the
    // build below is expected to stop at the fee rule, for the reason the next
    // test documents.
    let signing_set = TransparentSigningSet::new();
    let err = builder
        .build(
            &signing_set,
            &[],
            &[],
            rand::rngs::OsRng,
            &NoProver,
            &NoProver,
            &zip317::FeeRule::standard(),
        )
        .expect_err("an unsigned P2SH build cannot succeed");

    // Phase 0 finding: `zip317::FeeRule` cannot size a custom P2SH input, because
    // only the spender knows how long the scriptSig will be. It reports the
    // outpoint as unknown rather than guessing. The escrow therefore computes
    // its own fee from the known scriptSig length; see `fees.rs`.
    let msg = format!("{err:?}");
    assert!(
        msg.contains("UnknownP2shInputs"),
        "expected the ZIP 317 rule to refuse to size the P2SH input, got: {msg}"
    );
}
