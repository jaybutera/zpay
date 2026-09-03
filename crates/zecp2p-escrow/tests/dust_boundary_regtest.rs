//! The dust threshold, checked against a node instead of derived on paper.
//!
//! `treasury::DUST_THRESHOLD_ZAT` is 54, computed from Zcash's 100 zat/kB
//! `minRelayTxFee` and the inherited rule that an output is dust when spending
//! it would cost more than a third of its value. That arithmetic is pinned by
//! unit tests. What those cannot show is that the *node* agrees, and the
//! consequence of being wrong is specific: a treasury output one zatoshi under
//! the real threshold makes the whole release non-standard, so the trade fails
//! rather than merely going unbilled. The design asked for this boundary to be
//! probed in both directions, and this is that probe.
//!
//! ```text
//! ZECP2P_RPC_URL=<endpoint> \
//!   cargo test -p zecp2p-escrow --test dust_boundary_regtest -- --ignored --test-threads 1
//! ```
//!
//! # What a node can and cannot tell us here
//!
//! These transactions spend an outpoint that exists on no chain, exactly as
//! `mempool_gate.rs` does and for the same reason: no funded escrow is needed
//! to learn how the node judges the *outputs*. A node checks standardness
//! before it looks for the inputs, so the two answers separate cleanly:
//!
//! - a **dust** verdict means the node refused the output set, which is the
//!   answer the 53 zat case must get;
//! - a **missing inputs** verdict means the node accepted the output set and
//!   went looking for the outpoint, which is the answer the 54 zat case must
//!   get, and is as far as a fictional outpoint can take it.
//!
//! A 54 zat output that came back "dust" would mean the constant is too low and
//! every release at that size is unbroadcastable. A 53 zat output that came
//! back "missing inputs" would mean the constant is too high and the gate is
//! dropping fees it could have collected. Either is a finding; neither is
//! silent.

use std::time::Duration;

use secp256k1::{Message, Secp256k1, SecretKey};

use zecp2p_escrow::chain::{ChainClient, ChainError};
use zecp2p_escrow::rpc::{Network, RpcChainClient, RpcConfig};
use zecp2p_escrow::script::release_script_sig;
use zecp2p_escrow::treasury::DUST_THRESHOLD_ZAT;
use zecp2p_escrow::tx::{
    build_release_split, encode_signature, serialize_release_split, EscrowTerms, ReleaseSplit,
    TxOutSpec,
};

fn client() -> Option<RpcChainClient> {
    let url = std::env::var("ZECP2P_RPC_URL").ok()?;
    let mut config = RpcConfig::public(url, Network::Test);
    config.timeout = Duration::from_secs(45);
    // R8-3: zebra sits on a `sendrawtransaction` whose input it cannot find for
    // 60 s before answering. A shorter budget turns the node's verdict - which
    // is the whole point of this test - into a client timeout.
    config.broadcast_timeout = Duration::from_secs(120);
    RpcChainClient::new(config).ok()
}

fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// The node said the transaction has a dust output.
///
/// Matched loosely across implementations: `zcashd` answers `dust`, and a
/// non-standard rejection from either node carries the word.
fn is_dust_rejection(err: &ChainError) -> bool {
    let text = format!("{err}").to_lowercase();
    text.contains("dust") || text.contains("not standard") || text.contains("non-standard")
}

/// The node accepted the output set and went looking for the input.
fn is_missing_input(err: &ChainError) -> bool {
    let text = format!("{err}").to_lowercase();
    text.contains("could not find transparent input utxo")
        || text.contains("missing")
        || text.contains("not found")
        || text.contains("spent")
}

struct Vector {
    terms: EscrowTerms,
    u_priv: SecretKey,
    l_priv: SecretKey,
    secp: Secp256k1<secp256k1::All>,
}

fn vector(branch_id: u32, refund_height: u64) -> Vector {
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    Vector {
        terms: EscrowTerms {
            funding_txid: [0x11; 32],
            vout: 0,
            amount_zat: 5_000_000,
            u_pub: secp256k1::PublicKey::from_secret_key(&secp, &u_priv).serialize(),
            l_pub: secp256k1::PublicKey::from_secret_key(&secp, &l_priv).serialize(),
            refund_height,
            consensus_branch_id: branch_id,
        },
        u_priv,
        l_priv,
        secp,
    }
}

/// Builds and broadcasts a release whose treasury output is `fee_zat`, and
/// returns the node's verdict.
///
/// Above the threshold the output set comes from `ReleaseSplit`, so the bytes on
/// the wire are the bytes the escrow would really broadcast. Below it the split
/// refuses - that refusal is the behaviour under test on the other side - so the
/// list is assembled directly through `build_release_from_outputs`, leaving the
/// node as the one passing judgement rather than our own gate.
fn broadcast_with_treasury_output(
    c: &RpcChainClient,
    v: &Vector,
    fee_zat: u64,
) -> Result<[u8; 32], ChainError> {
    let redeem = v.terms.redeem_script().unwrap();
    let split = ReleaseSplit {
        payout_script: p2pkh([0x09; 20]),
        miner_fee_zat: 15_000,
        platform_fee_zat: fee_zat,
        treasury_script: zecp2p_escrow::treasury::treasury_script(
            zecp2p_escrow::address::AddrNetwork::Test,
        )
        .expect("the testnet treasury is pinned"),
    };

    // `ReleaseSplit::outputs` refuses a sub-dust output itself, which is the
    // behaviour under test on this side of the boundary. Below the threshold we
    // therefore have to assemble the output list directly, so the *node* is the
    // one judging rather than our own gate.
    let outputs = match split.outputs(v.terms.amount_zat) {
        Ok(o) => o,
        Err(_) => vec![
            TxOutSpec::new(
                split.payout_script.clone(),
                v.terms.amount_zat - split.miner_fee_zat - fee_zat,
            ),
            TxOutSpec::new(split.treasury_script.clone(), fee_zat),
        ],
    };

    let digest = zecp2p_escrow::tx::build_release_from_outputs(&v.terms, &outputs)
        .unwrap()
        .sighash()
        .unwrap();
    let sig_u = v.secp.sign_ecdsa(&Message::from_digest(digest), &v.u_priv);
    let sig_l = v.secp.sign_ecdsa(&Message::from_digest(digest), &v.l_priv);
    let script_sig = release_script_sig(
        &encode_signature(&sig_u),
        &encode_signature(&sig_l),
        &redeem,
    );

    let raw = zecp2p_escrow::tx::serialize_release_from_outputs(&v.terms, &outputs, &script_sig)
        .unwrap();
    c.broadcast(&raw)
}

#[test]
#[ignore = "needs a live node"]
fn the_node_agrees_with_the_dust_threshold_in_both_directions() {
    let Some(c) = client() else {
        panic!("set ZECP2P_RPC_URL to run this");
    };

    let branch = c.consensus_branch_id().expect("branch id");
    let height = c.height().expect("height");
    let v = vector(branch, height as u64 + 1152);

    // One zatoshi below the threshold. The node must refuse the output set.
    let below = DUST_THRESHOLD_ZAT - 1;
    let err = broadcast_with_treasury_output(&c, &v, below)
        .expect_err("a fictional outpoint cannot be spent, whatever the outputs");
    assert!(
        is_dust_rejection(&err),
        "a {below} zat treasury output must be refused as dust, but the node said: {err}. \
         If it went looking for the input instead, DUST_THRESHOLD_ZAT is higher than the \
         node's rule and the gate is dropping fees it could collect."
    );

    // At the threshold. The node must accept the output set and get as far as
    // the missing input, which is where a fictional outpoint stops it.
    let at = DUST_THRESHOLD_ZAT;
    let err = broadcast_with_treasury_output(&c, &v, at)
        .expect_err("a fictional outpoint cannot be spent");
    assert!(
        is_missing_input(&err) && !is_dust_rejection(&err),
        "a {at} zat treasury output must clear the dust rule, but the node said: {err}. \
         If it called this dust, DUST_THRESHOLD_ZAT is below the node's rule and every \
         release at that size is unbroadcastable."
    );
}

/// The escrow's own gate must agree with the node's, so that a fee the node
/// would refuse never reaches it.
///
/// This half needs no network: it checks that `ReleaseSplit` refuses exactly
/// what the test above expects the node to refuse.
#[test]
fn the_escrows_own_gate_sits_at_the_same_boundary() {
    let v = vector(0xc8e7_1055, 3_471_833);
    let treasury = zecp2p_escrow::treasury::treasury_script(
        zecp2p_escrow::address::AddrNetwork::Test,
    )
    .unwrap();

    let split = |fee: u64| ReleaseSplit {
        payout_script: p2pkh([0x09; 20]),
        miner_fee_zat: 15_000,
        platform_fee_zat: fee,
        treasury_script: treasury.clone(),
    };

    assert!(
        split(DUST_THRESHOLD_ZAT - 1)
            .outputs(v.terms.amount_zat)
            .is_err(),
        "the escrow must refuse below the threshold, so the node never sees it"
    );
    assert!(
        split(DUST_THRESHOLD_ZAT)
            .outputs(v.terms.amount_zat)
            .is_ok(),
        "and must accept at the threshold, or it refuses fees the node would take"
    );

    // And the release actually builds at the boundary, which is the shape the
    // live test above puts in front of a node.
    build_release_split(&v.terms, &split(DUST_THRESHOLD_ZAT)).expect("builds at the threshold");
    let raw = serialize_release_split(&v.terms, &split(DUST_THRESHOLD_ZAT), &[0x51])
        .expect("serializes at the threshold");
    assert!(raw.len() > 100);
}
