//! The LP's state machine, spec 5.3 to 5.6 and sections 7 and 8.
//!
//! The LP is the party that pays before it can claim. Every test here is a
//! situation in which it must not pay, or must not think it can release.

use zecp2p_escrow::chain::{ChainError, FakeChain, Utxo};
use zecp2p_escrow::deadlines::EscrowPolicy;
use zecp2p_escrow::lp::{
    attestation_matches_terms, check_branch, evaluate, may_send_payment, LpError, LpProgress,
    LpState, ProverRequest,
};
use zecp2p_escrow::terms::CanonicalTerms;
use zecp2p_escrow::tx::EscrowTerms;

const NU6_3: u32 = 0x37a5_165b;
const U_PUB: [u8; 33] = [0x02; 33];
const L_PUB: [u8; 33] = [0x03; 33];
const LOCK_HEIGHT: u32 = 3_400_000;
const REFUND_HEIGHT: u64 = 3_401_152;
const TXID: [u8; 32] = [0x7a; 32];

fn tx_terms() -> EscrowTerms {
    EscrowTerms {
        funding_txid: TXID,
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: U_PUB,
        l_pub: L_PUB,
        refund_height: REFUND_HEIGHT,
        consensus_branch_id: NU6_3,
    }
}

fn canonical() -> CanonicalTerms {
    CanonicalTerms {
        funding_txid: TXID,
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

/// A chain with the escrow funded and confirmed to the depth for its size.
fn funded_chain(height: u32, confirmations: u32) -> FakeChain {
    let mut c = FakeChain::new(height, NU6_3);
    c.add_utxo(
        TXID,
        0,
        Utxo {
            script_pubkey: tx_terms().script_pubkey().unwrap(),
            amount_zat: 5_000_000,
            confirmations,
        },
    );
    c
}

fn verified() -> LpProgress {
    LpProgress {
        pre_signature_verified: true,
        ..Default::default()
    }
}

fn state(chain: &FakeChain, progress: LpProgress) -> Result<LpState, LpError> {
    evaluate(
        chain,
        &tx_terms(),
        &canonical(),
        &EscrowPolicy::mainnet_default(),
        LOCK_HEIGHT,
        progress,
    )
}

#[test]
fn a_confirmed_escrow_inside_the_deadline_is_payable() {
    let chain = funded_chain(LOCK_HEIGHT + 10, 10);
    assert_eq!(state(&chain, verified()).unwrap(), LpState::ReadyToPay);
    may_send_payment(&LpState::ReadyToPay).unwrap();
}

#[test]
fn an_unmined_escrow_is_not_payable() {
    // Criterion 2: the LP must not pay before the escrow is confirmed.
    let chain = FakeChain::new(LOCK_HEIGHT, NU6_3);
    let s = state(&chain, verified()).unwrap();
    assert_eq!(s, LpState::AwaitingLock);
    assert!(matches!(may_send_payment(&s), Err(LpError::NotPayable(_))));
}

#[test]
fn a_shallow_escrow_is_not_payable() {
    // A 1 USD escrow needs 10 confirmations. Nine is not ten, and the guard
    // must refuse rather than round.
    let chain = funded_chain(LOCK_HEIGHT + 9, 9);
    let s = state(&chain, verified()).unwrap();
    assert_eq!(
        s,
        LpState::AwaitingDepth {
            confirmations: 9,
            required: 10
        }
    );
    assert!(matches!(may_send_payment(&s), Err(LpError::NotPayable(_))));
}

#[test]
fn a_reorg_that_unwinds_the_escrow_makes_it_unpayable_again() {
    // Section 7: if a reorg drops the funding tx, the LP waits. The dangerous
    // case is the LP having already decided to pay on a stale observation, so
    // the state must go backwards, not stick.
    let mut chain = funded_chain(LOCK_HEIGHT + 10, 10);
    assert_eq!(state(&chain, verified()).unwrap(), LpState::ReadyToPay);

    chain.remove_utxo(&TXID, 0);
    assert_eq!(state(&chain, verified()).unwrap(), LpState::AwaitingLock);

    // And a partial reorg that merely reduces depth also goes backwards.
    chain.add_utxo(
        TXID,
        0,
        Utxo {
            script_pubkey: tx_terms().script_pubkey().unwrap(),
            amount_zat: 5_000_000,
            confirmations: 3,
        },
    );
    assert_eq!(
        state(&chain, verified()).unwrap(),
        LpState::AwaitingDepth {
            confirmations: 3,
            required: 10
        }
    );
}

#[test]
fn the_lp_abandons_rather_than_paying_past_the_deadline() {
    // Section 8, the "LP never pays" row: nobody loses, because the user
    // refunds at T. Paying inside the margin is how that becomes a loss.
    let policy = EscrowPolicy::mainnet_default();
    let deadline = policy.pay_deadline(LOCK_HEIGHT);

    let chain = funded_chain(deadline - 1, 100);
    assert_eq!(state(&chain, verified()).unwrap(), LpState::ReadyToPay);

    let chain = funded_chain(deadline, 100);
    let s = state(&chain, verified()).unwrap();
    assert_eq!(s, LpState::AbandonedUnpaid);
    assert!(matches!(may_send_payment(&s), Err(LpError::NotPayable(_))));
}

#[test]
fn an_escrow_paying_the_wrong_script_is_refused() {
    // The outpoint existing is not enough; it must be the agreed P2SH address.
    let mut chain = FakeChain::new(LOCK_HEIGHT + 10, NU6_3);
    chain.add_utxo(
        TXID,
        0,
        Utxo {
            script_pubkey: vec![0xa9, 20, 0xff, 0xff, 0x87],
            amount_zat: 5_000_000,
            confirmations: 10,
        },
    );
    assert_eq!(state(&chain, verified()), Err(LpError::WrongEscrowScript));
}

#[test]
fn an_underfunded_escrow_is_refused() {
    // The LP quotes dollars against a ZEC amount. An escrow holding less than
    // the terms say is a user trying to buy dollars it did not lock for.
    let mut chain = FakeChain::new(LOCK_HEIGHT + 10, NU6_3);
    chain.add_utxo(
        TXID,
        0,
        Utxo {
            script_pubkey: tx_terms().script_pubkey().unwrap(),
            amount_zat: 4_999_999,
            confirmations: 10,
        },
    );
    assert_eq!(
        state(&chain, verified()),
        Err(LpError::WrongAmount {
            found: 4_999_999,
            expected: 5_000_000
        })
    );
}

#[test]
fn the_lp_will_not_pay_on_an_unverified_pre_signature() {
    // Section 8, "user sends a bad pre-signature": nobody loses, because the
    // LP verifies the DLEQ proof before paying. That only holds if reaching
    // ReadyToPay is impossible without it.
    let chain = funded_chain(LOCK_HEIGHT + 10, 10);
    assert_eq!(
        state(&chain, LpProgress::default()),
        Err(LpError::BadPreSignature)
    );
}

#[test]
fn a_branch_change_is_caught_before_the_lp_pays() {
    // A network upgrade between quoting and releasing changes the sighash, so
    // the pre-signature the LP holds becomes worthless. Better a refusal than
    // discovering it after paying.
    let chain = FakeChain::new(LOCK_HEIGHT, 0x5437_f330); // NU6.2
    assert_eq!(
        check_branch(&chain, &tx_terms()),
        Err(LpError::BranchMismatch {
            found: 0x5437_f330,
            expected: NU6_3
        })
    );

    let ok = FakeChain::new(LOCK_HEIGHT, NU6_3);
    check_branch(&ok, &tx_terms()).unwrap();
}

#[test]
fn a_paid_escrow_waits_on_the_attestation() {
    let chain = funded_chain(LOCK_HEIGHT + 20, 20);
    let progress = LpProgress {
        pre_signature_verified: true,
        venmo_paid: true,
        outcome_secret_held: false,
    };
    assert_eq!(state(&chain, progress).unwrap(), LpState::AwaitingAttestation);
}

#[test]
fn a_paid_escrow_past_the_broadcast_margin_is_flagged_rather_than_hidden() {
    // Section 8: the LP has paid and the release now races the refund. The
    // state says so, because the operational response is different.
    let policy = EscrowPolicy::mainnet_default();
    let chain = funded_chain(policy.broadcast_deadline(LOCK_HEIGHT) + 1, 100);
    let progress = LpProgress {
        pre_signature_verified: true,
        venmo_paid: true,
        outcome_secret_held: false,
    };
    assert_eq!(state(&chain, progress).unwrap(), LpState::PaidPastMargin);
}

#[test]
fn holding_the_outcome_secret_means_ready_to_release() {
    let chain = funded_chain(LOCK_HEIGHT + 20, 20);
    let progress = LpProgress {
        pre_signature_verified: true,
        venmo_paid: true,
        outcome_secret_held: true,
    };
    assert_eq!(state(&chain, progress).unwrap(), LpState::ReadyToRelease);
}

#[test]
fn an_offline_node_is_an_error_rather_than_a_payable_state() {
    // Section 8 has no row where the LP pays because it could not see the
    // chain. An unreachable node must not read as "nothing is wrong".
    let mut chain = funded_chain(LOCK_HEIGHT + 10, 10);
    chain.offline = true;
    assert!(matches!(
        state(&chain, verified()),
        Err(LpError::Chain(ChainError::Unreachable(_)))
    ));
}

#[test]
fn the_prover_request_is_built_from_the_terms() {
    // Spec 5.4 step 3. INTENT_TIMESTAMP_MS is the lock-confirmed time, not the
    // current time: the enclave only matches payments at or after the snapshot,
    // so a current timestamp would exclude the payment the LP just made.
    let t = canonical();
    let r = ProverRequest::from_terms(&t);

    assert_eq!(r.intent_hash, t.intent_hash());
    assert_eq!(r.intent_amount_6dec, 1_000_000);
    assert_eq!(r.payee_hash, t.payee_hash);
    assert_eq!(r.intent_timestamp_ms, t.lock_confirmed_ms);
    assert_eq!(r.rate_18dec, t.rate_18dec);
}

#[test]
fn the_lp_checks_an_attestation_against_the_terms_before_calling_the_attestor() {
    // The announcement is one per event, so a wasted /attest on a proof that
    // was never going to pass costs the LP its only shot.
    use zecp2p_escrow::attestation::PaymentAttestation;
    let t = canonical();

    let good = PaymentAttestation {
        intent_hash: t.intent_hash(),
        release_amount: 1_000_000,
        data_hash: [0; 32],
    };
    assert!(attestation_matches_terms(&good, &t));

    let wrong_intent = PaymentAttestation {
        intent_hash: [0xAB; 32],
        ..good.clone()
    };
    assert!(!attestation_matches_terms(&wrong_intent, &t));

    let underpaid = PaymentAttestation {
        release_amount: 999_999,
        ..good.clone()
    };
    assert!(!attestation_matches_terms(&underpaid, &t));

    let overpaid = PaymentAttestation {
        release_amount: 1_000_001,
        ..good
    };
    assert!(attestation_matches_terms(&overpaid, &t), "overpaying is fine");
}

#[test]
fn a_larger_escrow_waits_for_a_deeper_confirmation() {
    let mut c = canonical();
    c.usd_amount_6dec = 100_000_000; // 100 USD, so 30 confirmations
    let chain = funded_chain(LOCK_HEIGHT + 10, 10);

    let s = evaluate(
        &chain,
        &tx_terms(),
        &c,
        &EscrowPolicy::mainnet_default(),
        LOCK_HEIGHT,
        verified(),
    )
    .unwrap();
    assert_eq!(
        s,
        LpState::AwaitingDepth {
            confirmations: 10,
            required: 30
        }
    );
}
