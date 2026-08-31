//! Turning a sent Venmo payment into something `fulfillIntent` accepts.
//!
//! `fulfillIntent` calldata reaches the Venmo verifier named by
//! `attestation.verifier` in the taker config (UnifiedPaymentVerifierV3 on Base
//! mainnet), which checks an EIP-712 signature produced inside zk-p2p's
//! enclave. A proof is only valid if that enclave signed it.
//!
//! Obtaining that signature is fully automatable and needs no browser
//! extension. zk-p2p now runs a TEE attestation service: the client encrypts a
//! Venmo session cookie to a key whose AWS Nitro attestation document it
//! verifies first, POSTs it to `/buyer/verify`, and the enclave replays the
//! Venmo request itself and returns an EIP-712 signature over
//! `(intentHash, releaseAmount, dataHash)`. `scripts/proof/prove_payment.mjs`
//! does exactly this against the live service.
//!
//! Two properties of that service matter to a taker:
//!
//! - The enclave re-signs the same payment for whatever `intentHash` it is
//!   given, so one payment can be bound to a new intent without paying again.
//! - The signature is pinned to `chainId` 8453 and the verifier address, so it
//!   is Base-mainnet-only; there is no zk-p2p verifier on Base Sepolia.
//!
//! `scripts/dryrun/fork_base.sh claim` drives signalIntent + fulfillIntent
//! with a real attestation against the deployed mainnet contracts on a local
//! fork. Note the verifier compares the attested snapshot's intent timestamp
//! with the intent stored on chain: build the attestation with the intent's
//! real signal time or fulfilment reverts with
//! "UPV: Snapshot timestamp mismatch".
//!
//! What this module still leaves to the caller is the Venmo session material
//! itself, which is a live credential a human has to supply.

use alloy::primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};


/// Everything the taker needs to get an attestation for a sent payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    pub intent_hash: B256,
    /// Venmo username that was paid.
    pub recipient: String,
    /// Dollars and cents as sent.
    pub amount: String,
    /// When the payment went out, so the operator can find it in the feed.
    pub sent_at: chrono::DateTime<chrono::Utc>,
}

/// An enclave-attested proof, once the prover has produced one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedProof {
    /// ABI-encoded proof blob passed straight through to `fulfillIntent`.
    pub payment_proof: Bytes,
    /// Verifier-specific data accompanying it.
    #[serde(default)]
    pub verification_data: Bytes,
}

/// Why the agent stopped short of fulfilment.
#[derive(Debug, Clone)]
pub enum ProofStatus {
    /// The enclave handed us a proof; `fulfillIntent` can go ahead.
    Ready(AttestedProof),
    /// The payment is made and the intent is live, but no attestation exists
    /// yet. The operator has to run the prover against the enclave.
    NeedsAttestation(ProofRequest),
}

impl ProofStatus {
    /// The message the operator sees when a run stops here.
    ///
    /// Written to be actionable: it names the intent, the payment, and what to
    /// do, because at this point the taker's money has already left and only
    /// the proof stands between them and the escrowed USDC.
    pub fn manual_step_report(&self) -> Option<String> {
        self.manual_step_report_for("https://attestation-service.zkp2p.xyz")
    }

    /// The same report, naming the attestation service the operator configured.
    pub fn manual_step_report_for(&self, service_url: &str) -> Option<String> {
        match self {
            ProofStatus::Ready(_) => None,
            ProofStatus::NeedsAttestation(req) => Some(format!(
                "Manual step required: proof of payment.\n\
                 \n\
                 The Venmo payment of ${amount} to @{recipient} has been sent and\n\
                 intent {intent} is claimed on zk-p2p. The escrowed USDC is released\n\
                 only against an enclave-signed attestation of that payment.\n\
                 \n\
                 That attestation comes from zk-p2p's TEE at {service}. It replays\n\
                 your Venmo feed from inside an AWS Nitro enclave and signs the\n\
                 result, so it needs a logged-in account.venmo.com Cookie header\n\
                 and your numeric Venmo sender id. This agent never handles those.\n\
                 \n\
                 To finish:\n\
                   1. Capture the cookie and sender id (scripts/proof/README.md).\n\
                   2. INTENT_HASH={intent} INTENT_AMOUNT=<6-decimal units> \\\n\
                      INTENT_TIMESTAMP_MS=<the intent's on-chain signal time in ms> \\\n\
                      node scripts/proof/prove_payment.mjs\n\
                   3. Run: zecp2p-taker fulfill --intent {intent} --proof attestation.json\n\
                 \n\
                 The timestamp matters: the verifier compares the attested snapshot\n\
                 against the intent stored on chain and reverts with\n\
                 \"UPV: Snapshot timestamp mismatch\" if they differ.\n\
                 \n\
                 Until then the intent stays open. If you cannot prove it, run\n\
                 `zecp2p-taker cancel --intent {intent}` to release the maker's\n\
                 USDC and unlock your stake, and settle the Venmo side directly.",
                amount = req.amount,
                recipient = req.recipient,
                intent = req.intent_hash,
                service = service_url,
            )),
        }
    }
}

/// Load an attestation the prover wrote to disk.
pub fn load_proof(path: &str) -> anyhow::Result<AttestedProof> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read proof file '{path}': {e}"))?;
    let proof: AttestedProof = serde_json::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("'{path}' is not an attestation export: {e}"))?;
    if proof.payment_proof.is_empty() {
        anyhow::bail!("'{path}' contains an empty payment proof");
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ready_proof_needs_no_operator() {
        let status = ProofStatus::Ready(AttestedProof {
            payment_proof: Bytes::from(vec![1, 2, 3]),
            verification_data: Bytes::new(),
        });
        assert!(status.manual_step_report().is_none());
    }

    #[test]
    fn the_manual_report_names_the_intent_and_the_way_out() {
        let status = ProofStatus::NeedsAttestation(ProofRequest {
            intent_hash: B256::repeat_byte(0xab),
            recipient: "alice".to_string(),
            amount: "25.00".to_string(),
            sent_at: chrono::Utc::now(),
        });
        let report = status.manual_step_report().expect("should need a step");
        // the intent, the payment, and the tool that produces the attestation
        assert!(report.contains(&B256::repeat_byte(0xab).to_string()));
        assert!(report.contains("alice"));
        assert!(report.contains("25.00"));
        assert!(report.contains("prove_payment.mjs"));
        // the operator must be told how to get their stake back
        assert!(report.contains("cancel"));
    }

    #[test]
    fn the_report_names_the_configured_attestation_service() {
        let status = ProofStatus::NeedsAttestation(ProofRequest {
            intent_hash: B256::repeat_byte(0x01),
            recipient: "bob".to_string(),
            amount: "1.00".to_string(),
            sent_at: chrono::Utc::now(),
        });
        let report = status
            .manual_step_report_for("https://enclave.example")
            .expect("should need a step");
        assert!(report.contains("https://enclave.example"));
    }

    #[test]
    fn rejects_an_empty_proof_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.json");
        std::fs::write(&path, r#"{"payment_proof":"0x"}"#).unwrap();
        assert!(load_proof(path.to_str().unwrap()).is_err());
    }
}
