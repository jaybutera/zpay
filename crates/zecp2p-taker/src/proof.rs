//! Turning a sent Venmo payment into something `fulfillIntent` accepts.
//!
//! This is the step that does not fully automate, and the reason is structural
//! rather than a gap in this crate.
//!
//! `fulfillIntent` calldata reaches the Venmo verifier at
//! `0xC6F4a193576C60892a47e111Bb5706c30162502B`, which hands the proof to an
//! attestation verifier at `0x9Fe920b24e50e6a6362BA71a1BeB502A99c402d5`. That
//! contract holds a witness set and a signature threshold; on Base mainnet
//! today `witnessCount() == 2` and `requiredSignatures() == 1`. So a proof is
//! only valid if one of zk-p2p's witnesses signed an attestation that the
//! payment happened.
//!
//! A witness signs after observing the taker's authenticated Venmo session
//! through zk-p2p's PeerAuth browser extension, which performs the TLS
//! attestation. The signing key is theirs, not ours: no amount of local
//! automation produces that signature, and an agent cannot mint one.
//!
//! What this module does, therefore, is drive everything up to and after that
//! signature, and make the handoff explicit rather than silently stalling.

use alloy::primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

/// Base mainnet attestation contracts, read off-chain at time of writing.
pub const VENMO_VERIFIER: &str = "0xC6F4a193576C60892a47e111Bb5706c30162502B";
pub const ATTESTATION_VERIFIER: &str = "0x9Fe920b24e50e6a6362BA71a1BeB502A99c402d5";

/// Everything the taker needs to hand PeerAuth to get an attestation.
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

/// A witness-attested proof, once PeerAuth has produced one.
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
    /// PeerAuth handed us a proof; `fulfillIntent` can go ahead.
    Ready(AttestedProof),
    /// The payment is made and the intent is live, but no attestation exists
    /// yet. The operator has to run PeerAuth.
    NeedsPeerAuth(ProofRequest),
}

impl ProofStatus {
    /// The message the operator sees when a run stops here.
    ///
    /// Written to be actionable: it names the intent, the payment, and what to
    /// do, because at this point the taker's money has already left and only
    /// the proof stands between them and the escrowed USDC.
    pub fn manual_step_report(&self) -> Option<String> {
        match self {
            ProofStatus::Ready(_) => None,
            ProofStatus::NeedsPeerAuth(req) => Some(format!(
                "Manual step required: proof of payment.\n\
                 \n\
                 The Venmo payment of ${amount} to @{recipient} has been sent and\n\
                 intent {intent} is claimed on zk-p2p. The escrowed USDC is released\n\
                 only against a witness-signed attestation of that payment.\n\
                 \n\
                 zk-p2p's attestation verifier ({verifier}) requires\n\
                 {required} signature from its witness set, produced by the PeerAuth\n\
                 browser extension against your logged-in Venmo session. The witness\n\
                 key is zk-p2p's, so this agent cannot generate or forge it.\n\
                 \n\
                 To finish:\n\
                   1. Open PeerAuth and select the Venmo payment sent at {sent_at}.\n\
                   2. Let it produce the attestation (about 30 seconds).\n\
                   3. Run: zecp2p-taker fulfill --intent {intent} --proof <file>\n\
                 \n\
                 Until then the intent stays open. If you cannot prove it, run\n\
                 `zecp2p-taker cancel --intent {intent}` to release the maker's\n\
                 USDC and unlock your stake, and settle the Venmo side directly.",
                amount = req.amount,
                recipient = req.recipient,
                intent = req.intent_hash,
                verifier = ATTESTATION_VERIFIER,
                required = 1,
                sent_at = req.sent_at.format("%Y-%m-%d %H:%M:%S UTC"),
            )),
        }
    }
}

/// Load a proof PeerAuth exported to disk.
pub fn load_proof(path: &str) -> anyhow::Result<AttestedProof> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read proof file '{path}': {e}"))?;
    let proof: AttestedProof = serde_json::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("'{path}' is not a PeerAuth proof export: {e}"))?;
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
        let status = ProofStatus::NeedsPeerAuth(ProofRequest {
            intent_hash: B256::repeat_byte(0xab),
            recipient: "alice".to_string(),
            amount: "25.00".to_string(),
            sent_at: chrono::Utc::now(),
        });
        let report = status.manual_step_report().expect("should need a step");
        assert!(report.contains("PeerAuth"));
        assert!(report.contains("alice"));
        assert!(report.contains("25.00"));
        // the operator must be told how to get their stake back
        assert!(report.contains("cancel"));
    }

    #[test]
    fn rejects_an_empty_proof_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.json");
        std::fs::write(&path, r#"{"payment_proof":"0x"}"#).unwrap();
        assert!(load_proof(path.to_str().unwrap()).is_err());
    }
}
