//! A fiat rail that reports a payment nobody made.
//!
//! Behind the `test-rails` feature, so a production build has no path that
//! settles an escrow without a real Venmo payment and a real enclave
//! attestation. The feature is off by default and the binary refuses to use
//! this rail unless it was compiled with it *and* asked for it by name.
//!
//! It exists for one thing: driving the real page against the real coordinator
//! on a local chain, where the release must still be assembled, signed and
//! broadcast for real. Everything downstream of `pay` is the production path.

use anyhow::Result;

use crate::state::{FiatRail, PaidFiat};

/// Reports a payment, and hands back an attestation the local attestor accepts.
#[derive(Debug, Default)]
pub struct SimulatedRail;

#[async_trait::async_trait]
impl FiatRail for SimulatedRail {
    async fn pay(&self, leg: &zecp2p_taker::auto::rail::FiatLeg) -> Result<PaidFiat> {
        let cents = u64::try_from(leg.payment.cents())?;
        tracing::warn!(
            recipient = %leg.recipient,
            amount = %leg.payment.to_venmo_string(),
            "SIMULATED payment: no dollars left this machine"
        );
        Ok(PaidFiat {
            cents,
            fiat_left: true,
        })
    }

    async fn attest(
        &self,
        leg: &zecp2p_taker::auto::rail::FiatLeg,
    ) -> Result<zecp2p_escrow::lp_client::WireAttestation> {
        // The shape a real enclave export has. The local attestor checks the
        // terms rather than the signature, which is exactly the part of the
        // system this rail is not exercising.
        Ok(zecp2p_escrow::lp_client::WireAttestation {
            intent_hash: hex::encode(leg.intent_hash.0),
            release_amount: leg.intent_amount_6dec.to_string(),
            data_hash: hex::encode([0u8; 32]),
            signature: hex::encode([0u8; 65]),
            encoded_payment_details: hex::encode(vec![0u8; 448]),
        })
    }
}
