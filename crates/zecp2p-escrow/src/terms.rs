//! Canonical terms and `intentHash`, spec section 5.2.
//!
//! The hash is what the LP hands the enclave as `INTENT_HASH`, and the enclave
//! signs whatever 32 bytes it is given. So the binding between "this Venmo
//! payment" and "this escrow" is entirely this hash; if two different escrows
//! could produce the same one, an attestation for either would release both.
//!
//! Canonical JSON here means sorted keys, no whitespace, and integers written
//! as decimal strings. Integers are strings because `usd_amount_6dec` and
//! `rate_18dec` exceed what a JSON number safely represents, and a language
//! that parsed them as floats would produce a different hash from one that did
//! not.
//!
//! `platform_fee_zat` and `treasury_script` are in here for the same reason
//! every other field is: the hash is what binds the escrow, and a field outside
//! it is a field either party can restate. See their doc comments below.

use sha2::{Digest, Sha256};

const INTENT_TAG: &[u8] = b"zecp2p-intent-v1";

/// The canonical terms of spec 5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTerms {
    pub funding_txid: [u8; 32],
    pub vout: u32,
    pub amount_zat: u64,
    pub u_pub: [u8; 33],
    pub l_pub: [u8; 33],
    pub refund_height: u64,
    /// What the LP must send, in 6-decimal USD.
    pub usd_amount_6dec: u64,
    /// USD per ZEC, 18 decimals, quoted by the LP.
    pub rate_18dec: u128,
    /// The zk-p2p curator `hashedOnchainId` of the user's Venmo.
    pub payee_hash: [u8; 32],
    /// Set once the confirmation depth of section 7 is reached.
    pub lock_confirmed_ms: u64,
    /// The platform fee in zatoshis, paid to the treasury as a third output on
    /// the release. Zero means no treasury output and a two-output release.
    ///
    /// This is here, and not merely in the transaction, because `terms_hash`
    /// feeds `outcome_challenge` and therefore the outcome point `Y` the user's
    /// pre-signature is encrypted under. A scalar released against terms
    /// carrying one fee cannot decrypt a pre-signature made under terms
    /// carrying another. It is the same mechanism that protects
    /// `usd_amount_6dec`, applied to the fee.
    pub platform_fee_zat: u64,
    /// The treasury scriptPubKey the platform fee is paid to.
    ///
    /// An LP that rewrote this to its own address would produce terms that hash
    /// differently, which the user's whole-structure comparison in
    /// `client::prepare_escrow` rejects before any money is committed. The
    /// client derives it from a pinned constant rather than accepting it.
    pub treasury_script: Vec<u8>,
}

impl CanonicalTerms {
    /// JSON with sorted keys, no whitespace, integers as decimal strings.
    ///
    /// The field order below is alphabetical and must stay that way: it is the
    /// serialization, not a struct layout.
    pub fn canonical_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"amount_zat\":\"{}\",",
                "\"funding_txid\":\"{}\",",
                "\"l_pub\":\"{}\",",
                "\"lock_confirmed_ms\":\"{}\",",
                "\"payee_hash\":\"{}\",",
                "\"platform_fee_zat\":\"{}\",",
                "\"rate_18dec\":\"{}\",",
                "\"refund_height\":\"{}\",",
                "\"treasury_script\":\"{}\",",
                "\"u_pub\":\"{}\",",
                "\"usd_amount_6dec\":\"{}\",",
                "\"vout\":\"{}\"",
                "}}"
            ),
            self.amount_zat,
            hex::encode(self.funding_txid),
            hex::encode(self.l_pub),
            self.lock_confirmed_ms,
            hex::encode(self.payee_hash),
            self.platform_fee_zat,
            self.rate_18dec,
            self.refund_height,
            hex::encode(&self.treasury_script),
            hex::encode(self.u_pub),
            self.usd_amount_6dec,
            self.vout,
        )
    }

    /// `sha256(canonical_json)`, the value the announcement pins so the terms
    /// cannot change between announcement and attestation (spec 5.5 step 1).
    pub fn terms_hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_json().as_bytes()).into()
    }

    /// `intentHash = sha256("zecp2p-intent-v1" || canonical_json(terms))`.
    pub fn intent_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(INTENT_TAG);
        h.update(self.canonical_json().as_bytes());
        h.finalize().into()
    }
}
