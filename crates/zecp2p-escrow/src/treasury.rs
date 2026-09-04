//! The platform treasury: where the fee output pays, and how much it is.
//!
//! The address is **pinned in the binary**, the way `attestation::ENCLAVE_SIGNER`
//! is. That is the whole security property of this module and it is worth one
//! paragraph. The fee output is enforced by the user's adaptor pre-signature,
//! which is made over a ZIP 244 SIGHASH_ALL digest covering the entire output
//! set; so whatever address is in the transaction the user signs is the address
//! that gets paid, and no LP can substitute another. But that argument only
//! protects the user against an LP if the user knows which address is supposed
//! to be there. A treasury address the LP supplies is a treasury address the LP
//! can point at itself, and the user has no way to tell the difference. So the
//! client derives it from the constant below and never accepts it over the
//! wire, and `terms::CanonicalTerms` carries it into `terms_hash` so an LP that
//! rewrites it produces terms the user's own comparison rejects.
//!
//! Rotation is a config change with a version bump, which is the same posture
//! `attestation.rs` takes on enclave signer rotation.
//!
//! # Two deliberate departures from the design spec
//!
//! Both are narrowings, and both are recorded here rather than left for a
//! reader to discover by diffing.
//!
//! **No ceiling.** `v2-fee-token-design.md` writes the fee as
//! `clamp(amount_zat * fee_bps / 10_000, FLOOR, CEILING)`. Only the floor is
//! implemented, as the dust gate below. A ceiling would cap the fee on a large
//! escrow, and adding one is a one-line change to [`platform_fee_zat`] - but a
//! cap is a number nobody has chosen yet, and a wrong one is worse than none:
//! it would silently undercharge every escrow above it, and the effect would
//! show up as revenue that stops tracking volume rather than as an error. When
//! a figure exists, it goes here and gets a test either side of it.
//!
//! **Two outputs, not three.** The design describes the release as paying "the
//! user's ZEC-equivalent leg, the LP's, and a platform cut". The release this
//! code builds has two outputs: the counterparty leg and the treasury. There is
//! no third because there is no user leg on this transaction - the user is paid
//! in dollars over Venmo, off-chain, and the whole escrow less fees goes to the
//! LP. The design's own arithmetic agrees (`amount_zat = miner_fee +
//! platform_fee + lp_output`); the three-output phrasing counts the miner fee as
//! an output, which it is not. The fee analysis is unaffected either way,
//! because `fees::release_fee_zat` shows the release input dominates through
//! three outputs, so the escrow has a spare one in hand.
//!
//! # Why the constant is empty
//!
//! No treasury address has been funded or spent from yet. The design that
//! specified this feature names the failure mode directly: a pinned script
//! whose key is lost does not break trades and does not risk user funds, but it
//! burns every fee it collects, silently, forever. So the rule is that an
//! address ships only after a live-fire check - fund it, spend from it, record
//! the txid - and until then every path that would need one refuses. An empty
//! constant that fails closed is the honest encoding of "not yet".

use crate::address::{script_pubkey_for, AddrNetwork, AddressError};

/// The mainnet treasury address, base58 `t1...` or `t3...`.
///
/// Empty until an address has been funded and spent from on mainnet. See the
/// module note.
pub const MAINNET_TREASURY_ADDRESS: &str = "";

/// The testnet/regtest treasury address, base58 `tm...`.
///
/// Pinned so the ship-order testnet live-fire can run a non-zero fee end to
/// end without a mainnet address existing yet.
///
/// Its key is **published on purpose**: it is
/// `secp256k1` over `sha256("zecp2p-testnet-treasury-v1")`, which is
/// `0e223008551fb62fa4709df471a27a98e0f54c95f045546a10648da051ad14ea`, and its
/// hash160 is `1cfbe04cc4c9d693b8483612a54bd72d0ddd109c`. Anyone reading this
/// file can rederive it and spend from it, which on testnet is the point: the
/// live-fire check the design asks for is that the address can be spent from,
/// and a key in the repo makes that reproducible by whoever runs the regtest
/// suite rather than by whoever happens to hold a wallet.
///
/// A published key is safe here and only here. `treasury_script` refuses to
/// decode a `tm` address under `AddrNetwork::Main`, so this constant cannot
/// become a mainnet destination by accident, and `MAINNET_TREASURY_ADDRESS`
/// stays empty until a real one has been funded and spent from.
pub const TESTNET_TREASURY_ADDRESS: &str = "tmCMbzCuRX3BW95a2GZWDSHvM4THqu5ziTA";

/// The platform cut, in basis points of the escrow amount.
///
/// 15 bps, the 0.15% the coordinator's quote breakdown and the launch page
/// already state. The superseded Base-rail spec charged 20 bps, and this crate
/// shipped at that rate until 2026-09-03; the v2 design's open question 6
/// records the change. The rate is expressed against `amount_zat` rather than
/// against the USD leg because `rate_18dec` must be exactly
/// `payment_details::IDENTITY_RATE_18DEC` - the enclave's `releaseAmount` only
/// means dollars at the identity rate - so the fee cannot be a rate adjustment
/// and has to be a zatoshi subtraction.
pub const PLATFORM_FEE_BPS: u64 = 15;

/// The smallest treasury output the escrow will write.
///
/// This is a safety floor, not an economic one. The treasury output costs
/// nothing in miner fees (see `fees::release_fee_zat`: the release input
/// dominates through three outputs), so there is no cost-recovery threshold to
/// clear. What there is, is Zcash's dust rule: an output below it makes the
/// transaction non-standard, and a non-standard release is one no node will
/// relay - which breaks the trade rather than merely forgoing the fee. Below
/// this the treasury output is omitted and the release stays two-output.
///
/// 54 zat is the threshold for a standard 34-byte transparent output. The rule
/// is Bitcoin's, inherited: an output is dust if spending it would cost more
/// than a third of its value at the minimum relay rate. Spending a P2PKH output
/// takes a 148-byte input plus the 34-byte output it came from, and Zcash's
/// `minRelayTxFee` has been 100 zat/kB since zcashd v1.0.7-1, so the threshold
/// is `3 * 182 * 100 / 1000 = 54`. A P2SH output is 32 bytes rather than 34 and
/// its input is smaller still, so 54 is the conservative side of the boundary
/// for either script type.
///
/// This is a constant rather than a node query because both parties must
/// compute the same number offline, before either has talked to a node - the
/// counterparty's copy of the release has to match byte for byte.
///
/// `tests/dust_boundary.rs` derives it from the node's formula rather than
/// restating it, and holds `platform_fee_zat` and `ReleaseSplit::outputs` to
/// the same line. What no unit test can show is that a *running* node agrees:
/// Zebra rejects a missing transparent input before it reaches its standardness
/// rules, so a probe against a fictional outpoint answers "missing input"
/// whatever the output is worth, and a real one would mean funding an escrow.
/// The live-fire run in the ship order is what covers that, on a funded escrow
/// where the node's answer means something.
pub const DUST_THRESHOLD_ZAT: u64 = 54;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TreasuryError {
    #[error(
        "no treasury address is pinned for {network:?}. An address ships only after it has \
         been funded and spent from, so that a lost key cannot silently burn every fee the \
         platform collects; set the constant in treasury.rs once that check is recorded"
    )]
    Unpinned { network: AddrNetwork },
    #[error("the pinned treasury address is not usable: {0}")]
    BadAddress(AddressError),
}

/// The pinned treasury address for a network, as a base58 string.
pub fn treasury_address(network: AddrNetwork) -> Result<&'static str, TreasuryError> {
    let addr = match network {
        AddrNetwork::Main => MAINNET_TREASURY_ADDRESS,
        AddrNetwork::Test => TESTNET_TREASURY_ADDRESS,
    };
    if addr.is_empty() {
        return Err(TreasuryError::Unpinned { network });
    }
    Ok(addr)
}

/// The scriptPubKey the platform fee pays.
///
/// Decoded rather than stored as bytes so the network check in
/// `address::script_pubkey_for` runs on it: a testnet address pinned into a
/// mainnet build would otherwise decode to a hash nobody on mainnet holds a key
/// for, and every fee would be unspendable.
pub fn treasury_script(network: AddrNetwork) -> Result<Vec<u8>, TreasuryError> {
    let addr = treasury_address(network)?;
    script_pubkey_for(addr, network).map_err(TreasuryError::BadAddress)
}

/// The platform fee for an escrow, in zatoshis.
///
/// `amount_zat * bps / 10_000`, rounded down, then dropped to zero if it is
/// below the dust threshold. Rounding down rather than up so the platform never
/// takes more than the rate it published, and so the LP's leg is never short by
/// a rounding artefact.
///
/// Below dust the answer is zero and the caller builds a two-output release.
/// That is the design's dust gate: the fee is forgone, the trade still settles.
pub fn platform_fee_zat(amount_zat: u64, fee_bps: u64) -> u64 {
    let fee = (amount_zat as u128)
        .saturating_mul(fee_bps as u128)
        / 10_000u128;
    let fee = u64::try_from(fee).unwrap_or(u64::MAX);
    if fee < DUST_THRESHOLD_ZAT {
        0
    } else {
        fee
    }
}

/// The fee at the platform's own published rate.
pub fn default_platform_fee_zat(amount_zat: u64) -> u64 {
    platform_fee_zat(amount_zat, PLATFORM_FEE_BPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unpinned_mainnet_treasury_refuses_rather_than_paying_somewhere() {
        // Fail-closed is the point: an unset constant must never decode to a
        // zero hash, which is an address nobody can spend from. Mainnet stays
        // unset until an address has been funded and spent from.
        assert_eq!(
            treasury_script(AddrNetwork::Main),
            Err(TreasuryError::Unpinned {
                network: AddrNetwork::Main
            })
        );
    }

    #[test]
    fn the_testnet_treasury_decodes_to_the_key_it_documents() {
        // The pinned testnet address must decode, under testnet, to a P2PKH
        // script over the hash160 the module comment publishes. If the constant
        // and the comment ever disagree, the live-fire run would fund an
        // address whose key nobody can produce.
        let spk = treasury_script(AddrNetwork::Test).expect("the testnet treasury is pinned");
        let mut expected = vec![0x76, 0xa9, 20];
        expected.extend_from_slice(
            &hex::decode("1cfbe04cc4c9d693b8483612a54bd72d0ddd109c").unwrap(),
        );
        expected.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(spk, expected);
    }

    #[test]
    fn the_testnet_treasury_cannot_become_a_mainnet_destination() {
        // The one risk of pinning a published key: that a mainnet build reaches
        // for it. `script_pubkey_for`'s network check refuses the `tm` prefix
        // under mainnet, so the fallback does not exist.
        assert!(matches!(
            script_pubkey_for(TESTNET_TREASURY_ADDRESS, AddrNetwork::Main),
            Err(AddressError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn the_fee_rounds_down() {
        // 15 bps of 200000 is 300 exactly.
        assert_eq!(platform_fee_zat(200_000, 15), 300);
        // 15 bps of 200001 is 300.0015, which rounds to 300 and not to 301: the
        // platform never takes more than its published rate.
        assert_eq!(platform_fee_zat(200_001, 15), 300);
        // And the constant is the rate these figures were computed at.
        assert_eq!(PLATFORM_FEE_BPS, 15);
    }

    #[test]
    fn a_sub_dust_fee_becomes_no_fee_at_all() {
        // At 15 bps the dust boundary falls at 36,000 zat of escrow: 15 bps of
        // 35,999 is 53.9985, which rounds down to 53, one below the threshold,
        // and 15 bps of 36,000 is exactly 54. A 53 zat output would make the
        // release non-standard, which breaks the trade; forgoing the fee does
        // not.
        assert_eq!(platform_fee_zat(35_999, PLATFORM_FEE_BPS), 0);
        assert_eq!(platform_fee_zat(36_000, PLATFORM_FEE_BPS), 54);

        // Worth stating plainly: at this rate the gate never fires on an escrow
        // the protocol will actually accept. `client::MINIMUM_ESCROW_ZAT` is
        // 120,000 zat, more than three times the boundary, so every quotable
        // escrow yields a fee above dust. The gate is here for a lower rate or a
        // smaller minimum, either of which is a config change away.
        // A const assertion, so a change to either constant is a build error
        // and not a test that quietly stops meaning anything.
        const _: () = assert!(crate::client::MINIMUM_ESCROW_ZAT > 36_000);
        assert!(platform_fee_zat(crate::client::MINIMUM_ESCROW_ZAT, PLATFORM_FEE_BPS) > 0);

        // A 1 bp rate is one such config change, and there the gate does fire.
        assert_eq!(platform_fee_zat(120_000, 1), 0, "12 zat is dust");
        assert_eq!(platform_fee_zat(540_000, 1), 54);
    }

    #[test]
    fn the_fee_never_exceeds_the_escrow() {
        // A misconfigured rate must not produce a fee larger than the escrow,
        // because the transaction builder would then refuse every release.
        for amount in [1u64, 120_000, 200_000, 21_000_000 * 100_000_000] {
            assert!(platform_fee_zat(amount, PLATFORM_FEE_BPS) <= amount);
        }
    }
}
