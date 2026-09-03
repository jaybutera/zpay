//! What the page's session key derives, checked on the server side.
//!
//! The page generates one 32-byte secret per order and keeps it in the URL
//! fragment of the status link. Fragments are not sent to the server, so the
//! coordinator sees the order id and never the secret; what it sees is the
//! 33-byte compressed public key the page sends with the open request, and
//! everything below is derived from that alone.
//!
//! secp256k1 is the curve on both sides, so one secret yields the EVM address
//! that becomes `session.user` in the glue, the Zcash transparent address that
//! becomes 1Click's `refundTo`, and `u_pub` for the native escrow's 2-of-2
//! script.
//!
//! The objection `app.js` records against in-page signing is about a key
//! holding the sender's savings. A session key holds nothing but this order's
//! claim on returned funds, is created by the page, and is never typed. It is
//! a different object.

use alloy::primitives::{keccak256, Address};

use crate::error::AppError;

/// A session's public identity, derived from the 33-byte compressed key the
/// page sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// The compressed secp256k1 public key, 33 bytes.
    pub pubkey: [u8; 33],
    /// `session.user` in the glue: the only address `rescue` and
    /// `withdrawFromZkp2p` will pay.
    pub evm_address: Address,
    /// A transparent P2PKH address on Zcash mainnet, used as 1Click's
    /// `refundTo` when the sender has named no address of their own.
    pub transparent_address: String,
}

/// Parse the hex the page sends and derive everything from it.
pub fn identity_from_hex(hex_pubkey: &str) -> Result<SessionIdentity, AppError> {
    let raw = hex_pubkey.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw)
        .map_err(|_| AppError::InvalidRequest("session_pubkey is not hex".to_string()))?;

    let pubkey: [u8; 33] = bytes.as_slice().try_into().map_err(|_| {
        AppError::InvalidRequest(format!(
            "session_pubkey must be 33 bytes of compressed secp256k1, got {}",
            bytes.len()
        ))
    })?;

    // A compressed point starts 0x02 or 0x03. Anything else is an uncompressed
    // key or garbage, and would derive a different address than the page
    // expects, which is the kind of mismatch that strands a return.
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return Err(AppError::InvalidRequest(
            "session_pubkey must be compressed (leading 0x02 or 0x03)".to_string(),
        ));
    }

    // Reject a key that is not actually on the curve. An off-curve key would be
    // accepted here, used as session.user, and then no signature could ever
    // recover to it, so the order's returns would be unclaimable.
    let verifying = k256::PublicKey::from_sec1_bytes(&pubkey)
        .map_err(|_| AppError::InvalidRequest("session_pubkey is not a curve point".to_string()))?;

    let evm_address = evm_address_from_pubkey(&verifying);
    let transparent_address = transparent_p2pkh_from_pubkey(&pubkey);

    Ok(SessionIdentity {
        pubkey,
        evm_address,
        transparent_address,
    })
}

/// keccak256 of the 64-byte uncompressed key, last 20 bytes. The standard
/// derivation, so the address matches what any EVM tooling would compute.
fn evm_address_from_pubkey(key: &k256::PublicKey) -> Address {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.to_encoded_point(false);
    // to_encoded_point(false) is 65 bytes with a 0x04 tag; the hash is over the
    // 64 coordinate bytes.
    let hash = keccak256(&point.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

/// A Zcash mainnet transparent P2PKH address: Base58Check over the two-byte
/// version 0x1CB8 and HASH160 of the compressed public key.
fn transparent_p2pkh_from_pubkey(pubkey: &[u8; 33]) -> String {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    let sha = Sha256::digest(pubkey);
    let hash160 = Ripemd160::digest(sha);

    // Zcash mainnet t1 (P2PKH) prefix.
    let mut payload = vec![0x1C, 0xB8];
    payload.extend_from_slice(&hash160);

    base58check(&payload)
}

fn base58check(payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let checksum = Sha256::digest(Sha256::digest(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    base58(&full)
}

fn base58(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Leading zero bytes become leading '1's, one each, and are not part of the
    // big-number conversion.
    let zeros = input.iter().take_while(|b| **b == 0).count();

    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for byte in &input[zeros..] {
        let mut carry = *byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;

    fn pubkey_hex(signer: &PrivateKeySigner) -> String {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let verifying = signer.credential().verifying_key();
        let point = verifying.as_affine().to_encoded_point(true);
        hex::encode(point.as_bytes())
    }

    /// The address the coordinator derives has to be the address the signer
    /// actually signs as, or `session.user` names a key nobody holds and every
    /// return on that order is unclaimable.
    #[test]
    fn the_derived_evm_address_is_the_signers_own() {
        for _ in 0..20 {
            let signer = PrivateKeySigner::random();
            let identity = identity_from_hex(&pubkey_hex(&signer)).unwrap();
            assert_eq!(identity.evm_address, signer.address());
        }
    }

    /// A 0x prefix is what a page written against ethers or viem will send.
    #[test]
    fn the_hex_may_carry_an_0x_prefix() {
        let signer = PrivateKeySigner::random();
        let bare = identity_from_hex(&pubkey_hex(&signer)).unwrap();
        let prefixed = identity_from_hex(&format!("0x{}", pubkey_hex(&signer))).unwrap();
        assert_eq!(bare, prefixed);
    }

    #[test]
    fn the_transparent_address_looks_like_a_mainnet_t1() {
        let signer = PrivateKeySigner::random();
        let identity = identity_from_hex(&pubkey_hex(&signer)).unwrap();
        assert!(
            identity.transparent_address.starts_with("t1"),
            "{}",
            identity.transparent_address
        );
        // Base58Check t-addresses are 34 or 35 characters, which is what the
        // repo's own refund validator enforces.
        let n = identity.transparent_address.len();
        assert!((34..=35).contains(&n), "length {n}");
    }

    /// And the coordinator's own refund validator has to accept it, or a
    /// session key's address could not be used as 1Click's refundTo, which is
    /// the whole reason it is derived.
    #[test]
    fn the_derived_transparent_address_passes_the_refund_validator() {
        for _ in 0..20 {
            let signer = PrivateKeySigner::random();
            let identity = identity_from_hex(&pubkey_hex(&signer)).unwrap();
            crate::near::validate_zec_refund_address(&identity.transparent_address)
                .unwrap_or_else(|e| panic!("{} rejected: {e}", identity.transparent_address));
        }
    }

    /// Base58Check against a known vector, so a bug in the big-number loop
    /// cannot hide behind self-consistent tests. This is the Bitcoin genesis
    /// P2PKH hash160 under Zcash's t1 version bytes.
    #[test]
    fn base58check_matches_a_known_encoding() {
        // hash160 of the Bitcoin genesis coinbase pubkey.
        let hash160 = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let mut payload = vec![0x1C, 0xB8];
        payload.extend_from_slice(&hash160);
        assert_eq!(base58check(&payload), "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r");
    }

    /// Leading zero bytes are '1' characters and must not be swallowed by the
    /// big-number conversion.
    #[test]
    fn leading_zero_bytes_become_leading_ones() {
        assert_eq!(base58(&[0, 0, 1]), "112");
        assert_eq!(base58(&[]), "");
    }

    #[test]
    fn a_key_that_is_not_a_compressed_curve_point_is_refused() {
        // Right length, wrong tag.
        assert!(identity_from_hex(&format!("04{}", "11".repeat(32))).is_err());
        // Right tag, not on the curve.
        assert!(identity_from_hex(&format!("02{}", "ff".repeat(32))).is_err());
        // Wrong length.
        assert!(identity_from_hex(&format!("02{}", "11".repeat(31))).is_err());
        // Not hex.
        assert!(identity_from_hex("nonsense").is_err());
        assert!(identity_from_hex("").is_err());
    }

    /// Two different session keys must not collide onto one address, or two
    /// senders' returns would land in the same place.
    #[test]
    fn distinct_keys_give_distinct_addresses() {
        let mut evm = std::collections::HashSet::new();
        let mut zec = std::collections::HashSet::new();
        for _ in 0..50 {
            let signer = PrivateKeySigner::random();
            let id = identity_from_hex(&pubkey_hex(&signer)).unwrap();
            assert!(evm.insert(id.evm_address));
            assert!(zec.insert(id.transparent_address));
        }
    }
}
