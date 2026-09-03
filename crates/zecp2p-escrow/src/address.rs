//! Transparent address decoding for spend destinations.
//!
//! This lives in the library rather than in an example so the network check
//! below can be tested without a mainnet node.

/// Which chain an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrNetwork {
    Main,
    Test,
}

/// Why an address cannot be used as a spend destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// A character outside the base58 alphabet.
    BadCharacter(char),
    /// Fewer than 26 bytes after decoding.
    TooShort,
    /// The trailing four bytes are not the double-SHA256 of the payload.
    BadChecksum,
    /// A two-byte version prefix that is not a Zcash transparent address.
    UnknownPrefix([u8; 2]),
    /// A well-formed address for the other chain.
    ///
    /// Decoding it anyway yields a hash nobody on this chain holds a key for,
    /// so a spend to it would confirm and the coin would be unrecoverable.
    WrongNetwork {
        address_is: AddrNetwork,
        configured_for: AddrNetwork,
    },
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCharacter(c) => write!(f, "{c:?} is not a base58 character"),
            Self::TooShort => write!(f, "address is too short"),
            Self::BadChecksum => write!(f, "address checksum does not match; it is mistyped"),
            Self::UnknownPrefix(p) => {
                write!(f, "version prefix {p:02x?} is not a Zcash transparent address")
            }
            Self::WrongNetwork {
                address_is,
                configured_for,
            } => write!(
                f,
                "address is {address_is:?} but this run is configured for {configured_for:?}"
            ),
        }
    }
}

impl std::error::Error for AddressError {}

/// (version prefix, is_p2sh, network)
const KNOWN: [([u8; 2], bool, AddrNetwork); 4] = [
    ([0x1c, 0xb8], false, AddrNetwork::Main), // t1
    ([0x1c, 0xbd], true, AddrNetwork::Main),  // t3
    ([0x1d, 0x25], false, AddrNetwork::Test), // tm
    ([0x1c, 0xba], true, AddrNetwork::Test),  // t2
];

/// Decodes a transparent address into the scriptPubKey that pays it.
///
/// Refuses an address belonging to the other chain: recognising a prefix is
/// not the same as checking it is *ours*.
pub fn script_pubkey_for(addr: &str, network: AddrNetwork) -> Result<Vec<u8>, AddressError> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = Vec::new();
    for c in addr.bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|a| *a == c)
            .ok_or(AddressError::BadCharacter(c as char))? as u32;
        for d in num.iter_mut() {
            carry += (*d as u32) * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = addr.bytes().take_while(|b| *b == b'1').count();
    let mut full = vec![0u8; zeros];
    full.extend(num.iter().rev());
    if full.len() < 26 {
        return Err(AddressError::TooShort);
    }

    let (payload, checksum) = full.split_at(full.len() - 4);
    let expected = {
        use sha2::{Digest, Sha256};
        Sha256::digest(Sha256::digest(payload))
    };
    if checksum != &expected[..4] {
        return Err(AddressError::BadChecksum);
    }

    let prefix = [full[0], full[1]];
    let (_, is_p2sh, addr_network) = *KNOWN
        .iter()
        .find(|(p, _, _)| *p == prefix)
        .ok_or(AddressError::UnknownPrefix(prefix))?;

    if addr_network != network {
        return Err(AddressError::WrongNetwork {
            address_is: addr_network,
            configured_for: network,
        });
    }

    let hash = &full[2..22];
    Ok(if is_p2sh {
        let mut s = vec![0xa9, 20];
        s.extend_from_slice(hash);
        s.push(0x87);
        s
    } else {
        let mut s = vec![0x76, 0xa9, 20];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A testnet P2PKH address used throughout the regtest runs.
    const TM: &str = "tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn";

    #[test]
    fn testnet_address_decodes_under_testnet() {
        let spk = script_pubkey_for(TM, AddrNetwork::Test).expect("testnet address");
        assert_eq!(spk[0], 0x76, "expected a P2PKH script");
        assert_eq!(spk.len(), 25);
    }

    /// The round-10 finding: this used to decode happily and produce a
    /// mainnet output paying a hash derived from a testnet address.
    #[test]
    fn testnet_address_is_refused_under_mainnet() {
        let err = script_pubkey_for(TM, AddrNetwork::Main).unwrap_err();
        assert_eq!(
            err,
            AddressError::WrongNetwork {
                address_is: AddrNetwork::Test,
                configured_for: AddrNetwork::Main,
            }
        );
    }

    #[test]
    fn mistyped_address_is_refused() {
        let mut bad = TM.to_string();
        bad.pop();
        bad.push('X');
        assert_eq!(
            script_pubkey_for(&bad, AddrNetwork::Test).unwrap_err(),
            AddressError::BadChecksum
        );
    }

    /// `T1` and `TM` encode the *same* hash160 and differ only in their
    /// network prefix, so this isolates the network check from every other
    /// decode rule.
    const T1: &str = "t1dSuQrrrSUbeQsbzH9LmVqT8BZibPagj4B";

    #[test]
    fn the_two_literals_differ_only_by_network() {
        let m = script_pubkey_for(T1, AddrNetwork::Main).expect("mainnet address decodes");
        let t = script_pubkey_for(TM, AddrNetwork::Test).expect("testnet address decodes");
        assert_eq!(m, t, "same hash160, so the scripts must match");
    }

    #[test]
    fn a_mainnet_address_is_refused_under_testnet() {
        assert_eq!(
            script_pubkey_for(T1, AddrNetwork::Test).unwrap_err(),
            AddressError::WrongNetwork {
                address_is: AddrNetwork::Main,
                configured_for: AddrNetwork::Test,
            }
        );
    }
}
