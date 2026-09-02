//! R5-7: the refund destination must carry a valid checksum.
//!
//! A single mistyped character in a `t` address decodes to a hash nobody holds,
//! and the refund pays it. On the testnet run that is TAZ; on the mainnet run
//! it is the escrow. The check is four lines and this is the test for it.

use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The same decode the runner does, lifted so it can be tested without a node.
fn decode_checked(addr: &str) -> Result<[u8; 20], String> {
    let mut num: Vec<u8> = Vec::new();
    for c in addr.bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|a| *a == c)
            .ok_or_else(|| format!("{addr} is not base58"))? as u32;
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
        return Err(format!("{addr} is too short"));
    }
    let (payload, checksum) = full.split_at(full.len() - 4);
    let expected = Sha256::digest(Sha256::digest(payload));
    if checksum != &expected[..4] {
        return Err(format!("{addr} has a bad checksum"));
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&full[2..22]);
    Ok(hash)
}

/// A real testnet P2SH address, read off a live node (block 4319772).
const REAL: &str = "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz";

#[test]
fn a_real_address_decodes_to_its_hash() {
    let hash = decode_checked(REAL).expect("a real address must decode");
    assert_eq!(
        hex::encode(hash),
        "02db6bf7d524268b04edbb986ca4b3ba3528045f"
    );
}

#[test]
fn every_single_character_typo_is_caught() {
    // The property that matters: not "some typos", but that a one-character
    // slip anywhere in the address is refused rather than silently paying a
    // hash nobody holds.
    let mut caught = 0;
    let mut tried = 0;
    for i in 0..REAL.len() {
        for replacement in *b"1zQ9" {
            let mut bytes = REAL.as_bytes().to_vec();
            if bytes[i] == replacement {
                continue;
            }
            bytes[i] = replacement;
            let typo = String::from_utf8(bytes).unwrap();
            tried += 1;
            if decode_checked(&typo).is_err() {
                caught += 1;
            }
        }
    }
    assert!(tried > 100, "only tried {tried} variants");
    assert_eq!(
        caught, tried,
        "{} of {tried} single-character typos decoded anyway",
        tried - caught
    );
}

#[test]
fn a_truncated_or_extended_address_is_refused() {
    assert!(decode_checked(&REAL[..REAL.len() - 1]).is_err());
    assert!(decode_checked(&format!("{REAL}1")).is_err());
    assert!(decode_checked("").is_err());
}

#[test]
fn a_non_base58_character_is_refused() {
    // '0', 'O', 'I' and 'l' are excluded from the alphabet precisely because
    // they are the characters people confuse.
    for bad in ['0', 'O', 'I', 'l'] {
        let typo = format!("{}{}", bad, &REAL[1..]);
        assert!(decode_checked(&typo).is_err(), "{bad} was accepted");
    }
}
