//! Prints a transparent P2PKH address for a fixed key, for zebrad's
//! `mining.miner_address` on regtest. The key is in this file on purpose: it
//! holds regtest coin, which is worth nothing anywhere.
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

fn main() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x5e; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let h: [u8; 20] = Ripemd160::digest(Sha256::digest(pk)).into();

    // Testnet/regtest P2PKH prefix is 0x1d25 ("tm").
    let mut payload = vec![0x1d, 0x25];
    payload.extend_from_slice(&h);
    let ck = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&ck[..4]);

    const A: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for b in &payload {
        let mut carry = *b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = payload.iter().take_while(|b| **b == 0).count();
    let mut out = "1".repeat(zeros);
    for d in digits.iter().rev() {
        out.push(A[*d as usize] as char);
    }
    println!("miner_key   : {}", hex::encode(sk.secret_bytes()));
    println!("miner_pubkey: {}", hex::encode(pk));
    println!("hash160     : {}", hex::encode(h));
    println!("miner_addr  : {out}");
}
