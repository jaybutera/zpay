//! Prints the hex of a signed release and refund, so the exact bytes we would
//! broadcast can be handed to a node by other means. Signs with fixed test keys
//! against an outpoint that exists on no chain; it spends nothing.
use secp256k1::{Message, Secp256k1, SecretKey};
use zecp2p_escrow::fees::{refund_fee_to_shielded_zat, release_fee_to_transparent_zat};
use zecp2p_escrow::script::{refund_script_sig, release_script_sig};
use zecp2p_escrow::tx::{
    build_refund, build_release, encode_signature, serialize_refund, serialize_release,
    EscrowTerms,
};

fn p2pkh(h: [u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 20];
    s.extend_from_slice(&h);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn main() {
    let branch: u32 = std::env::args()
        .nth(1)
        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or(0x37a5_165b);
    let secp = Secp256k1::new();
    let u_priv = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let l_priv = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let terms = EscrowTerms {
        funding_txid: [0x11; 32],
        vout: 0,
        amount_zat: 5_000_000,
        u_pub: secp256k1::PublicKey::from_secret_key(&secp, &u_priv).serialize(),
        l_pub: secp256k1::PublicKey::from_secret_key(&secp, &l_priv).serialize(),
        refund_height: 4_320_000,
        consensus_branch_id: branch,
    };
    let redeem = terms.redeem_script().unwrap();
    let fee = release_fee_to_transparent_zat(redeem.len());
    let lp = p2pkh([0x09; 20]);
    let d = build_release(&terms, &lp, fee).unwrap().sighash().unwrap();
    let su = secp.sign_ecdsa(&Message::from_digest(d), &u_priv);
    let sl = secp.sign_ecdsa(&Message::from_digest(d), &l_priv);
    let ss = release_script_sig(&encode_signature(&su), &encode_signature(&sl), &redeem);
    let raw = serialize_release(&terms, &lp, fee, &ss).unwrap();
    println!("RELEASE_LEN {}", raw.len());
    println!("RELEASE {}", hex::encode(&raw));

    let rfee = refund_fee_to_shielded_zat(redeem.len());
    let us = p2pkh([0x0b; 20]);
    let rd = build_refund(&terms, &us, rfee).unwrap().sighash().unwrap();
    let rsu = secp.sign_ecdsa(&Message::from_digest(rd), &u_priv);
    let rss = refund_script_sig(&encode_signature(&rsu), &redeem);
    let rraw = serialize_refund(&terms, &us, rfee, &rss).unwrap();
    println!("REFUND_LEN {}", rraw.len());
    println!("REFUND {}", hex::encode(&rraw));
}
