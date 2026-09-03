//! Build a genuine ZIP 316 unified address (Orchard + transparent, the shape
//! Zashi hands out) so a 1Click recipient probe tests the format rather than a
//! hand-rolled checksum, and show that the transparent receiver can be pulled
//! back out, which is what the failure screen needs.
use zcash_address::unified::{self, Container, Encoding};

fn main() {
    let orchard = unified::Receiver::Orchard([3u8; 43]);
    let p2pkh = unified::Receiver::P2pkh([7u8; 20]);
    let ua = unified::Address::try_from_items(vec![orchard, p2pkh]).unwrap();
    let encoded = ua.encode(&zcash_protocol::consensus::NetworkType::Main);
    println!("ua_orchard_plus_transparent={encoded}");

    let (net, parsed) = unified::Address::decode(&encoded).unwrap();
    println!("network={net:?}");
    for item in parsed.items() {
        match item {
            unified::Receiver::P2pkh(h) => println!("transparent_p2pkh_hash={}", hex::encode(h)),
            other => println!("other_receiver={:?}", std::mem::discriminant(&other)),
        }
    }

    // A shielded-only UA: Orchard alone is legal, and is the case that has no
    // transparent receiver for 1Click to pay.
    let shielded_only =
        unified::Address::try_from_items(vec![unified::Receiver::Orchard([3u8; 43])]).unwrap();
    println!(
        "ua_shielded_only={}",
        shielded_only.encode(&zcash_protocol::consensus::NetworkType::Main)
    );
}
