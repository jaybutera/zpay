//! Verify signatures the page produced against the coordinator's own check.
//!
//! Reads the JSON that `frontend/app/test/session-key-vectors.js` prints and
//! runs each one through `auth::require_owner`, the same function the live
//! endpoint calls. This is the end-to-end check that the page's hand-written
//! secp256k1 and keccak agree with the server, at the one place a disagreement
//! would matter.
use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;
use zecp2p_coordinator::auth;

#[derive(Deserialize)]
struct Vector {
    address: String,
    pubkey: String,
    message: String,
    sig: String,
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: verify_js_sigs <vectors.json>");
    let raw = std::fs::read_to_string(path).expect("read vectors");
    let vectors: Vec<Vector> = serde_json::from_str(&raw).expect("parse vectors");

    let mut failed = 0;
    for v in &vectors {
        let address: alloy::primitives::Address = v.address.parse().expect("address");

        // The scope has to rebuild the exact message the page signed, or this
        // proves nothing about the endpoint.
        let scope = "q1:venmo:jane-doe";
        let rebuilt = auth::ownership_message("open", address, scope);
        if rebuilt != v.message {
            println!("FAIL message mismatch\n  page:   {}\n  server: {rebuilt}", v.message);
            failed += 1;
            continue;
        }

        let mut headers = HeaderMap::new();
        headers.insert(auth::SIGNATURE_HEADER, HeaderValue::from_str(&v.sig).unwrap());

        match auth::require_owner(&headers, "open", address, scope) {
            Ok(()) => println!("PASS {}", v.address),
            Err(e) => {
                println!("FAIL {} -> {e}", v.address);
                failed += 1;
            }
        }

        // And the address the coordinator derives from the page's public key
        // must be the same address, or session.user names the wrong key.
        match zecp2p_coordinator::backend::session_key::identity_from_hex(&v.pubkey) {
            Ok(id) if format!("{:?}", id.evm_address) == v.address => {
                println!("     derived address matches, t-addr {}", id.transparent_address)
            }
            Ok(id) => {
                println!("FAIL derived {:?} but page says {}", id.evm_address, v.address);
                failed += 1;
            }
            Err(e) => {
                println!("FAIL pubkey rejected: {e}");
                failed += 1;
            }
        }
    }

    if failed > 0 {
        eprintln!("\n{failed} checks failed");
        std::process::exit(1);
    }
    println!("\nthe page and the coordinator agree on every vector");
}
