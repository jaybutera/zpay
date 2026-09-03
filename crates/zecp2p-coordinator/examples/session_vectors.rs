//! Cross-check vectors for the page's in-browser session key.
//!
//! The page derives the EVM address and signs the open message itself, in
//! hand-written secp256k1 and keccak. If its derivation disagrees with this
//! one by a single bit, `session.user` names a key nobody holds and every
//! return on that order is unclaimable. So the two are compared on fixed keys
//! rather than trusted to agree.
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn main() {
    let seventh = "7f".repeat(32);
    for secret in ["01", "02", "f00d", seventh.as_str()] {
        let padded = format!("{:0>64}", secret);
        let bytes = hex::decode(&padded).unwrap();
        let signer = PrivateKeySigner::from_slice(&bytes).unwrap();

        let point = signer.credential().verifying_key().as_affine().to_encoded_point(true);
        let message = format!("zecp2p:open:{:?}:q1:venmo:jane-doe", signer.address());
        let sig = signer.sign_message_sync(message.as_bytes()).unwrap();

        println!(
            "{{\"secret\":\"{padded}\",\"pubkey\":\"{}\",\"address\":\"{:?}\",\"message\":\"{message}\",\"sig\":\"{}\"}}",
            hex::encode(point.as_bytes()),
            signer.address(),
            sig,
        );
    }
}
