//! Verification of the zk-p2p enclave's `PaymentAttestation`, pinned to the
//! domain and signer that Phase 0 read off two live attestations.
//!
//! This is step 3 of spec section 5.5. The attestor runs it before it will sign
//! an outcome, so everything here decides whether a user's ZEC moves.

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha3::{Digest, Keccak256};

/// The EIP-712 domain the enclave signs against (spec 12.1). Reproduced from
/// the recorded `domainSeparator` on two live attestations.
pub const DOMAIN_NAME: &str = "UnifiedPaymentVerifier";
pub const DOMAIN_VERSION: &str = "1";
pub const DOMAIN_CHAIN_ID: u64 = 8453;
pub const DOMAIN_VERIFYING_CONTRACT: [u8; 20] = [
    0xc6, 0xf4, 0xa1, 0x93, 0x57, 0x6c, 0x60, 0x89, 0x2a, 0x47, 0xe1, 0x11, 0xbb, 0x57, 0x06, 0xc3, 0x01, 0x62, 0x50, 0x2b,
];

/// The enclave signer, spec section 3. A rotation is a config change; the
/// attestor must pin it, because an unpinned signer is no check at all.
pub const ENCLAVE_SIGNER: [u8; 20] = [
    0xe0, 0x78, 0xd9, 0x3b, 0xfd, 0xd8, 0x7a, 0x8c, 0x5c, 0x5c, 0xca, 0x59, 0x05, 0xdc, 0xba, 0x0d, 0xd7, 0xa1, 0xf0, 0xbd,
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("signature is not 65 bytes, got {0}")]
    BadSignatureLength(usize),
    #[error("signature recovery id {0} is not 27 or 28")]
    BadRecoveryId(u8),
    #[error("signature does not recover to a public key")]
    Unrecoverable,
    #[error("attestation was signed by {got}, not the pinned enclave signer {expected}")]
    WrongSigner { got: String, expected: String },
    #[error("attestation is for intent {got}, not the expected {expected}")]
    WrongIntent { got: String, expected: String },
    #[error("releaseAmount {got} is below the required {expected}")]
    InsufficientAmount { got: u128, expected: u128 },
    #[error("dataHash does not equal keccak256(encodedPaymentDetails)")]
    DataHashMismatch,
}

/// The three signed fields of `PaymentAttestation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAttestation {
    pub intent_hash: [u8; 32],
    pub release_amount: u128,
    pub data_hash: [u8; 32],
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
/// applied to the pinned domain.
pub fn domain_separator() -> [u8; 32] {
    let type_hash = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&type_hash);
    buf.extend_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u256_be(DOMAIN_CHAIN_ID as u128));
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(&DOMAIN_VERIFYING_CONTRACT);
    buf.extend_from_slice(&addr_word);
    keccak(&buf)
}

/// `keccak256("PaymentAttestation(bytes32 intentHash,uint256 releaseAmount,bytes32 dataHash)")`.
pub fn type_hash() -> [u8; 32] {
    keccak(b"PaymentAttestation(bytes32 intentHash,uint256 releaseAmount,bytes32 dataHash)")
}

fn u256_be(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// The EIP-712 struct hash of the attestation.
pub fn struct_hash(a: &PaymentAttestation) -> [u8; 32] {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&type_hash());
    buf.extend_from_slice(&a.intent_hash);
    buf.extend_from_slice(&u256_be(a.release_amount));
    buf.extend_from_slice(&a.data_hash);
    keccak(&buf)
}

/// The EIP-712 digest: `keccak256(0x1901 || domainSeparator || structHash)`.
pub fn eip712_digest(a: &PaymentAttestation) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator());
    buf.extend_from_slice(&struct_hash(a));
    keccak(&buf)
}

/// Recovers the signing address from a 65-byte `r || s || v` signature.
pub fn recover_signer(
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<[u8; 20], AttestationError> {
    if signature.len() != 65 {
        return Err(AttestationError::BadSignatureLength(signature.len()));
    }
    // Ethereum's `v` is 27 or 28; secp256k1 wants 0 or 1.
    let v = match signature[64] {
        27 | 28 => signature[64] - 27,
        0 | 1 => signature[64],
        other => return Err(AttestationError::BadRecoveryId(other)),
    };
    let rec_id = RecoveryId::try_from(v as i32).map_err(|_| AttestationError::Unrecoverable)?;
    let sig = RecoverableSignature::from_compact(&signature[..64], rec_id)
        .map_err(|_| AttestationError::Unrecoverable)?;
    let msg = Message::from_digest(*digest);
    let pubkey = Secp256k1::new()
        .recover_ecdsa(&msg, &sig)
        .map_err(|_| AttestationError::Unrecoverable)?;

    // An Ethereum address is the last 20 bytes of keccak256 of the uncompressed
    // key without its 0x04 prefix.
    let uncompressed = pubkey.serialize_uncompressed();
    let h = keccak(&uncompressed[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    Ok(addr)
}

/// Full verification, spec 5.5 steps 2 to 4, against the pinned enclave signer.
///
/// `encoded_payment_details` is the preimage the signature actually commits to
/// through `dataHash`; checking it here means a caller cannot pass a
/// `typedDataValue` that disagrees with the signed payment.
pub fn verify(
    a: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    expected_intent_hash: &[u8; 32],
    minimum_release_amount: u128,
) -> Result<(), AttestationError> {
    verify_against_signer(
        a,
        signature,
        encoded_payment_details,
        expected_intent_hash,
        minimum_release_amount,
        &ENCLAVE_SIGNER,
    )
}

/// As [`verify`], but against a caller-supplied trusted signer.
///
/// Spec section 8 lists enclave signer rotation as a config change rather than
/// a protocol change, so the signer is a parameter here and pinned by the
/// caller. Production callers use [`verify`]; tests use this to construct
/// attestations bound to terms they control, which the real enclave key
/// obviously cannot be made to sign.
pub fn verify_against_signer(
    a: &PaymentAttestation,
    signature: &[u8],
    encoded_payment_details: &[u8],
    expected_intent_hash: &[u8; 32],
    minimum_release_amount: u128,
    trusted_signer: &[u8; 20],
) -> Result<(), AttestationError> {
    if keccak(encoded_payment_details) != a.data_hash {
        return Err(AttestationError::DataHashMismatch);
    }
    if &a.intent_hash != expected_intent_hash {
        return Err(AttestationError::WrongIntent {
            got: hex::encode(a.intent_hash),
            expected: hex::encode(expected_intent_hash),
        });
    }
    if a.release_amount < minimum_release_amount {
        return Err(AttestationError::InsufficientAmount {
            got: a.release_amount,
            expected: minimum_release_amount,
        });
    }
    let signer = recover_signer(&eip712_digest(a), signature)?;
    if &signer != trusted_signer {
        return Err(AttestationError::WrongSigner {
            got: hex::encode(signer),
            expected: hex::encode(trusted_signer),
        });
    }
    Ok(())
}
