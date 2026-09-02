//! The escrow redeem script from spec section 4.1, and the P2SH address it hashes to.
//!
//! ```text
//! OP_IF
//!     OP_2 <u_pub> <l_pub> OP_2 OP_CHECKMULTISIG
//! OP_ELSE
//!     <T> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!     <u_pub> OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! Zcash script is Bitcoin script circa 2015: P2SH and CLTV are enforced, there is
//! no CSV, no SegWit and no Taproot, and `nLockTime` compares against block height.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Raw opcode bytes. Named rather than spelled inline so the script below reads
/// like section 4.1 of the spec.
mod op {
    pub const IF: u8 = 0x63;
    pub const ELSE: u8 = 0x67;
    pub const ENDIF: u8 = 0x68;
    pub const DROP: u8 = 0x75;
    pub const CHECKSIG: u8 = 0xac;
    pub const CHECKMULTISIG: u8 = 0xae;
    pub const CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const HASH160: u8 = 0xa9;
    pub const EQUAL: u8 = 0x87;
    pub const PUSH_2: u8 = 0x52; // OP_2
    /// The CHECKMULTISIG dummy, and the `false` that selects the ELSE branch.
    pub const PUSH_0: u8 = 0x00;
    /// The `true` that selects the IF branch.
    pub const PUSH_1: u8 = 0x51;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScriptError {
    #[error("public key must be 33 bytes (compressed), got {0}")]
    NotCompressed(usize),
    #[error("refund height {0} is out of the range encodable as a script number")]
    BadHeight(u64),
}

/// A compressed secp256k1 public key as it appears in the script.
pub type CompressedPubkey = [u8; 33];

/// Encodes `n` as a minimally-encoded CScriptNum, which is what
/// CHECKLOCKTIMEVERIFY requires. Zcash heights are positive and fit in 4 bytes
/// for the foreseeable life of the chain, but the high-bit rule still applies:
/// if the top byte has bit 0x80 set, a zero byte is appended so the value is
/// not read as negative.
pub fn encode_script_num(n: u64) -> Result<Vec<u8>, ScriptError> {
    if n == 0 {
        return Ok(vec![]);
    }
    if n > 0x7fff_ffff_ffff_ffff {
        return Err(ScriptError::BadHeight(n));
    }
    let mut out = Vec::new();
    let mut v = n;
    while v > 0 {
        out.push((v & 0xff) as u8);
        v >>= 8;
    }
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(0x00);
    }
    Ok(out)
}

/// Pushes `data` onto the stack using the shortest valid encoding. Anything the
/// escrow pushes is either 33 bytes (a pubkey) or a 3-to-5 byte height, so only
/// the direct-push and PUSHDATA1 forms can arise; the rest is here so a caller
/// that pushes something longer does not silently produce a bad script.
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c); // OP_PUSHDATA1
        out.push(n as u8);
    } else {
        out.push(0x4d); // OP_PUSHDATA2
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Builds the redeem script of spec section 4.1.
///
/// The CHECKMULTISIG order is `u_pub` then `l_pub`, and the signatures in the
/// scriptSig must appear in that same order; CHECKMULTISIG pops signatures in
/// order and will not reorder them for you.
pub fn redeem_script(
    u_pub: &CompressedPubkey,
    l_pub: &CompressedPubkey,
    refund_height: u64,
) -> Result<Vec<u8>, ScriptError> {
    let height = encode_script_num(refund_height)?;
    let mut s = Vec::with_capacity(128);
    s.push(op::IF);
    s.push(op::PUSH_2);
    push_data(&mut s, u_pub);
    push_data(&mut s, l_pub);
    s.push(op::PUSH_2);
    s.push(op::CHECKMULTISIG);
    s.push(op::ELSE);
    push_data(&mut s, &height);
    s.push(op::CHECKLOCKTIMEVERIFY);
    s.push(op::DROP);
    push_data(&mut s, u_pub);
    s.push(op::CHECKSIG);
    s.push(op::ENDIF);
    Ok(s)
}

/// `HASH160(x) = RIPEMD160(SHA256(x))`.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rip);
    out
}

/// The P2SH scriptPubKey committing to `redeem_script`:
/// `OP_HASH160 <hash160(redeemScript)> OP_EQUAL`.
pub fn p2sh_script_pubkey(redeem_script: &[u8]) -> Vec<u8> {
    let h = hash160(redeem_script);
    let mut s = Vec::with_capacity(23);
    s.push(op::HASH160);
    push_data(&mut s, &h);
    s.push(op::EQUAL);
    s
}

/// scriptSig for the release (IF) branch, spec section 4.3:
/// `OP_0 <sig_u> <sig_l> OP_1 <redeemScript>`.
///
/// `OP_0` is the CHECKMULTISIG dummy that the off-by-one bug requires, `OP_1`
/// selects the IF branch, and each signature is DER with the sighash byte
/// already appended.
pub fn release_script_sig(sig_u: &[u8], sig_l: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(256);
    s.push(op::PUSH_0);
    push_data(&mut s, sig_u);
    push_data(&mut s, sig_l);
    s.push(op::PUSH_1);
    push_data(&mut s, redeem_script);
    s
}

/// scriptSig for the refund (ELSE) branch, spec section 4.4:
/// `<sig_u> OP_0 <redeemScript>`.
///
/// The `OP_0` here is the `false` that sends execution to the ELSE branch, not
/// a CHECKMULTISIG dummy.
pub fn refund_script_sig(sig_u: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(128);
    push_data(&mut s, sig_u);
    s.push(op::PUSH_0);
    push_data(&mut s, redeem_script);
    s
}
