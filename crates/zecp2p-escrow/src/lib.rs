//! Zcash-native two-party escrow: 2-of-2 plus CLTV, released by an
//! adaptor signature the attestor completes.
//!
//! See `specs/zec-native-escrow.md`. This crate holds the parts that must be
//! byte-identical between the user client and the LP daemon: the redeem script,
//! the P2SH address, and the transaction builders whose ZIP 244 digest both
//! sides sign.

pub mod attestation;
pub mod fees;
pub mod script;
