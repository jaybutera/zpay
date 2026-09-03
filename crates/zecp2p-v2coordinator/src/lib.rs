//! The coordinator for the native Zcash escrow: the LP's side of the v2
//! offramp, behind the six `/escrow/*` endpoints the page expects.
//!
//! # What this crate decides, and what it only carries
//!
//! Almost nothing here decides anything about money. The judgement that makes
//! the escrow safe is in `zecp2p-escrow` and is called rather than restated:
//! `lp::evaluate` decides whether the LP may pay, `dlc::verify_pre_signature`
//! decides whether the release will work, `tx::ReleaseSplit` decides what it
//! pays, and `treasury` decides the fee. The taker's `auto::fiat` sends the
//! dollars and `auto::money::payment_cents` sizes them.
//!
//! What this crate owns is the part that did not exist: the HTTP surface, the
//! order's stages and their persistence, and finding the funding output at an
//! address nobody told us the txid of.
//!
//! # The shape of the safety argument
//!
//! Three things must be true before a dollar leaves, and each is checked by
//! code that already existed:
//!
//! 1. The escrow is on chain, pays the agreed script, holds the agreed amount,
//!    and is confirmed to the depth its size requires. `lp::evaluate`.
//! 2. The user's pre-signature verifies against `u_pub` and the outcome point.
//!    `dlc::verify_pre_signature`, over a digest built from this order's own
//!    split rather than from anything the request carried.
//! 3. The chain is still on the branch the pre-signature was made for, and the
//!    pay deadline has not passed. `lp::check_branch` and `lp::may_pay_before`,
//!    re-read immediately before the browser opens.
//!
//! Everything else in this crate exists to get to those three checks with the
//! right arguments, and to record enough that a crash between them is
//! recoverable.

pub mod config;
pub mod driver;
pub mod funding;
pub mod order;
pub mod quote;
#[cfg(feature = "test-rails")]
pub mod simulated_rail;
pub mod state;
pub mod store;
pub mod view;
pub mod web;

/// A short, unguessable identifier.
///
/// Order ids are bearer-ish: knowing one lets you read that order's status.
/// They are not secrets - the user's key is the thing that matters and it never
/// leaves the browser - but they should not be enumerable either.
pub fn new_id(prefix: &str) -> String {
    use rand::Rng;
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}
