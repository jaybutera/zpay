//! The automated taker: filling a zpay offramp without a human in the loop.
//!
//! `agent.rs` is the general-market taker. This module is the narrower thing
//! that actually unlocks small orders: a daemon that fills **zpay's own** orders
//! and nobody else's, so per-fill attention drops to roughly zero.
//!
//! The design, the fork it answers, and the phased plan are in
//! `docs/status/auto-taker-daemon-design.md`. In short: build the self-service
//! version first, where the zpay user fills their own offramp and no capital is
//! fronted for a stranger. The 2026-09-01 mainnet fill was exactly that, done by
//! hand, and it is the sequence [`pipeline`] transcribes.
//!
//! - [`money`]: the intent's units and rate to the dollars Venmo is told to
//!   send, ceiled to cents in the taker's favour and capped.
//! - [`gating`]: the curator's `/v3/sign` signature and the mandatory 95 bps
//!   referral fee, neither of which can be derived locally.
//! - [`journal`]: durable state across the one window where a crash costs money.
//! - [`cookie`]: the stored Venmo session, and the check that runs before
//!   anything is spent.
//! - [`pipeline`]: the state machine, and the gates phase 1 leaves closed.

pub mod cookie;
pub mod gating;
pub mod journal;
pub mod money;
pub mod pipeline;
