//! Taker agent for zecp2p.
//!
//! The other side of the offramp. An offramp puts USDC into a zk-p2p deposit
//! that any staked taker may claim; this crate is a daemon that finds those
//! deposits, claims one, sends the Venmo payment through a browser the operator
//! has already logged in, and takes the fulfilment as far as it can go.
//!
//! Two things are worth knowing before running it:
//!
//! - Claiming locks stake. OrchestratorV3's lifecycle hook requires free USDC
//!   stake equal to the intent amount, so a taker needs capital beyond the
//!   payment itself. See `docs/taker-matching-design.md`.
//! - Fulfilment is not fully automatable. Releasing the escrowed USDC needs a
//!   witness signature that only zk-p2p's PeerAuth extension can obtain. The
//!   agent stops there and says exactly what to do; see [`proof`].

pub mod abi;
pub mod agent;
pub mod claim;
pub mod config;
pub mod discovery;
pub mod proof;
pub mod venmo;

pub use agent::TakerAgent;
pub use config::TakerConfig;
pub use venmo::SendMode;
