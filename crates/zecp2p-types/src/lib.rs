//! Shared types and ABIs for zecp2p offramp
//!
//! This crate contains:
//! - Offramp session types and state machine
//! - Contract ABIs (GlueContract, zk-p2p Escrow/Orchestrator)
//! - Configuration types
//! - API request/response types

pub mod abi;
pub mod config;
pub mod offramp;
pub mod pricing;

pub use config::Config;
pub use offramp::{OfframpRequest, OfframpResponse, OfframpSession, OfframpStatus, QuoteResponse};
