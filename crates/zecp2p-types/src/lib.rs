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
pub mod settlement;
pub mod zip321;

pub use config::Config;
pub use settlement::{
    Amount, BackendId, Capabilities, ClaimAuthorization, ClientStep, DepositInstruction,
    DepositKind, FeeLine, Opened, OpenRequest, OrderView, Overrides, PayoutDestination, Quote,
    Rail, Receipt, ReturnState, Stage, Timeline, TimelineEntry,
};
pub use offramp::{OfframpRequest, OfframpResponse, OfframpSession, OfframpStatus, QuoteResponse};
