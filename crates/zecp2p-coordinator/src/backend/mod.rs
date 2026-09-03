//! The settlement backends, behind one interface.
//!
//! Exactly two implementations, and the trait exists for those two: nothing in
//! it is shaped for a backend that has not been designed. Where the two
//! differ, the variance is carried as data in `client_steps` and `ReturnState`
//! rather than as methods only one of them would answer.
//!
//! Both routes call the same backend with the same `OpenRequest`. The advanced
//! route fills `overrides` and supplies its own `session_pubkey`; the main
//! route leaves both at their defaults. An order opened on either route
//! produces the same on-chain artefacts for the same inputs, because there is
//! only one path that produces them.

pub mod oneclick;
pub mod session_key;

use async_trait::async_trait;
use zecp2p_types::settlement::{
    Amount, BackendId, Capabilities, ClaimAuthorization, OpenRequest, Opened, PayoutDestination,
    Quote, Receipt, ReturnState, Timeline,
};

use crate::error::AppError;

/// What a caller wants priced.
#[derive(Debug, Clone)]
pub struct QuoteRequest {
    pub amount: Amount,
    pub destination_rail: zecp2p_types::settlement::Rail,
    /// The advanced route's spread override, 18 decimals. `None` takes the
    /// product's default, which is the whole point of the main route.
    pub min_rate: Option<alloy::primitives::U256>,
}

/// One settlement route.
#[async_trait]
pub trait SettlementBackend: Send + Sync {
    fn id(&self) -> BackendId;

    /// Rails, amount bounds, quote lifetime and expected time. The front end
    /// reads these to refuse an impossible order before spending a round trip.
    fn capabilities(&self) -> Capabilities;

    /// Price an amount. The returned quote is net and carries the zpay fee as
    /// one labelled line.
    async fn quote(&self, req: &QuoteRequest) -> Result<Quote, AppError>;

    /// Open an order against a quote. Nothing is spent on-chain here: on
    /// backend A the on-chain session waits for the ZEC, so an order nobody
    /// funds costs the keeper no gas.
    async fn open(&self, req: &OpenRequest, dest: &PayoutDestination) -> Result<Opened, AppError>;

    /// The progress view, mapped onto the canonical stages.
    async fn status(&self, id: uuid::Uuid) -> Result<Timeline, AppError>;

    /// What, if anything, is coming back.
    async fn returns(&self, id: uuid::Uuid) -> Result<ReturnState, AppError>;

    /// Act on a return with the sender's own signature over it.
    async fn claim_return(
        &self,
        id: uuid::Uuid,
        auth: ClaimAuthorization,
    ) -> Result<Receipt, AppError>;
}
