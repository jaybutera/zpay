//! Error types for the coordinator

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Session already exists")]
    SessionExists,

    #[error("Invalid session state: {0}")]
    InvalidState(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Chain error: {0}")]
    Chain(String),

    #[error("NEAR Intents error: {0}")]
    NearIntents(String),

    /// The amount is under 1Click's bridge floor, and this is the floor.
    ///
    /// Separate from `NearIntents` because it is the sender's fault and the
    /// sender can fix it. Flattening it into the category error printed
    /// "NEAR Intents error" for every amount below about a dollar and threw
    /// away the only number that would have told them what to type (U1-3).
    #[error("that is below the smallest swap this route can make right now: send at least {zatoshi} zatoshi")]
    BelowFloor {
        zatoshi: u64,
        /// The smallest dollar amount that quotes, when the caller asked in
        /// dollars and the rate was known at the point of the refusal.
        ///
        /// U2-3. The page used to convert the zatoshi floor itself, at the net
        /// rate from the last quote it had seen, while the coordinator sizes a
        /// dollar amount from a gross probe. The two disagreed by the fee and
        /// the rounding, and they disagreed in the wrong direction: the page
        /// suggested $1.08 on a day when $1.09 was the first amount that
        /// quoted, so a sender who did what they were told was refused again
        /// with the same number. Whoever owns the conversion has to own both
        /// halves of it, so the coordinator now names the dollar amount.
        cents: Option<u64>,
    },

    #[error("zk-p2p curator error: {0}")]
    Zkp2p(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),

    /// The caller is asking faster than this endpoint serves.
    #[error("too many requests; try again in {retry_after_seconds}s")]
    TooManyRequests { retry_after_seconds: u64 },
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::SessionNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::SessionExists => (StatusCode::CONFLICT, self.to_string()),
            AppError::InvalidState(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()),
            // The full text carries RPC endpoints, revert data and sometimes the
            // sender address. Log it, return the category.
            AppError::Chain(_) => (StatusCode::BAD_GATEWAY, "Chain error".to_string()),
            AppError::NearIntents(_) => (StatusCode::BAD_GATEWAY, "NEAR Intents error".to_string()),
            // The whole message, floor included: it is not sensitive and it is
            // the only thing that lets the page say what to type instead.
            AppError::BelowFloor { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Zkp2p(_) => (StatusCode::BAD_GATEWAY, "zk-p2p curator error".to_string()),
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
            AppError::TooManyRequests { .. } => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
        };

        // Log errors with appropriate level
        match &self {
            AppError::SessionNotFound
            | AppError::InvalidState(_)
            | AppError::InvalidRequest(_)
            | AppError::BelowFloor { .. }
            | AppError::TooManyRequests { .. }
            | AppError::Unauthorized(_) => {
                warn!(error = %self, status = %status, "Client error")
            }
            _ => {
                warn!(error = %self, status = %status, "Server error")
            }
        }

        let mut body = serde_json::json!({
            "error": message
        });
        // The page prices in ZEC and in dollars, and needs the floor as a
        // number to convert and to prefill. Prose is for the human; this is for
        // the code.
        if let AppError::BelowFloor { zatoshi, cents } = &self {
            body["min_zatoshi"] = serde_json::json!(zatoshi);
            // Only present when the caller asked in dollars: it is the first
            // amount that will actually quote, not a conversion of the floor,
            // so the page can suggest it and have it work (U2-3).
            if let Some(c) = cents {
                body["min_cents"] = serde_json::json!(c);
            }
        }

        if let AppError::TooManyRequests {
            retry_after_seconds,
        } = &self
        {
            return (
                status,
                [(
                    axum::http::header::RETRY_AFTER,
                    retry_after_seconds.to_string(),
                )],
                axum::Json(body),
            )
                .into_response();
        }

        (status, axum::Json(body)).into_response()
    }
}

impl AppError {
    /// Turn a 1Click quote failure into the right kind of error.
    ///
    /// A below-the-floor rejection is the sender's to fix and keeps its number;
    /// everything else is the opaque upstream category, because the raw text
    /// carries endpoints and request shapes.
    pub fn from_quote_error(err: anyhow::Error) -> Self {
        match err.downcast_ref::<crate::near::BelowFloor>() {
            Some(below) => AppError::BelowFloor {
                zatoshi: below.zatoshi,
                cents: None,
            },
            None => AppError::NearIntents(err.to_string()),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}
