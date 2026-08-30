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

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Chain error: {0}")]
    Chain(String),

    #[error("NEAR Intents error: {0}")]
    NearIntents(String),

    #[error("zk-p2p curator error: {0}")]
    Zkp2p(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::SessionNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::SessionExists => (StatusCode::CONFLICT, self.to_string()),
            AppError::InvalidState(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()),
            AppError::Chain(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::NearIntents(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Zkp2p(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
        };

        // Log errors with appropriate level
        match &self {
            AppError::SessionNotFound | AppError::InvalidState(_) => {
                warn!(error = %self, status = %status, "Client error")
            }
            _ => {
                warn!(error = %self, status = %status, "Server error")
            }
        }

        let body = serde_json::json!({
            "error": message
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}
