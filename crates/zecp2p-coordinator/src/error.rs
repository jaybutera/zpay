//! Error types for the coordinator

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
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
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
        };

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
