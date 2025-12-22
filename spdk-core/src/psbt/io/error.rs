//! Error types for I/O operations

use thiserror::Error;

/// Result type for I/O operations
pub type Result<T> = std::result::Result<T, IoError>;

/// I/O error types
#[derive(Debug, Error)]
pub enum IoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("PSBT error: {0}")]
    Psbt(#[from] crate::psbt::core::error::Error),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("File not found: {0}")]
    NotFound(String),

    #[error("Other error: {0}")]
    Other(String),
}
