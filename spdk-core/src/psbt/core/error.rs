//! Error types for BIP-375 operations

use thiserror::Error;

/// Result type alias for BIP-375 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for BIP-375 PSBT operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid PSBT magic bytes")]
    InvalidMagic,

    #[error("Invalid PSBT version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u32, actual: u32 },

    #[error("Invalid field type: {0}")]
    InvalidFieldType(u8),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field data: {0}")]
    InvalidFieldData(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Invalid ECDH share: {0}")]
    InvalidEcdhShare(String),

    #[error("Incomplete ECDH coverage for output {0}")]
    IncompleteEcdhCoverage(usize),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("DLEQ proof verification failed for input {0}")]
    DleqVerificationFailed(usize),

    #[error("Invalid silent payment address: {0}")]
    InvalidAddress(String),

    #[error("Transaction extraction failed: {0}")]
    ExtractionFailed(String),

    #[error("Invalid input index: {0}")]
    InvalidInputIndex(usize),

    #[error("Invalid output index: {0}")]
    InvalidOutputIndex(usize),

    #[error("Invalid public key (must be compressed)")]
    InvalidPublicKey,

    #[error(
        "Cannot add standard field type {0} via generic accessor - use specific method instead"
    )]
    StandardFieldNotAllowed(u8),

    #[error("Bitcoin error: {0}")]
    Bitcoin(#[from] bitcoin::consensus::encode::Error),

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}
