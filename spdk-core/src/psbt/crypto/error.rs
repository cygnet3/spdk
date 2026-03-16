//! Error types for cryptographic operations

use thiserror::Error;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("DLEQ proof generation failed: {0}")]
    DleqGenerationFailed(String),

    #[error("DLEQ proof verification failed")]
    DleqVerificationFailed,

    #[error("Invalid DLEQ proof length: expected 64 bytes, got {0}")]
    InvalidDleqProofLength(usize),

    #[error("Invalid ECDH result")]
    InvalidEcdh,

    #[error("Hash function error: {0}")]
    HashError(String),

    #[error("Other error: {0}")]
    Other(String),
}
