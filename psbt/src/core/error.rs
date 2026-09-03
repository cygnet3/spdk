//! Error types for BIP-375 operations

use std::fmt;

use bitcoin::consensus::encode::FromHexError;

/// Result type alias for BIP-375 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for BIP-375 PSBT operations
#[derive(Debug)]
pub enum Error {
    InvalidMagic,

    InvalidVersion { expected: u32, actual: u32 },

    InvalidFieldType(u8),

    MissingField(String),

    InvalidFieldData(String),

    Serialization(String),

    Deserialization(String),

    InvalidEcdhShare(String),

    IncompleteEcdhCoverage(usize),

    InvalidSignature(String),

    DleqVerificationFailed(usize),

    InvalidAddress(String),

    ExtractionFailed(String),

    InvalidInputIndex(usize),

    InvalidOutputIndex(usize),

    InvalidPublicKey,

    InvalidPsbtState(String),

    StandardFieldNotAllowed(u8),

    Bitcoin(bitcoin::consensus::encode::Error),

    Secp256k1(secp256k1::Error),

    Hex(FromHexError),

    Io(std::io::Error),

    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid PSBT magic bytes"),
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "Invalid PSBT version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidFieldType(field_type) => write!(f, "Invalid field type: {field_type}"),
            Self::MissingField(field) => write!(f, "Missing required field: {field}"),
            Self::InvalidFieldData(data) => write!(f, "Invalid field data: {data}"),
            Self::Serialization(err) => write!(f, "Serialization error: {err}"),
            Self::Deserialization(err) => write!(f, "Deserialization error: {err}"),
            Self::InvalidEcdhShare(err) => write!(f, "Invalid ECDH share: {err}"),
            Self::IncompleteEcdhCoverage(output_index) => {
                write!(f, "Incomplete ECDH coverage for output {output_index}")
            }
            Self::InvalidSignature(err) => write!(f, "Invalid signature: {err}"),
            Self::DleqVerificationFailed(input_index) => {
                write!(f, "DLEQ proof verification failed for input {input_index}")
            }
            Self::InvalidAddress(err) => write!(f, "Invalid silent payment address: {err}"),
            Self::ExtractionFailed(err) => write!(f, "Transaction extraction failed: {err}"),
            Self::InvalidInputIndex(index) => write!(f, "Invalid input index: {index}"),
            Self::InvalidOutputIndex(index) => write!(f, "Invalid output index: {index}"),
            Self::InvalidPublicKey => write!(f, "Invalid public key (must be compressed)"),
            Self::InvalidPsbtState(err) => write!(f, "Invalid PSBT state: {err}"),
            Self::StandardFieldNotAllowed(field_type) => write!(
                f,
                "Cannot add standard field type {field_type} via generic accessor - use specific method instead"
            ),
            Self::Bitcoin(err) => write!(f, "Bitcoin error: {err}"),
            Self::Secp256k1(err) => write!(f, "Secp256k1 error: {err}"),
            Self::Hex(err) => write!(f, "Hex decoding error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Other(err) => write!(f, "Other error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(value: bitcoin::consensus::encode::Error) -> Self {
        Self::Bitcoin(value)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(value: secp256k1::Error) -> Self {
        Self::Secp256k1(value)
    }
}

impl From<FromHexError> for Error {
    fn from(value: FromHexError) -> Self {
        Self::Hex(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<psbt_v2::v2::DetermineLockTimeError> for Error {
    fn from(value: psbt_v2::v2::DetermineLockTimeError) -> Self {
        Self::InvalidPsbtState(value.to_string())
    }
}
