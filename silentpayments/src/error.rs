use std::fmt;

#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidLabel(String),
    InvalidCode(String),
    InvalidSharedSecret(String),
    InvalidVin(String),
    InvalidNetwork(String),
    Secp256k1Error(secp256k1::Error),
    OutOfRangeError(secp256k1::scalar::OutOfRangeError),
    IOError(std::io::Error),
    EmptyArray,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::GenericError(msg)
            | Self::InvalidLabel(msg)
            | Self::InvalidCode(msg)
            | Self::InvalidSharedSecret(msg)
            | Self::InvalidVin(msg) => write!(f, "{msg}"),
            Self::InvalidNetwork(msg) => write!(f, "Invalid network: {msg}"),
            Self::Secp256k1Error(e) => e.fmt(f),
            Self::OutOfRangeError(e) => e.fmt(f),
            Self::IOError(e) => e.fmt(f),
            Self::EmptyArray => write!(f, "Non-empty array required"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(any(feature = "sending", feature = "receiving"))]
impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidLabel(e.to_string())
    }
}

#[cfg(feature = "encode")]
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Self::InvalidCode(e.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl From<secp256k1::scalar::OutOfRangeError> for Error {
    fn from(e: secp256k1::scalar::OutOfRangeError) -> Self {
        Self::OutOfRangeError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IOError(e)
    }
}
