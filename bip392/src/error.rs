//! Errors for parsing and materializing `sp()` descriptors.

use core::fmt;

use miniscript::bitcoin::bip32;

use crate::keys::SpKeyError;

/// A descriptor key expression cannot be used as silent-payment key material.
///
/// These are the failures of turning a [`DescriptorSecretKey`] into a scalar,
/// and the same failures on a public spend key.
///
/// [`DescriptorSecretKey`]: miniscript::DescriptorSecretKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The key is a BIP-389 multipath expression.
    Multipath,
    /// The derivation path contains a wildcard (`/*` or `/*h`).
    Wildcard,
    /// A single key is uncompressed.
    Uncompressed,
    /// BIP-32 child derivation failed.
    Derivation(bip32::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Multipath => f.write_str("must not be multipath"),
            Self::Wildcard => f.write_str("must not contain a wildcard"),
            Self::Uncompressed => f.write_str("must be compressed"),
            Self::Derivation(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Derivation(err) => Some(err),
            Self::Multipath | Self::Wildcard | Self::Uncompressed => None,
        }
    }
}

/// An error parsing or constructing an [`Sp`] descriptor.
///
/// [`Sp`]: crate::Sp
#[derive(Debug)]
pub enum Error {
    /// The scan key cannot be materialized.
    Scan(KeyError),
    /// The spend key cannot be materialized.
    Spend(KeyError),
    /// The descriptor string is not a valid expression.
    Parse(miniscript::Error),
    /// An `spscan` or `spspend` encoding is invalid.
    SpKey(SpKeyError),
    /// A constraint that is not one of the key-material failures above.
    Unexpected(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Scan(err) => write!(f, "sp() scan key: {err}"),
            Self::Spend(err) => write!(f, "sp() spend key: {err}"),
            Self::Parse(err) => fmt::Display::fmt(err, f),
            Self::SpKey(err) => fmt::Display::fmt(err, f),
            Self::Unexpected(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(err) | Self::Spend(err) => Some(err),
            Self::Parse(err) => Some(err),
            Self::SpKey(err) => Some(err),
            Self::Unexpected(_) => None,
        }
    }
}

impl From<miniscript::Error> for Error {
    fn from(err: miniscript::Error) -> Self {
        Self::Parse(err)
    }
}
