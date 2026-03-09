//! # Silent Payment Output Script Descriptors (BIP-392)
//!
//! This module implements `sp()` output script descriptors for silent payments
//! as defined in BIP-392. Unlike other descriptors, `sp()` is a standalone type
//! that does not participate in the [`super::Descriptor`] enum, because silent
//! payment descriptors cannot produce a `script_pubkey` or `address` without
//! external context (the sender's input public keys, as defined in BIP-352).
//!
//! # Forms
//!
//! The `sp()` descriptor has two forms:
//!
//! - **Single-argument**: `sp(KEY)` where KEY is an `spscan` or `spspend` encoded key
//! - **Two-argument**: `sp(KEY, KEY)` where the first key is a private scan key
//!   and the second is a spend key (public or private)
//!
//! # Examples
//!
//! ```text
//! sp(spscan1q...)          // Watch-only using spscan encoding
//! sp(spspend1q...)         // Full wallet using spspend encoding
//! sp(L4rK...,0260b2...)    // WIF scan key with compressed public spend key
//! sp([deadbeef/352h/0h/0h]xprv.../0h,xpub.../0h) // Extended keys with origin
//! ```

use core::fmt;
use core::str::FromStr;

pub use miniscript::descriptor::{checksum, DescriptorPublicKey, DescriptorSecretKey, SinglePubKey};
pub use miniscript::expression::{self, FromTree};
pub use miniscript::Error;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use spdk_core::keys::SpendKey;

mod keys;

pub use self::keys::{SpKey, SpScanKey, SpSpendKey};

/// A silent payment descriptor.
///
/// This is a standalone descriptor type (not part of [`super::Descriptor`])
/// because silent payment outputs cannot be computed without sender context.
///
/// It holds the key material needed by a wallet to scan for and/or spend
/// silent payment outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp {
    /// The key material for this silent payment descriptor.
    inner: SpInner,
}

/// The inner representation of an `sp()` descriptor's key material.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpInner {
    /// Single-argument form: an `spscan` or `spspend` encoded key.
    Encoded(SpKey),
    /// Two-argument form: a private scan key and a spend key expression.
    TwoKey {
        /// The scan key (must be private: WIF or xprv).
        scan: DescriptorSecretKey,
        /// The spend key (any BIP-380 key expression, public or private).
        /// We store it as a string representation for now since it can be
        /// either public or private and we don't want to force a choice.
        spend: DescriptorSpendKey,
    },
}

/// The spend key in the two-argument form.
///
/// Can be either a public or private key expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorSpendKey {
    /// A public key expression (compressed pubkey, xpub, etc.)
    Public(DescriptorPublicKey),
    /// A private key expression (WIF, xprv, etc.)
    Private(DescriptorSecretKey),
}

impl Sp {
    /// Creates a new `Sp` descriptor from an encoded `spscan` or `spspend` key.
    pub fn from_sp_key(key: SpKey) -> Self {
        Sp { inner: SpInner::Encoded(key) }
    }

    /// Creates a new `Sp` descriptor from a private scan key and a public spend key.
    pub fn from_keys(scan: DescriptorSecretKey, spend: DescriptorSpendKey) -> Result<Self, Error> {
        // Validate: scan key must not be uncompressed
        if let DescriptorSecretKey::Single(sk) = &scan {
            if !sk.key.compressed {
                return Err(Error::Unexpected(
                    "sp() scan key must be compressed".to_string(),
                ));
            }
        }
        // Validate spend key: must not be uncompressed
        match &spend {
            DescriptorSpendKey::Public(pk) => {
                if let DescriptorPublicKey::Single(s) = pk {
                    if let SinglePubKey::FullKey(full) = s.key {
                        if !full.compressed {
                            return Err(Error::Unexpected(
                                "sp() spend key must be compressed".to_string(),
                            ));
                        }
                    }
                }
            }
            DescriptorSpendKey::Private(sk) => {
                if let DescriptorSecretKey::Single(s) = sk {
                    if !s.key.compressed {
                        return Err(Error::Unexpected(
                            "sp() spend key must be compressed".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(Sp {
            inner: SpInner::TwoKey { scan, spend },
        })
    }

    /// Returns `true` if this descriptor contains spend private key material
    /// (i.e., the wallet can both scan and spend).
    pub fn has_spend_key(&self) -> bool {
        match &self.inner {
            SpInner::Encoded(key) => matches!(key, SpKey::Spend(_)),
            SpInner::TwoKey { spend, .. } => matches!(spend, DescriptorSpendKey::Private(_)),
        }
    }

    /// Returns `true` if this is a watch-only descriptor (can scan but not spend).
    pub fn is_watch_only(&self) -> bool {
        !self.has_spend_key()
    }

    /// Returns the scan private key bytes, if available.
    ///
    /// For the encoded form, this extracts from the spscan/spspend payload.
    /// For the two-key form, this extracts from the secret key.
    pub fn scan_key(&self) -> SecretKey {
        match &self.inner {
            SpInner::Encoded(key) => SecretKey::from_slice(key.scan_privkey_bytes()).unwrap(),
            SpInner::TwoKey {scan, ..} => {
                let scan_key = match scan {
                    DescriptorSecretKey::Single(sk) => sk.key,
                    _ => unreachable!()
                };
                SecretKey::from_slice(&scan_key.to_bytes()).unwrap()
            }
        }
    }

    pub fn spend_key(&self) -> SpendKey {
        match &self.inner {
            SpInner::Encoded(key) => match key {
                SpKey::Scan(scan_key) => {
                    SpendKey::Public(PublicKey::from_slice(&scan_key.spend_key).unwrap())
                }
                SpKey::Spend(spend_key) => {
                    SpendKey::Secret(SecretKey::from_slice(&spend_key.spend_key).unwrap())
                }
            },
            SpInner::TwoKey { spend, .. } => match spend {
                DescriptorSpendKey::Public(pk) => {
                    match pk {
                        DescriptorPublicKey::Single(s) => match s.key {
                            SinglePubKey::FullKey(full) => SpendKey::Public(full.inner),
                            SinglePubKey::XOnly(_) => unreachable!("sp() keys are always compressed"),
                        },
                        _ => unreachable!("sp() two-key form only supports single keys"),
                    }
                }
                DescriptorSpendKey::Private(sk) => {
                    match sk {
                        DescriptorSecretKey::Single(s) => {
                            SpendKey::Secret(s.key.inner)
                        }
                        _ => unreachable!("sp() two-key form only supports single keys"),
                    }
                }
            },
        }
    }
}

impl fmt::Display for DescriptorSpendKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DescriptorSpendKey::Public(pk) => fmt::Display::fmt(pk, f),
            DescriptorSpendKey::Private(sk) => fmt::Display::fmt(sk, f),
        }
    }
}

impl fmt::Display for Sp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        let mut wrapped_f = checksum::Formatter::new(f);
        match &self.inner {
            SpInner::Encoded(key) => write!(wrapped_f, "sp({})", key)?,
            SpInner::TwoKey { scan, spend } => {
                write!(wrapped_f, "sp({},{})", scan, spend)?;
            }
        }
        wrapped_f.write_checksum_if_not_alt()
    }
}

impl FromStr for Sp {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expr_tree = expression::Tree::from_str(s)?;
        Self::from_tree(expr_tree.root())
    }
}

impl FromTree for Sp {
    fn from_tree(root: expression::TreeIterItem) -> Result<Self, Error> {
        root.verify_toplevel("sp", 1..=2)
            .map_err(From::from)
            .map_err(Error::Parse)?;

        let mut children = root.children();
        let first = children.next().unwrap();

        match root.n_children() {
            1 => {
                // Single-argument form: must be spscan or spspend encoded key
                let key_str = first.name();
                if first.n_children() > 0 {
                    return Err(Error::Unexpected(
                        "sp() single-argument form expects a terminal key expression".to_string(),
                    ));
                }
                let key = SpKey::from_str(key_str)
                    .map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(Sp::from_sp_key(key))
            }
            2 => {
                // Two-argument form: private scan key, then spend key
                let second = children.next().unwrap();

                if first.n_children() > 0 || second.n_children() > 0 {
                    return Err(Error::Unexpected(
                        "sp() two-argument form expects terminal key expressions".to_string(),
                    ));
                }

                let scan_str = first.name();
                let spend_str = second.name();

                // Parse scan key as a secret key (WIF or xprv)
                let scan = DescriptorSecretKey::from_str(scan_str)
                    .map_err(|e| Error::Unexpected(format!("sp() scan key: {}", e)))?;

                // Try parsing spend key as secret first, then as public
                let spend = match DescriptorSecretKey::from_str(spend_str) {
                    Ok(sk) => DescriptorSpendKey::Private(sk),
                    Err(_) => {
                        let pk = DescriptorPublicKey::from_str(spend_str)
                            .map_err(|e| {
                                Error::Unexpected(format!("sp() spend key: {}", e))
                            })?;
                        DescriptorSpendKey::Public(pk)
                    }
                };

                Sp::from_keys(scan, spend)
            }
            _ => unreachable!("verify_toplevel checked 1..=2"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_key_form() {
        // WIF scan key + compressed public spend key
        let desc_str = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        let sp = Sp::from_str(desc_str).unwrap();
        assert!(sp.is_watch_only());
    }

    #[test]
    fn parse_two_key_form_both_private() {
        // WIF scan key + WIF spend key
        let desc_str = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)";
        let sp = Sp::from_str(desc_str).unwrap();
        assert!(sp.has_spend_key());
    }

    #[test]
    fn reject_uncompressed_scan_key() {
        // 5K... is uncompressed WIF
        let desc_str = "sp(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        assert!(Sp::from_str(desc_str).is_err());
    }

    #[test]
    fn display_roundtrip_two_key() {
        let desc_str = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        let sp = Sp::from_str(desc_str).unwrap();
        let displayed = sp.to_string();
        // Should roundtrip (the checksum will be appended)
        let sp2 = Sp::from_str(&displayed).unwrap();
        assert_eq!(sp, sp2);
    }

    #[test]
    fn reject_public_scan_key() {
        // Two-argument form requires private scan key
        let desc_str = "sp(0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        assert!(Sp::from_str(desc_str).is_err());
    }
}
