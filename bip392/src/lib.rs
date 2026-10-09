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
//! sp([deadbeef/352h/0h/0h]xprv.../0h,xpub.../0) // Extended keys with origin
//! ```

use core::fmt;
use core::str::FromStr;

pub use miniscript::Error;
use miniscript::bitcoin::bip32::{self, ChildNumber, DerivationPath, Fingerprint};
use miniscript::descriptor::Wildcard;
pub use miniscript::descriptor::{
    DescriptorPublicKey, DescriptorSecretKey, SinglePubKey, checksum,
};
pub use miniscript::expression::{self, FromTree};
use secp256k1::{PublicKey, SecretKey};
use silentpayments::Network as SpNetwork;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct TwoKey {
    scan: DescriptorSecretKey,
    spend: DescriptorSpendKey,
    scan_secret: SecretKey,
    spend_secret: Option<SecretKey>,
    spend_pubkey: PublicKey,
}

/// The inner representation of an `sp()` descriptor's key material.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpInner {
    /// Single-argument form: an `spscan` or `spspend` encoded key.
    ///
    /// `origin`, when present, is the master fingerprint and the path to the
    /// parent from which BIP-352 derives the scan key (`1h/0`) and the spend
    /// key (`0h/0`).
    Encoded {
        /// Optional key origin (`[fingerprint/path]`).
        origin: Option<bip32::KeySource>,
        /// The encoded silent payment key.
        key: SpKey,
    },
    /// Two-argument form: a private scan key and a spend key expression.
    TwoKey(TwoKey),
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
    fn from_encoded(origin: Option<bip32::KeySource>, key: SpKey) -> Self {
        Sp {
            inner: SpInner::Encoded { origin, key },
        }
    }

    /// Creates a new `Sp` descriptor from an encoded `spscan` or `spspend` key.
    pub fn from_sp_key(key: SpKey) -> Self {
        Self::from_encoded(None, key)
    }

    /// Creates a new `Sp` descriptor from a private scan key and a spend key.
    pub fn from_keys(scan: DescriptorSecretKey, spend: DescriptorSpendKey) -> Result<Self, Error> {
        Ok(Sp {
            inner: SpInner::TwoKey(TwoKey::new(scan, spend)?),
        })
    }

    /// Returns `true` if this descriptor contains spend private key material
    /// (i.e., the wallet can both scan and spend).
    pub fn has_spend_key(&self) -> bool {
        match &self.inner {
            SpInner::Encoded { key, .. } => matches!(key, SpKey::Spend(_)),
            SpInner::TwoKey(keys) => keys.spend_secret().is_some(),
        }
    }

    /// Returns `true` if this is a watch-only descriptor (can scan but not spend).
    pub fn is_watch_only(&self) -> bool {
        !self.has_spend_key()
    }

    /// Returns `true` if this descriptor is for mainnet.
    ///
    /// For the encoded form, this uses the `spscan`/`spspend` HRP.
    /// For the two-key form, this uses the scan key's network (WIF or xprv).
    pub fn is_mainnet(&self) -> bool {
        match &self.inner {
            SpInner::Encoded { key, .. } => key.network() == SpNetwork::Mainnet,
            SpInner::TwoKey(keys) => match keys.scan() {
                DescriptorSecretKey::Single(sk) => sk.key.network.is_mainnet(),
                DescriptorSecretKey::XPrv(xprv) => xprv.xkey.network.is_mainnet(),
                DescriptorSecretKey::MultiXPrv(_) => {
                    unreachable!("sp() does not support multipath keys")
                }
            },
        }
    }

    /// Returns the scan private key bytes, if available.
    ///
    /// For the encoded form, this extracts from the spscan/spspend payload.
    /// For the two-key form, this extracts from the secret key.
    pub fn scan_key(&self) -> SecretKey {
        match &self.inner {
            SpInner::Encoded { key, .. } => key.scan_privkey(),
            SpInner::TwoKey(keys) => keys.scan_secret(),
        }
    }

    /// Spend private key, when this descriptor can spend.
    pub fn spend_secret(&self) -> Option<SecretKey> {
        match &self.inner {
            SpInner::Encoded { key, .. } => match key {
                SpKey::Scan(_) => None,
                SpKey::Spend(spend_key) => Some(spend_key.spend_key),
            },
            SpInner::TwoKey(keys) => keys.spend_secret(),
        }
    }

    /// Spend public key. Derived from [`Self::spend_secret`] when the descriptor can spend.
    pub fn spend_pubkey(&self) -> PublicKey {
        match &self.inner {
            SpInner::Encoded { key, .. } => match key {
                SpKey::Scan(scan_key) => scan_key.spend_key,
                SpKey::Spend(spend_key) => spend_key
                    .spend_key
                    .public_key(&secp256k1::Secp256k1::signing_only()),
            },
            SpInner::TwoKey(keys) => keys.spend_pubkey(),
        }
    }
}

impl TwoKey {
    /// Rejects keys that cannot be materialized and stores the derived keys.
    fn new(scan: DescriptorSecretKey, spend: DescriptorSpendKey) -> Result<Self, Error> {
        let secp = secp256k1::Secp256k1::new();
        let scan_secret = derive_secret_key(&secp, &scan)?;
        let spend_secret: Option<SecretKey>;
        let spend_pubkey: PublicKey;
        match spend {
            DescriptorSpendKey::Private(ref desc) => {
                let secret = derive_secret_key(&secp, &desc)?;
                spend_pubkey = secret.public_key(&secp);
                spend_secret = Some(secret);
            },
            DescriptorSpendKey::Public(ref desc) => {
                spend_pubkey = derive_pubkey(&secp, &desc)?;
                spend_secret = None;
            }
        };
        // let (spend_secret, spend_pubkey) = materialize_spend(&secp, &spend)?;
        Ok(Self {
            scan,
            spend,
            scan_secret,
            spend_secret,
            spend_pubkey,
        })
    }

    fn scan(&self) -> &DescriptorSecretKey {
        &self.scan
    }

    fn spend(&self) -> &DescriptorSpendKey {
        &self.spend
    }

    fn scan_secret(&self) -> SecretKey {
        self.scan_secret
    }

    fn spend_secret(&self) -> Option<SecretKey> {
        self.spend_secret
    }

    fn spend_pubkey(&self) -> PublicKey {
        self.spend_pubkey
    }
}

fn derive_secret_key<C: secp256k1::Signing>(
    secp: &secp256k1::Secp256k1<C>,
    descriptor_secret_key: &DescriptorSecretKey,
) -> Result<SecretKey, Error> {
    let secret = match descriptor_secret_key {
        DescriptorSecretKey::MultiXPrv(_) => {
            return Err(Error::Unexpected(
                "sp() spend key must not be multipath".to_string(),
            ));
        }
        DescriptorSecretKey::XPrv(xprv) => {
            if xprv.wildcard != Wildcard::None {
                return Err(Error::Unexpected(
                    "sp() spend key must not contain a wildcard".to_string(),
                ));
            }
            xprv.xkey
                .derive_priv(secp, &xprv.derivation_path)
                .map(|derived| derived.private_key)
                .map_err(|e| Error::Unexpected(format!("sp() spend key: {e}")))?
        }
        DescriptorSecretKey::Single(s) if !s.key.compressed => {
            return Err(Error::Unexpected(
                "sp() spend key must be compressed".to_string(),
            ));
        }
        DescriptorSecretKey::Single(s) => s.key.inner,
    };
    Ok(secret)
}

fn derive_pubkey<C: secp256k1::Verification>(
    secp: &secp256k1::Secp256k1<C>,
    descriptor_pubkey: &DescriptorPublicKey,
) -> Result<PublicKey, Error> {
    let pubkey = match descriptor_pubkey {
        DescriptorPublicKey::MultiXPub(_) => Err(Error::Unexpected(
            "sp() spend key must not be multipath".to_string(),
        )),
        DescriptorPublicKey::XPub(xpub) => {
            if xpub.wildcard != Wildcard::None {
                return Err(Error::Unexpected(
                    "sp() spend key must not contain a wildcard".to_string(),
                ));
            }
            if descriptor_pubkey.has_hardened_step() {
                return Err(Error::Unexpected(
                    "sp() public spend key cannot use a hardened derivation step".to_string(),
                ));
            }
            xpub.xkey
                .derive_pub(secp, &xpub.derivation_path)
                .map(|derived| derived.public_key)
                .map_err(|e| Error::Unexpected(format!("sp() spend key: {e}")))
        }
        DescriptorPublicKey::Single(s) => match s.key {
            SinglePubKey::FullKey(full) if !full.compressed => Err(Error::Unexpected(
                "sp() spend key must be compressed".to_string(),
            )),
            SinglePubKey::FullKey(full) => Ok(full.inner),
            SinglePubKey::XOnly(_) => Err(Error::Unexpected(
                "sp() spend key must be compressed".to_string(),
            )),
        },
    }?;
    Ok(pubkey)
}

/// Splits a leading `[fingerprint/path]` off a key expression.
fn split_key_origin(s: &str) -> Result<(&str, Option<bip32::KeySource>), Error> {
    if !s.starts_with('[') {
        return Ok((s, None));
    }
    let (origin, key) = s[1..]
        .split_once(']')
        .ok_or_else(|| Error::Unexpected("sp() key origin is missing closing ']'".to_string()))?;
    if key.is_empty() {
        return Err(Error::Unexpected(
            "sp() key origin is not followed by a key".to_string(),
        ));
    }
    if key.contains(']') {
        return Err(Error::Unexpected(
            "sp() key expression contains multiple origins".to_string(),
        ));
    }

    let mut parts = origin.split('/');
    let fingerprint_hex = parts.next().unwrap_or("");
    if fingerprint_hex.len() != 8 {
        return Err(Error::Unexpected(format!(
            "sp() key origin fingerprint must be 8 hex chars, got '{fingerprint_hex}'"
        )));
    }
    let fingerprint = Fingerprint::from_hex(fingerprint_hex)
        .map_err(|e| Error::Unexpected(format!("sp() key origin fingerprint: {e}")))?;
    let children = parts
        .map(ChildNumber::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Unexpected(format!("sp() key origin path: {e}")))?;
    Ok((key, Some((fingerprint, DerivationPath::from(children)))))
}

fn write_key_origin(f: &mut impl fmt::Write, origin: &bip32::KeySource) -> fmt::Result {
    f.write_str("[")?;
    for byte in origin.0.as_bytes() {
        write!(f, "{byte:02x}")?;
    }
    for child in &origin.1 {
        write!(f, "/{child:#}")?;
    }
    f.write_str("]")
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
            SpInner::Encoded { origin, key } => {
                write!(wrapped_f, "sp(")?;
                if let Some(origin) = origin {
                    write_key_origin(&mut wrapped_f, origin)?;
                }
                write!(wrapped_f, "{key})")?;
            }
            SpInner::TwoKey(keys) => {
                write!(wrapped_f, "sp({},{})", keys.scan(), keys.spend())?;
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
                // Single-argument form: spscan or spspend, optionally with a key origin.
                if first.n_children() > 0 {
                    return Err(Error::Unexpected(
                        "sp() single-argument form expects an spscan or spspend key".to_string(),
                    ));
                }
                let (key_str, origin) = split_key_origin(first.name())?;
                let key = SpKey::from_str(key_str).map_err(|e| Error::Unexpected(e.to_string()))?;
                Ok(Sp::from_encoded(origin, key))
            }
            2 => {
                // Two-argument form: private scan key, then spend key.
                let second = children.next().unwrap();
                if first.n_children() > 0 {
                    return Err(Error::Unexpected(
                        "sp() scan key must be a single private key".to_string(),
                    ));
                }
                let scan = DescriptorSecretKey::from_str(first.name())
                    .map_err(|e| Error::Unexpected(format!("sp() scan key: {e}")))?;
                let spend = parse_spend_key(second)?;
                Sp::from_keys(scan, spend)
            }
            _ => unreachable!("verify_toplevel checked 1..=2"),
        }
    }
}

fn parse_spend_key(node: expression::TreeIterItem) -> Result<DescriptorSpendKey, Error> {
    if node.n_children() > 0 {
        return Err(Error::Unexpected(
            "sp() spend key must be a single key expression".to_string(),
        ));
    }

    match DescriptorSecretKey::from_str(node.name()) {
        Ok(sk) => Ok(DescriptorSpendKey::Private(sk)),
        Err(_) => {
            let pk = DescriptorPublicKey::from_str(node.name())
                .map_err(|e| Error::Unexpected(format!("sp() spend key: {e}")))?;
            Ok(DescriptorSpendKey::Public(pk))
        }
    }
}

#[cfg(test)]
mod tests {
    use miniscript::bitcoin::Network;
    use miniscript::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use secp256k1::{Secp256k1, SecretKey};

    use super::*;

    const WIF_SCAN: &str = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
    const SPEND_PUB: &str = "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
    const UNCOMPRESSED_WIF: &str = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).expect("valid scalar")
    }

    fn spscan() -> String {
        SpScanKey {
            scan_key: secret(0xab),
            spend_key: {
                let secp = Secp256k1::signing_only();
                secret(0xcd).public_key(&secp)
            },
            network: SpNetwork::Mainnet,
        }
        .to_string()
    }

    fn spscan_testnet() -> String {
        SpScanKey {
            scan_key: secret(0xab),
            spend_key: {
                let secp = Secp256k1::signing_only();
                secret(0xcd).public_key(&secp)
            },
            network: SpNetwork::Testnet,
        }
        .to_string()
    }

    fn spspend() -> String {
        SpSpendKey {
            scan_key: secret(0xab),
            spend_key: secret(0xcd),
            network: SpNetwork::Mainnet,
        }
        .to_string()
    }

    /// Account-level extended keys used to fill in the BIP's `xprv...` / `xpub...` placeholders.
    fn account_xkeys() -> (Xpriv, Xpub) {
        let master = Xpriv::new_master(Network::Bitcoin, &[0x11; 64]).expect("valid seed");
        let secp = Secp256k1::new();
        let path: DerivationPath = "m/352h/0h/0h".parse().unwrap();
        let xprv = master.derive_priv(&secp, &path).unwrap();
        let xpub = Xpub::from_priv(&secp, &xprv);
        (xprv, xpub)
    }

    fn assert_roundtrip(desc: &str) {
        let sp = Sp::from_str(desc).unwrap_or_else(|e| panic!("parse {desc}: {e}"));
        let displayed = sp.to_string();
        let again = Sp::from_str(&displayed).unwrap_or_else(|e| panic!("reparse {displayed}: {e}"));
        assert_eq!(sp, again);
    }

    #[test]
    fn valid_spscan() {
        let desc = format!("sp({})", spscan());
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.is_watch_only());
        assert!(sp.is_mainnet());
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_spscan_testnet() {
        let desc = format!("sp({})", spscan_testnet());
        let sp = Sp::from_str(&desc).unwrap();
        assert!(!sp.is_mainnet());
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_spscan_with_origin() {
        let desc = format!("sp([deadbeef/352h/0h/0h]{})", spscan());
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.is_watch_only());
        assert!(
            sp.to_string()
                .starts_with("sp([deadbeef/352h/0h/0h]spscan1")
        );
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_spspend() {
        let desc = format!("sp({})", spspend());
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.has_spend_key());
        assert!(sp.is_mainnet());
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_wif_and_compressed_pubkey() {
        let desc = format!("sp({WIF_SCAN},{SPEND_PUB})");
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.is_watch_only());
        assert!(sp.is_mainnet());
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_xprv_and_xpub() {
        let (xprv, xpub) = account_xkeys();
        let secp = Secp256k1::new();
        let scan_path: DerivationPath = "m/0h".parse().unwrap();
        let spend_path: DerivationPath = "m/0".parse().unwrap();
        let expected_scan = xprv.derive_priv(&secp, &scan_path).unwrap().private_key;
        // Hardened children cannot be derived from an xpub.
        let expected_spend = xpub.derive_pub(&secp, &spend_path).unwrap().public_key;

        let desc = format!("sp([deadbeef/352h/0h/0h]{xprv}/0h,{xpub}/0)");
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.is_watch_only());
        assert_eq!(sp.scan_key(), expected_scan);
        assert_ne!(sp.scan_key(), xprv.private_key);
        assert_eq!(sp.spend_secret(), None);
        assert_eq!(sp.spend_pubkey(), expected_spend);
        assert_ne!(sp.spend_pubkey(), xpub.public_key);
        assert_roundtrip(&desc);
    }

    #[test]
    fn valid_xprv_and_xprv() {
        let (xprv, _) = account_xkeys();
        let secp = Secp256k1::new();
        let child_path: DerivationPath = "m/0h".parse().unwrap();
        let expected = xprv.derive_priv(&secp, &child_path).unwrap().private_key;

        let desc = format!("sp([deadbeef/352h/0h/0h]{xprv}/0h,{xprv}/0h)");
        let sp = Sp::from_str(&desc).unwrap();
        assert!(sp.has_spend_key());
        assert_eq!(sp.scan_key(), expected);
        assert_ne!(sp.scan_key(), xprv.private_key);
        assert_eq!(sp.spend_secret(), Some(expected));
        assert_ne!(sp.spend_secret(), Some(xprv.private_key));
        assert_roundtrip(&desc);
    }

    #[test]
    fn invalid_empty() {
        assert!(Sp::from_str("sp()").is_err());
    }

    #[test]
    fn invalid_single_xpub() {
        let (_, xpub) = account_xkeys();
        assert!(Sp::from_str(&format!("sp({xpub})")).is_err());
    }

    #[test]
    fn invalid_two_xpubs() {
        let (_, xpub) = account_xkeys();
        assert!(Sp::from_str(&format!("sp({xpub},{xpub})")).is_err());
    }

    #[test]
    fn invalid_hardened_xpub() {
        let (xprv, xpub) = account_xkeys();
        for desc in [
            format!("sp({xprv},{xpub}/0h)"),
            format!("sp({xprv},{xpub}/1h/0)"),
        ] {
            match Sp::from_str(&desc) {
                Err(Error::Unexpected(msg)) => {
                    assert!(msg.contains("hardened"), "{desc}: {msg}");
                }
                other => panic!("expected hardened xpub rejection for {desc}, got {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_wildcard() {
        let (xprv, xpub) = account_xkeys();
        for desc in [
            format!("sp({xprv}/*,{xpub})"),
            format!("sp({xprv},{xpub}/*h)"),
            format!("sp({xprv},{xprv}/*)"),
        ] {
            match Sp::from_str(&desc) {
                Err(Error::Unexpected(msg)) => {
                    assert!(msg.contains("wildcard"), "{desc}: {msg}");
                }
                other => panic!("expected wildcard rejection for {desc}, got {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_two_spscan_keys() {
        let scan = spscan();
        assert!(Sp::from_str(&format!("sp({scan},{scan})")).is_err());
    }

    #[test]
    fn invalid_uncompressed_scan_key() {
        assert!(Sp::from_str(&format!("sp({UNCOMPRESSED_WIF},{SPEND_PUB})")).is_err());
    }

    #[test]
    fn invalid_nested_in_sh() {
        assert!(Sp::from_str(&format!("sh(sp({}))", spscan())).is_err());
    }

    #[test]
    fn invalid_nested_in_wsh() {
        assert!(Sp::from_str(&format!("wsh(sp({}))", spscan())).is_err());
    }
}
