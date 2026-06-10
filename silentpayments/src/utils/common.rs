#[cfg(feature = "encode")]
use core::fmt;

#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::utils::hash::SharedSecretHash;
use crate::Error;
#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::Result;
#[cfg(feature = "encode")]
use bech32::{FromBase32, ToBase32};
#[cfg(any(feature = "sending", feature = "receiving"))]
use bitcoin_hashes::Hash;
use secp256k1::PublicKey;
#[cfg(any(feature = "sending", feature = "receiving"))]
use secp256k1::{Scalar, Secp256k1, SecretKey};
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::ser::Serializer;
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::Deserializer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const SILENT_PAYMENT_ADDRESS_BYTE_LEN: usize = 67;

/// Struct representing an OutPoint type.
///
/// This can be constructed from a rust-bitcoin outpoint:
/// ```
/// use silentpayments::utils::OutPoint;
/// use bitcoin::consensus::serialize;
/// # use std::str::FromStr;
///
/// # let bitcoin_outpoint = bitcoin::OutPoint::from_str(&format!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f:0")).unwrap();
/// let serialized: [u8; 36] = serialize(&bitcoin_outpoint).try_into().unwrap();
/// let outpoint = OutPoint::from_bytes(serialized);
/// ```
#[cfg(any(feature = "sending", feature = "receiving"))]
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct OutPoint(pub(crate) [u8; 36]);

impl OutPoint {
    /// Parse outpoin from a [String] txid and [u32] vout.
    /// This may fail if the txid is not a valid 32 byte hex string.
    pub fn from_txid_and_vout(txid: String, vout: u32) -> Result<Self> {
        let mut bytes: Vec<u8> = hex::decode(&txid)?;

        if bytes.len() != 32 {
            return Err(Error::GenericError(format!(
                "Invalid outpoint hex representation: {}",
                txid
            )));
        }

        // txid in string format is big endian and we need little endian
        bytes.reverse();

        let mut buffer = [0u8; 36];

        buffer[..32].copy_from_slice(&bytes);
        buffer[32..].copy_from_slice(&vout.to_le_bytes());
        Ok(Self(buffer))
    }

    pub fn from_bytes(bytes: [u8; 36]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 36] {
        self.0
    }
}

#[cfg(any(feature = "sending", feature = "receiving"))]
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct SharedSecret(pub(crate) PublicKey);

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_t_n(ecdh_shared_secret: &SharedSecret, k: u32) -> Result<SecretKey> {
    let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}

/// The network format used for this silent payment address.
///
/// There are three network types: Mainnet (`sp1..`), Testnet (`tsp1..`), and Regtest (`sprt1..`).
/// Signet uses the same network type as Testnet.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for &str {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "bitcoin", // we use the same string as rust-bitcoin for compatibility
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = crate::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let res = match value {
            "bitcoin" | "main" => Self::Mainnet, // We also take the core style argument
            "regtest" => Self::Regtest,
            "testnet" | "signet" | "test" => Self::Testnet, // core arg
            _ => return Err(Error::InvalidNetwork(value.to_string())),
        };
        Ok(res)
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SpVersion {
    ZERO,
}

impl From<SpVersion> for u8 {
    fn from(value: SpVersion) -> Self {
        match value {
            SpVersion::ZERO => 0u8,
        }
    }
}

impl TryFrom<u8> for SpVersion {
    type Error = crate::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ZERO),
            _ => Err(Error::GenericError(
                "Unknwon silent payment version".to_string(),
            )),
        }
    }
}

/// A silent payment address struct that can be used to deserialize a silent payment address string.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: SpVersion,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

#[cfg(all(feature = "serde", feature = "encode"))]
impl Serialize for SilentPaymentAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = (*self).into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(all(feature = "serde", feature = "encode"))]
impl<'de> Deserialize<'de> for SilentPaymentAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr_str: String = Deserialize::deserialize(deserializer)?;

        SilentPaymentAddress::try_from(addr_str.as_str()).map_err(serde::de::Error::custom)
    }
}

impl SilentPaymentAddress {
    /// Construct a `SilentPaymentAddress` from its component parts.
    ///
    /// This constructor is always available, even without the `encode` feature.
    /// If you have your own bech32 parser, you can use it to extract the components
    /// and then construct the address using this method.
    ///
    /// # Bech32 Format (for external parsers)
    ///
    /// Silent payment addresses use bech32m encoding with the following structure:
    /// - **HRP (Human Readable Part)**:
    ///   - Mainnet: `"sp"`
    ///   - Testnet/Signet: `"tsp"`
    ///   - Regtest: `"sprt"`
    /// - **Data**: version (1 byte) + scan_pubkey (33 bytes) + spend_pubkey (33 bytes)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use secp256k1::PublicKey;
    /// use silentpayments::{SilentPaymentAddress, Network};
    ///
    /// // After parsing bech32 yourself and extracting the pubkeys:
    /// let scan_pubkey = PublicKey::from_slice(&scan_bytes)?;
    /// let spend_pubkey = PublicKey::from_slice(&spend_bytes)?;
    ///
    /// let address = SilentPaymentAddress::new(
    ///     scan_pubkey,
    ///     spend_pubkey,
    ///     Network::Mainnet,
    ///     0  // version
    /// )?;
    /// ```
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: SpVersion,
    ) -> Self {
        SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            network,
            version,
        }
    }

    /// Get the scan public key.
    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    /// Get the spend public key.
    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    /// Get the network.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Get the version byte.
    pub fn get_version(&self) -> u8 {
        self.version.into()
    }

    pub fn to_byte_array(&self) -> [u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN] {
        let mut bytes = [0u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN];
        bytes[0] = self.version.into();
        bytes[1..34].copy_from_slice(&self.scan_pubkey.serialize());
        bytes[34..67].copy_from_slice(&self.m_pubkey.serialize());
        bytes
    }

    pub fn try_from_byte_array(
        bytes: &[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN],
        network: Network,
    ) -> Result<Self> {
        let version: SpVersion = bytes[0].try_into()?;
        let scan_pubkey = PublicKey::from_slice(&bytes[1..34])?;
        let m_pubkey = PublicKey::from_slice(&bytes[34..])?;
        Ok(Self::new(scan_pubkey, m_pubkey, network, version))
    }
}

#[cfg(feature = "encode")]
impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <SilentPaymentAddress as Into<String>>::into(*self))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(addr)?;

        if data.len() != 107 {
            return Err(Error::GenericError("Address length is wrong".to_owned()));
        }

        let version: SpVersion = data[0].to_u8().try_into()?;

        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            "sprt" => Network::Regtest,
            _ => {
                return Err(Error::InvalidAddress(format!(
                    "Wrong prefix, expected \"sp\", \"tsp\", or \"sprt\", got \"{}\"",
                    &hrp
                )))
            }
        };

        let data = Vec::<u8>::from_base32(&data[1..])?;

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        Ok(SilentPaymentAddress::new(
            scan_pubkey,
            m_pubkey,
            network,
            version,
        ))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

#[cfg(feature = "encode")]
impl From<SilentPaymentAddress> for String {
    fn from(val: SilentPaymentAddress) -> Self {
        let hrp = match val.network {
            Network::Testnet => "tsp",
            Network::Regtest => "sprt",
            Network::Mainnet => "sp",
        };

        let version = bech32::u5::try_from_u8(val.version.into()).unwrap();

        let B_scan_bytes = val.scan_pubkey.serialize();
        let B_m_bytes = val.m_pubkey.serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }
}

pub(crate) struct NonEmptyArray<'a, T>(&'a [T]);

impl<'a, T> NonEmptyArray<'a, T> {
    pub fn new(arr: &'a [T]) -> crate::Result<Self> {
        match !arr.is_empty() {
            true => Ok(Self(arr)),
            false => Err(crate::Error::EmptyArray),
        }
    }

    pub fn as_inner(&'a self) -> &'a [T] {
        self.0
    }
}

impl<'a, T> NonEmptyArray<'a, T>
where
    T: Ord,
{
    pub fn min(&'a self) -> &'a T {
        self.0.iter().min().expect("Is non-empty")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::consensus::serialize;

    use crate::utils;

    #[test]
    fn outpoint_parsing_equivalence() {
        // example outpoint from genesis block
        let txid = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let vout = 0;

        let sp_outpoint_from_txid_and_vout =
            utils::OutPoint::from_txid_and_vout(txid.to_string(), vout).unwrap();

        let outpoint = bitcoin::OutPoint::from_str(&format!("{txid}:{vout}")).unwrap();
        // consensus serialization of bitcoin outpoint struct to byte array
        let outpoint_bytes: [u8; 36] = serialize(&outpoint).try_into().unwrap();
        let sp_outpoint_from_bytes = utils::OutPoint::from_bytes(outpoint_bytes);

        assert_eq!(sp_outpoint_from_txid_and_vout, sp_outpoint_from_bytes);
    }
}
