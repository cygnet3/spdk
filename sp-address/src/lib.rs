use bech32::{Bech32m, Hrp};
use secp256k1::PublicKey;
use std::fmt;
use std::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ADDRESS_DATA_LENGTH: usize = 67;
const HRP_MAINNET: Hrp = Hrp::parse_unchecked("sp");
const HRP_TESTNET: Hrp = Hrp::parse_unchecked("tsp");
const HRP_REGTEST: Hrp = Hrp::parse_unchecked("sprt");

/// Error types for silent payment address operations.
#[derive(Debug)]
pub enum Error {
    InvalidNetwork(String),
    InvalidAddress(String),
    UnsupportedVersion(u8),
    Bech32Decode(bech32::DecodeError),
    Bech32Encode(bech32::EncodeError),
    Secp256k1(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidNetwork(n) => write!(f, "Invalid network: {}", n),
            Error::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            Error::UnsupportedVersion(v) => write!(f, "Unsupported version: {}", v),
            Error::Bech32Decode(e) => write!(f, "Bech32 decode error: {}", e),
            Error::Bech32Encode(e) => write!(f, "Bech32 encode error: {}", e),
            Error::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<bech32::DecodeError> for Error {
    fn from(e: bech32::DecodeError) -> Self {
        Error::Bech32Decode(e)
    }
}

impl From<bech32::EncodeError> for Error {
    fn from(e: bech32::EncodeError) -> Self {
        Error::Bech32Encode(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp256k1(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

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
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let res = match value {
            "bitcoin" | "main" => Self::Mainnet, // We also take the core style argument
            "regtest" => Self::Regtest,
            "testnet" | "signet" | "test" => Self::Testnet, // core arg
            _ => return Err(Error::InvalidNetwork(value.to_string())),
        };
        Ok(res)
    }
}
/// A silent payment address struct that can be used to deserialize a silent payment address string.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

#[cfg(feature = "serde")]
impl Serialize for SilentPaymentAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = self.clone().into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
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
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: u8,
    ) -> Result<Self> {
        if version != 0 {
            return Err(Error::UnsupportedVersion(version));
        }

        Ok(SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            network,
            version,
        })
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
        self.version
    }
}

impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <SilentPaymentAddress as Into<String>>::into(*self))
    }
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(addr).map_err(|e| Error::Bech32Decode(e))?;

        if data.len() != ADDRESS_DATA_LENGTH {
            return Err(Error::InvalidAddress(format!("Wrong address length, expected {}, got {}", ADDRESS_DATA_LENGTH, data.len())));
        }

        let version = data[0];

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

        let data = &data[1..];

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, network, version)
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

impl From<SilentPaymentAddress> for String {
    fn from(val: SilentPaymentAddress) -> Self {
        let hrp: Hrp = match val.network {
            Network::Testnet => HRP_TESTNET,
            Network::Regtest => HRP_REGTEST,
            Network::Mainnet => HRP_MAINNET,
        };

        let mut data = [0; ADDRESS_DATA_LENGTH];
        data[0] = val.version;
        data[1..34].copy_from_slice(&val.scan_pubkey.serialize()[..]);
        data[34..67].copy_from_slice(&val.m_pubkey.serialize()[..]);

        bech32::encode::<Bech32m>(hrp, &data).expect("We should always be able to encode public keys")
    }
}