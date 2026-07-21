#[cfg(feature = "encode")]
use core::fmt;

#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::utils::hash::SharedSecretHash;
use crate::Error;
use crate::Result;
#[cfg(feature = "encode")]
use bech32::{FromBase32, ToBase32};
#[cfg(any(feature = "sending", feature = "receiving"))]
use bitcoin_hashes::Hash;
use secp256k1::constants::PUBLIC_KEY_SIZE;
use secp256k1::PublicKey;
#[cfg(any(feature = "sending", feature = "receiving"))]
use secp256k1::{Scalar, Secp256k1, SecretKey};
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::ser::Serializer;
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::Deserializer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

#[cfg(any(feature = "sending", feature = "receiving"))]
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
                "Unknown silent payment version".to_string(),
            )),
        }
    }
}

/// Silent payment address (version + scan pubkey + `m` pubkey), without network.
///
/// [`m_pubkey`](Self::m_pubkey) is the address spend pubkey (`B_m` in BIP352):
/// the receiver's spend public key, which may be unlabeled (`B_spend`) or labeled
/// (`B_spend + m·G`).
#[cfg_attr(
    feature = "encode",
    doc = "\n\nNetwork is only needed for bech32m strings; use [`SilentPaymentAddressDisplay`] or [`SilentPaymentAddress::to_display_for_network`] when encoding or showing an address."
)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: SpVersion,
    scan_key: PublicKey,
    m_pubkey: PublicKey,
}

impl SilentPaymentAddress {
    /// Create a silent payment address from version, scan pubkey, and `m` pubkey.
    ///
    /// `m_pubkey` is the address spend pubkey (`B_m`), which may be labeled or not.
    pub fn new(version: SpVersion, scan_key: PublicKey, m_pubkey: PublicKey) -> Self {
        Self {
            version,
            scan_key,
            m_pubkey,
        }
    }

    /// Create a version-0 silent payment address.
    ///
    /// `m_pubkey` is the address spend pubkey (`B_m`), which may be labeled or not.
    pub fn new_v0(scan_key: PublicKey, m_pubkey: PublicKey) -> Self {
        Self::new(SpVersion::ZERO, scan_key, m_pubkey)
    }

    #[cfg(feature = "encode")]
    /// Attach a [`Network`] for string encoding via [`SilentPaymentAddressDisplay`].
    pub fn to_display_for_network(&self, network: Network) -> SilentPaymentAddressDisplay {
        SilentPaymentAddressDisplay::from_sp_address(*self, network)
    }

    pub fn try_from_byte_array_v0(bytes: &[u8; PUBLIC_KEY_SIZE * 2]) -> Result<Self> {
        let scan_key = PublicKey::from_slice(&bytes[..PUBLIC_KEY_SIZE])?;
        let m_pubkey = PublicKey::from_slice(&bytes[PUBLIC_KEY_SIZE..])?;
        Ok(Self::new(SpVersion::ZERO, scan_key, m_pubkey))
    }

    pub fn version(&self) -> SpVersion {
        self.version
    }

    pub fn scan_key(&self) -> PublicKey {
        self.scan_key
    }

    /// The address spend pubkey (`B_m` in BIP352).
    ///
    /// This may be the unlabeled spend pubkey, or a labeled one (`B_spend + m·G`).
    pub fn m_pubkey(&self) -> PublicKey {
        self.m_pubkey
    }
}

#[cfg(feature = "encode")]
impl From<SilentPaymentAddressDisplay> for SilentPaymentAddress {
    fn from(value: SilentPaymentAddressDisplay) -> Self {
        value.sp_address
    }
}

#[cfg(feature = "encode")]
impl From<&SilentPaymentAddressDisplay> for SilentPaymentAddress {
    fn from(value: &SilentPaymentAddressDisplay) -> Self {
        value.sp_address
    }
}

/// A silent payment address with network, serializable as a bech32m string.
#[cfg(feature = "encode")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddressDisplay {
    sp_address: SilentPaymentAddress,
    network: Network,
}

#[cfg(feature = "serde")]
impl Serialize for SilentPaymentAddressDisplay {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = (*self).into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SilentPaymentAddressDisplay {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr_str: String = Deserialize::deserialize(deserializer)?;

        Self::try_from(addr_str.as_str()).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "encode")]
impl SilentPaymentAddressDisplay {
    /// Build a display address from an existing [`SilentPaymentAddress`] and [`Network`].
    pub fn from_sp_address(sp_address: SilentPaymentAddress, network: Network) -> Self {
        Self {
            sp_address,
            network,
        }
    }

    /// Construct a [`SilentPaymentAddressDisplay`] from its component parts.
    ///
    /// Combines a [`SilentPaymentAddress`] with a [`Network`] for bech32m string
    /// encoding. If you already have a [`SilentPaymentAddress`], prefer
    /// [`Self::from_sp_address`].
    ///
    /// If you use your own bech32 parser, extract the HRP and payload, then build
    /// a [`SilentPaymentAddress`] (or call this method) and attach the network.
    ///
    /// # Bech32 format (for external parsers)
    ///
    /// Silent payment addresses use bech32m encoding with the following structure:
    /// - **HRP (Human Readable Part)**:
    ///   - Mainnet: `"sp"`
    ///   - Testnet/Signet: `"tsp"`
    ///   - Regtest: `"sprt"`
    /// - **Data**: a single 5-bit version digit, then the 66-byte payload
    ///   `serP(B_scan) ‖ serP(B_m)` converted to 5-bit characters.
    ///   `B_m` is the address spend pubkey (labeled or not).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use secp256k1::PublicKey;
    /// use silentpayments::{Network, SilentPaymentAddressDisplay, SpVersion};
    ///
    /// // After parsing bech32 yourself and extracting the pubkeys:
    /// let scan_key = PublicKey::from_slice(&scan_bytes)?;
    /// let m_pubkey = PublicKey::from_slice(&m_pubkey_bytes)?;
    ///
    /// let display = SilentPaymentAddressDisplay::new(
    ///     scan_key,
    ///     m_pubkey,
    ///     Network::Mainnet,
    ///     SpVersion::ZERO,
    /// );
    ///
    /// // Sending/receiving APIs take the network-agnostic address:
    /// let sp_address: silentpayments::SilentPaymentAddress = display.into();
    /// ```
    ///
    /// `m_pubkey` is the address spend pubkey (`B_m`), which may be labeled or not.
    pub fn new(
        scan_key: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: SpVersion,
    ) -> Self {
        Self::from_sp_address(
            SilentPaymentAddress::new(version, scan_key, m_pubkey),
            network,
        )
    }

    /// Calls new() with version set at SpVersion::ZERO.
    ///
    /// `m_pubkey` is the address spend pubkey (`B_m`), which may be labeled or not.
    pub fn new_v0(scan_key: PublicKey, m_pubkey: PublicKey, network: Network) -> Self {
        Self::new(scan_key, m_pubkey, network, SpVersion::ZERO)
    }

    pub fn scan_key(&self) -> PublicKey {
        self.sp_address.scan_key()
    }

    /// The address spend pubkey (`B_m` in BIP352).
    ///
    /// This may be the unlabeled spend pubkey, or a labeled one (`B_spend + m·G`).
    pub fn m_pubkey(&self) -> PublicKey {
        self.sp_address.m_pubkey()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn version(&self) -> SpVersion {
        self.sp_address.version()
    }

    pub fn as_inner(&self) -> SilentPaymentAddress {
        self.sp_address
    }
}

#[cfg(feature = "encode")]
impl fmt::Display for SilentPaymentAddressDisplay {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <Self as Into<String>>::into(*self))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<&str> for SilentPaymentAddressDisplay {
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

        let scan_key = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        Ok(Self::from_sp_address(
            SilentPaymentAddress::new(version, scan_key, m_pubkey),
            network,
        ))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<String> for SilentPaymentAddressDisplay {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

#[cfg(feature = "encode")]
impl From<SilentPaymentAddressDisplay> for String {
    fn from(val: SilentPaymentAddressDisplay) -> Self {
        let hrp = match val.network {
            Network::Testnet => "tsp",
            Network::Regtest => "sprt",
            Network::Mainnet => "sp",
        };

        let version = bech32::u5::try_from_u8(val.version().into())
            .expect("SpVersion guarantees this conversion");

        let B_scan_bytes = val.scan_key().serialize();
        let B_m_bytes = val.m_pubkey().serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).expect("We know our hrps")
    }
}

pub(crate) struct NonEmptyArray<'a, T>(&'a [T]);

impl<'a, T> NonEmptyArray<'a, T> {
    pub fn new(arr: &'a [T]) -> crate::Result<Self> {
        if !arr.is_empty() {
            Ok(Self(arr))
        } else {
            Err(crate::Error::EmptyArray)
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
