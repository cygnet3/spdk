//! Silent payment key expressions (BIP-392).
//!
//! Defines `spscan` and `spspend` key types which are Bech32m encodings of
//! silent payment key material as specified in BIP-392:
//!
//! - `spscan`: scan private key (32 bytes) + spend public key (33 bytes)
//! - `spspend`: scan private key (32 bytes) + spend private key (32 bytes)

use core::fmt;
use core::str::FromStr;

use silentpayments::Network as SpNetwork;

use miniscript::bitcoin::bech32::{self, Bech32m, Hrp};

/// The HRP for spscan keys on mainnet.
const SPSCAN_MAINNET_HRP: &str = "spscan";
/// The HRP for spscan keys on testnets.
const SPSCAN_TESTNET_HRP: &str = "tspscan";
/// The HRP for spspend keys on mainnet.
const SPSPEND_MAINNET_HRP: &str = "spspend";
/// The HRP for spspend keys on testnets.
const SPSPEND_TESTNET_HRP: &str = "tspspend";

/// The silent payments version 0 byte in the 5-bit encoding.
/// 'q' in Bech32 corresponds to value 0.
const SP_VERSION_0: u8 = 0;

/// Total payload size for spscan: 32 (scan privkey) + 33 (spend pubkey) = 65 bytes.
const SPSCAN_PAYLOAD_LEN: usize = 65;
/// Total payload size for spspend: 32 (scan privkey) + 32 (spend privkey) = 64 bytes.
const SPSPEND_PAYLOAD_LEN: usize = 64;

/// An error when parsing an `spscan` or `spspend` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpKeyError {
    /// Bech32 decoding error.
    Bech32(String),
    /// Invalid or unrecognized HRP.
    InvalidHrp(String),
    /// Invalid silent payment version (expected 0).
    InvalidVersion(u8),
    /// Invalid payload length.
    InvalidPayloadLength {
        /// Expected payload length.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
}

impl fmt::Display for SpKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SpKeyError::Bech32(e) => write!(f, "bech32 error: {}", e),
            SpKeyError::InvalidHrp(hrp) => write!(f, "invalid HRP: {}", hrp),
            SpKeyError::InvalidVersion(v) => {
                write!(f, "invalid silent payment version: {} (expected 0)", v)
            }
            SpKeyError::InvalidPayloadLength { expected, actual } => {
                write!(f, "invalid payload length: {} (expected {})", actual, expected)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpKeyError {}

/// A unified silent payment key type.
///
/// This is either an `spscan` key (watch-only) or an `spspend` key (full wallet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpKey {
    /// A scan-only key (watch-only): holds scan private key + spend public key.
    Scan(SpScanKey),
    /// A full spend key: holds scan private key + spend private key.
    Spend(SpSpendKey),
}

impl SpKey {
    /// Returns the 32-byte scan private key.
    pub fn scan_privkey_bytes(&self) -> &[u8] {
        match self {
            SpKey::Scan(k) => &k.scan_key,
            SpKey::Spend(k) => &k.scan_key,
        }
    }

    /// Returns the network this key is for.
    pub fn network(&self) -> SpNetwork {
        match self {
            SpKey::Scan(k) => k.network,
            SpKey::Spend(k) => k.network,
        }
    }
}

impl fmt::Display for SpKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SpKey::Scan(k) => fmt::Display::fmt(k, f),
            SpKey::Spend(k) => fmt::Display::fmt(k, f),
        }
    }
}

impl FromStr for SpKey {
    type Err = SpKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Decode the bech32m string
        let (hrp, data) =
            bech32::decode(s).map_err(|e| SpKeyError::Bech32(e.to_string()))?;

        let hrp_str = hrp.to_string();
        let hrp_lower = hrp_str.to_ascii_lowercase();

        // Validate version byte: first byte of data must be 0 (version 0, 'q')
        if data.is_empty() {
            return Err(SpKeyError::InvalidPayloadLength { expected: 1, actual: 0 });
        }
        if data[0] != SP_VERSION_0 {
            return Err(SpKeyError::InvalidVersion(data[0]));
        }

        let payload = &data[1..];

        match hrp_lower.as_str() {
            SPSCAN_MAINNET_HRP | SPSCAN_TESTNET_HRP => {
                let network = if hrp_lower == SPSCAN_MAINNET_HRP {
                    SpNetwork::Mainnet
                } else {
                    SpNetwork::Testnet
                };
                if payload.len() != SPSCAN_PAYLOAD_LEN {
                    return Err(SpKeyError::InvalidPayloadLength {
                        expected: SPSCAN_PAYLOAD_LEN,
                        actual: payload.len(),
                    });
                }
                let mut scan_key = [0u8; 32];
                let mut spend_key = [0u8; 33];
                scan_key.copy_from_slice(&payload[..32]);
                spend_key.copy_from_slice(&payload[32..]);
                Ok(SpKey::Scan(SpScanKey { scan_key, spend_key, network }))
            }
            SPSPEND_MAINNET_HRP | SPSPEND_TESTNET_HRP => {
                let network = if hrp_lower == SPSPEND_MAINNET_HRP {
                    SpNetwork::Mainnet
                } else {
                    SpNetwork::Testnet
                };
                if payload.len() != SPSPEND_PAYLOAD_LEN {
                    return Err(SpKeyError::InvalidPayloadLength {
                        expected: SPSPEND_PAYLOAD_LEN,
                        actual: payload.len(),
                    });
                }
                let mut scan_key = [0u8; 32];
                let mut spend_key = [0u8; 32];
                scan_key.copy_from_slice(&payload[..32]);
                spend_key.copy_from_slice(&payload[32..]);
                Ok(SpKey::Spend(SpSpendKey { scan_key, spend_key, network }))
            }
            _ => Err(SpKeyError::InvalidHrp(hrp_lower)),
        }
    }
}

/// A watch-only silent payment key (`spscan`).
///
/// Contains the scan private key and spend public key.
/// This allows scanning for silent payment outputs but not spending them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpScanKey {
    /// The scan private key (32 bytes, `ser_256(b_scan)`).
    pub scan_key: [u8; 32],
    /// The spend public key (33 bytes, compressed, `ser_P(B_spend)`).
    pub spend_key: [u8; 33],
    /// The network this key is for.
    pub network: SpNetwork,
}

impl SpScanKey {
    fn hrp(&self) -> &str {
        match self.network {
            SpNetwork::Mainnet => SPSCAN_MAINNET_HRP,
            SpNetwork::Testnet | SpNetwork::Regtest => SPSCAN_TESTNET_HRP,
        }
    }

    fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + SPSCAN_PAYLOAD_LEN);
        payload.push(SP_VERSION_0);
        payload.extend_from_slice(&self.scan_key);
        payload.extend_from_slice(&self.spend_key);
        payload
    }
}

impl fmt::Display for SpScanKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hrp = Hrp::parse(self.hrp()).expect("valid HRP constant");
        let payload = self.to_payload();
        let encoded =
            bech32::encode::<Bech32m>(hrp, &payload).expect("valid payload for bech32m encoding");
        f.write_str(&encoded)
    }
}

/// A full silent payment key (`spspend`).
///
/// Contains both the scan private key and spend private key.
/// This allows both scanning for and spending silent payment outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpSpendKey {
    /// The scan private key (32 bytes, `ser_256(b_scan)`).
    pub scan_key: [u8; 32],
    /// The spend private key (32 bytes, `ser_256(b_spend)`).
    pub spend_key: [u8; 32],
    /// The network this key is for.
    pub network: SpNetwork,
}

impl SpSpendKey {
    fn hrp(&self) -> &str {
        match self.network {
            SpNetwork::Mainnet => SPSPEND_MAINNET_HRP,
            SpNetwork::Testnet | SpNetwork::Regtest => SPSPEND_TESTNET_HRP,
        }
    }

    fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + SPSPEND_PAYLOAD_LEN);
        payload.push(SP_VERSION_0);
        payload.extend_from_slice(&self.scan_key);
        payload.extend_from_slice(&self.spend_key);
        payload
    }
}

impl fmt::Display for SpSpendKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hrp = Hrp::parse(self.hrp()).expect("valid HRP constant");
        let payload = self.to_payload();
        let encoded =
            bech32::encode::<Bech32m>(hrp, &payload).expect("valid payload for bech32m encoding");
        f.write_str(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spscan_roundtrip() {
        let key = SpScanKey {
            scan_key: [0xab; 32],
            spend_key: {
                let mut k = [0u8; 33];
                k[0] = 0x02; // compressed pubkey prefix
                for i in 1..33 {
                    k[i] = 0xcd;
                }
                k
            },
            network: SpNetwork::Mainnet,
        };
        let encoded = key.to_string();
        assert!(encoded.starts_with("spscan1"));

        let decoded = SpKey::from_str(&encoded).unwrap();
        match &decoded {
            SpKey::Scan(k) => {
                assert_eq!(k.scan_key, key.scan_key);
                assert_eq!(k.spend_key, key.spend_key);
                assert_eq!(k.network, SpNetwork::Mainnet);
            }
            _ => panic!("Expected SpKey::Scan"),
        }
        // Display roundtrip
        assert_eq!(decoded.to_string(), encoded);
    }

    #[test]
    fn spspend_roundtrip() {
        let key = SpSpendKey {
            scan_key: [0xab; 32],
            spend_key: [0xcd; 32],
            network: SpNetwork::Mainnet,
        };
        let encoded = key.to_string();
        assert!(encoded.starts_with("spspend1"));

        let decoded = SpKey::from_str(&encoded).unwrap();
        match &decoded {
            SpKey::Spend(k) => {
                assert_eq!(k.scan_key, key.scan_key);
                assert_eq!(k.spend_key, key.spend_key);
                assert_eq!(k.network, SpNetwork::Mainnet);
            }
            _ => panic!("Expected SpKey::Spend"),
        }
        assert_eq!(decoded.to_string(), encoded);
    }

    #[test]
    fn testnet_spscan_roundtrip() {
        let key = SpScanKey {
            scan_key: [0x01; 32],
            spend_key: {
                let mut k = [0u8; 33];
                k[0] = 0x03;
                for i in 1..33 {
                    k[i] = 0x02;
                }
                k
            },
            network: SpNetwork::Testnet,
        };
        let encoded = key.to_string();
        assert!(encoded.starts_with("tspscan1"));

        let decoded = SpKey::from_str(&encoded).unwrap();
        assert_eq!(decoded.network(), SpNetwork::Testnet);
    }

    #[test]
    fn testnet_spspend_roundtrip() {
        let key = SpSpendKey {
            scan_key: [0x01; 32],
            spend_key: [0x02; 32],
            network: SpNetwork::Testnet,
        };
        let encoded = key.to_string();
        assert!(encoded.starts_with("tspspend1"));

        let decoded = SpKey::from_str(&encoded).unwrap();
        assert_eq!(decoded.network(), SpNetwork::Testnet);
    }

    #[test]
    fn invalid_hrp() {
        let err = SpKey::from_str("badhrp1qqqqqqqqqqqqqqqqqqqq").unwrap_err();
        match err {
            SpKeyError::InvalidHrp(_) | SpKeyError::Bech32(_) => {}
            e => panic!("Expected InvalidHrp or Bech32 error, got {:?}", e),
        }
    }
}
