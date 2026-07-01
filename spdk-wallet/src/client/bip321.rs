use std::fmt;

use bip21::de::{DeserializationError, DeserializationState, DeserializeParams, ParamKind};
use bip21::ser::SerializeParams;
use bip21::Param;
use silentpayments::{Network, SilentPaymentAddress};

/// Error returned when parsing silent payment extras fields of a BIP 321 URI.
#[derive(Debug)]
pub enum SpExtrasError {
    Utf8(std::str::Utf8Error),
    Address(silentpayments::Error),
    DuplicateParameter { key: String },
    InvalidParameterKey { key: String },
    NetworkMismatch {
        network: Network,
    },
}

impl fmt::Display for SpExtrasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpExtrasError::Utf8(e) => write!(f, "invalid UTF-8 in silent payment parameter: {}", e),
            SpExtrasError::Address(e) => write!(f, "invalid silent payment address: {}", e),
            SpExtrasError::DuplicateParameter { key } => {
                write!(f, "duplicate {key} parameter in URI")
            }
            SpExtrasError::InvalidParameterKey { key } => {
                write!(f, "silent payment parameter key must be lowercase: {key}")
            }
            SpExtrasError::NetworkMismatch { network } => match network {
                Network::Mainnet => write!(
                    f,
                    "Mainnet silent payment address must use the sp parameter"
                ),
                Network::Testnet => write!(
                    f,
                    "Testnet silent payment address must use the tsp parameter"
                ),
                Network::Regtest => write!(
                    f,
                    "regtest addresses are not supported in BIP 321 URIs"
                ),
            },
        }
    }
}

impl std::error::Error for SpExtrasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpExtrasError::Utf8(e) => Some(e),
            SpExtrasError::Address(e) => Some(e),
            _ => None,
        }
    }
}

fn expected_network_for_key(key: &str) -> Option<Network> {
    match key {
        "sp" => Some(Network::Mainnet),
        "tsp" => Some(Network::Testnet),
        _ => None,
    }
}

/// Classifies a query parameter key as a silent-payment parameter.
///
/// Returns `None` for unrelated keys, `Some(Ok(network))` for valid lowercase keys,
/// and `Some(Err(..))` for sp-related keys with invalid casing.
fn classify_sp_param_key(key: &str) -> Option<Result<Network, SpExtrasError>> {
    match expected_network_for_key(key) {
        Some(network) => Some(Ok(network)),
        None => {
            if key.eq_ignore_ascii_case("sp") || key.eq_ignore_ascii_case("tsp") {
                Some(Err(SpExtrasError::InvalidParameterKey {
                    key: key.to_owned(),
                }))
            } else {
                None
            }
        }
    }
}

fn slot_for_expected_network<'a>(
    state: &'a mut SpExtras,
    network: Network,
) -> &'a mut Option<SilentPaymentAddress> {
    match network {
        Network::Mainnet => &mut state.sp,
        Network::Testnet => &mut state.tsp,
        Network::Regtest => unreachable!("regtest addresses are not supported in BIP 321 URIs"),
    }
}

/// BIP 321 extras carrying Silent Payment addresses from query parameters.
///
/// BIP 321 defines `sp` for mainnet and `tsp` for testnet/signet BIP 352 Silent Payment
/// addresses, following the address format's human-readable part as the parameter key.
///
/// A URI may contain at most one `sp` and one `tsp` parameter. Parameter keys must be lowercase.
#[derive(Debug, Default, Clone)]
pub struct SpExtras {
    pub sp: Option<SilentPaymentAddress>,
    pub tsp: Option<SilentPaymentAddress>,
}

impl DeserializationError for SpExtras {
    type Error = SpExtrasError;
}

impl<'de> DeserializationState<'de> for SpExtras {
    type Value = SpExtras;

    fn is_param_known(&self, key: &str) -> bool {
        classify_sp_param_key(key).is_some()
    }

    fn deserialize_temp(
        &mut self,
        key: &str,
        value: Param<'_>,
    ) -> Result<ParamKind, SpExtrasError> {
        match classify_sp_param_key(key) {
            Some(Ok(expected_network)) => {
                let slot = slot_for_expected_network(self, expected_network);
                if slot.is_some() {
                    return Err(SpExtrasError::DuplicateParameter {
                        key: key.to_owned(),
                    });
                }
                let s = String::try_from(value).map_err(SpExtrasError::Utf8)?;
                let addr =
                    SilentPaymentAddress::try_from(s.as_str()).map_err(SpExtrasError::Address)?;
                if addr.get_network() != expected_network {
                    return Err(SpExtrasError::NetworkMismatch {
                        network: addr.get_network(),
                    });
                }
                *slot = Some(addr);
                Ok(ParamKind::Known)
            }
            Some(Err(err)) => Err(err),
            None => Ok(ParamKind::Unknown),
        }
    }

    fn finalize(self) -> Result<SpExtras, SpExtrasError> {
        Ok(self)
    }
}

impl<'de> DeserializeParams<'de> for SpExtras {
    type DeserializationState = SpExtras;
}

impl<'a> SerializeParams for &'a SpExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::iter::Chain<
        std::option::IntoIter<(&'static str, String)>,
        std::option::IntoIter<(&'static str, String)>,
    >;

    fn serialize_params(self) -> Self::Iterator {
        self.sp
            .as_ref()
            .map(|addr| ("sp", addr.to_string()))
            .into_iter()
            .chain(
                self.tsp
                    .as_ref()
                    .map(|addr| ("tsp", addr.to_string()))
                    .into_iter(),
            )
    }
}

/// A BIP 321 URI with Silent Payment address support.
///
/// Parse with `SpUri::try_from(s)` or `s.parse::<SpUri<'static>>()`.
///
/// # Examples
/// ```ignore
/// // SP-only, no on-chain fallback
/// let uri: SpUri<'_> = "bitcoin:?sp=sp1qq...&amount=0.001".try_into().unwrap();
/// let sp_addr = uri.extras.sp.as_ref();
///
/// // SP with on-chain fallback
/// let uri: SpUri<'_> = "bitcoin:bc1q...?sp=sp1qq...".try_into().unwrap();
/// let onchain  = uri.address.as_ref();   // Option<Address<NetworkUnchecked>>
/// let sp_addr  = uri.extras.sp.as_ref(); // Option<SilentPaymentAddress>
///
/// // Testnet/signet silent payment address
/// let uri: SpUri<'_> = "bitcoin:?tsp=tsp1qq...".try_into().unwrap();
/// let tsp_addr = uri.extras.tsp.as_ref();
///
/// // Mainnet and testnet silent payment addresses
/// let uri: SpUri<'_> = "bitcoin:?sp=sp1qq...&tsp=tsp1qq...".try_into().unwrap();
/// ```
pub type SpUri<'a> = bip21::Uri<'a, bitcoin::address::NetworkUnchecked, SpExtras>;

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bip21::de::Error as Bip21Error;
    use silentpayments::SpVersion;

    use super::{Network, SilentPaymentAddress, SpExtrasError, SpUri};

    fn make_sp_address(network: Network) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        let (scan_bytes, spend_bytes) = match network {
            Network::Mainnet => ([0x03; 32], [0x04; 32]),
            Network::Testnet => ([0x01; 32], [0x02; 32]),
            Network::Regtest => panic!("unexpected network"),
        };
        let scan = SecretKey::from_slice(&scan_bytes)
            .unwrap()
            .public_key(&secp);
        let spend = SecretKey::from_slice(&spend_bytes)
            .unwrap()
            .public_key(&secp);
        SilentPaymentAddress::new(scan, spend, network, SpVersion::ZERO)
    }

    #[test]
    fn parse_sp_parameter() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = format!("bitcoin:?sp={sp}");
        let parsed = SpUri::try_from(uri.as_str()).unwrap();
        assert_eq!(
            parsed.extras.sp.as_ref().unwrap().get_network(),
            Network::Mainnet
        );
        assert!(parsed.extras.tsp.is_none());
    }

    #[test]
    fn parse_tsp_parameter() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = format!("bitcoin:?tsp={tsp}");
        let parsed = SpUri::try_from(uri.as_str()).unwrap();
        assert_eq!(
            parsed.extras.tsp.as_ref().unwrap().get_network(),
            Network::Testnet
        );
        assert!(parsed.extras.sp.is_none());
    }

    #[test]
    fn reject_uppercase_sp_parameter_key() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = format!("bitcoin:?SP={sp}");
        assert!(matches!(
            SpUri::try_from(uri.as_str()),
            Err(Bip21Error::Extras(SpExtrasError::InvalidParameterKey { .. }))
        ));
    }

    #[test]
    fn reject_mainnet_address_in_tsp_parameter() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = format!("bitcoin:?tsp={sp}");
        assert!(matches!(
            SpUri::try_from(uri.as_str()),
            Err(Bip21Error::Extras(SpExtrasError::NetworkMismatch { .. }))
        ));
    }

    #[test]
    fn reject_testnet_address_in_sp_parameter() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = format!("bitcoin:?sp={tsp}");
        assert!(matches!(
            SpUri::try_from(uri.as_str()),
            Err(Bip21Error::Extras(SpExtrasError::NetworkMismatch { .. }))
        ));
    }

    #[test]
    fn reject_duplicate_sp_parameters() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = format!("bitcoin:?sp={sp}&sp={sp}");
        assert!(matches!(
            SpUri::try_from(uri.as_str()),
            Err(Bip21Error::Extras(SpExtrasError::DuplicateParameter { .. }))
        ));
    }

    #[test]
    fn reject_duplicate_tsp_parameters() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = format!("bitcoin:?tsp={tsp}&tsp={tsp}");
        assert!(matches!(
            SpUri::try_from(uri.as_str()),
            Err(Bip21Error::Extras(SpExtrasError::DuplicateParameter { .. }))
        ));
    }

    #[test]
    fn accept_both_sp_and_tsp_parameters() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = format!("bitcoin:?sp={sp}&tsp={tsp}");
        let parsed = SpUri::try_from(uri.as_str()).unwrap();
        assert_eq!(
            parsed.extras.sp.as_ref().unwrap().get_network(),
            Network::Mainnet
        );
        assert_eq!(
            parsed.extras.tsp.as_ref().unwrap().get_network(),
            Network::Testnet
        );
    }
}
