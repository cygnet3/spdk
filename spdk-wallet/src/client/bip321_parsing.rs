use std::fmt;

use bip321::{Bip321Error, ExtensionHandler, FieldWithAttributes};
use silentpayments::{Network, SilentPaymentCode};

/// Error returned when validating silent payment fields of a BIP 321 URI.
#[derive(Debug)]
pub enum SpUriParseError {
    Address(silentpayments::Error),
    NetworkMismatch { expected: Network, got: Network },
}

impl fmt::Display for SpUriParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpUriParseError::Address(e) => write!(f, "invalid silent payment address: {e}"),
            SpUriParseError::NetworkMismatch { expected, got } => match expected {
                Network::Mainnet => write!(
                    f,
                    "expected mainnet silent payment address, got {}",
                    <silentpayments::Network as Into<&str>>::into(*got)
                ),
                _ => write!(
                    f,
                    "expected non-mainnet silent payment address, got {}",
                    <silentpayments::Network as Into<&str>>::into(*got)
                ),
            },
        }
    }
}

impl std::error::Error for SpUriParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpUriParseError::Address(e) => Some(e),
            _ => None,
        }
    }
}

/// Extension handler for the BIP 321 `tsp` silent-payment query parameter.
///
/// `sp` is already first-class in the bip321 crate; `tsp` is collected here as
/// the non-mainnet counterpart. Network checks are applied later by
/// [`parse_sp`] / [`parse_tsp`], matching how bip321 leaves `sp` as a raw
/// string while validating `bc` / `tb` itself.
///
/// Use as the type parameter of [`bip321::Bip321Uri`]:
/// `Bip321Uri::<SpUriExtension>::from_str(s)`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpUriExtension {
    tsp: Vec<FieldWithAttributes<String>>,
}

impl SpUriExtension {
    /// Raw `tsp=` fields as collected from the URI (not yet network-checked).
    pub fn tsp(&self) -> &[FieldWithAttributes<String>] {
        &self.tsp
    }
}

impl ExtensionHandler for SpUriExtension {
    fn handle_param(
        &mut self,
        key: &str,
        value: &str,
        required: bool,
    ) -> Result<bool, Bip321Error> {
        let field = FieldWithAttributes::new(value.to_owned(), required);
        match key {
            "tsp" => {
                self.tsp.push(field);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn is_empty(&self) -> bool {
        self.tsp.is_empty()
    }

    /// The bip321 crate always passes `required=false` to `write_query_param`
    /// for extension parameters, so the `req-` prefix must be embedded in the
    /// key string directly when needed.
    fn serialize_params(&self) -> Vec<(String, String)> {
        self.tsp
            .iter()
            .map(|field| {
                let key = if field.required() {
                    "req-tsp".to_owned()
                } else {
                    "tsp".to_owned()
                };
                (key, field.inner().clone())
            })
            .collect()
    }
}

fn parse_slot(
    fields: &[FieldWithAttributes<String>],
    expected: Network,
) -> Result<Vec<SilentPaymentCode>, SpUriParseError> {
    fields
        .iter()
        .map(|field| {
            let addr = SilentPaymentCode::try_from(field.inner().as_str())
                .map_err(SpUriParseError::Address)?;
            let got = addr.network();
            let ok = match expected {
                Network::Mainnet => got == Network::Mainnet,
                _ => got != Network::Mainnet,
            };
            if !ok {
                return Err(SpUriParseError::NetworkMismatch { expected, got });
            }
            Ok(addr)
        })
        .collect()
}

/// Parse `sp=` fields.
///
/// BIP 321 allows multiple payment-instruction parameters with the same key;
/// every entry is parsed. Each address must be mainnet.
pub fn parse_sp(
    fields: &[FieldWithAttributes<String>],
) -> Result<Vec<SilentPaymentCode>, SpUriParseError> {
    parse_slot(fields, Network::Mainnet)
}

/// Parse `tsp=` fields.
///
/// BIP 321 allows multiple payment-instruction parameters with the same key;
/// every entry is parsed. Each address must be non-mainnet (testnet or
/// regtest), matching bip321's `tb` rule.
pub fn parse_tsp(
    fields: &[FieldWithAttributes<String>],
) -> Result<Vec<SilentPaymentCode>, SpUriParseError> {
    parse_slot(fields, Network::Testnet)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bip321::Bip321Uri;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use silentpayments::SpVersion;

    use super::{
        Network, SilentPaymentCode, SpUriExtension, SpUriParseError, parse_sp, parse_tsp,
    };

    fn make_sp_address(network: Network) -> SilentPaymentCode {
        let secp = Secp256k1::new();
        let (scan_bytes, spend_bytes) = match network {
            Network::Mainnet => ([0x03; 32], [0x04; 32]),
            Network::Testnet => ([0x01; 32], [0x02; 32]),
            Network::Regtest => ([0x05; 32], [0x06; 32]),
        };
        let scan = SecretKey::from_slice(&scan_bytes)
            .unwrap()
            .public_key(&secp);
        let spend = SecretKey::from_slice(&spend_bytes)
            .unwrap()
            .public_key(&secp);
        SilentPaymentCode::new(scan, spend, network, SpVersion::ZERO)
    }

    fn parse(s: &str) -> Bip321Uri<SpUriExtension> {
        Bip321Uri::<SpUriExtension>::from_str(s).unwrap()
    }

    #[test]
    fn parse_sp_parameter() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = parse(&format!("bitcoin:?sp={sp}"));
        let addrs = parse_sp(uri.sp()).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].network(), Network::Mainnet);
        assert!(uri.extensions().tsp().is_empty());
    }

    #[test]
    fn parse_tsp_parameter() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = parse(&format!("bitcoin:?tsp={tsp}"));
        let addrs = parse_tsp(uri.extensions().tsp()).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].network(), Network::Testnet);
        assert!(uri.sp().is_empty());
    }

    #[test]
    fn parse_regtest_address_in_tsp_parameter() {
        let regtest = make_sp_address(Network::Regtest).to_string();
        let uri = parse(&format!("bitcoin:?tsp={regtest}"));
        let addrs = parse_tsp(uri.extensions().tsp()).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].network(), Network::Regtest);
        assert!(uri.sp().is_empty());
    }

    #[test]
    fn reject_mainnet_address_in_tsp_parameter() {
        let sp = make_sp_address(Network::Mainnet).to_string();
        let uri = parse(&format!("bitcoin:?tsp={sp}"));
        assert!(matches!(
            parse_tsp(uri.extensions().tsp()),
            Err(SpUriParseError::NetworkMismatch {
                expected: Network::Testnet,
                got: Network::Mainnet,
            })
        ));
    }

    #[test]
    fn reject_testnet_address_in_sp_parameter() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let uri = parse(&format!("bitcoin:?sp={tsp}"));
        assert!(matches!(
            parse_sp(uri.sp()),
            Err(SpUriParseError::NetworkMismatch {
                expected: Network::Mainnet,
                got: Network::Testnet,
            })
        ));
    }

    #[test]
    fn reject_regtest_address_in_sp_parameter() {
        let regtest = make_sp_address(Network::Regtest).to_string();
        let uri = parse(&format!("bitcoin:?sp={regtest}"));
        assert!(matches!(
            parse_sp(uri.sp()),
            Err(SpUriParseError::NetworkMismatch {
                expected: Network::Mainnet,
                got: Network::Regtest,
            })
        ));
    }

    #[test]
    fn sprt_query_key_is_stored_as_custom() {
        let regtest = make_sp_address(Network::Regtest).to_string();
        let sp = make_sp_address(Network::Mainnet).to_string();
        // `sprt` is not handled; unknown non-required params go to `custom`.
        let uri = parse(&format!("bitcoin:?sp={sp}&sprt={regtest}"));
        assert!(uri.extensions().tsp().is_empty());
        assert!(uri.custom().contains_key("sprt"));
        assert_eq!(parse_sp(uri.sp()).unwrap().len(), 1);
    }

    #[test]
    fn parse_mixed_non_mainnet_tsp_parameters() {
        let tsp = make_sp_address(Network::Testnet).to_string();
        let regtest = make_sp_address(Network::Regtest).to_string();
        let uri = parse(&format!("bitcoin:?tsp={tsp}&tsp={regtest}"));
        let addrs = parse_tsp(uri.extensions().tsp()).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].network(), Network::Testnet);
        assert_eq!(addrs[1].network(), Network::Regtest);
    }

    #[test]
    fn empty_slots() {
        let uri = parse("bitcoin:?bc=bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert!(parse_sp(uri.sp()).unwrap().is_empty());
        assert!(parse_tsp(uri.extensions().tsp()).unwrap().is_empty());
    }
}
