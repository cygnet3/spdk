use std::fmt;
use std::string::String;

use bip21::de::{DeserializationError, DeserializationState, DeserializeParams, ParamKind};
use bip21::ser::SerializeParams;
use bip21::Param;
use silentpayments::SilentPaymentAddress;

/// Error returned when parsing the `sp=` extras field of a BIP 321 URI.
#[derive(Debug)]
pub enum SpExtrasError {
    Utf8(std::str::Utf8Error),
    Address(silentpayments::Error),
    DuplicateSp,
}

impl fmt::Display for SpExtrasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpExtrasError::Utf8(e) => write!(f, "invalid UTF-8 in sp parameter: {}", e),
            SpExtrasError::Address(e) => write!(f, "invalid silent payment address: {}", e),
            SpExtrasError::DuplicateSp => write!(f, "duplicate sp parameter in URI"),
        }
    }
}

impl std::error::Error for SpExtrasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpExtrasError::Utf8(e) => Some(e),
            SpExtrasError::Address(e) => Some(e),
            SpExtrasError::DuplicateSp => None,
        }
    }
}

/// BIP 321 extras carrying a Silent Payment address from the `sp=` query parameter.
///
/// BIP 321 defines `sp` as the standard key for BIP 352 Silent Payment addresses.
#[derive(Debug, Default, Clone)]
pub struct SpExtras {
    pub sp: Option<SilentPaymentAddress>,
}

impl DeserializationError for SpExtras {
    type Error = SpExtrasError;
}

/// Deserialization state for [`SpExtras`].
#[derive(Debug, Default)]
pub struct SpExtrasState {
    sp: Option<SilentPaymentAddress>,
}

impl<'de> DeserializationState<'de> for SpExtrasState {
    type Value = SpExtras;

    fn is_param_known(&self, key: &str) -> bool {
        // BIP 321: query parameter keys are case-insensitive
        key.eq_ignore_ascii_case("sp")
    }

    fn deserialize_temp(
        &mut self,
        key: &str,
        value: Param<'_>,
    ) -> Result<ParamKind, SpExtrasError> {
        if key.eq_ignore_ascii_case("sp") {
            if self.sp.is_some() {
                return Err(SpExtrasError::DuplicateSp);
            }
            let s = String::try_from(value).map_err(SpExtrasError::Utf8)?;
            let addr =
                SilentPaymentAddress::try_from(s.as_str()).map_err(SpExtrasError::Address)?;
            self.sp = Some(addr);
            Ok(ParamKind::Known)
        } else {
            Ok(ParamKind::Unknown)
        }
    }

    fn finalize(self) -> Result<SpExtras, SpExtrasError> {
        Ok(SpExtras { sp: self.sp })
    }
}

impl<'de> DeserializeParams<'de> for SpExtras {
    type DeserializationState = SpExtrasState;
}

impl<'a> SerializeParams for &'a SpExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::option::IntoIter<(&'static str, String)>;

    fn serialize_params(self) -> Self::Iterator {
        self.sp
            .as_ref()
            .map(|addr| ("sp", addr.to_string()))
            .into_iter()
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
/// ```
pub type SpUri<'a> = bip21::Uri<'a, bitcoin::address::NetworkUnchecked, SpExtras>;
