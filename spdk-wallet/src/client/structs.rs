use std::str::FromStr as _;

// re-export from bdk_coin_select, as we use this in the api
pub use bdk_coin_select::FeeRate;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::script::PushBytesBuf;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use silentpayments::SilentPaymentCode;
use silentpayments::utils::sending::PartialSecret;
use spdk_core::scanner::DiscoveredOutput;

use super::coin_select::Strategy;

#[derive(Debug, Clone, PartialEq)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpCode(SilentPaymentCode),
    Data(PushBytesBuf), // OpReturn output
}

impl TryFrom<String> for RecipientAddress {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp_code) = SilentPaymentCode::try_from(value.as_str()) {
            Ok(Self::SpCode(sp_code))
        } else if let Ok(legacy_address) = Address::from_str(&value) {
            Ok(Self::LegacyAddress(legacy_address))
        } else if let Ok(data) = Vec::from_hex(&value) {
            let mut buf = PushBytesBuf::new();
            buf.extend_from_slice(&data)?;

            Ok(Self::Data(buf))
        } else {
            Err(anyhow::Error::msg("Unknown recipient address type"))
        }
    }
}

impl From<RecipientAddress> for String {
    fn from(value: RecipientAddress) -> Self {
        match value {
            RecipientAddress::LegacyAddress(address) => address.assume_checked().to_string(),
            RecipientAddress::SpCode(sp_code) => sp_code.to_string(),
            RecipientAddress::Data(data) => data.as_bytes().to_lower_hex_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Recipient {
    pub address: RecipientAddress, // either old school or silent payment
    pub amount: Amount,            // must be 0 if address is Data.
}

#[derive(Debug, Clone)]
// this will be replaced by a proper psbt as soon as sp support is standardised
pub struct SilentPaymentUnsignedTransaction {
    pub selected_utxos: Vec<(OutPoint, DiscoveredOutput)>,
    pub recipients: Vec<Recipient>,
    pub partial_secret: PartialSecret,
    pub unsigned_tx: Option<Transaction>,
    pub network: Network,
    /// Wallet change amount (zero for drain / changeless selections).
    pub change: Amount,
    /// Index into `recipients` of the change output, if any.
    pub change_index: Option<usize>,
    pub fee: Amount,
    pub actual_fee_rate: FeeRate,
    /// Coin-selection strategy used for a payment; `None` for drain transactions.
    pub strategy: Option<Strategy>,
}
