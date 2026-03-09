use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use serde::{Deserialize, Serialize};
use silentpayments::SilentPaymentAddress;

use spdk_core::updater::DiscoveredOutput;

// re-export from bdk_coin_select, as we use this in the api
pub use bdk_coin_select::FeeRate;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpAddress(SilentPaymentAddress),
    Data(Vec<u8>), // OpReturn output
}

impl TryFrom<String> for RecipientAddress {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp_address) = SilentPaymentAddress::try_from(value.as_str()) {
            Ok(Self::SpAddress(sp_address))
        } else if let Ok(legacy_address) = Address::from_str(&value) {
            Ok(Self::LegacyAddress(legacy_address))
        } else if let Ok(data) = Vec::from_hex(&value) {
            Ok(Self::Data(data))
        } else {
            Err(anyhow::Error::msg("Unknown recipient address type"))
        }
    }
}

impl From<RecipientAddress> for String {
    fn from(value: RecipientAddress) -> Self {
        match value {
            RecipientAddress::LegacyAddress(address) => address.assume_checked().to_string(),
            RecipientAddress::SpAddress(sp_address) => sp_address.to_string(),
            RecipientAddress::Data(data) => data.to_lower_hex_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Recipient {
    pub address: RecipientAddress, // either old school or silent payment
    pub amount: Amount,            // must be 0 if address is Data.
}

#[derive(Debug, Clone)]
// this will be replaced by a proper psbt as soon as sp support is standardised
pub struct SilentPaymentUnsignedTransaction {
    pub selected_utxos: Vec<(OutPoint, DiscoveredOutput)>,
    pub recipients: Vec<Recipient>,
    pub partial_secret: SecretKey,
    pub unsigned_tx: Option<Transaction>,
    pub network: Network,
}

pub use spdk_core::keys::SpendKey;
