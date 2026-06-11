#![allow(dead_code)]
use bitcoin::{Amount, BlockHash, Network, ScriptBuf, Txid, absolute::Height};
use serde::{Deserialize, Deserializer, Serialize};
use spdk_core::chain::{FilterData, SpentIndexData, UtxoData};

#[derive(Debug, Deserialize)]
pub struct BlockHeightResponse {
    pub block_height: Height,
}

#[derive(Debug, Deserialize)]
pub struct UtxoResponse {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
    pub scriptpubkey: ScriptBuf,
    pub block_height: Height,
    pub block_hash: BlockHash,
    pub timestamp: i32,
    pub spent: bool,
}

impl From<UtxoResponse> for UtxoData {
    fn from(value: UtxoResponse) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
            value: value.value,
            scriptpubkey: value.scriptpubkey,
            spent: value.spent,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SpentIndexResponse {
    pub block_hash: BlockHash,
    pub data: Vec<MyHex>,
}

impl From<SpentIndexResponse> for SpentIndexData {
    fn from(value: SpentIndexResponse) -> Self {
        Self {
            data: value.data.into_iter().map(|x| x.hex).collect(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(transparent)]
pub struct MyHex {
    #[serde(with = "hex::serde")]
    pub hex: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct FilterResponse {
    pub block_hash: BlockHash,
    pub block_height: Height,
    pub data: MyHex,
    pub filter_type: i32,
}

impl From<FilterResponse> for FilterData {
    fn from(value: FilterResponse) -> Self {
        Self {
            block_hash: value.block_hash,
            data: value.data.hex,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ForwardTxRequest {
    data: String,
}

impl ForwardTxRequest {
    pub fn new(tx_hex: String) -> Self {
        Self { data: tx_hex }
    }
}

#[derive(Debug, Deserialize)]
pub struct InfoResponse {
    #[serde(deserialize_with = "deserialize_network")]
    pub network: Network,
    pub height: Height,
    pub tweaks_only: bool,
    pub tweaks_full_basic: bool,
    pub tweaks_full_with_dust_filter: bool,
    pub tweaks_cut_through_with_dust_filter: bool,
}

fn deserialize_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    Network::from_core_arg(&buf).map_err(serde::de::Error::custom)
}

impl InfoResponse {
    /// Validates whether the server supports the requested parameters.
    ///
    /// Returns:
    /// - `Ok(use_tweaks_endpoint)` - true means use tweaks(), false means use tweak_index()
    /// - `Err(String)` if the request cannot be satisfied
    pub fn validate_and_resolve_endpoint(
        &self,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<bool, String> {
        let has_dust_limit = dust_limit > Amount::ZERO;

        match (with_cutthrough, has_dust_limit) {
            // Request: cutthrough with dust filtering
            (true, true) => {
                if self.tweaks_cut_through_with_dust_filter {
                    Ok(true)
                } else if self.tweaks_full_with_dust_filter {
                    Ok(false)
                } else {
                    Err(
                        "Server does not support dust filtering; cannot satisfy request with dust_limit"
                            .to_string(),
                    )
                }
            }

            // Request: cutthrough without dust filtering
            (true, false) => {
                // Can use tweaks endpoint without dust limit
                if self.tweaks_only
                    || self.tweaks_full_basic
                    || self.tweaks_cut_through_with_dust_filter
                {
                    Ok(true)
                } else {
                    Err("Server does not support tweaks endpoint".to_string())
                }
            }

            // Request: full index with dust filtering
            (false, true) => {
                if self.tweaks_full_with_dust_filter {
                    Ok(false)
                } else if self.tweaks_cut_through_with_dust_filter {
                    Ok(true)
                } else {
                    Err(
                        "Server does not support dust filtering; cannot satisfy request with dust_limit"
                            .to_string(),
                    )
                }
            }

            // Request: full index without dust filtering
            (false, false) => {
                if self.tweaks_full_basic {
                    Ok(false)
                } else if self.tweaks_cut_through_with_dust_filter || self.tweaks_only {
                    Ok(true)
                } else {
                    Err("Server does not support any tweak endpoints".to_string())
                }
            }
        }
    }
}
