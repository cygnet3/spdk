#![allow(dead_code)]
use anyhow::bail;
use bitcoin::absolute::Height;
use bitcoin::{Amount, BlockHash, Network, ScriptBuf, Txid, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize};
use spdk_core::chain::{SpentIndexData, UtxoData};

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

impl TryFrom<UtxoResponse> for UtxoData {
    type Error = anyhow::Error;

    fn try_from(value: UtxoResponse) -> Result<Self, Self::Error> {
        if value.scriptpubkey.is_p2tr() {
            let output_key = XOnlyPublicKey::from_slice(&value.scriptpubkey.to_bytes()[2..])?;
            Ok(Self {
                txid: value.txid,
                vout: value.vout,
                value: value.value,
                output_key,
                spent: value.spent,
            })
        } else {
            bail!("Non-taproot scriptpubkey: {}", value.scriptpubkey)
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

#[derive(Debug, Serialize)]
pub struct ForwardTxRequest {
    data: String,
}

impl ForwardTxRequest {
    pub const fn new(tx_hex: String) -> Self {
        Self { data: tx_hex }
    }
}

#[expect(clippy::struct_excessive_bools)]
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
