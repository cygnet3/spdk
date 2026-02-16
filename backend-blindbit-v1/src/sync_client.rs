use std::time::Duration;

use spdk_core::bitcoin::{Amount, Txid, absolute::Height, secp256k1::PublicKey};
use ureq::Agent;

use anyhow::Result;

use super::api_structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, InfoResponse, SpentIndexResponse,
    UtxoResponse,
};

#[derive(Clone, Debug)]
pub struct SyncBlindbitClient {
    agent: Agent,
    host_url: String,
}

impl SyncBlindbitClient {
    pub fn new(host_url: String) -> Result<Self> {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(30))
            .build();

        // we need a trailing slash, if not present we append it
        let host_url = if host_url.ends_with('/') {
            host_url
        } else {
            format!("{}/", host_url)
        };

        Ok(SyncBlindbitClient { agent, host_url })
    }

    pub fn block_height(&self) -> Result<Height> {
        let url = format!("{}block-height", self.host_url);
        let body = self.agent.get(&url).call()?.into_string()?;
        let blkheight: BlockHeightResponse = serde_json::from_str(&body)?;
        Ok(blkheight.block_height)
    }

    pub fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = format!("{}tweaks/{}", self.host_url, block_height);
        let body = self
            .agent
            .get(&url)
            .query("dustLimit", &dust_limit.to_sat().to_string())
            .call()?
            .into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn tweak_index(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = format!("{}tweak-index/{}", self.host_url, block_height);
        let body = self
            .agent
            .get(&url)
            .query("dustLimit", &dust_limit.to_sat().to_string())
            .call()?
            .into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = format!("{}utxos/{}", self.host_url, block_height);
        let body = self.agent.get(&url).call()?.into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = format!("{}spent-index/{}", self.host_url, block_height);
        let body = self.agent.get(&url).call()?.into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/new-utxos/{}", self.host_url, block_height);
        let body = self.agent.get(&url).call()?.into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/spent/{}", self.host_url, block_height);
        let body = self.agent.get(&url).call()?.into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = format!("{}forward-tx", self.host_url);
        let body = ForwardTxRequest::new(tx_hex);
        let resp = self
            .agent
            .post(&url)
            .send_json(serde_json::to_value(&body)?)?
            .into_string()?;
        Ok(serde_json::from_str(&resp)?)
    }

    pub fn info(&self) -> Result<InfoResponse> {
        let url = format!("{}info", self.host_url);
        let body = self.agent.get(&url).call()?.into_string()?;
        Ok(serde_json::from_str(&body)?)
    }
}
