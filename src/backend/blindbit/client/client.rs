use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, Txid};
use url::Url;

use anyhow::Result;

use crate::backend::blindbit::client::structs::InfoResponse;

use super::structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, SpentIndexResponse, UtxoResponse,
};

#[derive(Clone, Debug)]
pub struct BlindbitClient {
    host_url: Url,
}

impl BlindbitClient {
    pub fn new(host_url: String) -> Result<Self> {
        let mut host_url = Url::parse(&host_url)?;

        // we need a trailing slash, if not present we append it
        if !host_url.path().ends_with('/') {
            host_url.set_path(&format!("{}/", host_url.path()));
        }

        Ok(BlindbitClient { host_url })
    }

    pub fn block_height(&self) -> Result<Height> {
        let url = self.host_url.join("block-height")?;

        let res = minreq::get(url).with_timeout(5).send()?;
        let blkheight: BlockHeightResponse = res.json()?;
        Ok(blkheight.block_height)
    }

    pub fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let mut url = self.host_url.join(&format!("tweaks/{}", block_height))?;

        url.set_query(Some(&format!("dustLimit={}", dust_limit.to_sat())));

        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn tweak_index(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let mut url = self
            .host_url
            .join(&format!("tweak-index/{}", block_height))?;
        url.set_query(Some(&format!("dustLimit={}", dust_limit.to_sat())));

        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = self.host_url.join(&format!("utxos/{}", block_height))?;
        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = self
            .host_url
            .join(&format!("spent-index/{}", block_height))?;
        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/new-utxos/{}", block_height))?;

        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/spent/{}", block_height))?;
        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }

    pub fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = self.host_url.join("forward-tx")?;

        let body = ForwardTxRequest::new(tx_hex);

        let res = minreq::post(url.as_str())
            .with_body(serde_json::to_string(&body)?)
            .with_header("Content-Type", "application/json")
            .send()?;
        Ok(res.json()?)
    }

    pub fn info(&self) -> Result<InfoResponse> {
        let url = self.host_url.join("info")?;

        let res = minreq::get(url).send()?;
        Ok(res.json()?)
    }
}
