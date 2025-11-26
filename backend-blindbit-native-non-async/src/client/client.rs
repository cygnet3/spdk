use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, Txid};
use url::Url;

use anyhow::Result;

use crate::client::structs::InfoResponse;

use super::http_trait::HttpClient;
use super::structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, SpentIndexResponse, UtxoResponse,
};

/// Client for interacting with a Blindbit server.
///
/// Generic over the HTTP client implementation, allowing consumers to provide
/// their own HTTP client by implementing the `HttpClient` trait.
#[derive(Clone)]
pub struct BlindbitClient<H: HttpClient> {
    http_client: H,
    host_url: Url,
}

impl<H: HttpClient> BlindbitClient<H> {
    /// Create a new Blindbit client with a custom HTTP client implementation.
    ///
    /// # Arguments
    /// * `host_url` - Base URL of the Blindbit server
    /// * `http_client` - HTTP client implementation
    pub fn new(host_url: String, http_client: H) -> Result<Self> {
        let mut host_url = Url::parse(&host_url)?;

        // we need a trailing slash, if not present we append it
        if !host_url.path().ends_with('/') {
            host_url.set_path(&format!("{}/", host_url.path()));
        }

        Ok(BlindbitClient {
            http_client,
            host_url,
        })
    }

    pub fn block_height(&self) -> Result<Height> {
        let url = self.host_url.join("block-height")?;
        let body = self.http_client.get(url.as_str(), &[])?;
        let blkheight: BlockHeightResponse = serde_json::from_str(&body)?;
        Ok(blkheight.block_height)
    }

    pub fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = self.host_url.join(&format!("tweaks/{}", block_height))?;
        let body = self.http_client.get(
            url.as_str(),
            &[("dustLimit", dust_limit.to_sat().to_string())],
        )?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn tweak_index(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = self
            .host_url
            .join(&format!("tweak-index/{}", block_height))?;
        let body = self.http_client.get(
            url.as_str(),
            &[("dustLimit", dust_limit.to_sat().to_string())],
        )?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = self.host_url.join(&format!("utxos/{}", block_height))?;
        let body = self.http_client.get(url.as_str(), &[])?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = self
            .host_url
            .join(&format!("spent-index/{}", block_height))?;
        let body = self.http_client.get(url.as_str(), &[])?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/new-utxos/{}", block_height))?;
        let body = self.http_client.get(url.as_str(), &[])?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = self
            .host_url
            .join(&format!("filter/spent/{}", block_height))?;
        let body = self.http_client.get(url.as_str(), &[])?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = self.host_url.join("forward-tx")?;
        let request = ForwardTxRequest::new(tx_hex);
        let json_body = serde_json::to_string(&request)?;
        let body = self.http_client.post_json(url.as_str(), &json_body)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn info(&self) -> Result<InfoResponse> {
        let url = self.host_url.join("info")?;
        let body = self.http_client.get(url.as_str(), &[])?;
        Ok(serde_json::from_str(&body)?)
    }
}
