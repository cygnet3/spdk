use anyhow::Result;
use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, Txid};

use crate::backend::http_client::native::{NativeHttpClient, NativeHttpClientTrait};

use crate::backend::blindbit::client::structs::InfoResponse;

use super::structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, SpentIndexResponse, UtxoResponse,
};

#[derive(Clone, Debug)]
pub struct NativeBlindbitClient {
    http_client: NativeHttpClient,
    host_url: String,
}

impl NativeBlindbitClient {
    pub fn host_url(&self) -> &str {
        &self.host_url
    }
    pub fn http_client(&self) -> &NativeHttpClient {
        &self.http_client
    }

    pub fn new(host_url: String) -> Self {
        let mut host_url = host_url;

        // we need a trailing slash, if not present we append it
        if !host_url.ends_with('/') {
            host_url.push('/');
        }

        let http_client = NativeHttpClient::new();

        Self {
            http_client,
            host_url,
        }
    }

    pub async fn block_height(&self) -> Result<Height> {
        let url = format!("{}block-height", self.host_url());
        let blkheight: BlockHeightResponse = self.http_client().get(&url).await?;
        Ok(blkheight.block_height)
    }

    pub async fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = format!(
            "{}tweaks/{}?dustLimit={}",
            self.host_url(),
            block_height,
            dust_limit.to_sat()
        );
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn tweak_index(
        &self,
        block_height: Height,
        dust_limit: Amount,
    ) -> Result<Vec<PublicKey>> {
        let url = format!(
            "{}tweak-index/{}?dustLimit={}",
            self.host_url(),
            block_height,
            dust_limit.to_sat()
        );
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = format!("{}utxos/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = format!("{}spent-index/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/new-utxos/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/spent/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    pub async fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = format!("{}forward-tx", self.host_url());
        let body = ForwardTxRequest::new(tx_hex);
        Ok(self.http_client().post(&url, &body).await?)
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let url = format!("{}info", self.host_url());
        Ok(self.http_client().get(&url).await?)
    }
}
