use std::rc::Rc;

use anyhow::Result;
use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, Txid};
use wasm_bindgen::prelude::*;

use crate::backend::{blindbit::client::structs::{BlockHeightResponse, FilterResponse, ForwardTxRequest, InfoResponse, SpentIndexResponse, UtxoResponse}, http_client::wasm::{WasmHttpClient, WasmHttpClientTrait}};

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmBlindbitClient {
    http_client: Rc<WasmHttpClient>,
    host_url: String,
}

#[wasm_bindgen]
impl WasmBlindbitClient {
    #[wasm_bindgen(constructor)]
    pub fn new(host_url: String, http_client: JsValue) -> Self {
        let js_client = http_client.dyn_into().unwrap_or_else(|_| {
            wasm_bindgen::throw_str("Failed to convert to JsHttpClient");
        });
        let wasm_client = WasmHttpClient::new(js_client);
        Self {
            http_client: Rc::new(wasm_client),
            host_url,
        }
    }
}

impl WasmBlindbitClient {
    pub fn host_url(&self) -> &str {
        &self.host_url
    }

    pub fn http_client(&self) -> &WasmHttpClient {
        self.http_client.as_ref()
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
