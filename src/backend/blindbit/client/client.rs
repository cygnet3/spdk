use anyhow::Result;
use bitcoin::{absolute::Height, secp256k1::PublicKey, Amount, Txid};

use crate::backend::http_client::HttpClient;
#[cfg(not(target_arch = "wasm32"))]
use crate::backend::http_client::NativeHttpClient;
#[cfg(target_arch = "wasm32")]
use crate::backend::http_client::WasmHttpClient;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

use crate::backend::blindbit::client::structs::InfoResponse;

use super::structs::{
    BlockHeightResponse, FilterResponse, ForwardTxRequest, SpentIndexResponse, UtxoResponse,
};

pub trait BlindbitClient {
    type Client: HttpClient;

    fn host_url(&self) -> &str;
    fn http_client(&self) -> &Self::Client;

    async fn block_height(&self) -> Result<Height> {
        let url = format!("{}block-height", self.host_url());
        let blkheight: BlockHeightResponse = self.http_client().get(&url).await?;
        Ok(blkheight.block_height)
    }

    async fn tweaks(&self, block_height: Height, dust_limit: Amount) -> Result<Vec<PublicKey>> {
        let url = format!(
            "{}tweaks/{}?dustLimit={}",
            self.host_url(),
            block_height,
            dust_limit.to_sat()
        );
        Ok(self.http_client().get(&url).await?)
    }

    async fn tweak_index(
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

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoResponse>> {
        let url = format!("{}utxos/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexResponse> {
        let url = format!("{}spent-index/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    async fn filter_new_utxos(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/new-utxos/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    async fn filter_spent(&self, block_height: Height) -> Result<FilterResponse> {
        let url = format!("{}filter/spent/{}", self.host_url(), block_height);
        Ok(self.http_client().get(&url).await?)
    }

    async fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        let url = format!("{}forward-tx", self.host_url());
        let body = ForwardTxRequest::new(tx_hex);
        Ok(self.http_client().post(&url, &body).await?)
    }

    async fn info(&self) -> Result<InfoResponse> {
        let url = format!("{}info", self.host_url());
        Ok(self.http_client().get(&url).await?)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct NativeBlindbitClient {
    http_client: NativeHttpClient,
    host_url: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeBlindbitClient {
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

    pub fn host_url(&self) -> &str {
        &self.host_url
    }

    pub fn http_client(&self) -> &NativeHttpClient {
        &self.http_client
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl BlindbitClient for NativeBlindbitClient {
    type Client = NativeHttpClient;

    fn host_url(&self) -> &str {
        &self.host_url
    }
    fn http_client(&self) -> &Self::Client {
        &self.http_client
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmBlindbitClient {
    http_client: Rc<WasmHttpClient>,
    host_url: String,
}

#[cfg(target_arch = "wasm32")]
impl WasmBlindbitClient {
    pub fn http_client(&self) -> &WasmHttpClient {
        self.http_client.as_ref()
    }
}
#[cfg(target_arch = "wasm32")]
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

#[cfg(target_arch = "wasm32")]
impl BlindbitClient for WasmBlindbitClient {
    type Client = WasmHttpClient;

    fn host_url(&self) -> &str {
        &self.host_url
    }
    fn http_client(&self) -> &Self::Client {
        self.http_client.as_ref()
    }
}
