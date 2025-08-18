use anyhow::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[async_trait(?Send)]
pub trait WasmHttpClientTrait {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T>;
    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<T>;
}

#[wasm_bindgen]
extern "C" {
    pub type JsHttpClient;

    #[wasm_bindgen(method, catch)]
    fn get(this: &JsHttpClient, url: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn post(this: &JsHttpClient, url: &str, body: &JsValue) -> Result<Promise, JsValue>;
}

pub struct WasmHttpClient {
    pub inner: JsHttpClient,
}

impl WasmHttpClient {
    pub fn new(inner: JsHttpClient) -> Self {
        Self { inner }
    }
}

#[async_trait(?Send)]
impl WasmHttpClientTrait for WasmHttpClient {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let p = self
            .inner
            .get(url)
            .map_err(|e| anyhow::anyhow!("get() threw: {:?}", e))?;
        let v = JsFuture::from(p)
            .await
            .map_err(|e| anyhow::anyhow!("promise rejected: {:?}", e))?;
        let t: T = serde_wasm_bindgen::from_value(v)
            .map_err(|e| anyhow::anyhow!("deserialize error: {}", e))?;
        Ok(t)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<T> {
        let body_js = serde_wasm_bindgen::to_value(body)
            .map_err(|e| anyhow::anyhow!("serialize body error: {}", e))?;
        let p = self
            .inner
            .post(url, &body_js)
            .map_err(|e| anyhow::anyhow!("post() threw: {:?}", e))?;
        let v = JsFuture::from(p)
            .await
            .map_err(|e| anyhow::anyhow!("promise rejected: {:?}", e))?;
        let t: T = serde_wasm_bindgen::from_value(v)
            .map_err(|e| anyhow::anyhow!("deserialize error: {}", e))?;
        Ok(t)
    }
}
