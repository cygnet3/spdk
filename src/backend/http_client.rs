use anyhow::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

// Define the trait differently for WASM vs native
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait HttpClient {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T>;
    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<T>;
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait HttpClient {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T>;
    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<T>;
}

// Native implementation using reqwest
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct NativeHttpClient {
    client: reqwest::Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl HttpClient for NativeHttpClient {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = self.client.get(url).send().await?;
        let text: String = response.text().await?;
        Ok(serde_json::from_str(&text)?)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<T> {
        let response = self.client.post(url).json(body).send().await?;
        let text: String = response.text().await?;
        Ok(serde_json::from_str(&text)?)
    }
}

#[cfg(target_arch = "wasm32")]
use js_sys::Promise;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    pub type JsHttpClient;

    #[wasm_bindgen(method, catch)]
    fn get(this: &JsHttpClient, url: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn post(this: &JsHttpClient, url: &str, body: &JsValue) -> Result<Promise, JsValue>;
}

#[cfg(target_arch = "wasm32")]
pub struct WasmHttpClient {
    pub inner: JsHttpClient,
}

#[cfg(target_arch = "wasm32")]
impl WasmHttpClient {
    pub fn new(inner: JsHttpClient) -> Self {
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl HttpClient for WasmHttpClient {
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
        body: &(impl Serialize + Sync),
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
