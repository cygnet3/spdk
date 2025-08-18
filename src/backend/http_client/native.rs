use anyhow::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
pub trait NativeHttpClientTrait {
    async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T>;
    async fn post<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<T>;
}

// Native implementation using reqwest
#[derive(Clone, Debug)]
pub struct NativeHttpClient {
    client: reqwest::Client,
}

impl NativeHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl NativeHttpClientTrait for NativeHttpClient {
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
