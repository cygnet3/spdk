use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use super::http_trait::HttpClient;

/// Default HTTP client implementation using reqwest.
///
/// This is the full-featured but heavier option (~1.5MB with rustls + tokio).
///
/// **Binary size impact:**
/// - reqwest + hyper: ~200KB
/// - rustls + ring: ~1.1MB
/// - tokio runtime: ~500KB
///
/// If you need smaller binaries, implement `HttpClient` with a lighter alternative.
#[derive(Clone, Debug)]
pub struct ReqwestClient {
    client: Client,
}

impl ReqwestClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
        let mut req = self.client.get(url).timeout(Duration::from_secs(5));

        for (key, val) in query_params {
            req = req.query(&[(key, val)]);
        }

        let res = req.send().await?;
        Ok(res.text().await?)
    }

    async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        let res = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(json_body.to_string())
            .send()
            .await?;
        Ok(res.text().await?)
    }
}
