use std::time::Duration;

use async_trait::async_trait;

use crate::error::{Error, Result};
use super::http_trait::HttpClient;

/// Minimal HTTP client implementation using ureq.
///
/// This is a lightweight, blocking HTTP client that's perfect for basic needs.
/// It uses about ~200KB of binary size and has minimal dependencies.
///
/// # Example
///
/// ```ignore
/// use backend_blindbit_native::{UreqClient, BlindbitBackend};
///
/// let http_client = UreqClient::new();
/// let backend = BlindbitBackend::new("https://blindbit.io".to_string(), http_client)?;
/// ```
#[derive(Clone)]
pub struct UreqClient {
    agent: ureq::Agent,
}

impl UreqClient {
    /// Create a new ureq HTTP client with default settings.
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(30)))
                .build()
                .into(),
        }
    }

    /// Create a new ureq HTTP client with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(timeout_secs)))
                .build()
                .into(),
        }
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for UreqClient {
    async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
        let mut req = self.agent.get(url);

        for (key, value) in query_params {
            req = req.query(key, value);
        }

        // Perform blocking request (wrapped in async for trait compatibility)
        let mut response = req
            .call()
            .map_err(|e| Error::HttpGet(e.to_string()))?;

        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::ResponseBody(e.to_string()))?;

        Ok(body)
    }

    async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        // Perform blocking request (wrapped in async for trait compatibility)
        let response = self
            .agent
            .post(url)
            .header("Content-Type", "application/json")
            .send(json_body)
            .map_err(|e| Error::HttpPost(e.to_string()))?
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::ResponseBody(e.to_string()))?;

        Ok(response)
    }
}
