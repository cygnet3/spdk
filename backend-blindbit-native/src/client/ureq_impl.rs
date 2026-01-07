use anyhow::{anyhow, Result};
use async_trait::async_trait;

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
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }

    /// Create a new ureq HTTP client with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build(),
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
        // Build URL with query parameters
        let mut full_url = url.to_string();
        if !query_params.is_empty() {
            full_url.push('?');
            for (i, (key, value)) in query_params.iter().enumerate() {
                if i > 0 {
                    full_url.push('&');
                }
                full_url.push_str(key);
                full_url.push('=');
                full_url.push_str(value);
            }
        }

        // Perform blocking request (wrapped in async for trait compatibility)
        let response = self
            .agent
            .get(&full_url)
            .call()
            .map_err(|e| anyhow!("HTTP GET request failed: {}", e))?
            .into_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }

    async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        // Perform blocking request (wrapped in async for trait compatibility)
        let response = self
            .agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_string(json_body)
            .map_err(|e| anyhow!("HTTP POST request failed: {}", e))?
            .into_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }
}
