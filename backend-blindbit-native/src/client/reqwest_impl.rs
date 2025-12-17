use anyhow::{anyhow, Result};
use async_trait::async_trait;

use super::http_trait::HttpClient;

/// Async HTTP client implementation using reqwest.
///
/// This is a fully async HTTP client built on top of tokio/hyper.
/// It's more feature-rich than ureq but requires an async runtime.
///
/// # Performance Recommendation
///
/// **Use with `AsyncBlindbitBackend` for best performance:**
/// - Enables 200+ concurrent requests
/// - Full connection pooling and async benefits
/// - Proper utilization of tokio runtime
///
/// **Avoid with `BlindbitBackend` (sync):**
/// - Each request blocks the thread via `block_on`
/// - No concurrency (sequential processing)
/// - Pulls in ~2MB tokio runtime with zero async benefit
/// - Consider `UreqClient` instead for sync usage (~800KB, truly blocking)
///
/// # Example (Recommended - Async)
///
/// ```ignore
/// use backend_blindbit_native::{ReqwestClient, AsyncBlindbitBackend};
///
/// #[tokio::main]
/// async fn main() {
///     let http_client = ReqwestClient::new();
///     let backend = AsyncBlindbitBackend::new("https://blindbit.io".to_string(), http_client)?;
///     // Benefits from concurrent requests
/// }
/// ```
///
/// # Example (Not Recommended - Sync)
///
/// ```ignore
/// use backend_blindbit_native::{ReqwestClient, BlindbitBackend};
///
/// // This works but is inefficient - use UreqClient instead
/// let http_client = ReqwestClient::new();
/// let backend = BlindbitBackend::new("https://blindbit.io".to_string(), http_client)?;
/// ```
#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
}

impl ReqwestClient {
    /// Create a new reqwest HTTP client with default settings.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build reqwest client"),
        }
    }

    /// Create a new reqwest HTTP client with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()
                .expect("Failed to build reqwest client"),
        }
    }

    /// Create a new reqwest HTTP client with a custom client configuration.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
        // Build request with query parameters
        let mut request = self.client.get(url);

        for (key, value) in query_params {
            request = request.query(&[(key, value)]);
        }

        // Perform async request
        let response = request
            .send()
            .await
            .map_err(|e| anyhow!("HTTP GET request failed: {}", e))?
            .error_for_status()
            .map_err(|e| anyhow!("HTTP GET request returned error status: {}", e))?
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }

    async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        // Perform async request
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(json_body.to_string())
            .send()
            .await
            .map_err(|e| anyhow!("HTTP POST request failed: {}", e))?
            .error_for_status()
            .map_err(|e| anyhow!("HTTP POST request returned error status: {}", e))?
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }
}
