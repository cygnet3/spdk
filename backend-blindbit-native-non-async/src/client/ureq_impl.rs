use std::time::Duration;

use anyhow::{anyhow, Result};

use super::http_trait::HttpClient;

/// Minimal HTTP client implementation using ureq.
#[derive(Clone)]
pub struct UreqClient {
    timeout: Duration,
}

impl UreqClient {
    /// Create a new ureq HTTP client with default settings.
    pub fn new() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Create a new ureq HTTP client with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
        }
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
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

        let response = ureq::get(&full_url)
            .timeout(self.timeout)
            .call()
            .map_err(|e| anyhow!("HTTP GET request failed: {}", e))?
            .into_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }

    fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        let response = ureq::post(url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_string(json_body)
            .map_err(|e| anyhow!("HTTP POST request failed: {}", e))?
            .into_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }
}
