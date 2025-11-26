use std::time::Duration;

use anyhow::{anyhow, Result};

use super::http_trait::HttpClient;

/// Minimal HTTP client implementation using ureq.
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

impl HttpClient for UreqClient {
    fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
        let mut req = self.agent.get(url);

        for (key, value) in query_params {
            req = req.query(key, value);
        }

        let mut response = req
            .call()
            .map_err(|e| anyhow!("HTTP GET request failed: {}", e))?;

        let body = String::new();
        response
            .body_mut()
            .read_to_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(body)
    }

    fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        let response = self
            .agent
            .post(url)
            .header("Content-Type", "application/json")
            .send(json_body)
            .map_err(|e| anyhow!("HTTP POST request failed: {}", e))?
            .body_mut()
            .read_to_string()
            .map_err(|e| anyhow!("Failed to read response body: {}", e))?;

        Ok(response)
    }
}
