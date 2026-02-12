use std::time::Duration;

use crate::error::{Error, Result};

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
                // ureq defaults to max 10 idle connections (3 per host), but the
                // scanner runs up to 200 concurrent threads (CONCURRENT_FILTER_REQUESTS).
                // With the default pool size, ~197 threads open fresh TCP sockets on
                // every request; those sockets enter TIME_WAIT for ~60s after use,
                // eventually exhausting the OS ephemeral port range (~28k ports) and
                // causing EADDRNOTAVAIL (os error 99).
                // Setting the pool size to match concurrency lets all threads reuse
                // persistent HTTP keep-alive connections instead of opening new ones.
                .max_idle_connections(200)
                .max_idle_connections_per_host(200)
                .build()
                .into(),
        }
    }

    /// Create a new ureq HTTP client with a custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(timeout_secs)))
                // See new() for rationale on pool size.
                .max_idle_connections(200)
                .max_idle_connections_per_host(200)
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
            .map_err(|e| Error::HttpGet(e.to_string()))?;

        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::ResponseBody(e.to_string()))?;

        Ok(body)
    }

    fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
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
