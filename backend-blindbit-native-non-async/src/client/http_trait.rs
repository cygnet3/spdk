use anyhow::Result;

/// Minimal async HTTP client trait that can be implemented with any HTTP library.
///
/// This allows consumers to bring their own HTTP client implementation.
/// You can use any HTTP library you prefer: hyper, isahc, surf, ureq,
/// platform-specific APIs (NSURLSession, fetch, etc.), or any other HTTP client.
pub trait HttpClient: Send + Sync + Clone {
    /// Perform a GET request with optional query parameters.
    ///
    /// # Arguments
    /// * `url` - The full URL to request
    /// * `query_params` - Optional query parameters as key-value pairs
    ///
    /// # Returns
    /// The response body as a string
    fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String>;

    /// Perform a POST request with a JSON body.
    ///
    /// # Arguments
    /// * `url` - The full URL to request
    /// * `json_body` - The JSON body as a string
    ///
    /// # Returns
    /// The response body as a string
    fn post_json(&self, url: &str, json_body: &str) -> Result<String>;
}
