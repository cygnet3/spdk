use crate::error::Result;
use async_trait::async_trait;

/// Minimal async HTTP client trait that can be implemented with any HTTP library.
///
/// This allows consumers to bring their own HTTP client implementation.
/// You can use any HTTP library you prefer: hyper, isahc, surf, ureq,
/// platform-specific APIs (NSURLSession, fetch, etc.), or any other HTTP client.
///
/// The trait is async because HTTP I/O is inherently async and the library
/// benefits from concurrent requests (e.g., 200 parallel block fetches).
///
/// # Implementing the trait
///
/// Simply implement the two methods with your preferred HTTP library:
///
/// ```ignore
/// use async_trait::async_trait;
/// use backend_blindbit_native::{HttpClient, error::Result};
///
/// #[derive(Clone)]
/// struct MyHttpClient {
///     // Your HTTP client here
/// }
///
/// #[async_trait]
/// impl HttpClient for MyHttpClient {
///     async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
///         // Implement GET request with your HTTP library
///         // Build URL with query params and return response body
///         Ok("response".to_string())
///     }
///
///     async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
///         // Implement POST request with your HTTP library
///         // Send JSON body and return response body
///         Ok("response".to_string())
///     }
/// }
/// ```
#[async_trait]
pub trait HttpClient: Send + Sync + Clone {
    /// Perform a GET request with optional query parameters.
    ///
    /// # Arguments
    /// * `url` - The full URL to request
    /// * `query_params` - Optional query parameters as key-value pairs
    ///
    /// # Returns
    /// The response body as a string
    async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String>;

    /// Perform a POST request with a JSON body.
    ///
    /// # Arguments
    /// * `url` - The full URL to request
    /// * `json_body` - The JSON body as a string
    ///
    /// # Returns
    /// The response body as a string
    async fn post_json(&self, url: &str, json_body: &str) -> Result<String>;
}
