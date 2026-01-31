use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP GET failed: {0}")]
    HttpGet(String),
    #[error("HTTP POST failed: {0}")]
    HttpPost(String),
    #[error("failed to read response body: {0}")]
    ResponseBody(String),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidHeight(#[from] bitcoin::absolute::ConversionError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for spdk_core::Error {
    fn from(e: Error) -> Self {
        spdk_core::Error::Backend(Box::new(e))
    }
}
