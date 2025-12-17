// Sync backend - wraps async calls with block_on, requires futures and async-trait
#[cfg(feature = "sync")]
mod backend;

// Async backend - available with "async" feature
#[cfg(feature = "async")]
mod backend_async;

mod client;

// Re-export backend functionality
#[cfg(feature = "sync")]
pub use backend::BlindbitBackend;

#[cfg(feature = "async")]
pub use backend_async::AsyncBlindbitBackend;

pub use client::{BlindbitClient, HttpClient};

#[cfg(feature = "ureq-client")]
pub use client::UreqClient;

#[cfg(feature = "reqwest-client")]
pub use client::ReqwestClient;

#[cfg(feature = "async")]
pub use async_trait;
#[cfg(feature = "async")]
pub use futures;
#[cfg(feature = "async")]
pub use futures_util;
