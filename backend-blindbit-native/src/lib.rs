#![allow(clippy::module_inception)]
mod backend;

// Async backend - available with "async" feature
#[cfg(feature = "async")]
mod backend_async;

mod client;

// Re-export backend functionality
pub use backend::BlindbitBackend;

#[cfg(feature = "async")]
pub use backend_async::AsyncBlindbitBackend;

pub use client::{BlindbitClient, HttpClient};

#[cfg(feature = "ureq-client")]
pub use client::UreqClient;

#[cfg(feature = "async")]
pub use async_trait;
#[cfg(feature = "async")]
pub use futures;
#[cfg(feature = "async")]
pub use futures_util;
