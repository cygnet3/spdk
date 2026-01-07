//! Blockchain data source abstraction.
//!
//! This module defines traits for fetching blockchain data needed for
//! silent payment scanning, including transaction filters and UTXOs.
//!
//! ## Traits
//!
//! - [`ChainBackend`] - Synchronous blockchain data interface
//! - [`AsyncChainBackend`] - Asynchronous blockchain data interface (requires `async` feature)
//!
//! ## Feature Requirements
//!
//! - [`AsyncChainBackend`] requires the `async` feature (enabled by default)
//!
//! Implementations can connect to Bitcoin Core RPC, Electrum servers,
//! or specialized indexers like Blindbit.

mod backend;

// Async backend - available by default, excluded when "sync" feature is enabled
#[cfg(feature = "async")]
mod backend_async;

pub use backend::{BlockDataIterator, ChainBackend};

#[cfg(feature = "async")]
pub use backend_async::{AsyncChainBackend, BlockDataStream};
