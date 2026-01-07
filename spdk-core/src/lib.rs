//! # spdk-core: Silent Payments Development Kit
//!
//! A modular implementation of [BIP352 Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
//! with flexible feature flags for different use cases.
//!
//! ## Feature Flags
//!
//! ### Protocol Features
//! - **`sending`** - Create silent payment outputs (requires `bitcoin_hashes`, `hex-conservative`)
//! - **`receiving`** - Scan for owned outputs (requires `bitcoin_hashes`, `hex-conservative`, `bimap`)
//!
//! ### High-Level Features  
//! - **`client`** - Wallet client with scanning (requires `receiving`)
//! - **`spending`** - Client with spending capability (requires `client` + `sending`)
//! - **`scanner`** - Blockchain scanning infrastructure (requires `client`)
//! - **`wallet`** - Full wallet functionality (requires `spending` + `scanner`) - **Default**
//!
//! ### Optional Capabilities
//! - **`async`** - Async APIs (requires `futures`, `async-trait`)
//! - **`parallel`** - CPU parallelization with rayon (native only)
//!
//! ## Usage Examples
//!
//! ### Scan-only client (lightweight)
//! ```toml
//! spdk-core = { version = "0.1", default-features = false, features = ["client"] }
//! ```
//!
//! ### Full wallet (default)
//! ```toml
//! spdk-core = "0.1"
//! ```
//!
//! ### Just sending (minimal)
//! ```toml
//! spdk-core = { version = "0.1", default-features = false, features = ["sending"] }
//! ```

pub mod backend;
#[cfg(feature = "client")]
pub mod client;
pub mod constants;
pub mod protocol;
#[cfg(feature = "scanner")]
pub mod scanner;
pub mod types;
#[cfg(feature = "client")]
pub mod updater;

// Re-export core functionality
pub use backend::{BlockDataIterator, ChainBackend};
#[cfg(feature = "client")]
pub use client::*;
pub use constants::*;
#[cfg(feature = "scanner")]
pub use scanner::SpScanner;
pub use types::*;
#[cfg(feature = "client")]
pub use updater::Updater;

// Re-export commonly used external types
pub use bdk_coin_select::FeeRate;
pub use bitcoin;

// Re-export protocol modules based on features
#[cfg(feature = "sending")]
pub use protocol::sending;
#[cfg(feature = "receiving")]
pub use protocol::receiving;

// Async types available when "async" feature is enabled
#[cfg(feature = "async")]
pub use backend::{AsyncChainBackend, BlockDataStream};
#[cfg(all(feature = "async", feature = "client"))]
pub use updater::AsyncUpdater;
