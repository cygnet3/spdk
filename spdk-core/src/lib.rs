pub mod backend;
pub mod client;
pub mod constants;
pub mod psbt;
pub mod scanner;
pub mod types;
pub mod updater;

// Re-export core functionality
pub use backend::{BlockDataIterator, ChainBackend};
pub use client::*;
pub use constants::*;
// SpScanner is the concrete implementation - consumers don't implement traits anymore
pub use scanner::SpScanner;
pub use types::*;
pub use updater::Updater;
// Re-export commonly used external types
pub use bdk_coin_select::FeeRate;
pub use bitcoin;
pub use silentpayments;

// Async types available when "async" feature is enabled
#[cfg(feature = "async")]
pub use backend::{AsyncChainBackend, BlockDataStream};
#[cfg(feature = "async")]
pub use updater::AsyncUpdater;
