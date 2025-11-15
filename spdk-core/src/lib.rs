pub mod backend;
pub mod client;
pub mod constants;
pub mod scanner;
pub mod types;
pub mod updater;

// Re-export core functionality
pub use backend::{BlockDataIterator, ChainBackend};
pub use client::*;
pub use constants::*;
pub use types::*;
pub use updater::Updater;

// Re-export commonly used external types
pub use bdk_coin_select::FeeRate;
pub use bitcoin;
pub use silentpayments;
