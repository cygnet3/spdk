#![allow(clippy::module_inception)]

pub mod client;
pub mod constants;
pub mod types;
pub mod updater;

// Re-export core functionality
pub use client::*;
pub use constants::*;
pub use types::*;
pub use updater::Updater;

// Re-export commonly used external types
pub use bdk_coin_select::FeeRate;
#[cfg(feature = "mnemonic")]
pub use bip39;
pub use bitcoin;
pub use silentpayments;
