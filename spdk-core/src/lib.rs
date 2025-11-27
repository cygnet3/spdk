#![allow(clippy::module_inception)]
#[cfg(all(feature = "async", feature = "sync"))]
compile_error!("Cannot use both sync & async features together");

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
pub use scanner::SpScanner;
pub use types::*;
pub use updater::Updater;
// Re-export commonly used external types
pub use bdk_coin_select::FeeRate;
pub use bitcoin;
pub use silentpayments;

// Async types available by default, excluded when "sync" feature is enabled
#[cfg(feature = "async")]
pub use backend::{AsyncChainBackend, BlockDataStream};
#[cfg(feature = "async")]
pub use scanner::AsyncSpScanner;
#[cfg(feature = "async")]
pub use updater::AsyncUpdater;
