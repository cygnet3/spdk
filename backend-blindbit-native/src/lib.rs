#![allow(clippy::module_inception)]
mod backend;
mod scanner;

// Re-export backend functionality
pub use backend::{BlindbitBackend, BlindbitClient, ChainBackend};
pub use scanner::SpScanner;

// Re-export core client for convenience (includes Updater)
pub use sp_client::*;
