//! # Backend Blindbit WASM
//!
//! **⚠️ WASM-only crate**: This crate is designed specifically for WebAssembly targets.
//!
//! ## Build Requirements
//!
//! This crate must be compiled with the `wasm32-unknown-unknown` target:
//!
//! ```bash
//! cargo build -p backend-blindbit-wasm --target wasm32-unknown-unknown
//! ```
//!
//! ## IDE Setup
//!
//! If you see errors in rust-analyzer, it's because it's checking with the native target.
//! To fix this, you can either:
//!
//! 1. Set your IDE to use the WASM target for this crate
//! 2. Or ignore the errors - they won't appear when building with the correct target
//!
//! ## HTTP Client
//!
//! This crate uses `reqwest` which automatically uses the browser's `fetch()` API when
//! compiled to WebAssembly.

#![allow(clippy::module_inception)]

mod backend;
mod scanner;

// Re-export backend functionality
pub use backend::{BlindbitBackend, BlindbitClient, ChainBackend};
pub use scanner::SpScanner;

use sp_client::*;

pub use wasm_bindgen_futures;
