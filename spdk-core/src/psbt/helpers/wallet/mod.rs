//! Wallet utilities for examples and demos
//!
//! Provides virtual wallet and transaction configuration types for building
//! BIP-375 demonstration applications.

pub mod types;

pub use types::{SimpleWallet, TransactionConfig, Utxo, VirtualWallet};
