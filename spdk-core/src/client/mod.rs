//! Silent payment wallet client.
//!
//! This module provides the [`SpClient`] type which manages silent payment
//! keys, labels, and provides methods for scanning and (optionally) spending.
//!
//! ## Feature Requirements
//!
//! - Requires the `client` feature (enabled by default via `wallet`)
//! - Spending functionality requires the `sending` feature
//!
//! ## Core Types
//!
//! - [`SpClient`] - Main wallet client with scan key, spend key, and receiver
//! - [`OwnedOutput`] - Represents a detected silent payment output
//! - [`Recipient`] - Transaction recipient (silent payment or legacy address)
//! - [`SpendKey`] - Either a secret key or public key for spending
//!
//! See [`SpClient`] documentation for usage examples.

mod client;
#[cfg(feature = "sending")]
mod spend;
mod structs;

pub use client::SpClient;
pub use structs::*;
