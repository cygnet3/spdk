//! BIP352 Silent Payments protocol implementation.
//!
//! This module provides the core protocol primitives for sending and receiving
//! silent payments according to [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki).
//!
//! ## Module Organization
//!
//! - [`sending`] - Create outputs for silent payment recipients
//! - [`receiving`] - Scan and identify owned silent payment outputs  
//! - [`utils`] - Low-level utilities for both sending and receiving
//! - [`error`] - Protocol-specific error types
//!
//! ## Feature Flags
//!
//! This module is feature-gated:
//!
//! - **`sending`** - Enables [`sending`] module (requires `bitcoin_hashes`, `hex-conservative`)
//! - **`receiving`** - Enables [`receiving`] module (requires `bitcoin_hashes`, `hex-conservative`, `bimap`)
//!
//! ## Examples
//!
//! ### Sending to a Silent Payment Address
//!
//! ```ignore
//! use spdk_core::protocol::sending::generate_recipient_pubkeys;
//! 
//! // Calculate partial secret first (see utils::sending)
//! let outputs = generate_recipient_pubkeys(recipients, partial_secret)?;
//! ```
//!
//! ### Scanning for Received Outputs
//!
//! ```ignore
//! use spdk_core::protocol::receiving::Receiver;
//!
//! let receiver = Receiver::new(version, scan_pubkey, spend_pubkey, change_label, network)?;
//! let found = receiver.scan_transaction(&ecdh_shared_secret, pubkeys_to_check)?;
//! ```
#![allow(dead_code, non_snake_case)]
pub mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
pub mod utils;

#[cfg(any(feature = "sending", feature = "receiving"))]
pub use bitcoin_hashes;
pub use bitcoin::secp256k1;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
