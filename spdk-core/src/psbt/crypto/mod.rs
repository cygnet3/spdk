//! BIP-375 Cryptographic Primitives
//!
//! This crate provides cryptographic functions for BIP-375 silent payments:
//! - BIP-352 silent payment cryptography
//! - BIP-374 DLEQ proofs
//! - Transaction signing (P2WPKH)
//! - Script type utilities

pub mod bip352;
pub mod dleq;
pub mod error;
pub mod signing;

pub use bip352::*;
pub use dleq::*;
pub use error::{CryptoError, Result};
pub use signing::*;
