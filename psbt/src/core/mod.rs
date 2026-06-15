//! BIP-375 Core Library
//!
//! Core data structures and types for BIP-375 (Sending Silent Payments with PSBTs).
//!
//! This crate provides:
//! - PSBT v2 data structures
//! - Silent payment address types
//! - ECDH share types
//! - UTXO types

pub mod error;
pub mod utils;

pub use error::{Error, Result};
pub use psbt_v2::v2::{Global, Input, Output, Psbt};

pub type PsbtKey = psbt_v2::raw::Key;
