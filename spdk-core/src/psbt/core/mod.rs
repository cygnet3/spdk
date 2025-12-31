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
pub mod extensions;
pub mod shares;
pub mod types;

pub use error::{Error, Result};
pub use extensions::{
    get_input_bip32_pubkeys, get_input_outpoint, get_input_outpoint_bytes, get_input_pubkey,
    get_input_txid, get_input_vout, Bip375PsbtExt, GlobalFieldsExt, InputFieldsExt,
    OutputFieldsExt,
};
pub use shares::{aggregate_ecdh_shares, AggregatedShare, AggregatedShares};
pub use types::{EcdhShareData, PsbtInput, PsbtOutput};

/// Type alias for PSBT v2 with BIP-375 extensions
///
/// Use the `Bip375PsbtExt` trait to access BIP-375 specific functionality.
pub type SilentPaymentPsbt = psbt_v2::v2::Psbt;
pub type PsbtKey = psbt_v2::raw::Key;
