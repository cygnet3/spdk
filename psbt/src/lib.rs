//! BIP-375 PSBT Module
//!
//! This module contains all BIP-375 PSBT functionality, organized into submodules:
//! - `core`: Core data structures and types
//! - `crypto`: Cryptographic primitives
//! - `helpers`: Helper utilities for display and wallet operations
//! - `roles`: PSBT role implementations (creator, constructor, updater, signer, etc.)

pub mod core;
pub mod roles;

// Re-export commonly used types from core
pub use core::{Error, Psbt, PsbtKey, Result};

// Re-export DleqProof from psbt_v2
pub use rust_dleq::{generate_dleq_proof, verify_dleq_proof, DleqError, DleqProof};
