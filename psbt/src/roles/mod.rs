//! BIP-375 PSBT Roles
//!
//! Implements the PSBT roles defined in BIP-174/370/375:
//! - Signer
//!
//! ## TODO: Future Enhancements
//!
//! - **Combiner role**: For async multi-party signing workflows
//!   - Current examples use sequential signing (hardware-signer, multi-signer)
//!   - Future enhancement: Merge PSBTs from concurrent signers
//!   - Would handle union of ECDH shares, DLEQ proofs, and signatures
//!   - Conflict detection for same-field different-value scenarios

pub mod signer;

pub use signer::*;
