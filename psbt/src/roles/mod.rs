//! BIP-375 PSBT Roles
//!
//! Implements the PSBT roles defined in BIP-174/370/375:
//! - Creator
//! - Constructor
//! - Updater
//! - Signer
//! - SP Output Finalizer (`finalize_sp_outputs`) — BIP-352 output script derivation
//! - Input Witness Finalizer (`finalize_input_witnesses`) — BIP-174 input finalization
//! - Extractor
//!
//! ## TODO: Future Enhancements
//!
//! - **Combiner role**: For async multi-party signing workflows
//!   - Current examples use sequential signing (hardware-signer, multi-signer)
//!   - Future enhancement: Merge PSBTs from concurrent signers
//!   - Would handle union of ECDH shares, DLEQ proofs, and signatures
//!   - Conflict detection for same-field different-value scenarios

pub mod constructor;
pub mod extractor;
pub mod input_witness_finalizer;
pub mod signer;
pub mod updater;
// pub mod validation;

pub use constructor::*;
pub use extractor::*;
pub use input_witness_finalizer::*;
pub use signer::*;
pub use updater::*;
// pub use validation::*;
