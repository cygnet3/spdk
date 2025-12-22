//! BIP-375 PSBT Roles
//!
//! Implements the six PSBT roles defined in BIP-174/370/375:
//! - Creator
//! - Constructor
//! - Updater
//! - Signer
//! - Input Finalizer
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
pub mod creator;
pub mod extractor;
pub mod input_finalizer;
pub mod signer;
pub mod updater;
pub mod validation;

pub use constructor::*;
pub use creator::*;
pub use extractor::*;
pub use input_finalizer::*;
pub use signer::*;
pub use updater::*;
pub use validation::*;
