//! BIP-375 extensions for `psbt-v2` PSBTs.
//!
//! - [`signer`]: ECDH shares and silent-payment output derivation.
//! - [`extractor`]: output-script check before extraction.
//!
//! `Psbt` and the upstream signer, finalizer, and extractor types are in `psbt-v2`.
//!
//! A combiner for concurrent signers is not implemented. It would merge ECDH shares, DLEQ
//! proofs, and signatures, and reject conflicting values for the same field.

pub mod extractor;
pub mod signer;
