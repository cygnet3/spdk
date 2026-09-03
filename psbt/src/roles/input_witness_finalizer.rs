//! PSBT Input Witness Finalizer Role
//!
//! BIP-174 input finalization. Thin spdk facade over rust-psbt's `Finalizer`,
//! which builds `final_script_witness`/`final_script_sig` from the signature
//! fields and runs an interpreter check.

use crate::core::{Error, Psbt, Result};
use psbt_v2::v2::Finalizer;
use secp256k1::Secp256k1;

pub trait InputWitnessFinalizerPsbtExt {
    /// Finalize all inputs, returning the finalized PSBT.
    fn finalize(self) -> Result<Psbt>;
}

impl InputWitnessFinalizerPsbtExt for Psbt {
    fn finalize(self) -> Result<Psbt> {
        let secp = Secp256k1::verification_only();
        Finalizer::new(self)
            .map_err(|e| Error::InvalidPsbtState(e.to_string()))?
            .finalize(&secp)
            .map_err(|e| Error::Other(e.to_string()))
    }
}
