//! BIP-374 DLEQ (Discrete Log Equality) Proofs
//!
//! This module provides DLEQ proof generation and verification using rust-dleq.
//! The rust-dleq library can be used with either:
//! - `dleq-standalone` feature: Pure Rust implementation (default)
//! - `dleq-native` feature: Direct FFI to libsecp256k1
//!
//! Note: We provide conversion between rust-dleq::DleqProof and psbt_v2::v2::dleq::DleqProof
//! since psbt-v2 defines its own DleqProof type.

use super::error::{CryptoError, Result};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// Re-export rust-dleq types for convenience
pub use rust_dleq::{DleqError, DleqProof as RustDleqProof};

// Import psbt-v2's DleqProof type under an alias
use psbt_v2::v2::dleq::DleqProof as PsbtV2DleqProof;

// ============================================================================
// Type Conversion
// ============================================================================

/// Convert rust-dleq proof to psbt-v2 proof format
pub fn to_psbt_v2_proof(proof: &RustDleqProof) -> PsbtV2DleqProof {
    PsbtV2DleqProof(*proof.as_bytes())
}

/// Convert psbt-v2 proof to rust-dleq format
pub fn from_psbt_v2_proof(proof: &PsbtV2DleqProof) -> RustDleqProof {
    RustDleqProof(proof.0)
}

// ============================================================================
// DLEQ Proof Generation and Verification
// ============================================================================

/// Generate a DLEQ proof using rust-dleq
///
/// Proves that log_G(A) = log_B(C), i.e., A = a*G and C = a*B for some secret a.
/// Returns proof in psbt-v2 format for compatibility.
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `a` - Secret scalar (private key)
/// * `b` - Public key B
/// * `r` - 32 bytes of randomness for aux randomization
/// * `m` - Optional 32-byte message to include in proof
///
/// # Returns
/// PsbtV2DleqProof (64-byte proof: e || s)
pub fn dleq_generate_proof(
    secp: &Secp256k1<secp256k1::All>,
    a: &SecretKey,
    b: &PublicKey,
    r: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<PsbtV2DleqProof> {
    let proof = rust_dleq::generate_dleq_proof(secp, a, b, r, m)
        .map_err(|e| CryptoError::DleqGenerationFailed(format!("rust-dleq error: {:?}", e)))?;

    Ok(to_psbt_v2_proof(&proof))
}

/// Verify a DLEQ proof using rust-dleq
///
/// Verifies that log_G(A) = log_B(C).
/// Accepts proof in psbt-v2 format for compatibility.
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `a` - Public key A = a*G
/// * `b` - Public key B
/// * `c` - Public key C = a*B
/// * `proof` - 64-byte proof in psbt-v2 format
/// * `m` - Optional 32-byte message
pub fn dleq_verify_proof(
    secp: &Secp256k1<secp256k1::All>,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &PsbtV2DleqProof,
    m: Option<&[u8; 32]>,
) -> Result<bool> {
    let rust_dleq_proof = from_psbt_v2_proof(proof);

    rust_dleq::verify_dleq_proof(secp, a, b, c, &rust_dleq_proof, m)
        .map_err(|_e| CryptoError::DleqVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_conversion() {
        let proof_bytes = [0x42u8; 64];
        let rust_dleq_proof = RustDleqProof(proof_bytes);
        let psbt_v2_proof = to_psbt_v2_proof(&rust_dleq_proof);
        let converted_back = from_psbt_v2_proof(&psbt_v2_proof);

        assert_eq!(rust_dleq_proof, converted_back);
        assert_eq!(psbt_v2_proof.0, proof_bytes);
    }

    #[test]
    fn test_dleq_proof_generation_and_verification() {
        let secp = Secp256k1::new();

        // Generate random keypair for party A
        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);

        // Generate random public key for party B
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);

        // Compute shared secret C = a*B
        let c = b.mul_tweak(&secp, &a.into()).unwrap();

        // Generate proof
        let rand_aux = [3u8; 32];
        let proof = dleq_generate_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Verify proof
        let valid = dleq_verify_proof(&secp, &a_pub, &b, &c, &proof, None).unwrap();
        assert!(valid);

        // Test with message
        let message = [4u8; 32];
        let proof_with_msg = dleq_generate_proof(&secp, &a, &b, &rand_aux, Some(&message)).unwrap();
        let valid_with_msg =
            dleq_verify_proof(&secp, &a_pub, &b, &c, &proof_with_msg, Some(&message)).unwrap();
        assert!(valid_with_msg);

        // Verify that proof without message doesn't verify with message
        let invalid = dleq_verify_proof(&secp, &a_pub, &b, &c, &proof, Some(&message)).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_dleq_proof_invalid() {
        let secp = Secp256k1::new();

        let a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let a_pub = PublicKey::from_secret_key(&secp, &a);
        let b_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let b = PublicKey::from_secret_key(&secp, &b_priv);
        let c = b.mul_tweak(&secp, &a.into()).unwrap();

        // Generate valid proof
        let rand_aux = [3u8; 32];
        let mut proof = dleq_generate_proof(&secp, &a, &b, &rand_aux, None).unwrap();

        // Corrupt the proof by flipping a bit
        proof.0[0] ^= 1;

        // Verification should fail
        let valid = dleq_verify_proof(&secp, &a_pub, &b, &c, &proof, None).unwrap();
        assert!(!valid);
    }
}
