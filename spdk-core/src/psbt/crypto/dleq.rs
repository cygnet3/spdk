//! BIP-374 DLEQ (Discrete Log Equality) Proofs
//!
//! Implements DLEQ proof generation and verification for secp256k1.
//! Based on BIP-374 specification.

use super::error::{CryptoError, Result};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use psbt_v2::v2::dleq::DleqProof;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

// Tagged hash tags for BIP-374
const DLEQ_TAG_AUX: &str = "BIP0374/aux";
const DLEQ_TAG_NONCE: &str = "BIP0374/nonce";
const DLEQ_TAG_CHALLENGE: &str = "BIP0374/challenge";

/// Compute a tagged hash as defined in BIP-340
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// XOR two 32-byte arrays
fn xor_bytes(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = lhs[i] ^ rhs[i];
    }
    result
}

/// Compute DLEQ challenge value
///
/// e = H_challenge(A || B || C || G || R1 || R2 || m)
fn dleq_challenge(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
    m: Option<&[u8; 32]>,
) -> Scalar {
    let mut data = Vec::with_capacity(6 * 33 + if m.is_some() { 32 } else { 0 });
    data.extend_from_slice(&a.serialize());
    data.extend_from_slice(&b.serialize());
    data.extend_from_slice(&c.serialize());
    data.extend_from_slice(&g.serialize());
    data.extend_from_slice(&r1.serialize());
    data.extend_from_slice(&r2.serialize());
    if let Some(msg) = m {
        data.extend_from_slice(msg);
    }

    let hash = tagged_hash(DLEQ_TAG_CHALLENGE, &data);
    Scalar::from_be_bytes(hash).expect("Valid scalar from hash")
}

/// Generate a DLEQ proof
///
/// Proves that log_G(A) = log_B(C), i.e., A = a*G and C = a*B for some secret a.
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `a` - Secret scalar (private key)
/// * `b` - Public key B
/// * `r` - 32 bytes of randomness for aux randomization
/// * `g` - Generator point (default: secp256k1 generator G)
/// * `m` - Optional 32-byte message to include in proof
///
/// # Returns
/// 64-byte proof: e (32 bytes) || s (32 bytes)
pub fn dleq_generate_proof(
    secp: &Secp256k1<secp256k1::All>,
    a: &SecretKey,
    b: &PublicKey,
    r: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Result<DleqProof> {
    // Compute A = a*G and C = a*B
    let a_point = PublicKey::from_secret_key(secp, a);
    let a_scalar: Scalar = (*a).into();
    let c_point = b.mul_tweak(secp, &a_scalar)?;

    // Get generator G
    let g_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap(),
    );

    // Compute t = a XOR H_aux(r)
    let aux_hash = tagged_hash(DLEQ_TAG_AUX, r);
    let a_bytes = a.secret_bytes();
    let t = xor_bytes(&a_bytes, &aux_hash);

    // Compute nonce: k = H_nonce(t || A || C || m) mod n
    let mut nonce_data = Vec::with_capacity(32 + 33 + 33 + if m.is_some() { 32 } else { 0 });
    nonce_data.extend_from_slice(&t);
    nonce_data.extend_from_slice(&a_point.serialize());
    nonce_data.extend_from_slice(&c_point.serialize());
    if let Some(msg) = m {
        nonce_data.extend_from_slice(msg);
    }

    let nonce_hash = tagged_hash(DLEQ_TAG_NONCE, &nonce_data);
    let k = Scalar::from_be_bytes(nonce_hash)
        .map_err(|_| CryptoError::DleqGenerationFailed("Invalid nonce scalar".to_string()))?;

    // Check if k is zero by trying to convert to SecretKey
    let k_key = SecretKey::from_slice(&k.to_be_bytes())?;

    // Compute R1 = k*G and R2 = k*B
    let r1 = PublicKey::from_secret_key(secp, &k_key);
    let r2 = b.mul_tweak(secp, &k)?;

    // Compute challenge e = H_challenge(A, B, C, G, R1, R2, m)
    let e = dleq_challenge(&a_point, b, &c_point, &g_point, &r1, &r2, m);

    // Compute s = k + e*a (mod n)
    // We need to do scalar arithmetic. Since `Scalar` doesn't support arithmetic directly,
    // we convert to SecretKey for operations
    let e_key = SecretKey::from_slice(&e.to_be_bytes())?;
    let ea = e_key.mul_tweak(&a_scalar)?;
    let s_key = k_key.add_tweak(&ea.into())?;
    let s = Scalar::from(s_key);

    // Construct proof: e || s
    let mut proof_bytes = [0u8; 64];
    proof_bytes[0..32].copy_from_slice(&e.to_be_bytes());
    proof_bytes[32..64].copy_from_slice(&s.to_be_bytes());

    // Verify the proof before returning
    let proof = DleqProof(proof_bytes);

    // Verify the proof before returning
    if !dleq_verify_proof(secp, &a_point, b, &c_point, &proof, m)? {
        return Err(CryptoError::DleqGenerationFailed(
            "Self-verification failed".to_string(),
        ));
    }

    Ok(proof)
}

/// Verify a DLEQ proof
///
/// Verifies that log_G(A) = log_B(C).
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `a` - Public key A = a*G
/// * `b` - Public key B
/// * `c` - Public key C = a*B
/// * `proof` - 64-byte proof
/// * `m` - Optional 32-byte message
pub fn dleq_verify_proof(
    secp: &Secp256k1<secp256k1::All>,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &DleqProof,
    m: Option<&[u8; 32]>,
) -> Result<bool> {
    // Parse proof: e || s
    let mut e_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    e_bytes.copy_from_slice(&proof.0[0..32]);
    s_bytes.copy_from_slice(&proof.0[32..64]);

    let e = Scalar::from_be_bytes(e_bytes).map_err(|_| CryptoError::DleqVerificationFailed)?;
    let s = Scalar::from_be_bytes(s_bytes).map_err(|_| CryptoError::DleqVerificationFailed)?;

    // Get generator G
    let g_point = PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap(),
    );

    // Compute R1 = s*G - e*A
    let s_key = SecretKey::from_slice(&s.to_be_bytes())?;
    let s_g = PublicKey::from_secret_key(secp, &s_key);

    let e_key = SecretKey::from_slice(&e.to_be_bytes())?;
    let e_a = a.mul_tweak(secp, &e_key.into())?;

    let r1 = s_g
        .combine(&e_a.negate(secp))
        .map_err(|_| CryptoError::DleqVerificationFailed)?;

    // Compute R2 = s*B - e*C
    let s_b = b.mul_tweak(secp, &s)?;
    let e_c = c.mul_tweak(secp, &e)?;

    let r2 = s_b
        .combine(&e_c.negate(secp))
        .map_err(|_| CryptoError::DleqVerificationFailed)?;

    // Verify challenge
    let e_prime = dleq_challenge(a, b, c, &g_point, &r1, &r2, m);

    Ok(e == e_prime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        let data = b"test data";
        let hash = tagged_hash(DLEQ_TAG_AUX, data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0xFFu8; 32];
        let b = [0xAAu8; 32];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, [0x55u8; 32]);
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
