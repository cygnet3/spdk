//! Transaction Signing for P2WPKH Inputs
//!
//! Implements ECDSA signature generation with RFC 6979 deterministic nonces.

use super::error::{CryptoError, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{sighash::SighashCache, Amount, ScriptBuf, Transaction};
use hmac::{Hmac, Mac};
use secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a deterministic nonce using RFC 6979
///
/// This generates a deterministic k value for ECDSA signing based on the
/// private key and message hash, ensuring signatures are deterministic while
/// remaining secure.
pub fn deterministic_nonce(privkey: &SecretKey, message_hash: &[u8; 32]) -> Result<SecretKey> {
    let privkey_bytes = privkey.secret_bytes();

    // Step b: V = 0x01 0x01 0x01 ... 0x01
    let mut v = [0x01u8; 32];

    // Step c: K = 0x00 0x00 0x00 ... 0x00
    let mut k = [0x00u8; 32];

    // Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(&privkey_bytes);
    mac.update(message_hash);
    k = mac.finalize().into_bytes().into();

    // Step e: V = HMAC_K(V)
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    v = mac.finalize().into_bytes().into();

    // Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(&privkey_bytes);
    mac.update(message_hash);
    k = mac.finalize().into_bytes().into();

    // Step g: V = HMAC_K(V)
    let mut mac = HmacSha256::new_from_slice(&k).unwrap();
    mac.update(&v);
    v = mac.finalize().into_bytes().into();

    // Step h: Generate nonce
    loop {
        // Generate candidate k from V
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        v = mac.finalize().into_bytes().into();

        // Try to create a valid secret key from v
        if let Ok(nonce) = SecretKey::from_slice(&v) {
            return Ok(nonce);
        }

        // If not valid, continue: K = HMAC_K(V || 0x00)
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        mac.update(&[0x00]);
        k = mac.finalize().into_bytes().into();

        // V = HMAC_K(V)
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        v = mac.finalize().into_bytes().into();
    }
}

/// Sign a P2WPKH input using ECDSA with SIGHASH_ALL
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input to sign
/// * `script_pubkey` - The script pubkey of the UTXO being spent
/// * `amount` - The amount of the UTXO being spent
/// * `privkey` - Private key to sign with
///
/// # Returns
/// Serialized signature with SIGHASH_ALL flag appended (DER + 0x01)
pub fn sign_p2wpkh_input(
    secp: &Secp256k1<secp256k1::All>,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &ScriptBuf,
    amount: Amount,
    privkey: &SecretKey,
) -> Result<Vec<u8>> {
    // Create sighash cache
    let mut sighash_cache = SighashCache::new(tx);

    // Compute sighash for this input
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            input_index,
            script_pubkey,
            amount,
            bitcoin::sighash::EcdsaSighashType::All,
        )
        .map_err(|e| CryptoError::Other(format!("Sighash computation failed: {}", e)))?;

    // Convert sighash to message
    let message = Message::from_digest(sighash.to_byte_array());

    // Sign the message
    let signature = secp.sign_ecdsa(&message, privkey);

    // Serialize to DER format and append SIGHASH_ALL (0x01)
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL

    Ok(sig_bytes)
}

/// Sign a P2PKH input using ECDSA with SIGHASH_ALL
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input to sign
/// * `script_pubkey` - The script pubkey of the UTXO being spent
/// * `amount` - The amount of the UTXO being spent (not strictly needed for legacy, but good for API consistency)
/// * `privkey` - Private key to sign with
///
/// # Returns
/// Serialized signature with SIGHASH_ALL flag appended (DER + 0x01)
pub fn sign_p2pkh_input(
    secp: &Secp256k1<secp256k1::All>,
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &ScriptBuf,
    _amount: Amount,
    privkey: &SecretKey,
) -> Result<Vec<u8>> {
    // Create sighash cache
    let sighash_cache = SighashCache::new(tx);

    // Compute sighash for this input
    let sighash = sighash_cache
        .legacy_signature_hash(
            input_index,
            script_pubkey,
            bitcoin::sighash::EcdsaSighashType::All.to_u32(),
        )
        .map_err(|e| CryptoError::Other(format!("Sighash computation failed: {}", e)))?;

    // Convert sighash to message
    let message = Message::from_digest(sighash.to_byte_array());

    // Sign the message
    let signature = secp.sign_ecdsa(&message, privkey);

    // Serialize to DER format and append SIGHASH_ALL (0x01)
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL

    Ok(sig_bytes)
}

/// Sign a message hash with ECDSA (low-level function)
///
/// This is a lower-level function that signs a raw 32-byte hash.
/// For transaction signing, use `sign_p2wpkh_input` instead.
pub fn sign_hash(
    secp: &Secp256k1<secp256k1::All>,
    privkey: &SecretKey,
    message_hash: &[u8; 32],
) -> Result<Signature> {
    let message = Message::from_digest(*message_hash);
    Ok(secp.sign_ecdsa(&message, privkey))
}

/// Verify an ECDSA signature
pub fn verify_signature(
    secp: &Secp256k1<secp256k1::All>,
    pubkey: &secp256k1::PublicKey,
    message_hash: &[u8; 32],
    signature: &Signature,
) -> bool {
    let message = Message::from_digest(*message_hash);
    secp.verify_ecdsa(&message, signature, pubkey).is_ok()
}

/// Compute SHA256 hash
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// Compute double SHA256 hash (Bitcoin's hash256)
pub fn double_sha256_hash(data: &[u8]) -> [u8; 32] {
    let first = sha256::Hash::hash(data);
    sha256::Hash::hash(&first.to_byte_array()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, transaction::Version, OutPoint, Sequence, TxIn, TxOut, Txid, Witness,
    };

    #[test]
    fn test_deterministic_nonce() {
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let message_hash = [2u8; 32];

        let nonce1 = deterministic_nonce(&privkey, &message_hash).unwrap();
        let nonce2 = deterministic_nonce(&privkey, &message_hash).unwrap();

        // Same inputs should produce same nonce
        assert_eq!(nonce1.secret_bytes(), nonce2.secret_bytes());

        // Different message should produce different nonce
        let different_message = [3u8; 32];
        let nonce3 = deterministic_nonce(&privkey, &different_message).unwrap();
        assert_ne!(nonce1.secret_bytes(), nonce3.secret_bytes());
    }

    #[test]
    fn test_sign_hash() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);
        let message_hash = [2u8; 32];

        let signature = sign_hash(&secp, &privkey, &message_hash).unwrap();

        // Verify the signature
        assert!(verify_signature(&secp, &pubkey, &message_hash, &signature));

        // Wrong message should fail
        let wrong_message = [3u8; 32];
        assert!(!verify_signature(
            &secp,
            &pubkey,
            &wrong_message,
            &signature
        ));
    }

    #[test]
    fn test_sign_p2wpkh_input() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);

        // Create a simple transaction
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Create P2WPKH script
        let wpubkey_hash = bitcoin::PublicKey::new(pubkey).wpubkey_hash().unwrap();
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpubkey_hash);

        let amount = Amount::from_sat(50000);

        // Sign the input
        let signature = sign_p2wpkh_input(&secp, &tx, 0, &script_pubkey, amount, &privkey).unwrap();

        // Signature should be DER encoded + SIGHASH_ALL flag
        assert!(signature.len() >= 70); // Typical DER signature size
        assert_eq!(signature.last(), Some(&0x01)); // SIGHASH_ALL flag
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);

        // Same data should produce same hash
        let hash2 = sha256_hash(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_double_sha256_hash() {
        let data = b"test data";
        let hash = double_sha256_hash(data);
        assert_eq!(hash.len(), 32);

        // Verify it's actually double hashed
        let single = sha256_hash(data);
        let double = sha256_hash(&single);
        assert_eq!(hash, double);
    }
}
