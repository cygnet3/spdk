//! Example: Using DLEQ proofs with rust-dleq integration
//!
//! This example demonstrates how to use DLEQ proofs in SPDK with rust-dleq.
//! The same code works with both `dleq-standalone` and `dleq-native` features.
//!
//! Run with standalone (default):
//!   cargo run --example dleq_example
//!
//! Run with native:
//!   cargo run --example dleq_example --no-default-features --features dleq-native,async,parallel

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use spdk_core::psbt::crypto::dleq::{dleq_generate_proof, dleq_verify_proof};
use spdk_core::psbt::{from_psbt_v2_proof, to_psbt_v2_proof};

fn main() {
    println!("DLEQ Proof Example with rust-dleq Integration\n");

    let secp = Secp256k1::new();

    // Party A: Generate a keypair
    let secret_a = SecretKey::from_slice(&[0x01; 32]).expect("valid secret key");
    let pubkey_a = PublicKey::from_secret_key(&secp, &secret_a);
    println!("Party A public key: {}", pubkey_a);

    // Party B: Generate a public key (scan key in silent payments context)
    let secret_b = SecretKey::from_slice(&[0x02; 32]).expect("valid secret key");
    let pubkey_b = PublicKey::from_secret_key(&secp, &secret_b);
    println!("Party B public key (scan key): {}", pubkey_b);

    // Compute ECDH share: C = a * B
    let ecdh_share = pubkey_b
        .mul_tweak(&secp, &secret_a.into())
        .expect("valid ECDH computation");
    println!("ECDH share: {}\n", ecdh_share);

    // Generate DLEQ proof
    println!("Generating DLEQ proof...");
    let aux_randomness = [0x42; 32]; // In practice, use secure randomness
    let message = Some([0xAB; 32]); // Optional message to bind to proof

    let proof = dleq_generate_proof(
        &secp,
        &secret_a,
        &pubkey_b,
        &aux_randomness,
        message.as_ref(),
    )
    .expect("proof generation successful");

    println!("✓ Proof generated successfully");
    println!("  Proof bytes (first 16): {:02x?}...\n", &proof.0[..16]);

    // Verify the DLEQ proof
    println!("Verifying DLEQ proof...");
    let is_valid = dleq_verify_proof(
        &secp,
        &pubkey_a,
        &pubkey_b,
        &ecdh_share,
        &proof,
        message.as_ref(),
    )
    .expect("verification executed");

    if is_valid {
        println!("✓ Proof is VALID");
        println!("  The prover knows the discrete log relationship:");
        println!("  log_G(A) = log_B(C)\n");
    } else {
        println!("✗ Proof is INVALID");
    }

    // Demonstrate proof conversion between types
    println!("Demonstrating type conversion...");
    let rust_dleq_proof = from_psbt_v2_proof(&proof);
    println!("  Converted psbt-v2 proof to rust-dleq proof");

    let converted_back = to_psbt_v2_proof(&rust_dleq_proof);
    println!("  Converted back to psbt-v2 proof");

    assert_eq!(proof.0, converted_back.0);
    println!("✓ Round-trip conversion successful\n");

    // Test with invalid proof
    println!("Testing with corrupted proof...");
    let mut corrupted_proof = proof;
    corrupted_proof.0[0] ^= 0xFF; // Flip bits

    let is_valid_corrupted = dleq_verify_proof(
        &secp,
        &pubkey_a,
        &pubkey_b,
        &ecdh_share,
        &corrupted_proof,
        message.as_ref(),
    )
    .expect("verification executed");

    if !is_valid_corrupted {
        println!("✓ Corrupted proof correctly rejected\n");
    } else {
        println!("✗ Corrupted proof incorrectly accepted\n");
    }

    // Feature detection
    #[cfg(all(feature = "dleq-standalone", not(feature = "dleq-native")))]
    println!("Using: dleq-standalone feature (Pure Rust implementation)");

    #[cfg(all(feature = "dleq-native", not(feature = "dleq-standalone")))]
    println!("Using: dleq-native feature (Native FFI to libsecp256k1)");

    println!("\n✓ Example completed successfully!");
}
