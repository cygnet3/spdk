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

    // Sender A: Generate a keypair
    let sender_input_secret = SecretKey::from_slice(&[0x01; 32]).expect("valid secret key");
    let sender_input_public = PublicKey::from_secret_key(&secp, &sender_input_secret);
    println!("Sender A public key: {}", sender_input_public);

    // Receiver B: Generate a public key (scan key in silent payments context)
    let receiver_scan_secret = SecretKey::from_slice(&[0x02; 32]).expect("valid secret key");
    let receiver_scan_public = PublicKey::from_secret_key(&secp, &receiver_scan_secret);
    println!("Receiver B scan public key: {}", receiver_scan_public);

    // Compute ECDH share: C = a * B
    let ecdh_share = receiver_scan_public
        .mul_tweak(&secp, &sender_input_secret.into())
        .expect("valid ECDH computation");
    println!("ECDH share: {}\n", ecdh_share);

    // Generate DLEQ proof
    println!("Generating DLEQ proof...");
    let aux_randomness = [0x42; 32]; // In practice, use secure randomness
    let message = Some([0xAB; 32]); // Optional message to bind to proof

    let proof = dleq_generate_proof(
        &secp,
        &sender_input_secret,
        &receiver_scan_public,
        &aux_randomness,
        message.as_ref(),
    )
    .expect("proof generation successful");

    println!("✓ Proof generated successfully");
    let hex_proof: String = proof.0.iter().map(|b| format!("{:02x}", b)).collect();
    println!("  Proof bytes (hex): {}\n", hex_proof);

    // Verify the DLEQ proof
    println!("Verifying DLEQ proof...");
    let is_valid = dleq_verify_proof(
        &secp,
        &sender_input_public,
        &receiver_scan_public,
        &ecdh_share,
        &proof,
        message.as_ref(),
    )
    .expect("verification executed");

    if is_valid {
        println!("✓ Proof is VALID");
        println!("  The prover knows the discrete log relationship:");
        println!("  log_G(sender_input_public) = log_B(ecdh_share)\n");
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
        &sender_input_public,
        &receiver_scan_public,
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
