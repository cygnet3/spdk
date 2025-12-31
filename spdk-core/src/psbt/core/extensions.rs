//! BIP-375 Extension Traits and PSBT Accessors
//!
//! This module provides extension traits that add BIP-375 silent payment functionality
//! to the `psbt_v2::v2::Psbt` type, along with convenience accessor functions for
//! common PSBT field access patterns.
//!
//! # Module Contents
//!
//! - **`Bip375PsbtExt` trait**: Adds BIP-375 specific methods to PSBT
//!   - ECDH share management (global and per-input)
//!   - DLEQ proof handling
//!   - Silent payment address/label fields
//!   - SP tweak fields for spending
//!
//! - **Convenience Accessors**: Higher-level functions for extracting typed data
//!   - Input field extraction (txid, vout, outpoint, pubkeys)
//!   - Output field extraction (SP keys)
//!   - Fallback logic for public key detection
//!
//! # Design Philosophy
//!
//! - **Non-invasive**: Uses extension traits rather than wrapping types
//! - **Idiomatic**: Follows rust-psbt patterns and conventions
//! - **Upstreamable**: Clean API that could be contributed to rust-psbt
//! - **Type-safe**: Leverages Rust's type system for correctness

use super::{
    error::{Error, Result},
    types::EcdhShareData,
    SilentPaymentPsbt,
};
use bitcoin::{OutPoint, Txid};
use psbt_v2::{
    bitcoin::CompressedPublicKey,
    raw::Key,
    v2::{dleq::DleqProof, Psbt},
};
use silentpayments::secp256k1::PublicKey;
use silentpayments::SilentPaymentAddress;

pub const PSBT_OUT_DNSSEC_PROOF: u8 = 0x35;
pub const PSBT_IN_SP_TWEAK: u8 = 0x1f;
/// Extension trait for BIP-375 silent payment fields on PSBT v2
///
/// This trait adds methods to access and modify BIP-375 specific fields:
/// - ECDH shares (global and per-input)
/// - DLEQ proofs (global and per-input)
/// - Silent payment addresses (per-output)
/// - Silent payment labels (per-output)
pub trait Bip375PsbtExt {
    // ===== Global ECDH Shares =====

    /// Get all global ECDH shares
    ///
    /// Global shares are used when one party knows all input private keys.
    /// Field type: PSBT_GLOBAL_SP_ECDH_SHARE (0x07)
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData>;

    /// Add a global ECDH share
    ///
    /// # Arguments
    /// * `share` - The ECDH share to add
    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()>;

    // ===== Per-Input ECDH Shares =====

    /// Get ECDH shares for a specific input
    ///
    /// Returns per-input shares if present, otherwise falls back to global shares.
    /// Field type: PSBT_IN_SP_ECDH_SHARE (0x1d)
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData>;

    /// Add an ECDH share to a specific input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `share` - The ECDH share to add
    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()>;

    // ===== Silent Payment Outputs =====

    /// Get silent payment scan and spend keys for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_INFO (0x09)
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_info_v0(&self, output_index: usize) -> Option<(PublicKey, PublicKey)>;

    /// Set silent payment v0 keys for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `address` - The silent payment address
    fn set_output_sp_info_v0(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()>;

    /// Get silent payment label for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_LABEL (0x0a)
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_label(&self, output_index: usize) -> Option<u32>;

    /// Set silent payment label for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `label` - The label value
    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()>;

    // ===== Silent Payment Spending =====

    /// Get silent payment tweak for an input
    ///
    /// Returns the 32-byte tweak that should be added to the spend private key
    /// to spend this silent payment output.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]>;

    /// Set silent payment tweak for an input
    ///
    /// The tweak is derived from BIP-352 output derivation during wallet scanning.
    /// Hardware signer uses this to compute: tweaked_privkey = spend_privkey + tweak
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `tweak` - The 32-byte tweak
    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()>;

    /// Remove silent payment tweak from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()>;

    // ===== Convenience Methods =====

    /// Get the number of inputs
    fn num_inputs(&self) -> usize;

    /// Get the number of outputs
    fn num_outputs(&self) -> usize;

    /// Get partial signatures for an input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Get all scan keys from outputs with PSBT_OUT_SP_V0_INFO set
    ///
    /// Iterates through all outputs and extracts scan keys from silent payment addresses.
    /// This is used by signers to determine which scan keys need ECDH shares.
    fn get_output_scan_keys(&self) -> Vec<PublicKey>;
}

impl Bip375PsbtExt for Psbt {
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData> {
        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &self.global.sp_ecdh_shares {
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for corresponding DLEQ proof
            let dleq_proof = get_global_dleq_proof(self, &scan_key_pk);
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()> {
        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        self.global.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_global_dleq_proof(self, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &input.sp_ecdh_shares {
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for DLEQ proof (input-specific or global)
            let dleq_proof = get_input_dleq_proof(self, input_index, &scan_key_pk)
                .or_else(|| get_global_dleq_proof(self, &scan_key_pk));
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        input.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_input_dleq_proof(self, input_index, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_output_sp_info_v0(&self, output_index: usize) -> Option<(PublicKey, PublicKey)> {
        let output = self.outputs.get(output_index)?;

        if let Some(bytes) = &output.sp_v0_info {
            if bytes.len() != 66 {
                return None;
            };
            let scan_key = PublicKey::from_slice(&bytes[..33]).ok();
            let spend_key = PublicKey::from_slice(&bytes[33..]).ok();
            if scan_key.is_some() && spend_key.is_some() {
                return Some((scan_key.unwrap(), spend_key.unwrap()));
            }
        }

        None
    }

    fn set_output_sp_info_v0(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        // PSBT_OUT_SP_V0_INFO contains only the keys (66 bytes)
        // Label is stored separately in PSBT_OUT_SP_V0_LABEL
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&address.get_scan_key().serialize());
        bytes.extend_from_slice(&address.get_spend_key().serialize());
        output.sp_v0_info = Some(bytes);

        Ok(())
    }

    fn get_output_sp_label(&self, output_index: usize) -> Option<u32> {
        let output = self.outputs.get(output_index)?;

        if let Some(label) = output.sp_v0_label {
            return Some(label);
        }

        None
    }

    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()> {
        let output = self
            .outputs
            .get_mut(output_index)
            .ok_or(Error::InvalidOutputIndex(output_index))?;

        output.sp_v0_label = Some(label);

        Ok(())
    }

    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]> {
        let input = self.inputs.get(input_index)?;

        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_SP_TWEAK && key.key.is_empty() && value.len() == 32 {
                let mut tweak = [0u8; 32];
                tweak.copy_from_slice(value);
                return Some(tweak);
            }
        }
        None
    }

    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let key = Key {
            type_value: PSBT_IN_SP_TWEAK,
            key: vec![],
        };

        input.unknowns.insert(key, tweak.to_vec());
        Ok(())
    }

    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        let key = Key {
            type_value: PSBT_IN_SP_TWEAK,
            key: vec![],
        };

        input.unknowns.remove(&key);
        Ok(())
    }

    fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if let Some(input) = self.inputs.get(input_index) {
            input
                .partial_sigs
                .iter()
                .map(|(pk, sig)| (pk.inner.serialize().to_vec(), sig.to_vec()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn get_output_scan_keys(&self) -> Vec<PublicKey> {
        let mut scan_keys = Vec::new();
        for output_idx in 0..self.outputs.len() {
            if let Some(sp_info) = self.get_output_sp_info_v0(output_idx) {
                scan_keys.push(sp_info.0);
            }
        }
        scan_keys
    }
}

// Private helper functions for DLEQ proof management
fn get_global_dleq_proof(psbt: &Psbt, scan_key: &PublicKey) -> Option<DleqProof> {
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;
    psbt.global
        .sp_dleq_proofs
        .get(&scan_key_compressed)
        .map(|proof| *proof)
}

fn add_global_dleq_proof(psbt: &mut Psbt, scan_key: &PublicKey, proof: DleqProof) -> Result<()> {
    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    psbt.global
        .sp_dleq_proofs
        .insert(scan_key_compressed, proof);

    Ok(())
}

fn get_input_dleq_proof(
    psbt: &Psbt,
    input_index: usize,
    scan_key: &PublicKey,
) -> Option<DleqProof> {
    let input = psbt.inputs.get(input_index)?;
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;

    input
        .sp_dleq_proofs
        .get(&scan_key_compressed)
        .map(|proof| *proof)
}

fn add_input_dleq_proof(
    psbt: &mut Psbt,
    input_index: usize,
    scan_key: &PublicKey,
    proof: DleqProof,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    input.sp_dleq_proofs.insert(scan_key_compressed, proof);

    Ok(())
}

// ============================================================================
// Convenience Accessor Functions
// ============================================================================
//
// These provide ergonomic access patterns for common PSBT field operations.

/// Get the transaction ID (TXID) for an input
pub fn get_input_txid(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Txid> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // PSBT v2 inputs have explicit previous_txid field
    Ok(input.previous_txid)
}

/// Get the output index (vout) for an input
pub fn get_input_vout(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<u32> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    Ok(input.spent_output_index)
}

/// Get the outpoint (TXID + vout) for an input as raw bytes
pub fn get_input_outpoint_bytes(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Vec<u8>> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;

    let mut outpoint = Vec::with_capacity(36);
    outpoint.extend_from_slice(&txid[..]);
    outpoint.extend_from_slice(&vout.to_le_bytes());
    Ok(outpoint)
}

/// Get the outpoint (TXID + vout) for an input as a typed OutPoint
pub fn get_input_outpoint(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<OutPoint> {
    let txid = get_input_txid(psbt, input_idx)?;
    let vout = get_input_vout(psbt, input_idx)?;
    Ok(OutPoint { txid, vout })
}

/// Get all BIP32 derivation public keys for an input
pub fn get_input_bip32_pubkeys(psbt: &SilentPaymentPsbt, input_idx: usize) -> Vec<PublicKey> {
    let mut pubkeys = Vec::new();

    if let Some(input) = psbt.inputs.get(input_idx) {
        for key in input.bip32_derivations.keys() {
            // key is bitcoin::PublicKey, inner is secp256k1::PublicKey
            pubkeys.push(*key);
        }
    }

    pubkeys
}

/// Get input public key from PSBT fields with fallback priority
///
/// Tries multiple sources in this order:
/// 1. BIP32 derivation field (highest priority)
/// 2. Taproot internal key (for Taproot inputs)
/// 3. Partial signature field
pub fn get_input_pubkey(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<PublicKey> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // Method 1: Extract from Taproot BIP32 derivation (tap_key_origins for P2TR)
    if !input.tap_key_origins.is_empty() {
        // Return the first key, converting x-only to full pubkey (even Y)
        if let Some(xonly_key) = input.tap_key_origins.keys().next() {
            let mut pubkey_bytes = vec![0x02];
            pubkey_bytes.extend_from_slice(&xonly_key.serialize());
            if let Ok(pubkey) = PublicKey::from_slice(&pubkey_bytes) {
                return Ok(pubkey);
            }
        }
    }

    // Method 2: Extract from BIP32 derivation field (for non-Taproot)
    if !input.bip32_derivations.is_empty() {
        // Return the first key
        if let Some(key) = input.bip32_derivations.keys().next() {
            return Ok(*key);
        }
    }

    // Method 3: Extract from Taproot internal key (for Taproot inputs)
    if let Some(tap_key) = input.tap_internal_key {
        // tap_key is bitcoin::XOnlyPublicKey
        // We need to convert to secp256k1::PublicKey (even y)
        // bitcoin::XOnlyPublicKey has into_inner() -> secp256k1::XOnlyPublicKey
        let x_only = tap_key;

        // Convert x-only to full pubkey (assumes even y - prefix 0x02)
        let mut pubkey_bytes = vec![0x02];
        pubkey_bytes.extend_from_slice(&x_only.serialize());
        if let Ok(pubkey) = PublicKey::from_slice(&pubkey_bytes) {
            return Ok(pubkey);
        }
    }

    // Method 4: Extract from partial signature field
    if !input.partial_sigs.is_empty() {
        if let Some(key) = input.partial_sigs.keys().next() {
            return Ok(key.inner);
        }
    }

    Err(Error::Other(format!(
        "Input {} missing public key (no BIP32 derivation, Taproot key, or partial signature found)",
        input_idx
    )))
}

pub fn get_output_sp_keys(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<(PublicKey, PublicKey)> {
    // Use the extension trait method via SilentPaymentPsbt wrapper
    let sp_info = psbt.get_output_sp_info_v0(output_idx).ok_or_else(|| {
        Error::MissingField(format!("Output {} missing PSBT_OUT_SP_V0_INFO", output_idx))
    })?;
    Ok((sp_info.0, sp_info.1))
}
/// Get silent payment keys (scan_key, spend_key) from output SP_V0_INFO field

// ============================================================================
// Display Extension Traits
// ============================================================================
//
// The following traits provide methods for extracting and serializing PSBT fields
// for display purposes. These are used by GUI and analysis tools to inspect PSBT contents.

/// Extension trait for accessing psbt_v2::v2::Global fields for display
///
/// This trait provides convenient methods to access all standard PSBT v2 global fields
/// in a serialized format suitable for display or further processing.
pub trait GlobalFieldsExt {
    /// Iterator over all standard global fields as (field_type, key_data, value_data) tuples
    ///
    /// Returns fields in the following order:
    /// - PSBT_GLOBAL_XPUB (0x01) - Multiple entries possible
    /// - PSBT_GLOBAL_TX_VERSION (0x02)
    /// - PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03) - If present
    /// - PSBT_GLOBAL_INPUT_COUNT (0x04)
    /// - PSBT_GLOBAL_OUTPUT_COUNT (0x05)
    /// - PSBT_GLOBAL_TX_MODIFIABLE (0x06)
    /// - PSBT_GLOBAL_SP_ECDH_SHARE (0x07) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_SP_DLEQ (0x08) - Multiple entries possible (BIP-375)
    /// - PSBT_GLOBAL_VERSION (0xFB)
    /// - PSBT_GLOBAL_PROPRIETARY (0xFC) - Multiple entries possible
    /// - Unknown fields from the unknowns map
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_GLOBAL_XPUB = 0x01 - Can have multiple entries
        for (xpub, key_source) in &self.xpubs {
            let field_type = 0x01;
            // Key is the serialized xpub
            let key_data = xpub.to_string().as_bytes().to_vec();
            // Value is the key source (fingerprint + derivation path)
            let mut value_data = Vec::new();
            // Fingerprint is 4 bytes
            value_data.extend_from_slice(&key_source.0.to_bytes());
            // Derivation path - each ChildNumber is 4 bytes (u32)
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_VERSION = 0x02 - Always present
        {
            let field_type = 0x02;
            let key_data = vec![];
            let value_data = self.tx_version.0.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03 - Optional
        if let Some(lock_time) = self.fallback_lock_time {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = lock_time.to_consensus_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_INPUT_COUNT = 0x04 - Always present
        {
            let field_type = 0x04;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.input_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_OUTPUT_COUNT = 0x05 - Always present
        {
            let field_type = 0x05;
            let key_data = vec![];
            // Serialize as VarInt (compact size)
            let mut value_data = vec![];
            let count = self.output_count as u64;
            if count < 0xFD {
                value_data.push(count as u8);
            } else if count <= 0xFFFF {
                value_data.push(0xFD);
                value_data.extend_from_slice(&(count as u16).to_le_bytes());
            } else if count <= 0xFFFF_FFFF {
                value_data.push(0xFE);
                value_data.extend_from_slice(&(count as u32).to_le_bytes());
            } else {
                value_data.push(0xFF);
                value_data.extend_from_slice(&count.to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_TX_MODIFIABLE = 0x06 - Always present
        {
            let field_type = 0x06;
            let key_data = vec![];
            let value_data = vec![self.tx_modifiable_flags];
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_SP_ECDH_SHARE = 0x07 - BIP-375, can have multiple entries
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            let field_type = 0x07;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                ecdh_share.to_bytes().to_vec(),
            ));
        }

        // PSBT_GLOBAL_SP_DLEQ = 0x08 - BIP-375, can have multiple entries
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            let field_type = 0x08;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                dleq_proof.as_bytes().to_vec(),
            ));
        }

        // PSBT_GLOBAL_VERSION = 0xFB - Always present
        {
            let field_type = 0xFB;
            let key_data = vec![];
            let value_data = self.version.to_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_GLOBAL_PROPRIETARY = 0xFC - Can have multiple entries
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            // Key data is the proprietary key structure
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields from the unknowns map
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}

/// Extension trait for accessing psbt_v2::v2::Input fields for display
///
/// This trait provides convenient methods to access all standard PSBT v2 input fields
/// in a serialized format suitable for display or further processing.
pub trait InputFieldsExt {
    /// Iterator over all standard input fields as (field_type, key_data, value_data) tuples
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl InputFieldsExt for psbt_v2::v2::Input {
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_IN_NON_WITNESS_UTXO (0x00) - Optional
        if let Some(ref tx) = self.non_witness_utxo {
            use bitcoin::consensus::Encodable;
            let field_type = 0x00;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = tx.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_WITNESS_UTXO (0x01) - Optional
        if let Some(ref utxo) = self.witness_utxo {
            use bitcoin::consensus::Encodable;
            let field_type = 0x01;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = utxo.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_PARTIAL_SIG (0x02) - Multiple entries possible
        for (pubkey, sig) in &self.partial_sigs {
            let field_type = 0x02;
            let key_data = pubkey.inner.serialize().to_vec();
            let value_data = sig.to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SIGHASH_TYPE (0x03) - Optional
        if let Some(sighash_type) = self.sighash_type {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = (sighash_type.to_u32()).to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_REDEEM_SCRIPT (0x04) - Optional
        if let Some(ref script) = self.redeem_script {
            let field_type = 0x04;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_WITNESS_SCRIPT (0x05) - Optional
        if let Some(ref script) = self.witness_script {
            let field_type = 0x05;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_BIP32_DERIVATION (0x06) - Multiple entries possible
        for (pubkey, key_source) in &self.bip32_derivations {
            let field_type = 0x06;
            let key_data = pubkey.serialize().to_vec();
            let mut value_data = Vec::new();
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_FINAL_SCRIPTSIG (0x07) - Optional
        if let Some(ref script) = self.final_script_sig {
            let field_type = 0x07;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_FINAL_SCRIPTWITNESS (0x08) - Optional
        if let Some(ref witness) = self.final_script_witness {
            use bitcoin::consensus::Encodable;
            let field_type = 0x08;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = witness.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_PREVIOUS_TXID (0x0e) - Always present
        {
            use bitcoin::consensus::Encodable;
            let field_type = 0x0e;
            let key_data = vec![];
            let mut value_data = vec![];
            let _ = self.previous_txid.consensus_encode(&mut value_data);
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_OUTPUT_INDEX (0x0f) - Always present
        {
            let field_type = 0x0f;
            let key_data = vec![];
            let value_data = self.spent_output_index.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SEQUENCE (0x10) - Optional
        if let Some(sequence) = self.sequence {
            let field_type = 0x10;
            let key_data = vec![];
            let value_data = sequence.to_consensus_u32().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_TAP_BIP32_DERIVATION (0x16) - Multiple entries possible
        for (xonly_pubkey, (leaf_hashes, key_source)) in &self.tap_key_origins {
            let field_type = 0x16;
            let key_data = xonly_pubkey.serialize().to_vec();
            let mut value_data = Vec::new();

            // Encode leaf_hashes (compact size + hashes)
            value_data.push(leaf_hashes.len() as u8);
            for leaf_hash in leaf_hashes {
                value_data.extend_from_slice(leaf_hash.as_ref());
            }

            // Encode key_source (fingerprint + derivation path)
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }

            fields.push((field_type, key_data, value_data));
        }

        // PSBT_IN_SP_ECDH_SHARE (0x1d) - BIP-375, multiple entries possible
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            let field_type = 0x1d;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                ecdh_share.to_bytes().to_vec(),
            ));
        }

        // PSBT_IN_SP_DLEQ (0x1e) - BIP-375, multiple entries possible
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            let field_type = 0x1e;
            fields.push((
                field_type,
                scan_key.to_bytes().to_vec(),
                dleq_proof.as_bytes().to_vec(),
            ));
        }

        // PSBT_IN_PROPRIETARY (0xFC) - Multiple entries possible
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}

/// Extension trait for accessing psbt_v2::v2::Output fields for display
///
/// This trait provides convenient methods to access all standard PSBT v2 output fields
/// in a serialized format suitable for display or further processing.
pub trait OutputFieldsExt {
    /// Iterator over all standard output fields as (field_type, key_data, value_data) tuples
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl OutputFieldsExt for psbt_v2::v2::Output {
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut fields = Vec::new();

        // PSBT_OUT_REDEEM_SCRIPT (0x00) - Optional
        if let Some(ref script) = self.redeem_script {
            let field_type = 0x00;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_WITNESS_SCRIPT (0x01) - Optional
        if let Some(ref script) = self.witness_script {
            let field_type = 0x01;
            let key_data = vec![];
            let value_data = script.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_BIP32_DERIVATION (0x02) - Multiple entries possible
        for (pubkey, key_source) in &self.bip32_derivations {
            let field_type = 0x02;
            let key_data = pubkey.serialize().to_vec();
            let mut value_data = Vec::new();
            value_data.extend_from_slice(&key_source.0.to_bytes());
            for child in &key_source.1 {
                value_data.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_AMOUNT (0x03) - Always present
        {
            let field_type = 0x03;
            let key_data = vec![];
            let value_data = self.amount.to_sat().to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_SCRIPT (0x04) - Always present
        {
            let field_type = 0x04;
            let key_data = vec![];
            let value_data = self.script_pubkey.to_bytes();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_SP_V0_INFO (0x09) - BIP-375, optional
        if let Some(ref sp_info) = self.sp_v0_info {
            let field_type = 0x09;
            let key_data = vec![];
            fields.push((field_type, key_data, sp_info.clone()));
        }

        // PSBT_OUT_SP_V0_LABEL (0x0a) - BIP-375, optional
        if let Some(label) = self.sp_v0_label {
            let field_type = 0x0a;
            let key_data = vec![];
            let value_data = label.to_le_bytes().to_vec();
            fields.push((field_type, key_data, value_data));
        }

        // PSBT_OUT_PROPRIETARY (0xFC) - Multiple entries possible
        for (prop_key, value) in &self.proprietaries {
            use bitcoin::consensus::Encodable;
            let field_type = 0xFC;
            let mut key_data = vec![];
            let _ = prop_key.consensus_encode(&mut key_data);
            fields.push((field_type, key_data, value.clone()));
        }

        // Unknown fields
        for (key, value) in &self.unknowns {
            fields.push((key.type_value, key.key.clone(), value.clone()));
        }

        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn create_test_psbt() -> Psbt {
        // Create a minimal valid PSBT v2
        Psbt {
            global: psbt_v2::v2::Global::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    #[test]
    fn test_global_ecdh_share() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = EcdhShareData::without_proof(scan_key, share_point);

        // Add share
        psbt.add_global_ecdh_share(&share).unwrap();

        // Retrieve shares
        let shares = psbt.get_global_ecdh_shares();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].scan_key, scan_key);
        assert_eq!(shares[0].share, share_point);
    }

    #[test]
    fn test_global_dleq_proof() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let proof = DleqProof([0x42u8; 64]);

        // Add proof
        add_global_dleq_proof(&mut psbt, &scan_key, proof).unwrap();

        // Retrieve proof
        let retrieved = get_global_dleq_proof(&psbt, &scan_key);
        assert_eq!(retrieved, Some(proof));
    }

    #[test]
    fn test_output_sp_address() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let address =
            SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, 0)
                .unwrap();

        // Set address
        psbt.set_output_sp_info_v0(0, &address).unwrap();

        // Retrieve address
        let retrieved = psbt.get_output_sp_info_v0(0);
        assert_eq!(
            retrieved.map(|res| (res.0, res.1)),
            Some((address.get_scan_key(), address.get_spend_key()))
        );
    }

    #[test]
    fn test_output_sp_label() {
        let mut psbt = create_test_psbt();
        psbt.outputs.push(psbt_v2::v2::Output::default());

        let label = 42u32;

        // Set label
        psbt.set_output_sp_label(0, label).unwrap();

        // Retrieve label
        let retrieved = psbt.get_output_sp_label(0);
        assert_eq!(retrieved, Some(label));
    }
}
