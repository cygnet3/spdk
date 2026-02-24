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
pub const PSBT_IN_SP_SPEND_BIP32_DERIVATION: u8 = 0x1f;
pub const PSBT_IN_SP_TWEAK: u8 = 0x20;
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
    fn get_output_sp_info(&self, output_index: usize) -> Option<(PublicKey, PublicKey)>;

    /// Set silent payment v0 keys for an output
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `address` - The silent payment address
    fn set_output_sp_info(
        &mut self,
        output_index: usize,
        address: &SilentPaymentAddress,
    ) -> Result<()>;

    /// Get silent payment label for an output
    ///
    /// Field type: PSBT_OUT_SP_V0_LABEL (0x0a)
    ///
    /// **Important:** This field is metadata only. When present, the spend key in
    /// PSBT_OUT_SP_V0_INFO is already labeled. The label value is not used for
    /// cryptographic derivation during finalization.
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    fn get_output_sp_label(&self, output_index: usize) -> Option<u32>;

    /// Set silent payment label for an output
    ///
    /// **Important:** When setting this field, ensure that the spend key in
    /// PSBT_OUT_SP_V0_INFO is already labeled. This field is metadata only.
    ///
    /// # Arguments
    /// * `output_index` - Index of the output
    /// * `label` - The label value (0 = change, 1+ = labeled receiving addresses)
    fn set_output_sp_label(&mut self, output_index: usize, label: u32) -> Result<()>;

    // ===== Silent Payment Spend Key Derivation (BIP-376) =====

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

    /// Get silent payment spend key BIP32 derivation for an input
    ///
    /// Returns the 33-byte spend public key and its BIP32 derivation path.
    /// This is used by hardware wallets to identify inputs they control when
    /// spending Silent Payment outputs.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    ///
    /// # Returns
    /// * `Some((spend_pubkey, fingerprint, path))` - The spend key and derivation info
    /// * `None` - If the field is not present
    fn get_input_sp_spend_bip32_derivation(
        &self,
        input_index: usize,
    ) -> Option<(PublicKey, [u8; 4], Vec<u32>)>;

    /// Set silent payment spend key BIP32 derivation for an input
    ///
    /// Used by the UPDATER role when spending Silent Payment outputs.
    /// The spend key is the 33-byte compressed public key that, when tweaked
    /// with PSBT_IN_SP_TWEAK, produces the key locking the output.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `spend_pubkey` - The 33-byte spend public key
    /// * `fingerprint` - Master key fingerprint (4 bytes)
    /// * `path` - BIP32 derivation path (e.g., [352', 0', 0', 1, index])
    fn set_input_sp_spend_bip32_derivation(
        &mut self,
        input_index: usize,
        spend_pubkey: &PublicKey,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<()>;

    /// Remove silent payment spend key BIP32 derivation from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()>;

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

    fn get_output_sp_info(&self, output_index: usize) -> Option<(PublicKey, PublicKey)> {
        let output = self.outputs.get(output_index)?;

        if let Some(bytes) = &output.sp_v0_info {
            if bytes.len() != 66 {
                return None;
            };
            let scan_key = PublicKey::from_slice(&bytes[..33]).ok();
            let spend_key = PublicKey::from_slice(&bytes[33..]).ok();
            if let (Some(scan_key), Some(spend_key)) = (scan_key, spend_key) {
                return Some((scan_key, spend_key));
            }
        }

        None
    }

    fn set_output_sp_info(
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

        //FIXME: migrate to dedicated field in psbt_v2 once available instead of using unknowns
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

    fn get_input_sp_spend_bip32_derivation(
        &self,
        input_index: usize,
    ) -> Option<(PublicKey, [u8; 4], Vec<u32>)> {
        let input = self.inputs.get(input_index)?;

        for (key, value) in &input.unknowns {
            if key.type_value == PSBT_IN_SP_SPEND_BIP32_DERIVATION && key.key.len() == 33 {
                // Key data is 33-byte spend public key
                let spend_pubkey = PublicKey::from_slice(&key.key).ok()?;

                // Value is fingerprint (4 bytes) + path (4 bytes per element)
                if value.len() < 4 || (value.len() - 4) % 4 != 0 {
                    return None;
                }

                let mut fingerprint = [0u8; 4];
                fingerprint.copy_from_slice(&value[0..4]);

                let path: Vec<u32> = value[4..]
                    .chunks(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunk is 4 bytes")))
                    .collect();

                return Some((spend_pubkey, fingerprint, path));
            }
        }
        None
    }

    fn set_input_sp_spend_bip32_derivation(
        &mut self,
        input_index: usize,
        spend_pubkey: &PublicKey,
        fingerprint: [u8; 4],
        path: Vec<u32>,
    ) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Key: type 0x1f with 33-byte spend pubkey as key data
        let key = Key {
            type_value: PSBT_IN_SP_SPEND_BIP32_DERIVATION,
            key: spend_pubkey.serialize().to_vec(),
        };

        // Value: fingerprint (4 bytes) + path (4 bytes per element, little-endian)
        let mut value = Vec::with_capacity(4 + path.len() * 4);
        value.extend_from_slice(&fingerprint);
        for child in &path {
            value.extend_from_slice(&child.to_le_bytes());
        }

        //FIXME: migrate to dedicated field in psbt_v2 once available instead of using unknowns
        input.unknowns.insert(key, value);
        Ok(())
    }

    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Find and remove the key with type 0x1f (any key data)
        let keys_to_remove: Vec<Key> = input
            .unknowns
            .keys()
            .filter(|k| k.type_value == PSBT_IN_SP_SPEND_BIP32_DERIVATION)
            .cloned()
            .collect();

        for key in keys_to_remove {
            input.unknowns.remove(&key);
        }

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
            if let Some(sp_info) = self.get_output_sp_info(output_idx) {
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
        .copied()
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

    input.sp_dleq_proofs.get(&scan_key_compressed).copied()
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
/// 1. SP spend BIP32 derivation (for Silent Payment inputs, highest priority)
/// 2. Taproot BIP32 derivation (tap_internal_key for P2TR)
/// 3. Standard BIP32 derivation field (for non-Taproot)
/// 4. Partial signature field
pub fn get_input_pubkey(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<PublicKey> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or_else(|| Error::InvalidInputIndex(input_idx))?;

    // Method 1: Extract from SP spend BIP32 derivation (for Silent Payment inputs)
    if let Some((spend_pubkey, _, _)) = psbt.get_input_sp_spend_bip32_derivation(input_idx) {
        return Ok(spend_pubkey);
    }

    // Method 2: Extract from Taproot BIP32 derivation (tap_internal_key for P2TR)
    if !input.tap_internal_key.is_none() {
        // Return the first key, converting x-only to full pubkey (even Y)
        if let Some(xonly_key) = input.tap_internal_key {
            let mut pubkey_bytes = vec![0x02];
            pubkey_bytes.extend_from_slice(&xonly_key.serialize());
            if let Ok(pubkey) = PublicKey::from_slice(&pubkey_bytes) {
                return Ok(pubkey);
            }
        }
    }

    // Method 3: Extract from BIP32 derivation field (for non-Taproot)
    if !input.bip32_derivations.is_empty() {
        // Return the first key
        if let Some(key) = input.bip32_derivations.keys().next() {
            return Ok(*key);
        }
    }

    Err(Error::Other(format!(
        "Input {} missing public key (no SP spend, BIP32 derivation, or tap key origin found)",
        input_idx
    )))
}

pub fn get_output_sp_keys(
    psbt: &SilentPaymentPsbt,
    output_idx: usize,
) -> Result<(PublicKey, PublicKey)> {
    // Use the extension trait method via SilentPaymentPsbt wrapper
    let sp_info = psbt.get_output_sp_info(output_idx).ok_or_else(|| {
        Error::MissingField(format!("Output {} missing PSBT_OUT_SP_V0_INFO", output_idx))
    })?;
    Ok((sp_info.0, sp_info.1))
}

// ============================================================================
// Display Extension Traits
// ============================================================================
//
// The following traits provide methods for extracting and serializing PSBT fields
// for display purposes. These are used by GUI and analysis tools to inspect PSBT contents.

/// Extension trait for iterating all PSBT global map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait GlobalFieldsExt {
    /// Returns all global map fields as (field_type, key_data, value_data) tuples.
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT input map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait InputFieldsExt {
    /// Returns all input map fields as (field_type, key_data, value_data) tuples.
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl InputFieldsExt for psbt_v2::v2::Input {
    fn iter_input_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT output map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait OutputFieldsExt {
    /// Returns all output map fields as (field_type, key_data, value_data) tuples.
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)>;
}

impl OutputFieldsExt for psbt_v2::v2::Output {
    fn iter_output_fields(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
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
        psbt.set_output_sp_info(0, &address).unwrap();

        // Retrieve address
        let retrieved = psbt.get_output_sp_info(0);
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
