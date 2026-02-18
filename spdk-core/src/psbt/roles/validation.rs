//! PSBT Validation Functions
//!
//! Validates PSBTs according to BIP-375 rules.

use crate::psbt::core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use crate::psbt::crypto::bip352::is_input_eligible;
use crate::psbt::crypto::dleq_verify_proof;
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashSet;

/// Validation level for PSBT checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Basic structural validation only
    Basic,
    /// Validate existing DLEQ proofs without requiring complete ECDH coverage (for partial signing)
    DleqOnly,
    /// Full validation including complete ECDH coverage and DLEQ proofs
    Full,
}

/// Validate a PSBT according to BIP-375 rules
pub fn validate_psbt(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &SilentPaymentPsbt,
    level: ValidationLevel,
) -> Result<()> {
    // Basic validations
    validate_psbt_version(psbt)?;
    validate_psbt_state(psbt)?;
    validate_input_fields(psbt)?;
    validate_output_fields(psbt)?;

    // Validate SP spend fields BIP-376 (if any inputs have them)
    validate_sp_spend_fields(psbt)?;

    // Check if this PSBT has silent payment outputs
    let has_sp_outputs = (0..psbt.num_outputs()).any(|i| psbt.get_output_sp_info(i).is_some());

    if has_sp_outputs {
        // Segwit version restrictions (must be v0 or v1 for silent payments)
        validate_segwit_versions(psbt)?;
        // SIGHASH_ALL requirement (only SIGHASH_ALL allowed with silent payments)
        validate_sighash_types(psbt)?;
    }

    // DLEQ-only validation (for partial signing workflows)
    if level == ValidationLevel::DleqOnly && has_sp_outputs {
        validate_dleq_proofs(secp, psbt)?;
    }

    // Full validation
    if level == ValidationLevel::Full && has_sp_outputs {
        // Check DLEQ proofs first (includes global ECDH/DLEQ pairing check)
        validate_dleq_proofs(secp, psbt)?;
        // Then verify ECDH coverage
        validate_ecdh_coverage(psbt)?;
        validate_output_scripts(secp, psbt)?;
    }

    Ok(())
}

/// Validate PSBT version is v2
fn validate_psbt_version(psbt: &SilentPaymentPsbt) -> Result<()> {
    if psbt.global.version != psbt_v2::V2 {
        return Err(Error::InvalidVersion {
            expected: 2,
            actual: psbt.global.version.into(),
        });
    }

    Ok(())
}

/// Verify script_pubkey presence and tx_modifiable_flags consistency
///
/// Per BIP 375, the Signer clears tx_modifiable_flags when it computes
/// PSBT_OUT_SCRIPT for SP outputs. Regular (non-SP) outputs may have
/// script_pubkey set at construction time while flags are still modifiable.
fn validate_psbt_state(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, output) in psbt.outputs.iter().enumerate() {
        let is_sp_output = psbt.get_output_sp_info(i).is_some();
        if is_sp_output
            && !output.script_pubkey.is_empty()
            && psbt.global.tx_modifiable_flags != 0
        {
            return Err(Error::InvalidPsbtState(
                "SP output has script_pubkey set while tx_modifiable_flags is non-zero".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate all inputs have required fields
fn validate_input_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        // previous_txid and spent_output_index are mandatory in struct

        if input.sequence.is_none() {
            return Err(Error::MissingField(format!("Input {} missing sequence", i)));
        }
    }

    Ok(())
}

/// Validate all outputs have required fields
fn validate_output_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, output) in psbt.outputs.iter().enumerate() {
        // Amount is mandatory in struct

        // Check if this is a silent payment output
        let has_sp_address = psbt.get_output_sp_info(i).is_some();
        let has_script = !output.script_pubkey.is_empty();

        // Output must have either a script OR a silent payment address
        if !has_sp_address && !has_script {
            return Err(Error::MissingField(format!(
                "Output {} missing both script and SP address",
                i
            )));
        }

        // PSBT_OUT_SP_V0_LABEL requires SP address
        let has_sp_label = psbt.get_output_sp_label(i).is_some();

        if has_sp_label && !has_sp_address {
            return Err(Error::MissingField(format!(
                "Output {} has label but missing SP address",
                i
            )));
        }
    }

    Ok(())
}

/// Validate SP spend fields on inputs (BIP-376)
///
/// Checks that inputs with `PSBT_IN_SP_TWEAK` are properly configured:
/// - PSBT_IN_SP_SPEND_BIP32_DERIVATION must be present
fn validate_sp_spend_fields(psbt: &SilentPaymentPsbt) -> Result<()> {
    for input_idx in 0..psbt.num_inputs() {
        // Check if this input has an SP tweak
        if psbt.get_input_sp_tweak(input_idx).is_some() {
            if psbt.get_input_sp_spend_bip32_derivation(input_idx).is_none() {
                return Err(Error::MissingField(format!(
                    "Input {} has SP tweak but missing SP spend BIP32 derivation",
                    input_idx
                )));
            }
        }
    }

    Ok(())
}

/// Validate segwit version restrictions
fn validate_segwit_versions(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(witness_utxo) = &input.witness_utxo {
            let script = &witness_utxo.script_pubkey;

            if let Some(version) = script.witness_version() {
                // version is WitnessVersion enum.
                use bitcoin::WitnessVersion;
                match version {
                    WitnessVersion::V0 | WitnessVersion::V1 => {}
                    _ => {
                        return Err(Error::InvalidFieldData(format!(
                            "Input {} uses segwit version {:?} (incompatible with silent payments)",
                            i, version
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Validate SIGHASH_ALL requirement
fn validate_sighash_types(psbt: &SilentPaymentPsbt) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(sighash_type) = input.sighash_type {
            // Check if it is SIGHASH_ALL (0x01)
            // PsbtSighashType wraps EcdsaSighashType
            // EcdsaSighashType::All is 0x01
            if sighash_type.to_u32() != 0x01 {
                return Err(Error::InvalidFieldData(format!(
                    "Input {} uses non-SIGHASH_ALL (0x{:02x}) with silent payments",
                    i,
                    sighash_type.to_u32()
                )));
            }
        }
    }
    Ok(())
}

/// Validate ECDH coverage for silent payment outputs
///
/// Per BIP-375:
/// - Each scan key in SP outputs must have corresponding ECDH share(s)
/// - Complete coverage (all eligible inputs) required when output scripts are computed
fn validate_ecdh_coverage(psbt: &SilentPaymentPsbt) -> Result<()> {
    let num_inputs = psbt.num_inputs();

    // Collect all unique scan keys from SP outputs
    let mut scan_keys = HashSet::new();
    for i in 0..psbt.num_outputs() {
        if let Some((scan_key, _spend_key)) = psbt.get_output_sp_info(i) {
            scan_keys.insert(scan_key);
        }
    }

    // For EACH scan key, verify ECDH coverage
    for scan_key in &scan_keys {
        // Check global shares for this specific scan key
        let global_shares = psbt.get_global_ecdh_shares();
        let has_global_ecdh = global_shares.iter().any(|s| &s.scan_key == scan_key);

        // Check per-input shares for this specific scan key
        let has_input_ecdh = (0..num_inputs).any(|i| {
            psbt.get_input_ecdh_shares(i)
                .iter()
                .any(|s| &s.scan_key == scan_key)
        });

        // Check if any outputs with this scan key have PSBT_OUT_SCRIPT set
        let has_computed_outputs = (0..psbt.num_outputs()).any(|i| {
            let output = &psbt.outputs[i];
            let has_script = !output.script_pubkey.is_empty();
            if let Some((sk, _)) = psbt.get_output_sp_info(i) {
                has_script && &sk == scan_key
            } else {
                false
            }
        });

        // Only require ECDH shares when output scripts have been computed
        if !has_computed_outputs {
            continue;
        }

        // Must have at least one ECDH share for this scan key when scripts are computed
        if !has_global_ecdh && !has_input_ecdh {
            return Err(Error::Other(
                "Silent payment output present but no ECDH share for scan key".to_string(),
            ));
        }

        // If using per-input shares (not global), require complete ECDH coverage
        // of all eligible inputs
        if has_input_ecdh && !has_global_ecdh {
            for i in 0..num_inputs {
                if let Some(input) = psbt.inputs.get(i) {
                    if is_input_eligible(input) {
                        let has_share_for_key = psbt
                            .get_input_ecdh_shares(i)
                            .iter()
                            .any(|s| &s.scan_key == scan_key);
                        if !has_share_for_key {
                            return Err(Error::Other(format!(
                                "Output script set but eligible input {} missing ECDH share for scan key",
                                i
                            )));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validate that output scripts match computed silent payment addresses
fn validate_output_scripts(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &SilentPaymentPsbt,
) -> Result<()> {
    use crate::psbt::core::{
        aggregate_ecdh_shares, get_input_bip32_pubkeys, get_input_outpoint_bytes,
    };
    use crate::psbt::crypto::{
        compute_shared_secrets, derive_silent_payment_output_pubkey, tweaked_key_to_p2tr_script,
    };
    use std::collections::HashMap;

    // Extract outpoints and BIP32 pubkeys from PSBT
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();

    for input_idx in 0..psbt.num_inputs() {
        outpoints.push(get_input_outpoint_bytes(psbt, input_idx)?);
        let bip32_pubkeys = get_input_bip32_pubkeys(psbt, input_idx);
        if bip32_pubkeys.is_empty() {
            eprintln!(
                "Warning: Input {} has no BIP32 derivation, skipping output script validation",
                input_idx
            );
            return Ok(());
        }
        input_pubkeys.push(bip32_pubkeys[0]);
    }

    if input_pubkeys.is_empty() {
        return Ok(());
    }

    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    let share_pairs: Vec<(PublicKey, PublicKey)> = aggregated_shares
        .iter()
        .map(|(sk, agg)| (*sk, agg.aggregated_share))
        .collect();

    let shared_secrets =
        compute_shared_secrets(secp, &share_pairs, &outpoints, &input_pubkeys)
            .map_err(|e| Error::Other(format!("Shared secret computation failed: {}", e)))?;

    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    for output_idx in 0..psbt.num_outputs() {
        let output = &psbt.outputs[output_idx];
        if output.script_pubkey.is_empty() {
            continue;
        }

        let (scan_key, spend_key) = match psbt.get_output_sp_info(output_idx) {
            Some(keys) => keys,
            None => continue,
        };

        let shared_secret = shared_secrets.get(&scan_key).ok_or_else(|| {
            Error::Other(format!(
                "Output {} missing shared secret for scan key",
                output_idx
            ))
        })?;

        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);

        let shared_secret_bytes = shared_secret.serialize();
        let expected_pubkey =
            derive_silent_payment_output_pubkey(secp, &spend_key, &shared_secret_bytes, k)
                .map_err(|e| Error::Other(format!("Failed to derive output pubkey: {}", e)))?;

        let expected_script = tweaked_key_to_p2tr_script(&expected_pubkey);

        if output.script_pubkey != expected_script {
            return Err(Error::Other(format!(
                "Output {} script mismatch: expected silent payment address doesn't match actual script",
                output_idx
            )));
        }

        scan_key_output_indices.insert(scan_key, k + 1);
    }

    Ok(())
}

/// Validate all DLEQ proofs in the PSBT
fn validate_dleq_proofs(secp: &Secp256k1<secp256k1::All>, psbt: &SilentPaymentPsbt) -> Result<()> {
    use crate::psbt::core::get_input_pubkey;

    // Check global DLEQ if global ECDH exists
    let global_shares = psbt.get_global_ecdh_shares();
    for share in global_shares {
        if share.dleq_proof.is_none() {
            return Err(Error::Other(
                "Global ECDH share missing DLEQ proof".to_string(),
            ));
        }
    }

    // Validate per-input ECDH shares
    for input_idx in 0..psbt.num_inputs() {
        let shares = psbt.get_input_ecdh_shares(input_idx);

        for share in shares {
            if share.dleq_proof.is_none() {
                return Err(Error::Other(format!(
                    "Input {} missing required DLEQ proof for ECDH share",
                    input_idx
                )));
            }

            if let Some(proof) = share.dleq_proof {
                let input_pubkey = get_input_pubkey(psbt, input_idx)?;

                let is_valid = dleq_verify_proof(
                    secp,
                    &input_pubkey,
                    &share.scan_key,
                    &share.share,
                    &proof,
                    None,
                )
                .map_err(|e| Error::Other(format!("DLEQ verification error: {}", e)))?;

                if !is_valid {
                    return Err(Error::DleqVerificationFailed(input_idx));
                }
            }
        }
    }

    Ok(())
}

/// Validate that a PSBT is ready for extraction
///
/// Checks that all inputs are signed (either P2WPKH with `partial_sigs` or P2TR with `tap_key_sig`)
/// and all outputs have scripts.
pub fn validate_ready_for_extraction(psbt: &SilentPaymentPsbt) -> Result<()> {
    for input_idx in 0..psbt.num_inputs() {
        let input = &psbt.inputs[input_idx];

        // Check for either tap_key_sig (P2TR) or partial_sigs (P2WPKH)
        let has_tap_sig = input.tap_key_sig.is_some();
        let has_partial_sigs = !psbt.get_input_partial_sigs(input_idx).is_empty();

        if !has_tap_sig && !has_partial_sigs {
            return Err(Error::ExtractionFailed(format!(
                "Input {} is not signed (no tap_key_sig or partial_sigs)",
                input_idx
            )));
        }
    }

    for output_idx in 0..psbt.num_outputs() {
        if psbt.outputs[output_idx].script_pubkey.is_empty() {
            return Err(Error::ExtractionFailed(format!(
                "Output {} missing script",
                output_idx
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::{PsbtInput, PsbtOutput};
    use crate::psbt::crypto::pubkey_to_p2wpkh_script;
    use crate::psbt::roles::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, Sequence, TxOut, Txid};
    use secp256k1::SecretKey;
    use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

    #[test]
    fn test_validate_psbt_version() {
        let psbt = create_psbt(1, 1);
        assert!(validate_psbt_version(&psbt).is_ok());
    }

    #[test]
    fn test_validate_input_fields() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1);

        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: pubkey_to_p2wpkh_script(&pubkey),
            },
            Sequence::MAX,
            Some(privkey),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();

        assert!(validate_input_fields(&psbt).is_ok());
    }

    #[test]
    fn test_validate_output_fields() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(1, 1);

        // Create a valid output with a real script (P2WPKH)
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);
        let script = pubkey_to_p2wpkh_script(&pubkey);

        let outputs = vec![PsbtOutput::regular(Amount::from_sat(29000), script)];

        add_outputs(&mut psbt, &outputs).unwrap();

        assert!(validate_output_fields(&psbt).is_ok());
    }

    #[test]
    fn test_validate_ecdh_coverage() {
        use crate::psbt::core::{Bip375PsbtExt, EcdhShareData};

        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1); // 2 inputs, 1 output

        // Setup keys
        let scan_priv = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_pub = PublicKey::from_secret_key(&secp, &scan_priv);
        let spend_priv = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_priv);

        let sp_addr =
            SilentPaymentAddress::new(scan_pub, spend_pub, SpNetwork::Regtest, 0).unwrap();

        // Add SP output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(10000),
            sp_addr,
            None,
        )];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add dummy inputs so we have something to check against
        let input_priv = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let input_pub = PublicKey::from_secret_key(&secp, &input_priv);
        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(10000),
                    script_pubkey: pubkey_to_p2wpkh_script(&input_pub),
                },
                Sequence::MAX,
                Some(input_priv),
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(10000),
                    script_pubkey: pubkey_to_p2wpkh_script(&input_pub),
                },
                Sequence::MAX,
                Some(input_priv),
            ),
        ];
        add_inputs(&mut psbt, &inputs).unwrap();

        // Case 1: Global share present -> Valid
        {
            let mut psbt_global = psbt.clone();
            // Create a dummy share
            let share_point =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
            let share = EcdhShareData::without_proof(scan_pub, share_point);
            psbt_global.add_global_ecdh_share(&share).unwrap();

            assert!(validate_ecdh_coverage(&psbt_global).is_ok());
        }

        // Case 2: Per-input shares for ALL inputs -> Valid
        {
            let mut psbt_inputs = psbt.clone();
            let share_point =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
            let share = EcdhShareData::without_proof(scan_pub, share_point);

            // Add to all inputs
            for i in 0..psbt_inputs.num_inputs() {
                psbt_inputs.add_input_ecdh_share(i, &share).unwrap();
            }

            assert!(validate_ecdh_coverage(&psbt_inputs).is_ok());
        }

        // Case 3: Per-input shares for SOME inputs -> Valid
        {
            let mut psbt_partial = psbt.clone();
            let share_point =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
            let share = EcdhShareData::without_proof(scan_pub, share_point);

            // Add to only first input
            psbt_partial.add_input_ecdh_share(0, &share).unwrap();

            assert!(validate_ecdh_coverage(&psbt_partial).is_ok());
        }

    }
}
