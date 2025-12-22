//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.
//!
//! This module handles both regular P2WPKH signing and Silent Payment P2TR signing:
//! - **P2WPKH inputs**: Use [`sign_inputs()`] with ECDSA signatures → `partial_sigs`
//! - **P2TR SP inputs**: Use [`sign_sp_inputs()`] with tweaked key + Schnorr → `tap_key_sig`
//! - **Mixed transactions**: Call both functions as needed for different input types

use crate::psbt::core::{Bip375PsbtExt, EcdhShareData, Error, PsbtInput, Result, SilentPaymentPsbt};
use crate::psbt::crypto::{
    apply_tweak_to_privkey, compute_ecdh_share, dleq_generate_proof, sign_p2pkh_input,
    sign_p2tr_input, sign_p2wpkh_input,
};
use bitcoin::ScriptBuf;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashSet;

/// Add ECDH shares for all inputs (full signing)
pub fn add_ecdh_shares_full(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[PsbtInput],
    scan_keys: &[PublicKey],
    include_dleq: bool,
) -> Result<()> {
    for (input_idx, input) in inputs.iter().enumerate() {
        let Some(ref privkey) = input.private_key else {
            return Err(Error::Other(format!(
                "Input {} missing private key",
                input_idx
            )));
        };

        for scan_key in scan_keys {
            let share_point = compute_ecdh_share(secp, privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32];
                Some(
                    dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
                        .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
                )
            } else {
                None
            };

            let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
            psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
        }
    }
    Ok(())
}

pub fn add_ecdh_shares_partial(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[PsbtInput],
    scan_keys: &[PublicKey],
    controlled_indices: &[usize],
    include_dleq: bool,
) -> Result<()> {
    let controlled_set: HashSet<usize> = controlled_indices.iter().copied().collect();

    for (input_idx, input) in inputs.iter().enumerate() {
        if !controlled_set.contains(&input_idx) {
            continue;
        }

        let Some(ref base_privkey) = input.private_key else {
            return Err(Error::Other(format!(
                "Controlled input {} missing private key",
                input_idx
            )));
        };

        // Check for Silent Payment tweak in PSBT and apply if present
        // This ensures DLEQ proofs match the on-chain tweaked public key
        let mut privkey = if let Some(tweak) = psbt.get_input_sp_tweak(input_idx) {
            apply_tweak_to_privkey(base_privkey, &tweak)
                .map_err(|e| Error::Other(format!("Tweak application failed: {}", e)))?
        } else {
            *base_privkey
        };

        // For P2TR inputs, the public key is x-only (implicitly even Y).
        // If our private key produces an odd Y point, we must negate it
        // to match the on-chain public key for DLEQ verification.
        if input.witness_utxo.script_pubkey.is_p2tr() {
            let keypair = secp256k1::Keypair::from_secret_key(secp, &privkey);
            let (_, parity) = keypair.x_only_public_key();
            if parity == secp256k1::Parity::Odd {
                privkey = privkey.negate();
            }
        }

        for scan_key in scan_keys {
            let share_point = compute_ecdh_share(secp, &privkey, scan_key)
                .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

            let dleq_proof = if include_dleq {
                let rand_aux = [input_idx as u8; 32];
                Some(
                    dleq_generate_proof(secp, &privkey, scan_key, &rand_aux, None)
                        .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
                )
            } else {
                None
            };

            let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
            psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
        }
    }
    Ok(())
}

/// Sign inputs based on their script type (P2PKH, P2WPKH, P2TR)
///
/// This function automatically detects the input type and applies the correct signing logic:
/// - **P2PKH**: Signs with ECDSA (legacy)
/// - **P2WPKH**: Signs with ECDSA (SegWit v0)
/// - **P2TR**: Signs with Schnorr (Taproot v1). Checks for Silent Payment tweaks (`PSBT_IN_SP_TWEAK`)
///   and applies them to the private key if present.
pub fn sign_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    inputs: &[PsbtInput],
) -> Result<()> {
    let tx = extract_tx_for_signing(psbt)?;
    let mut prevouts: Option<Vec<bitcoin::TxOut>> = None; // Lazy loaded for P2TR

    for (input_idx, input) in inputs.iter().enumerate() {
        let Some(ref privkey) = input.private_key else {
            continue;
        };

        if input.witness_utxo.script_pubkey.is_p2pkh() {
            let signature = sign_p2pkh_input(
                secp,
                &tx,
                input_idx,
                &input.witness_utxo.script_pubkey,
                input.witness_utxo.value, // Not needed for legacy but passed
                privkey,
            )
            .map_err(|e| Error::Other(format!("P2PKH signing failed: {}", e)))?;

            let pubkey = PublicKey::from_secret_key(secp, privkey);
            let bitcoin_pubkey = bitcoin::PublicKey::new(pubkey);

            let sig = bitcoin::ecdsa::Signature::from_slice(&signature)
                .map_err(|e| Error::Other(format!("Invalid signature DER: {}", e)))?;

            psbt.inputs[input_idx]
                .partial_sigs
                .insert(bitcoin_pubkey, sig);
        } else if input.witness_utxo.script_pubkey.is_p2wpkh() {
            let signature = sign_p2wpkh_input(
                secp,
                &tx,
                input_idx,
                &input.witness_utxo.script_pubkey,
                input.witness_utxo.value,
                privkey,
            )
            .map_err(|e| Error::Other(format!("P2WPKH signing failed: {}", e)))?;

            let pubkey = PublicKey::from_secret_key(secp, privkey);
            let bitcoin_pubkey = bitcoin::PublicKey::new(pubkey);

            let sig = bitcoin::ecdsa::Signature::from_slice(&signature)
                .map_err(|e| Error::Other(format!("Invalid signature DER: {}", e)))?;

            psbt.inputs[input_idx]
                .partial_sigs
                .insert(bitcoin_pubkey, sig);
        } else if input.witness_utxo.script_pubkey.is_p2tr() {
            // Load prevouts if not already loaded (needed for Taproot sighash)
            if prevouts.is_none() {
                prevouts = Some(
                    psbt.inputs
                        .iter()
                        .enumerate()
                        .map(|(idx, input)| {
                            input.witness_utxo.clone().ok_or(Error::Other(format!(
                                "Input {} missing witness_utxo (required for P2TR)",
                                idx
                            )))
                        })
                        .collect::<Result<Vec<_>>>()?,
                );
            }

            // Check for SP tweak
            let tweak = psbt.get_input_sp_tweak(input_idx);
            let signing_key = if let Some(tweak) = tweak {
                apply_tweak_to_privkey(privkey, &tweak)
                    .map_err(|e| Error::Other(format!("Tweak application failed: {}", e)))?
            } else {
                *privkey
            };

            // Sign with BIP-340 Schnorr
            let signature = sign_p2tr_input(
                secp,
                &tx,
                input_idx,
                prevouts.as_ref().unwrap(),
                &signing_key,
            )
            .map_err(|e| Error::Other(format!("Schnorr signing failed: {}", e)))?;

            // Add tap_key_sig to PSBT
            psbt.inputs[input_idx].tap_key_sig = Some(signature);
        }
    }
    Ok(())
}

/// Sign Silent Payment P2TR inputs using tweaked private keys
///
/// For each input with `PSBT_IN_SP_TWEAK` (0x1f):
/// 1. Apply tweak: `tweaked_privkey = spend_privkey + tweak`
/// 2. Sign with BIP-340 Schnorr signature
/// 3. Add `tap_key_sig` to PSBT input
///
/// The tweak is derived from BIP-352 output derivation during wallet scanning.
/// This allows spending silent payment outputs without revealing the connection
/// between the scan key and spend key.
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `psbt` - PSBT to sign
/// * `spend_privkey` - The spend private key (before tweaking)
/// * `input_indices` - Indices of inputs to sign
///
/// # Witness Format
/// Creates P2TR key-path witness: `[<bip340_signature>]` (65 bytes: 64-byte sig + sighash byte)
///
/// See also: [`sign_inputs()`] for P2WPKH signing
pub fn sign_sp_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    spend_privkey: &SecretKey,
    input_indices: &[usize],
) -> Result<()> {
    // Build prevouts array for Taproot sighash
    let prevouts: Vec<bitcoin::TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(idx, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(Error::Other(format!("Input {} missing witness_utxo", idx)))
        })
        .collect::<Result<Vec<_>>>()?;

    // Build unsigned transaction for signing
    let tx = extract_tx_for_signing(psbt)?;

    // Sign each input with tweak
    for &input_idx in input_indices {
        let Some(tweak) = psbt.get_input_sp_tweak(input_idx) else {
            continue; // Not a silent payment input, skip
        };

        // Apply tweak to spend key: tweaked_privkey = spend_privkey + tweak
        let tweaked_privkey = apply_tweak_to_privkey(spend_privkey, &tweak)
            .map_err(|e| Error::Other(format!("Tweak application failed: {}", e)))?;

        // Sign with BIP-340 Schnorr
        let signature = sign_p2tr_input(secp, &tx, input_idx, &prevouts, &tweaked_privkey)
            .map_err(|e| Error::Other(format!("Schnorr signing failed: {}", e)))?;

        // Add tap_key_sig to PSBT
        psbt.inputs[input_idx].tap_key_sig = Some(signature);
    }

    Ok(())
}

/// Extract transaction data needed for signing
fn extract_tx_for_signing(psbt: &SilentPaymentPsbt) -> Result<bitcoin::Transaction> {
    use bitcoin::{absolute::LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut};

    let global = &psbt.global;
    let version = global.tx_version; // Already Version type
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    let mut inputs = Vec::new();
    for input in &psbt.inputs {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: input.previous_txid,
                vout: input.spent_output_index,
            },
            script_sig: ScriptBuf::new(),
            sequence: input.sequence.unwrap_or(Sequence::MAX),
            witness: bitcoin::Witness::new(),
        });
    }

    let mut outputs = Vec::new();
    for output in &psbt.outputs {
        outputs.push(TxOut {
            value: output.amount, // Already Amount type
            script_pubkey: output.script_pubkey.clone(),
        });
    }

    Ok(Transaction {
        version,
        lock_time,
        input: inputs,
        output: outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::roles::{constructor::add_inputs, creator::create_psbt};
    use crate::psbt::core::PsbtInput;
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::SecretKey;

    #[test]
    fn test_add_ecdh_shares_full() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1);

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                Some(privkey1),
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                Some(privkey2),
            ),
        ];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], true).unwrap();

        // Verify ECDH shares were added
        let shares0 = psbt.get_input_ecdh_shares(0);
        assert_eq!(shares0.len(), 1);
        assert_eq!(shares0[0].scan_key, scan_key);

        let shares1 = psbt.get_input_ecdh_shares(1);
        assert_eq!(shares1.len(), 1);
    }

    #[test]
    fn test_add_ecdh_shares_partial() {
        let secp = Secp256k1::new();
        let mut psbt = create_psbt(2, 1);

        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let scan_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                Some(privkey1),
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                Some(privkey2),
            ),
        ];

        add_inputs(&mut psbt, &inputs).unwrap();

        // Only sign input 0
        add_ecdh_shares_partial(&secp, &mut psbt, &inputs, &[scan_key], &[0], false).unwrap();

        // Input 0 should have shares
        let shares0 = psbt.get_input_ecdh_shares(0);
        assert_eq!(shares0.len(), 1);

        // Input 1 should not have shares
        let shares1 = psbt.get_input_ecdh_shares(1);
        assert_eq!(shares1.len(), 0);
    }
}
