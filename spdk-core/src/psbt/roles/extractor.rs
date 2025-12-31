//! PSBT Extractor Role
//!
//! Extracts the final Bitcoin transaction from a completed PSBT.
//!
//! Supports both P2WPKH and P2TR witness extraction:
//! - **P2WPKH**: Extracts from `partial_sigs` → witness: `[<ecdsa_sig>, <pubkey>]`
//! - **P2TR**: Extracts from `tap_key_sig` → witness: `[<schnorr_sig>]`
//!
//! After successful extraction, `PSBT_IN_SP_TWEAK` fields are cleaned up to prevent
//! accidental re-use and keep PSBTs cleaner.

use crate::psbt::core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Extract the final signed transaction from a PSBT
///
/// After successful extraction, cleans up `PSBT_IN_SP_TWEAK` fields to prevent
/// accidental re-use and keep PSBTs cleaner.
///
/// # Note
/// This function takes a mutable reference to allow cleanup of SP tweaks.
pub fn extract_transaction(psbt: &mut SilentPaymentPsbt) -> Result<Transaction> {
    let global = &psbt.global;
    let version = global.tx_version;
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    // Extract inputs with witnesses
    let mut inputs = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        inputs.push(extract_input(psbt, input_idx)?);
    }

    // Extract outputs
    let mut outputs = Vec::new();
    for output_idx in 0..psbt.num_outputs() {
        outputs.push(extract_output(psbt, output_idx)?);
    }

    let tx = Transaction {
        version,
        lock_time,
        input: inputs,
        output: outputs,
    };

    // Clean up SP tweaks after successful extraction
    // This prevents accidental re-use of tweaks and keeps PSBTs cleaner
    for input_idx in 0..psbt.num_inputs() {
        if psbt.get_input_sp_tweak(input_idx).is_some() {
            psbt.remove_input_sp_tweak(input_idx)?;
        }
    }

    Ok(tx)
}

/// Extract a single input from the PSBT
fn extract_input(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<TxIn> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // Build witness from partial signatures
    let witness = extract_witness(psbt, input_idx)?;

    Ok(TxIn {
        previous_output: OutPoint {
            txid: input.previous_txid,
            vout: input.spent_output_index,
        },
        script_sig: ScriptBuf::new(), // SegWit inputs have empty script_sig
        sequence: input.sequence.unwrap_or(Sequence::MAX),
        witness,
    })
}

/// Extract witness data from input
///
/// Handles both P2WPKH and P2TR witness formats:
/// - **P2TR** (Taproot key path): Check for `tap_key_sig` first
///   - Witness: `[<bip340_signature>]` (single element, 65 bytes)
/// - **P2WPKH**: Fall back to `partial_sigs`
///   - Witness: `[<ecdsa_signature>, <pubkey>]` (two elements)
fn extract_witness(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Witness> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // Check for P2TR tap_key_sig first (Taproot key-path spend)
    if let Some(tap_sig) = &input.tap_key_sig {
        // P2TR witness has single element: BIP-340 Schnorr signature
        let mut witness = Witness::new();
        witness.push(tap_sig.to_vec());
        return Ok(witness);
    }

    // Fall back to P2WPKH partial_sigs (ECDSA)
    let sigs = psbt.get_input_partial_sigs(input_idx);

    if sigs.is_empty() {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has no signatures (neither tap_key_sig nor partial_sigs)",
            input_idx
        )));
    }

    // For P2WPKH, witness is: <signature> <pubkey>
    // We expect exactly one signature for single-key P2WPKH
    if sigs.len() != 1 {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has {} partial signatures, expected 1 for P2WPKH",
            input_idx,
            sigs.len()
        )));
    }

    let (pubkey, signature) = &sigs[0];

    // Build P2WPKH witness stack
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(pubkey);

    Ok(witness)
}

/// Extract a single output from the PSBT
fn extract_output(psbt: &SilentPaymentPsbt, output_idx: usize) -> Result<TxOut> {
    let output = psbt
        .outputs
        .get(output_idx)
        .ok_or(Error::InvalidOutputIndex(output_idx))?;

    Ok(TxOut {
        value: Amount::from_sat(output.amount.to_sat()),
        script_pubkey: output.script_pubkey.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::{PsbtInput, PsbtOutput};
    use crate::psbt::crypto::pubkey_to_p2wpkh_script;
    use crate::psbt::roles::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
        input_finalizer::finalize_inputs,
        signer::{add_ecdh_shares_full, sign_inputs},
    };
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use silentpayments::SilentPaymentAddress;

    #[test]
    fn test_extract_transaction_regular_output() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 regular output
        let mut psbt = create_psbt(2, 1);

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        // Create P2WPKH script for output
        let output_script = pubkey_to_p2wpkh_script(&pubkey1);

        let inputs = vec![
            PsbtInput::new(
                OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
                Some(privkey1),
            ),
            PsbtInput::new(
                OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
                },
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
                Some(privkey2),
            ),
        ];

        let outputs = vec![PsbtOutput::regular(Amount::from_sat(55000), output_script)];

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Extract transaction
        let tx = extract_transaction(&mut psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_transaction_silent_payment() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1);

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address =
            SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, 0)
                .unwrap();

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
                Some(privkey1),
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
                Some(privkey2),
            ),
        ];

        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(55000),
            sp_address,
            None,
        )];

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_inputs(&secp, &mut psbt, None).unwrap();

        // Sign inputs
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Extract transaction
        let tx = extract_transaction(&mut psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify output is P2TR (silent payment outputs are taproot)
        assert!(tx.output[0].script_pubkey.is_p2tr());

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_fails_without_signatures() {
        let mut psbt = create_psbt(1, 1);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
            None, // No private key = no signature
        )];

        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(29000),
            ScriptBuf::new(),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        // Extraction should fail without signatures
        let result = extract_transaction(&mut psbt);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ExtractionFailed(_))));
    }
}
