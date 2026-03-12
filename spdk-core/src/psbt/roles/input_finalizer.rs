//! PSBT Input Finalizer Role
//!
//! Aggregates ECDH shares and computes final output scripts for silent payments.

use crate::psbt::core::{
    aggregate_ecdh_shares, get_input_bip32_pubkeys, get_input_outpoint_bytes, Bip375PsbtExt,
    Error, Result, SilentPaymentPsbt,
};
use crate::psbt::crypto::{
    compute_shared_secrets, derive_silent_payment_output_pubkey, tweaked_key_to_p2tr_script,
};
use secp256k1::{PublicKey, Secp256k1};
use std::collections::HashMap;

/// Finalize inputs by computing output scripts from ECDH shares.
///
/// Per BIP 352, the shared secret for output derivation is:
///   shared_secret = input_hash * aggregated_ecdh_share
/// where input_hash = hash_BIP0352/Inputs(smallest_outpoint || sum_of_pubkeys)
pub fn finalize_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
) -> Result<()> {
    // Aggregate ECDH shares by scan key (detects global vs per-input automatically)
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Verify all inputs contributed shares (unless global)
    for (scan_key, aggregated) in aggregated_shares.iter() {
        if !aggregated.is_global && aggregated.num_inputs != psbt.num_inputs() {
            let output_idx = (0..psbt.num_outputs())
                .find(|&i| {
                    psbt.get_output_sp_info(i)
                        .map(|(sk, _)| sk == *scan_key)
                        .unwrap_or(false)
                })
                .unwrap_or(0);
            return Err(Error::IncompleteEcdhCoverage(output_idx));
        }
    }

    // Extract outpoints and BIP32 pubkeys from PSBT
    let mut outpoints: Vec<Vec<u8>> = Vec::new();
    let mut input_pubkeys: Vec<PublicKey> = Vec::new();
    for input_idx in 0..psbt.num_inputs() {
        outpoints.push(get_input_outpoint_bytes(psbt, input_idx)?);
        let bip32_pubkeys = get_input_bip32_pubkeys(psbt, input_idx);
        if !bip32_pubkeys.is_empty() {
            input_pubkeys.push(bip32_pubkeys[0]);
        }
    }

    // Build (scan_key, aggregated_share) pairs for BIP-352 computation
    let share_pairs: Vec<(PublicKey, PublicKey)> = aggregated_shares
        .iter()
        .map(|(sk, agg)| (*sk, agg.aggregated_share))
        .collect();

    let shared_secrets = compute_shared_secrets(secp, &share_pairs, &outpoints, &input_pubkeys)
        .map_err(|e| Error::Other(format!("Shared secret computation failed: {}", e)))?;

    // Track output index per scan key (for BIP 352 k parameter)
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    // Process each output
    for output_idx in 0..psbt.num_outputs() {
        // Check if this is a silent payment output
        let (scan_key, spend_key) = match psbt.get_output_sp_info(output_idx) {
            Some(keys) => keys,
            None => continue,
        };

        let shared_secret = shared_secrets
            .get(&scan_key)
            .ok_or(Error::IncompleteEcdhCoverage(output_idx))?;

        // Get or initialize the output index for this scan key
        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);

        // Derive the output public key using BIP-352
        let shared_secret_bytes = shared_secret.serialize();
        let output_pubkey = derive_silent_payment_output_pubkey(
            secp,
            &spend_key,
            &shared_secret_bytes,
            k,
        )
        .map_err(|e| Error::Other(format!("Output derivation failed: {}", e)))?;

        let output_script = tweaked_key_to_p2tr_script(&output_pubkey);

        psbt.outputs[output_idx].script_pubkey = output_script;

        scan_key_output_indices.insert(scan_key, k + 1);
    }

    // Clear tx_modifiable_flags after finalizing outputs
    psbt.global.tx_modifiable_flags = 0x00;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::{PsbtInput, PsbtOutput};
    use crate::psbt::roles::{
        constructor::add_outputs, creator::create_psbt, signer::add_ecdh_shares_full,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::SecretKey;
    use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

    #[test]
    fn test_finalize_inputs_basic() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1);

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address =
            SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Regtest, 0).unwrap();

        // Add output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(50000),
            sp_address,
            None,
        )];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let inputs = vec![
            PsbtInput::new(
                OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: ScriptBuf::new(),
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
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                Some(privkey2),
            ),
        ];

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_inputs(&secp, &mut psbt).unwrap();

        // Verify output script was added
        let script = &psbt.outputs[0].script_pubkey;
        assert!(!script.is_empty());

        // P2TR scripts are 34 bytes: OP_1 + 32-byte x-only pubkey
        assert_eq!(script.len(), 34);
        assert!(script.is_p2tr());
    }

    #[test]
    fn test_incomplete_ecdh_coverage() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1);

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address =
            SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Regtest, 0).unwrap();

        // Add output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(50000),
            sp_address,
            None,
        )];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Only add ECDH share for one input (incomplete)
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
            Some(privkey1),
        )];

        // Use partial signing to only add share for input 0
        use crate::psbt::roles::signer::add_ecdh_shares_partial;
        add_ecdh_shares_partial(&secp, &mut psbt, &inputs, &[scan_key], &[0], false).unwrap();

        // Finalize should fail due to incomplete coverage
        let result = finalize_inputs(&secp, &mut psbt);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::IncompleteEcdhCoverage(0))));
    }

    #[test]
    fn test_tx_modifiable_flags_cleared_after_finalization() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1);

        // Verify initial tx_modifiable_flags is non-zero
        assert_ne!(
            psbt.global.tx_modifiable_flags, 0x00,
            "Initial flags should be non-zero"
        );

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address =
            SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Regtest, 0).unwrap();

        // Add output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(50000),
            sp_address,
            None,
        )];
        add_outputs(&mut psbt, &outputs).unwrap();

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(30000),
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

        // Add ECDH shares
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_inputs(&secp, &mut psbt).unwrap();

        // Verify tx_modifiable_flags is cleared after finalization
        assert_eq!(
            psbt.global.tx_modifiable_flags, 0x00,
            "tx_modifiable_flags should be 0x00 after finalization (BIP-370)"
        );
    }
}
