//! PSBT Input Finalizer Role
//!
//! Aggregates ECDH shares and computes final output scripts for silent payments.

use crate::psbt::core::{aggregate_ecdh_shares, Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use crate::psbt::crypto::{
    apply_label_to_spend_key, derive_silent_payment_output_pubkey, tweaked_key_to_p2tr_script,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;

/// Finalize inputs by computing output scripts from ECDH shares
pub fn finalize_inputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    scan_privkeys: Option<&HashMap<PublicKey, SecretKey>>,
) -> Result<()> {
    // Aggregate ECDH shares by scan key (detects global vs per-input automatically)
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // Track output index per scan key (for BIP 352 k parameter)
    let mut scan_key_output_indices: HashMap<PublicKey, u32> = HashMap::new();

    // Process each output
    for output_idx in 0..psbt.num_outputs() {
        // Check if this is a silent payment output
        let (scan_key, spend_key) = match psbt.get_output_sp_info_v0(output_idx) {
            Some(keys) => keys,
            None => continue, // Not a silent payment output, skip
        };

        // Get the aggregated share for this scan key
        let aggregated = aggregated_shares
            .get(&scan_key)
            .ok_or(Error::IncompleteEcdhCoverage(output_idx))?;

        // Verify all inputs contributed shares (unless it's a global share)
        if !aggregated.is_global && aggregated.num_inputs != psbt.num_inputs() {
            return Err(Error::IncompleteEcdhCoverage(output_idx));
        }

        let aggregated_share = aggregated.aggregated_share;

        // Check for label and apply if present and we have scan private key
        let mut spend_key_to_use = spend_key.clone();

        if let Some(label) = psbt.get_output_sp_label(output_idx) {
            // If we have the scan private key, apply the label tweak to spend key
            if let Some(privkeys) = scan_privkeys {
                if let Some(scan_privkey) = privkeys.get(&scan_key) {
                    spend_key_to_use =
                        apply_label_to_spend_key(secp, &spend_key, scan_privkey, label).map_err(
                            |e| Error::Other(format!("Failed to apply label tweak: {}", e)),
                        )?;
                }
            }
        }

        // Get or initialize the output index for this scan key
        let k = *scan_key_output_indices.get(&scan_key).unwrap_or(&0);

        // Derive the output public key using BIP-352
        let ecdh_secret = aggregated_share.serialize();
        let output_pubkey = derive_silent_payment_output_pubkey(
            secp,
            &spend_key_to_use, // Use labeled spend key if label was applied
            &ecdh_secret,
            k, // Use per-scan-key index
        )
        .map_err(|e| Error::Other(format!("Output derivation failed: {}", e)))?;

        // Create P2TR output script from already-tweaked Silent Payment output key
        // The output_pubkey is already tweaked via BIP-352 derivation, so we use
        // tweaked_key_to_p2tr_script (no additional BIP-341 tweak needed)

        let output_script = tweaked_key_to_p2tr_script(&output_pubkey);

        // Add output script to PSBT
        psbt.outputs[output_idx].script_pubkey = output_script;

        // Increment the output index for this scan key
        scan_key_output_indices.insert(scan_key, k + 1);
    }

    // BIP-370: Clear tx_modifiable_flags after finalizing outputs
    // Once output scripts are computed, the transaction structure is locked
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
        finalize_inputs(&secp, &mut psbt, None).unwrap();

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
        let result = finalize_inputs(&secp, &mut psbt, None);
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
        finalize_inputs(&secp, &mut psbt, None).unwrap();

        // Verify tx_modifiable_flags is cleared after finalization
        assert_eq!(
            psbt.global.tx_modifiable_flags, 0x00,
            "tx_modifiable_flags should be 0x00 after finalization (BIP-370)"
        );
    }
}
