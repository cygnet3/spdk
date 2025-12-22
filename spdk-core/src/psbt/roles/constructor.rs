//! PSBT Constructor Role
//!
//! Adds inputs and outputs to the PSBT.

use crate::psbt::core::{Bip375PsbtExt, Error, PsbtInput, PsbtOutput, Result, SilentPaymentPsbt};

/// Add inputs to the PSBT
pub fn add_inputs(psbt: &mut SilentPaymentPsbt, inputs: &[PsbtInput]) -> Result<()> {
    if psbt.num_inputs() != inputs.len() {
        return Err(Error::Other(format!(
            "PSBT has {} input slots but {} inputs provided",
            psbt.num_inputs(),
            inputs.len()
        )));
    }

    for (i, input) in inputs.iter().enumerate() {
        let psbt_input = &mut psbt.inputs[i];

        psbt_input.previous_txid = input.outpoint.txid;
        psbt_input.spent_output_index = input.outpoint.vout;
        psbt_input.sequence = Some(input.sequence);

        // Add PSBT_IN_WITNESS_UTXO (required for SegWit inputs)
        let witness_utxo = psbt_v2::bitcoin::TxOut {
            value: psbt_v2::bitcoin::Amount::from_sat(input.witness_utxo.value.to_sat()),
            script_pubkey: psbt_v2::bitcoin::ScriptBuf::from(
                input.witness_utxo.script_pubkey.to_bytes(),
            ),
        };

        psbt_input.witness_utxo = Some(witness_utxo);
        psbt_input.final_script_witness = None; // Clear any existing witness

        // For P2TR inputs, we should set the tap_internal_key if possible.
        // In the absence of separate internal key info in PsbtInput, we assume for this
        // demo/constructor that the key in the script is what we want to track.
        if input.witness_utxo.script_pubkey.is_p2tr() {
            // P2TR script: OP_1 <32-byte x-only pubkey>
            if input.witness_utxo.script_pubkey.len() == 34
                && input.witness_utxo.script_pubkey.as_bytes()[0] == 0x51
            {
                if let Ok(x_only) = bitcoin::key::XOnlyPublicKey::from_slice(
                    &input.witness_utxo.script_pubkey.as_bytes()[2..34],
                ) {
                    psbt_input.tap_internal_key = Some(x_only);
                }
            }
        }
    }

    Ok(())
}

/// Add outputs to the PSBT
pub fn add_outputs(psbt: &mut SilentPaymentPsbt, outputs: &[PsbtOutput]) -> Result<()> {
    for (i, output) in outputs.iter().enumerate() {
        match output {
            PsbtOutput::Regular(txout) => {
                let psbt_output = &mut psbt.outputs[i];
                // Convert between potentially different bitcoin::Amount types
                psbt_output.amount = psbt_v2::bitcoin::Amount::from_sat(txout.value.to_sat());
                psbt_output.script_pubkey = txout.script_pubkey.clone();
            }
            PsbtOutput::SilentPayment { amount, address, label } => {
                let psbt_output = &mut psbt.outputs[i];
                // Convert between potentially different bitcoin::Amount types
                psbt_output.amount = psbt_v2::bitcoin::Amount::from_sat(amount.to_sat());
                // Note: SilentPayment outputs will have empty script_pubkey here,
                // which is computed during finalization

                // Set BIP-375 fields
                psbt.set_output_sp_info_v0(i, address)?;

                if let Some(label) = label {
                    psbt.set_output_sp_label(i, *label)?;
                }
            }
        }
    }

    Ok(())
}

/// Add both inputs and outputs to the PSBT (convenience function)
pub fn construct_psbt(
    psbt: &mut SilentPaymentPsbt,
    inputs: &[PsbtInput],
    outputs: &[PsbtOutput],
) -> Result<()> {
    add_inputs(psbt, inputs)?;
    add_outputs(psbt, outputs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::roles::creator::create_psbt;
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};

    #[test]
    fn test_add_inputs() {
        let mut psbt = create_psbt(2, 1);

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                None,
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: ScriptBuf::new(),
                },
                Sequence::MAX,
                None,
            ),
        ];

        add_inputs(&mut psbt, &inputs).unwrap();

        // Verify inputs were added
        assert_eq!(psbt.inputs[0].previous_txid, inputs[0].outpoint.txid);
        assert_eq!(psbt.inputs[0].spent_output_index, inputs[0].outpoint.vout);
        assert_eq!(psbt.inputs[1].previous_txid, inputs[1].outpoint.txid);
    }

    #[test]
    fn test_add_outputs() {
        let mut psbt = create_psbt(1, 2);

        let outputs = vec![
            PsbtOutput::regular(Amount::from_sat(40000), ScriptBuf::new()),
            PsbtOutput::regular(Amount::from_sat(10000), ScriptBuf::new()),
        ];

        add_outputs(&mut psbt, &outputs).unwrap();

        // Verify outputs were added
        assert_eq!(psbt.outputs[0].amount, Amount::from_sat(40000));
        assert!(psbt.outputs[0].script_pubkey.len() == 0); // Empty script in test
        assert_eq!(psbt.outputs[1].amount, Amount::from_sat(10000));
    }

    #[test]
    fn test_construct_psbt() {
        let mut psbt = create_psbt(1, 1);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
            None,
        )];

        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(49000),
            ScriptBuf::new(),
        )];

        construct_psbt(&mut psbt, &inputs, &outputs).unwrap();

        // Verify both inputs and outputs were added
        assert_eq!(psbt.inputs[0].previous_txid, inputs[0].outpoint.txid);
        assert_eq!(psbt.outputs[0].amount, Amount::from_sat(49000));
    }
}
