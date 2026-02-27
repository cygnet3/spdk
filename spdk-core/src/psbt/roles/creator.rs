//! PSBT Creator Role
//!
//! Creates the initial PSBT structure.

use crate::psbt::core::SilentPaymentPsbt;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::Txid;
use psbt_v2::v2::{Global, Psbt as PsbtV2};

/// Create a new PSBT with specified number of inputs and outputs
pub fn create_psbt(num_inputs: usize, num_outputs: usize) -> SilentPaymentPsbt {
    // Create inputs
    let mut inputs = Vec::with_capacity(num_inputs);
    for _ in 0..num_inputs {
        inputs.push(psbt_v2::v2::Input {
            previous_txid: Txid::all_zeros(),
            spent_output_index: 0,
            sequence: None,
            witness_utxo: None,
            partial_sigs: std::collections::BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: std::collections::BTreeMap::new(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: std::collections::BTreeMap::new(),
            sha256_preimages: std::collections::BTreeMap::new(),
            hash160_preimages: std::collections::BTreeMap::new(),
            hash256_preimages: std::collections::BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: std::collections::BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            sp_ecdh_shares: std::collections::BTreeMap::new(),
            sp_dleq_proofs: std::collections::BTreeMap::new(),
            unknowns: std::collections::BTreeMap::new(),
            min_time: None,
            min_height: None,
            non_witness_utxo: None,
            tap_scripts: std::collections::BTreeMap::new(),
            tap_key_origins: std::collections::BTreeMap::new(),
            proprietaries: std::collections::BTreeMap::new(),
        });
    }

    // Create outputs
    let mut outputs = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        outputs.push(psbt_v2::v2::Output {
            amount: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::new(),
            redeem_script: None,
            witness_script: None,
            bip32_derivations: std::collections::BTreeMap::new(),
            tap_internal_key: None,
            tap_tree: None,
            tap_key_origins: std::collections::BTreeMap::new(),
            sp_v0_info: None,
            sp_v0_label: None,
            unknowns: std::collections::BTreeMap::new(),
            proprietaries: std::collections::BTreeMap::new(),
        });
    }

    PsbtV2 {
        global: Global {
            version: psbt_v2::V2,
            tx_version: Version(2),
            fallback_lock_time: None,
            input_count: num_inputs,
            output_count: num_outputs,
            tx_modifiable_flags: 3,
            sp_dleq_proofs: std::collections::BTreeMap::new(),
            sp_ecdh_shares: std::collections::BTreeMap::new(),
            unknowns: std::collections::BTreeMap::new(),
            xpubs: std::collections::BTreeMap::new(),
            proprietaries: std::collections::BTreeMap::new(),
        },
        inputs,
        outputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::Bip375PsbtExt;

    #[test]
    fn test_create_psbt() {
        let psbt = create_psbt(2, 3);

        assert_eq!(psbt.num_inputs(), 2);
        assert_eq!(psbt.num_outputs(), 3);

        // Check version field
        assert_eq!(psbt.global.version, psbt_v2::V2);
    }
}
