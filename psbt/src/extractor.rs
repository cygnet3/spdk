//! BIP-375 Transaction Extractor.
//!
//! BIP-375: "For silent payment capable PSBTs, the transaction extractor should compute all
//! output scripts for silent payment codes and verify they are correct using the ECDH shares and
//! DLEQ proofs, otherwise fail."
//!
//! `psbt_v2::Extractor` leaves that check to the caller, because it needs BIP-352 output
//! derivation and BIP-374 proof verification. This role performs it before extracting.

use std::fmt;

use bitcoin::Transaction;
use psbt_v2::{ExtractError, ExtractTxFeeRateError, Extractor, Psbt};
use secp256k1::{Secp256k1, Signing, Verification};
use silentpayments::TransactionInputs;
use silentpayments::utils::OutPoint as SpOutPoint;
use silentpayments::utils::receiving::get_pubkey_from_input;

use super::signer::{SpSignerError, derive_sp_output_scripts_from_inputs};

#[derive(Debug)]
pub enum SpExtractorError {
    /// The public key of a finalized input could not be recovered from its scriptSig and
    /// witness.
    InputPubkey {
        vin: usize,
        error: silentpayments::Error,
    },
    /// The silent payment output scripts could not be derived from the ECDH shares.
    Derive(SpSignerError),
    /// A silent payment output does not match the script derived from the ECDH shares.
    OutputScriptMismatch { index: usize },
    /// rust-psbt refused to build an extractor for the PSBT.
    Extractor(ExtractError),
    /// rust-psbt failed to extract the transaction.
    ExtractTx(ExtractTxFeeRateError),
}

impl fmt::Display for SpExtractorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SpExtractorError as E;
        match self {
            E::InputPubkey { vin, error } => {
                write!(f, "input {vin}: cannot recover its public key: {error}")
            }
            E::Derive(e) => write!(f, "cannot derive silent payment output scripts: {e}"),
            E::OutputScriptMismatch { index } => write!(
                f,
                "silent payment output {index} does not match the script derived from the ECDH shares"
            ),
            E::Extractor(e) => write!(f, "cannot extract: {e}"),
            E::ExtractTx(e) => write!(f, "cannot extract the transaction: {e}"),
        }
    }
}

impl std::error::Error for SpExtractorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SpExtractorError as E;
        match self {
            E::InputPubkey { error, .. } => Some(error),
            E::Derive(e) => Some(e),
            E::Extractor(e) => Some(e),
            E::ExtractTx(e) => Some(e),
            E::OutputScriptMismatch { .. } => None,
        }
    }
}

impl From<SpSignerError> for SpExtractorError {
    fn from(value: SpSignerError) -> Self {
        Self::Derive(value)
    }
}

pub trait SpExtractorExt {
    /// Derives every silent payment output script from the ECDH shares and DLEQ proofs and
    /// checks it against the PSBT, as BIP-375 requires of the Transaction Extractor.
    ///
    /// The Input Finalizer clears the fields the Signer reads input public keys from, so they
    /// are recovered from the final scriptSig and witness, as a BIP-352 receiver does.
    fn verify_sp_output_scripts<C>(&self, secp: &Secp256k1<C>) -> Result<(), SpExtractorError>
    where
        C: Signing + Verification;

    /// Verifies the silent payment output scripts, then extracts the transaction with
    /// `psbt_v2::Extractor`.
    fn extract_tx<C>(self, secp: &Secp256k1<C>) -> Result<Transaction, SpExtractorError>
    where
        C: Signing + Verification;
}

impl SpExtractorExt for Psbt {
    fn verify_sp_output_scripts<C>(&self, secp: &Secp256k1<C>) -> Result<(), SpExtractorError>
    where
        C: Signing + Verification,
    {
        if self
            .outputs
            .iter()
            .all(|output| output.sp_v0_info.is_none())
        {
            return Ok(());
        }

        let mut transaction_inputs = TransactionInputs::with_capacity(self.global.input_count);
        for (vin, input) in self.inputs.iter().enumerate() {
            let outpoint = SpOutPoint::from_txid_and_vout(
                &input.previous_txid.to_string(),
                input.spent_output_index,
            )
            .map_err(SpSignerError::from)?;
            let spk = &input
                .funding_utxo()
                .map_err(SpSignerError::from)?
                .script_pubkey;
            let script_sig = input
                .final_script_sig
                .as_ref()
                .map(|script| script.as_bytes())
                .unwrap_or_default();
            let witness = input
                .final_script_witness
                .as_ref()
                .map(|witness| witness.to_vec())
                .unwrap_or_default();
            let pubkey = get_pubkey_from_input(script_sig, &witness, spk.as_bytes())
                .map_err(|error| SpExtractorError::InputPubkey { vin, error })?;
            transaction_inputs.push(outpoint, spk.to_bytes(), pubkey);
        }

        for (index, script) in
            derive_sp_output_scripts_from_inputs(self, secp, &transaction_inputs)?
        {
            if self.outputs[index].script_pubkey != script {
                return Err(SpExtractorError::OutputScriptMismatch { index });
            }
        }
        Ok(())
    }

    fn extract_tx<C>(self, secp: &Secp256k1<C>) -> Result<Transaction, SpExtractorError>
    where
        C: Signing + Verification,
    {
        self.verify_sp_output_scripts(secp)?;
        Extractor::new(self)
            .map_err(SpExtractorError::Extractor)?
            .extract_tx()
            .map_err(SpExtractorError::ExtractTx)
    }
}
