use crate::core::{Error, Psbt, Result};
use bitcoin::{ScriptBuf, Witness};

pub trait InputWitnessFinalizerPsbtExt {
    fn finalize(&mut self) -> Result<()>;
}

impl InputWitnessFinalizerPsbtExt for Psbt {
    fn finalize(&mut self) -> Result<()> {
        for (i, input) in self.inputs.iter_mut().enumerate() {
            if let Some(sig) = input.tap_key_sig {
                let mut witness = Witness::new();
                witness.push(sig.to_vec());
                input.final_script_sig = Some(ScriptBuf::new());
                input.final_script_witness = Some(witness);
                input.tap_key_sig = None;
                input.sighash_type = None;
            } else {
                // We can't finalize a partially signed transaction
                return Err(Error::InvalidPsbtState(format!(
                    "Missing signature on input {}",
                    i
                )));
            }
        }
        Ok(())
    }
}
