use anyhow::Result;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use psbt::Psbt;

use super::SpClient;

impl SpClient {
    pub fn sign_transaction(
        &self,
        mut psbt: Psbt,
    ) -> Result<Psbt> {
        let k: SecretKey = self.get_spend_key().try_into()?;
        let secp = Secp256k1::new();
        let _xonly_keys = psbt.sign_silent_payment_inputs(&k, &secp);
        Ok(psbt)
    }
}
