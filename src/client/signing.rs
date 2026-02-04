use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, PrivateKey, Witness};
use silentpayments::SilentPaymentAddress;

use crate::SpClient;

impl SpClient {
    /// Signs a message using the client's spend key.
    pub fn sign_message(&self, msg: &[u8]) -> anyhow::Result<Witness> {
        let network = Network::Bitcoin;
        let secp = Secp256k1::new();

        let spend_sk = self.try_get_secret_spend_key()?;
        let spend_pk = spend_sk.public_key(&secp);
        let spend_privkey = PrivateKey::new(spend_sk, network);

        let xonly = spend_pk.x_only_public_key().0;

        let address = Address::p2tr(&secp, xonly, None, network);

        Ok(bip322::sign_simple(&address, msg, spend_privkey)?)
    }
}

pub fn verify_message(
    address: SilentPaymentAddress,
    msg: &[u8],
    signature: Witness,
) -> anyhow::Result<()> {
    let spend_pk = address.get_spend_key();

    let xonly = spend_pk.x_only_public_key().0;

    let network = Network::Bitcoin;
    let secp = Secp256k1::new();
    let taproot_address = Address::p2tr(&secp, xonly, None, network);

    Ok(bip322::verify_simple(&taproot_address, msg, signature)?)
}

#[cfg(test)]
mod test {
    use bitcoin::{Network, Witness};
    use silentpayments::secp256k1::SecretKey;

    use crate::{client::signing::verify_message, SpClient, SpendKey};

    fn create_random_client() -> SpClient {
        use rand::prelude::*;
        let mut rng = rand::rng();

        let scan_sk_bytes: [u8; 32] = rng.random();
        let spend_sk_bytes: [u8; 32] = rng.random();

        let network = Network::Bitcoin;
        let scan_sk = SecretKey::from_slice(&scan_sk_bytes).unwrap();
        let spend_sk = SecretKey::from_slice(&spend_sk_bytes).unwrap();

        SpClient::new(scan_sk, SpendKey::Secret(spend_sk), network).unwrap()
    }

    #[test]
    fn sign_and_verify() {
        // message to sign
        let message = b"random message to sign";

        // different, unrelated message
        let unrelated_message = b"wrong message";

        // create a random sp-client with an sp-address
        let client = create_random_client();
        let sp_address = client.get_receiving_address();

        // create a different, unrelated client
        let unrelated_client = create_random_client();
        let unrelated_sp_address = unrelated_client.get_receiving_address();

        // sign message and verify it is correct with the client's sp-address
        let witness = client.sign_message(message).unwrap();
        assert!(verify_message(sp_address, message, witness.clone()).is_ok());

        // different message should be an error
        assert!(verify_message(sp_address, unrelated_message, witness.clone()).is_err());

        // different sp_address should be an error
        assert!(verify_message(unrelated_sp_address, message, witness).is_err());

        // different witness should be an error
        let random_witness = Witness::from_slice(&[[]]);
        assert!(verify_message(sp_address, message, random_witness).is_err());
    }
}
