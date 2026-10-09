use std::io::Write as _;

use anyhow::{Error, Result};
use bitcoin::Network;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use silentpayments::bitcoin_hashes::{Hash as _, sha256};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::{Network as SpNetwork, SilentPaymentCode, SpVersion};

use super::SpendKey;

#[derive(Debug, PartialEq, Clone)]
pub struct SpClient {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub(crate) sp_receiver: Receiver,
    network: Network,
}

impl SpClient {
    pub fn new(scan_sk: SecretKey, spend_key: SpendKey, network: Network) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let scan_pubkey = scan_sk.public_key(&secp);
        let change_label = Label::new(scan_sk, 0);

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            Network::Testnet | Network::Signet | Network::Testnet4 => SpNetwork::Testnet,
        };

        let sp_receiver = Receiver::new(
            SpVersion::ZERO,
            scan_pubkey,
            (&spend_key).into(),
            change_label,
            sp_network,
        )?;

        Ok(Self {
            scan_sk,
            spend_key,
            sp_receiver,
            network,
        })
    }

    /// Builds a client from an `sp()` descriptor.
    ///
    /// `network` must be mainnet when the descriptor is mainnet, and a non-mainnet
    /// network otherwise. The descriptor cannot tell regtest, signet, and testnet apart.
    #[cfg(feature = "bip392")]
    pub fn from_descriptor(descriptor: &bip392::Sp, network: Network) -> Result<Self> {
        if descriptor.is_mainnet() != matches!(network, Network::Bitcoin) {
            return Err(Error::msg(
                "descriptor network does not match the wallet network",
            ));
        }
        Self::new(descriptor.scan_key(), SpendKey::from(descriptor), network)
    }

    pub fn receiver(&self) -> Receiver {
        self.sp_receiver.clone()
    }

    pub const fn receiving_code(&self) -> SilentPaymentCode {
        self.sp_receiver.receiving_code()
    }

    pub fn change_code(&self) -> SilentPaymentCode {
        self.sp_receiver.change_code()
    }

    pub const fn scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn spend_key(&self) -> SpendKey {
        self.spend_key.clone()
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    pub fn try_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::msg("Don't have secret key")),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    pub fn client_fingerprint(&self) -> Result<[u8; 8]> {
        let sp_code: SilentPaymentCode = self.receiving_code();
        let scan_pk = sp_code.scan_key();
        let spend_pk = sp_code.m_pubkey();

        // take a fingerprint of the wallet by hashing its keys
        let mut engine = sha256::HashEngine::default();
        engine.write_all(&scan_pk.serialize())?;
        engine.write_all(&spend_pk.serialize())?;
        let hash = sha256::Hash::from_engine(engine);

        // take first 8 bytes as fingerprint
        let mut wallet_fingerprint = [0u8; 8];
        wallet_fingerprint.copy_from_slice(&hash.to_byte_array()[..8]);

        Ok(wallet_fingerprint)
    }
}

impl Drop for SpClient {
    fn drop(&mut self) {
        // Erase the scan key before dropping; the spend key is erased
        // by SpendKey's own Drop impl.
        self.scan_sk.non_secure_erase();
    }
}

#[cfg(all(test, feature = "bip392"))]
mod tests {
    use std::str::FromStr as _;

    use bip392::Sp;

    use super::{Network, SpClient, SpendKey};

    const WIF: &str = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
    const SPEND_PUB: &str = "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";

    #[test]
    fn descriptor_spend_pubkey_wraps_into_client() {
        let descriptor = Sp::from_str(&format!("sp({WIF},{SPEND_PUB})")).unwrap();
        let SpendKey::Public(pk) = SpendKey::from(&descriptor) else {
            panic!("watch-only descriptor");
        };
        assert_eq!(pk, descriptor.spend_pubkey());
        assert!(descriptor.spend_secret().is_none());

        let client = SpClient::from_descriptor(&descriptor, Network::Bitcoin).unwrap();
        assert!(client.try_secret_spend_key().is_err());
        assert!(SpClient::from_descriptor(&descriptor, Network::Signet).is_err());
    }

    #[test]
    fn descriptor_spend_secret_wraps_into_client() {
        let descriptor = Sp::from_str(&format!("sp({WIF},{WIF})")).unwrap();
        let SpendKey::Secret(sk) = SpendKey::from(&descriptor) else {
            panic!("descriptor with spend secret");
        };
        assert_eq!(Some(sk), descriptor.spend_secret());

        let client = SpClient::from_descriptor(&descriptor, Network::Bitcoin).unwrap();
        assert_eq!(client.try_secret_spend_key().unwrap(), sk);
    }
}
