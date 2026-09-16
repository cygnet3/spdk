use std::{collections::HashMap, io::Write};

use bitcoin::{
    Network,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use serde::{Deserialize, Serialize, de};
use silentpayments::{Network as SpNetwork, SharedSecret, SilentPaymentCode, SpVersion};
use silentpayments::{bitcoin_hashes::Hash, utils as sp_utils};
use silentpayments::{
    bitcoin_hashes::sha256,
    receiving::{Label, Receiver},
};

use anyhow::{Error, Result};

use super::SpendKey;

#[derive(Debug, PartialEq, Clone)]
pub struct SpClient {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub(crate) sp_receiver: Receiver,
    network: Network,
}

/// On-disk shape: keys, network, and extra label scalars. `Receiver` is rebuilt
/// with [`SpClient::new`] plus [`Receiver::add_label`], so it is not trusted from JSON.
#[derive(Serialize, Deserialize)]
struct SpClientSerde {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    network: Network,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    labels: Vec<Label>,
}

fn sp_network_from_bitcoin(network: Network) -> Result<SpNetwork> {
    match network {
        Network::Bitcoin => Ok(SpNetwork::Mainnet),
        Network::Regtest => Ok(SpNetwork::Regtest),
        Network::Testnet | Network::Signet => Ok(SpNetwork::Testnet),
        other => Err(Error::msg(format!("Unsupported network: {other}"))),
    }
}

impl SpClient {
    pub fn new(scan_sk: SecretKey, spend_key: SpendKey, network: Network) -> Result<Self> {
        let secp = Secp256k1::signing_only();
        let scan_pubkey = scan_sk.public_key(&secp);
        let change_label = Label::new(scan_sk, 0);
        let sp_network = sp_network_from_bitcoin(network)?;

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

    pub fn receiving_code(&self) -> SilentPaymentCode {
        self.sp_receiver.receiving_code()
    }

    pub fn change_code(&self) -> SilentPaymentCode {
        self.sp_receiver.change_code()
    }

    pub fn scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn spend_key(&self) -> SpendKey {
        self.spend_key.clone()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn try_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::msg("Don't have secret key")),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    pub fn script_to_secret_map(
        &self,
        tweak_data_vec: Vec<PublicKey>,
    ) -> Result<HashMap<[u8; 34], SharedSecret>> {
        // if using rayon feature, import the preludes
        #[cfg(feature = "rayon")]
        use rayon::prelude::*;

        let b_scan = &self.scan_key();

        // parallel iterator using rayon
        #[cfg(feature = "rayon")]
        let tweak_data_iterator = tweak_data_vec.into_par_iter();

        // regular iterator
        #[cfg(not(feature = "rayon"))]
        let tweak_data_iterator = tweak_data_vec.into_iter();

        let items: Result<Vec<_>> = tweak_data_iterator
            .map(|tweak| {
                let secret = sp_utils::receiving::calculate_ecdh_shared_secret(&tweak, b_scan);
                let spks = self
                    .sp_receiver
                    .script_pubkeys_from_shared_secret(&secret)?;

                Ok((secret, spks.into_values()))
            })
            .collect();

        let mut res = HashMap::new();
        for (secret, spks) in items? {
            for spk in spks {
                res.insert(spk, secret);
            }
        }
        Ok(res)
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

    fn extra_labels(&self) -> Vec<Label> {
        let change_label = Label::new(self.scan_sk, 0);
        let mut labels: Vec<Label> = self
            .sp_receiver
            .list_labels()
            .into_iter()
            .filter(|label| label != &change_label)
            .collect();
        labels.sort_by(|a, b| a.as_inner().to_be_bytes().cmp(&b.as_inner().to_be_bytes()));
        labels
    }
}

impl Serialize for SpClient {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SpClientSerde {
            scan_sk: self.scan_sk,
            spend_key: self.spend_key.clone(),
            network: self.network,
            labels: self.extra_labels(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SpClient {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SpClientSerde::deserialize(deserializer)?;
        let mut client = SpClient::new(helper.scan_sk, helper.spend_key, helper.network)
            .map_err(de::Error::custom)?;
        for label in helper.labels {
            client
                .sp_receiver
                .add_label(label)
                .map_err(de::Error::custom)?;
        }
        Ok(client)
    }
}

impl Drop for SpClient {
    fn drop(&mut self) {
        // Erase the scan key before dropping; the spend key is erased
        // by SpendKey's own Drop impl.
        self.scan_sk.non_secure_erase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::DisplayHex;

    fn test_client() -> SpClient {
        let scan = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let spend = SecretKey::from_slice(&[2u8; 32]).unwrap();
        SpClient::new(scan, SpendKey::Secret(spend), Network::Testnet).unwrap()
    }

    #[test]
    fn roundtrip_without_extra_labels() {
        let client = test_client();
        let json = serde_json::to_string(&client).unwrap();
        let loaded: SpClient = serde_json::from_str(&json).unwrap();
        assert_eq!(client, loaded);
        assert!(
            !json.contains("sp_receiver"),
            "Receiver must not be serialized: {json}"
        );
        assert!(
            !json.contains("labels"),
            "empty extra labels should be omitted: {json}"
        );
    }

    #[test]
    fn roundtrip_with_extra_label() {
        let mut client = test_client();
        let label = Label::new(client.scan_sk, 1);
        assert!(client.sp_receiver.add_label(label).unwrap());
        let json = serde_json::to_string(&client).unwrap();
        let loaded: SpClient = serde_json::from_str(&json).unwrap();
        assert_eq!(client, loaded);
    }

    #[test]
    fn ignores_nested_receiver_from_old_backups() {
        let client = test_client();
        let mut value = serde_json::to_value(&client).unwrap();
        value["sp_receiver"] = serde_json::json!({
            "version": 7,
            "scan_pubkey": vec![255u8; 33],
        });
        let loaded: SpClient = serde_json::from_value(value).unwrap();
        assert_eq!(client, loaded);
    }

    #[test]
    fn malformed_label_returns_err() {
        let mut value = serde_json::to_value(&test_client()).unwrap();
        value["labels"] = serde_json::json!(["deadbeef"]);
        assert!(serde_json::from_value::<SpClient>(value).is_err());
    }

    #[test]
    fn label_that_negates_spend_pubkey_returns_err() {
        let client = test_client();
        let spend = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let mut value = serde_json::to_value(&client).unwrap();
        value["labels"] = serde_json::json!([spend.negate().secret_bytes().to_lower_hex_string()]);
        let err = serde_json::from_value::<SpClient>(value).unwrap_err();
        assert!(
            err.to_string().contains("sum of public keys"),
            "expected invalid key-sum error, got: {err}"
        );
    }
}
