use super::SpendKey;
use crate::error::{Error, Result};
use bitcoin::{
    bip32,
    secp256k1::{All, PublicKey, Secp256k1, SecretKey},
    Network,
};
use serde::{Deserialize, Serialize};
use silentpayments::{
    bitcoin_hashes::{sha256, Hash},
    receiving::{Label, Receiver},
    utils as sp_utils, Network as SpNetwork, SilentPaymentAddress,
};
use std::{collections::HashMap, io::Write};

#[cfg(test)]
use {
    crate::constants::NUMS,
    bitcoin::{key::constants::ONE, secp256k1::Scalar, XOnlyPublicKey},
    std::str::FromStr,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpClient {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub sp_receiver: Receiver,
    network: Network,
}

#[cfg(test)]
impl Default for SpClient {
    fn default() -> Self {
        let default_sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let default_pubkey = XOnlyPublicKey::from_str(NUMS)
            .unwrap()
            .public_key(bitcoin::key::Parity::Even);
        Self {
            scan_sk: default_sk,
            spend_key: SpendKey::Secret(default_sk),
            sp_receiver: Receiver::new(
                0,
                default_pubkey,
                default_pubkey,
                Scalar::from_be_bytes(ONE).unwrap().into(),
                SpNetwork::Regtest,
            )
            .unwrap(),
            network: Network::Regtest,
        }
    }
}

impl SpClient {
    pub fn new(scan_sk: SecretKey, spend_key: SpendKey, network: Network) -> Result<Self> {
        let secp = Secp256k1::new();
        Self::new_inner(scan_sk, spend_key, network, secp)
    }
    fn new_inner(
        scan_sk: SecretKey,
        spend_key: SpendKey,
        network: Network,
        secp: Secp256k1<All>,
    ) -> Result<Self> {
        let scan_pubkey = scan_sk.public_key(&secp);
        let change_label = Label::new(scan_sk, 0);

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            _ => unreachable!(),
        };

        let sp_receiver = Receiver::new(
            0,
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
    #[cfg(feature = "mnemonic")]
    pub fn new_from_mnemonic(mnemonic: bip39::Mnemonic, network: Network) -> Result<Self> {
        use bitcoin::bip32::ChildNumber;

        Self::new_from_mnemonic_with_passphrase_and_account(
            mnemonic,
            "",
            network,
            ChildNumber::from_hardened_idx(0).expect("zero"),
        )
    }

    #[cfg(feature = "mnemonic")]
    pub fn new_from_mnemonic_with_account(
        mnemonic: bip39::Mnemonic,
        network: Network,
        account: bip32::ChildNumber,
    ) -> Result<Self> {
        Self::new_from_mnemonic_with_passphrase_and_account(mnemonic, "", network, account)
    }

    #[cfg(feature = "mnemonic")]
    pub fn new_from_mnemonic_with_passphrase_and_account(
        mnemonic: bip39::Mnemonic,
        pp: &str,
        network: Network,
        account: bip32::ChildNumber,
    ) -> Result<Self> {
        use bitcoin::bip32;

        let secp = Secp256k1::new();
        let seed = mnemonic.to_seed(pp);
        let master_xpriv = bip32::Xpriv::new_master(network, &seed)
            .map_err(|_| Error::SeedDerivation)?;
        let network_idx = match network {
            Network::Bitcoin => 0u32,
            _ => 1,
        };
        let base_deriv = vec![
            bip32::ChildNumber::from_hardened_idx(352).expect("352"),
            bip32::ChildNumber::from_hardened_idx(network_idx).expect("0 or 1"),
            account,
        ];

        let mut scan_deriv = base_deriv.clone();
        scan_deriv.push(bip32::ChildNumber::from_hardened_idx(1).expect("1"));
        scan_deriv.push(bip32::ChildNumber::from_normal_idx(0).expect("0"));

        let mut spend_deriv = base_deriv;
        spend_deriv.push(bip32::ChildNumber::from_hardened_idx(0).expect("0"));
        spend_deriv.push(bip32::ChildNumber::from_normal_idx(0).expect("0"));

        let scan = master_xpriv
            .derive_priv(&secp, &scan_deriv)
            .map_err(|_| Error::KeyDerivation("scan"))?
            .private_key;

        let spend = master_xpriv
            .derive_priv(&secp, &spend_deriv)
            .map_err(|_| Error::KeyDerivation("spend"))?
            .private_key;

        Self::new_inner(scan, spend.into(), network, secp)
    }

    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
        self.sp_receiver.get_receiving_address()
    }

    pub fn get_scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn get_spend_key(&self) -> SpendKey {
        self.spend_key.clone()
    }

    pub fn get_network(&self) -> Network {
        self.network
    }

    pub fn try_get_secret_spend_key(&self) -> Result<SecretKey> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::MissingSecretKey),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }

    pub fn get_script_to_secret_map(
        &self,
        tweak_data_vec: Vec<PublicKey>,
    ) -> Result<HashMap<[u8; 34], PublicKey>> {
        let b_scan = &self.get_scan_key();

        // Use parallel iteration for CPU-intensive ECDH calculations
        #[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
        let shared_secrets: Vec<PublicKey> = {
            use rayon::prelude::*;
            tweak_data_vec
                .into_par_iter()
                .map(|tweak| sp_utils::receiving::calculate_ecdh_shared_secret(&tweak, b_scan))
                .collect()
        };

        // Sequential fallback (WASM or no parallel feature)
        #[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
        let shared_secrets: Vec<PublicKey> = tweak_data_vec
            .into_iter()
            .map(|tweak| sp_utils::receiving::calculate_ecdh_shared_secret(&tweak, b_scan))
            .collect();

        // Use parallel iteration for CPU-intensive SPK derivation
        #[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
        let items: Result<Vec<_>> = {
            use rayon::prelude::*;
            shared_secrets
                .into_par_iter()
                .map(|secret| {
                    let spks = self.sp_receiver.get_spks_from_shared_secret(&secret)?;
                    Ok((secret, spks.into_values()))
                })
                .collect()
        };

        // Sequential fallback (WASM or no parallel feature)
        #[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
        let items: Result<Vec<_>> = shared_secrets
            .into_iter()
            .map(|secret| {
                let spks = self.sp_receiver.get_spks_from_shared_secret(&secret)?;

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

    pub fn get_client_fingerprint(&self) -> Result<[u8; 8]> {
        let sp_address: SilentPaymentAddress = self.get_receiving_address();
        let scan_pk = sp_address.get_scan_key();
        let spend_pk = sp_address.get_spend_key();

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
