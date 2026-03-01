use std::collections::HashMap;
use std::str::FromStr;

use bdk_coin_select::{
    Candidate, ChangePolicy, CoinSelector, DrainWeights, FeeRate, Target, TargetFee, TargetOutputs,
    TR_DUST_RELAY_MIN_VALUE,
};
#[cfg(feature = "bitcoin_32")]
use bitcoin::hashes::Hash;
#[cfg(feature = "bitcoin_31")]
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::{
    absolute::LockTime,
    key::TapTweak,
    psbt::Psbt,
    script::PushBytesBuf,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};

use silentpayments::utils as sp_utils;
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

use crate::error::{Error, Result};

use crate::constants::{DATA_CARRIER_SIZE, NUMS};

use super::{
    OutputSpendStatus, OwnedOutput, Recipient, RecipientAddress, SilentPaymentUnsignedTransaction,
    SpClient,
};

impl SpClient {
    // For now it's only suitable for wallet that spends only silent payments outputs that it owns
    pub fn create_new_transaction(
        &self,
        available_utxos: Vec<(OutPoint, OwnedOutput)>,
        mut recipients: Vec<Recipient>,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // check that all available outputs are unspent
        if available_utxos
            .iter()
            .any(|(_, o)| o.spend_status != OutputSpendStatus::Unspent)
        {
            return Err(Error::UnspentOutputsRequired);
        }

        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let tx_outs = recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let value = recipient.amount;
                    let script_pubkey = unchecked_address
                        .clone()
                        .require_network(network)
                        .map_err(|e| Error::Address(e.to_string()))?
                        .script_pubkey();

                    Ok(TxOut {
                        value,
                        script_pubkey,
                    })
                }
                RecipientAddress::SpAddress(sp_address) => {
                    if sp_address.get_network() != address_sp_network {
                        return Err(Error::WrongNetwork(sp_address.to_string()));
                    }

                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: placeholder_spk.clone(),
                    })
                }
                RecipientAddress::Data(data) => {
                    let value = recipient.amount;
                    let data_len = data.len();
                    if value > Amount::from_sat(0) {
                        Err(Error::DataOutputNonZero)
                    } else if data_len > DATA_CARRIER_SIZE {
                        Err(Error::DataTooLarge {
                            len: data_len,
                            max: DATA_CARRIER_SIZE,
                        })
                    } else {
                        let mut op_return = PushBytesBuf::with_capacity(data_len);
                        op_return.extend_from_slice(data)?;
                        let script_pubkey = ScriptBuf::new_op_return(op_return);

                        Ok(TxOut {
                            value,
                            script_pubkey,
                        })
                    }
                }
            })
            .collect::<Result<Vec<TxOut>>>()?;

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.amount.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // The min may need to be adjusted, 2 or 3x that would be sensible
        let change_policy =
            ChangePolicy::min_value(DrainWeights::TR_KEYSPEND, TR_DUST_RELAY_MIN_VALUE);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: TargetOutputs::fund_outputs(
                tx_outs
                    .iter()
                    .map(|o| (o.weight().to_wu(), o.value.to_sat())),
            ),
        };

        coin_selector.select_until_target_met(target)?;

        // get the utxos that have been chosen by the coin selector
        let selected_indices = coin_selector.selected_indices();
        let mut selected_utxos = vec![];
        for i in selected_indices {
            let (outpoint, output) = &available_utxos[*i];
            selected_utxos.push((*outpoint, output.clone()));
        }

        // if there is change, add a return address to the list of recipients
        let change = coin_selector.drain(target, change_policy);
        let change_value = if change.is_some() { change.value } else { 0 };
        if change_value > 0 {
            let change_address = self.sp_receiver.get_change_address();
            recipients.push(Recipient {
                address: RecipientAddress::SpAddress(change_address),
                amount: Amount::from_sat(change_value),
            });
        };

        let partial_secret = self.get_partial_secret_for_selected_utxos(&selected_utxos)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos,
            recipients,
            partial_secret,
            unsigned_tx: None,
            network,
        })
    }

    /// A drain transaction spends all the available utxos to a single RecipientAddress.
    pub fn create_drain_transaction(
        &self,
        available_utxos: Vec<(OutPoint, OwnedOutput)>,
        recipient: RecipientAddress,
        fee_rate: FeeRate,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        // check that all available outputs are unspent
        if available_utxos
            .iter()
            .any(|(_, o)| o.spend_status != OutputSpendStatus::Unspent)
        {
            return Err(Error::UnspentOutputsRequired);
        }

        // used to estimate the size of a taproot output
        let placeholder_spk = ScriptBuf::new_p2tr_tweaked(
            bitcoin::XOnlyPublicKey::from_str(NUMS)
                .expect("NUMS is always valid")
                .dangerous_assume_tweaked(),
        );

        let address_sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            Network::Regtest => SpNetwork::Regtest,
            _ => unreachable!(),
        };

        let output = match &recipient {
            RecipientAddress::LegacyAddress(address) => Ok(TxOut {
                value: Amount::ZERO,
                script_pubkey: address
                    .clone()
                    .require_network(network)
                    .map_err(|e| Error::Address(e.to_string()))?
                    .script_pubkey(),
            }),
            RecipientAddress::SpAddress(sp_address) => {
                if sp_address.get_network() != address_sp_network {
                    return Err(Error::WrongNetwork(sp_address.to_string()));
                }

                Ok(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: placeholder_spk.clone(),
                })
            }
            RecipientAddress::Data(_) => Err(Error::DrainToOpReturn),
        }?;

        // for a drain transaction, we have no target outputs.
        // instead, we register the recipient as the drain output.
        let target_outputs = TargetOutputs {
            value_sum: 0,
            weight_sum: 0,
            n_outputs: 0,
        };

        let drain_output = DrainWeights {
            output_weight: output.weight().to_wu(),
            spend_weight: 0,
            n_outputs: 1,
        };

        // as a silent payment wallet, we only spend taproot outputs
        let candidates: Vec<Candidate> = available_utxos
            .iter()
            .map(|(_, o)| Candidate::new_tr_keyspend(o.amount.to_sat()))
            .collect();

        let mut coin_selector = CoinSelector::new(&candidates);

        // we force a change, by having the min_value be set to 0
        let change_policy = ChangePolicy::min_value(drain_output, 0);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: target_outputs,
        };

        // for a drain transaction, we select all avaliable inputs
        coin_selector.select_all();

        let change = coin_selector.drain(target, change_policy);

        if change.is_none() {
            return Err(Error::NoFunds);
        }

        let recipients = vec![Recipient {
            address: recipient,
            amount: Amount::from_sat(change.value),
        }];

        let partial_secret = self.get_partial_secret_for_selected_utxos(&available_utxos)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos: available_utxos,
            recipients,
            partial_secret,
            unsigned_tx: None,
            network,
        })
    }

    /// Once we reviewed the temporary transaction state, we can turn it into a transaction
    pub fn finalize_transaction(
        mut unsigned_transaction: SilentPaymentUnsignedTransaction,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        let tx_ins: Vec<TxIn> = unsigned_transaction
            .selected_utxos
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();

        let sp_addresses: Vec<SilentPaymentAddress> = unsigned_transaction
            .recipients
            .iter()
            .filter_map(|r| match &r.address {
                RecipientAddress::SpAddress(sp_address) => Some(sp_address.to_owned()),
                _ => None,
            })
            .collect();

        let sp_address2xonlypubkeys = silentpayments::sending::generate_recipient_pubkeys(
            sp_addresses,
            unsigned_transaction.partial_secret,
        )?;

        // Per-address counter for BIP352 k value
        let mut sp_output_counters: HashMap<&SilentPaymentAddress, usize> = HashMap::new();
        let mut tx_outs = Vec::with_capacity(unsigned_transaction.recipients.len());

        for recipient in &unsigned_transaction.recipients {
            let tx_out = match &recipient.address {
                RecipientAddress::SpAddress(s) => {
                    let pubkeys = sp_address2xonlypubkeys
                        .get(s)
                        .ok_or(Error::UnknownSpAddress)?;
                    let k = sp_output_counters.entry(s).or_insert(0);
                    let pubkey = *pubkeys
                        .get(*k)
                        .expect("pubkey count matches recipient count");
                    *k += 1;

                    let script = ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked());
                    TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    }
                }
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let script = unchecked_address
                        .clone()
                        .require_network(unsigned_transaction.network)
                        .map_err(|e| Error::Address(e.to_string()))?
                        .script_pubkey();

                    TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    }
                }
                RecipientAddress::Data(data) => {
                    if recipient.amount > Amount::from_sat(0) {
                        return Err(Error::DataOutputNonZero);
                    }
                    let data_len = data.len();
                    if data_len > DATA_CARRIER_SIZE {
                        return Err(Error::DataTooLarge {
                            len: data_len,
                            max: DATA_CARRIER_SIZE,
                        });
                    }
                    let mut op_return = PushBytesBuf::with_capacity(data_len);
                    op_return.extend_from_slice(data)?;
                    let script = ScriptBuf::new_op_return(op_return);
                    TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    }
                }
            };
            tx_outs.push(tx_out);
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: tx_outs,
        };
        unsigned_transaction.unsigned_tx = Some(tx);
        Ok(unsigned_transaction)
    }
    pub fn sign_transaction(
        &self,
        unsigned_tx: SilentPaymentUnsignedTransaction,
        aux_rand: &[u8; 32],
    ) -> Result<Transaction> {
        // TODO check that we have aux_rand, at least that it's not all `0`s
        let b_spend = self.try_get_secret_spend_key()?;

        let to_sign = match unsigned_tx.unsigned_tx.as_ref() {
            Some(tx) => tx,
            None => return Err(Error::MissingUnsignedTx),
        };

        let mut signed = to_sign.clone();

        let mut cache = SighashCache::new(to_sign);

        let prevouts: Vec<_> = unsigned_tx
            .selected_utxos
            .iter()
            .map(|(_, owned_output)| TxOut {
                value: owned_output.amount,
                script_pubkey: owned_output.script.clone(),
            })
            .collect();

        let secp = Secp256k1::signing_only();
        let hash_ty = bitcoin::TapSighashType::Default; // We impose Default for now

        for (i, input) in to_sign.input.iter().enumerate() {
            let tap_leaf_hash: Option<TapLeafHash> = None;

            let msg = taproot_sighash(hash_ty, &prevouts, i, &mut cache, tap_leaf_hash)?;

            // Construct the signing key
            let (_, owned_output) = unsigned_tx
                .selected_utxos
                .iter()
                .find(|(outpoint, _)| *outpoint == input.previous_output)
                .ok_or(Error::MissingPrevout(i))?;

            let tweak = SecretKey::from_slice(owned_output.tweak.as_slice())?;

            let sk = b_spend.add_tweak(&tweak.into())?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            let mut witness = Witness::new();
            #[cfg(feature = "bitcoin_31")]
            let signature = Signature { sig, hash_ty }.to_vec();
            #[cfg(feature = "bitcoin_32")]
            let signature = Signature {
                signature: sig,
                sighash_type: hash_ty,
            }
            .to_vec();
            witness.push(signature);

            signed.input[i].witness = witness;
        }

        Ok(signed)
    }

    pub fn get_partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[(OutPoint, OwnedOutput)],
    ) -> Result<SecretKey> {
        let b_spend = self.try_get_secret_spend_key()?;

        let outpoints: Vec<_> = selected_utxos
            .iter()
            .map(|(outpoint, _)| (outpoint.txid.to_string(), outpoint.vout))
            .collect();
        let input_privkeys = selected_utxos
            .iter()
            .map(|(_, output)| {
                let sk = SecretKey::from_slice(&output.tweak)?;
                let signing_key = b_spend.add_tweak(&sk.into())?;
                Ok((signing_key, true))
            })
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}

/// Compute taproot sighash for key-spend or script-spend.
pub(crate) fn taproot_sighash<
    T: std::ops::Deref<Target = Transaction> + std::borrow::Borrow<Transaction>,
>(
    hash_ty: bitcoin::TapSighashType,
    prevouts: &[TxOut],
    input_index: usize,
    cache: &mut SighashCache<T>,
    tapleaf_hash: Option<TapLeafHash>,
) -> Result<Message> {
    let prevouts = Prevouts::All(prevouts);

    let sighash = match tapleaf_hash {
        Some(leaf_hash) => cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, hash_ty)
            .map_err(|e| Error::Sighash(e.to_string()))?,
        None => cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)
            .map_err(|e| Error::Sighash(e.to_string()))?,
    };
    #[cfg(feature = "bitcoin_31")]
    let msg = Message::from_digest(sighash.into_32());
    #[cfg(feature = "bitcoin_32")]
    let msg = Message::from_digest(*sighash.as_raw_hash().as_byte_array());
    Ok(msg)
}

/// Sign a single taproot input using SP tweak-based key derivation.
/// signing_key = b_spend + tweak
pub fn sign_sp_input(
    b_spend: &SecretKey,
    tweak: &[u8; 32],
    psbt: &mut Psbt,
    input_index: usize,
    aux_rand: &[u8; 32],
) -> Result<()> {
    let unsigned_tx = &psbt.unsigned_tx;

    // Collect all prevouts from PSBT inputs
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or(Error::MissingWitnessUtxo(i))
        })
        .collect::<Result<Vec<_>>>()?;

    let secp = Secp256k1::signing_only();
    let hash_ty = bitcoin::TapSighashType::Default;

    let mut cache = SighashCache::new(unsigned_tx);
    let msg = taproot_sighash(hash_ty, &prevouts, input_index, &mut cache, None)?;

    // Derive signing key: b_spend + tweak
    let tweak_sk = SecretKey::from_slice(tweak)?;
    let sk = b_spend.add_tweak(&tweak_sk.into())?;
    let keypair = Keypair::from_secret_key(&secp, &sk);

    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

    #[cfg(feature = "bitcoin_31")]
    let signature = Signature { sig, hash_ty };
    #[cfg(feature = "bitcoin_32")]
    let signature = Signature {
        signature: sig,
        sighash_type: hash_ty,
    };

    psbt.inputs[input_index].tap_key_sig = Some(signature);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{OutputSpendStatus, OwnedOutput, Recipient, RecipientAddress};
    #[cfg(feature = "mnemonic")]
    use bip39::Mnemonic;
    use bitcoin::absolute::Height;
    #[cfg(feature = "bitcoin_32")]
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    #[cfg(feature = "mnemonic")]
    fn create_test_sp_client() -> SpClient {
        let mnemonic = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        SpClient::new_from_mnemonic(mnemonic, Network::Regtest).unwrap()
    }

    fn create_mock_utxo(amount_sats: u64, tweak: [u8; 32]) -> (OutPoint, OwnedOutput) {
        #[cfg(feature = "bitcoin_32")]
        let txid = Txid::from_slice(&tweak).unwrap();
        #[cfg(feature = "bitcoin_31")]
        let txid = Txid::from_slice(&tweak).unwrap();

        let outpoint = OutPoint { txid, vout: 0 };
        let output = OwnedOutput {
            blockheight: Height::from_consensus(100).unwrap(),
            tweak,
            amount: Amount::from_sat(amount_sats),
            script: ScriptBuf::new_p2tr_tweaked(
                bitcoin::XOnlyPublicKey::from_str(NUMS)
                    .unwrap()
                    .dangerous_assume_tweaked(),
            ),
            label: None,
            spend_status: OutputSpendStatus::Unspent,
        };
        (outpoint, output)
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_multiple_outputs_same_sp_address() {
        let client = create_test_sp_client();
        let sp_address = client.get_receiving_address();

        // Create mock UTXO with enough funds
        let utxo = create_mock_utxo(100_000, [1u8; 32]);

        let recipients = vec![
            Recipient {
                address: RecipientAddress::SpAddress(sp_address.clone()),
                amount: Amount::from_sat(10_000),
            },
            Recipient {
                address: RecipientAddress::SpAddress(sp_address),
                amount: Amount::from_sat(20_000),
            },
        ];

        let unsigned_tx = client
            .create_new_transaction(
                vec![utxo],
                recipients,
                FeeRate::from_sat_per_vb(1.0),
                Network::Regtest,
            )
            .unwrap();

        let finalized = SpClient::finalize_transaction(unsigned_tx).unwrap();
        let tx = finalized.unsigned_tx.unwrap();

        let out_10k = tx
            .output
            .iter()
            .find(|o| o.value == Amount::from_sat(10_000))
            .unwrap();
        let out_20k = tx
            .output
            .iter()
            .find(|o| o.value == Amount::from_sat(20_000))
            .unwrap();

        // Expected scriptpubkeys for k=0 and k=1
        let expected_spk_k0 = ScriptBuf::from_hex(
            "51204b8420258e7eabcdf1b0847962796c2376428e2c7f0226bc0f78307ca3e3d7e4",
        )
        .unwrap();
        let expected_spk_k1 = ScriptBuf::from_hex(
            "51206007d5b346a334ef9de0c21e2e15c1a46b4e0f727d5e3ab4ab826f6b6509abfc",
        )
        .unwrap();

        assert_eq!(out_10k.script_pubkey, expected_spk_k0);
        assert_eq!(out_20k.script_pubkey, expected_spk_k1);
    }
}
