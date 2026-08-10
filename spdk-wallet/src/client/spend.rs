use anyhow::{Error, Result};
use bdk_coin_select::{TR_DUST_RELAY_MIN_VALUE, TR_KEYSPEND_SATISFACTION_WEIGHT};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};
use silentpayments::utils as sp_utils;
use silentpayments::utils::sending::PartialSecret;
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

use spdk_core::constants::DATA_CARRIER_SIZE;
use spdk_core::updater::DiscoveredOutput;

use super::coin_select::{
    candidate_from_external_utxo, pick_utxos_for_fee_rate, select_all_utxos_for_fee_rate,
    UtxoCandidate,
};
use super::{
    FeeRate, InputSelection, Recipient, RecipientAddress, SelectedUtxo,
    SilentPaymentUnsignedTransaction, SpClient, SpendingData, Strategy,
};

fn sp_network_from_network(network: Network) -> SpNetwork {
    match network {
        Network::Bitcoin => SpNetwork::Mainnet,
        Network::Testnet | Network::Signet => SpNetwork::Testnet,
        Network::Regtest => SpNetwork::Regtest,
        _ => unreachable!(),
    }
}

/// Converts the wallet's native UTXO representation to the generic
/// [`UtxoCandidate`] type expected by the coin-selection functions.
///
/// All outputs owned by a silent-payment wallet are P2TR key-spend outputs,
/// so `is_ours = true` and `satisfaction_weight` is the canonical TR key-spend
/// weight.
fn discovered_outputs_to_candidates(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
) -> Vec<UtxoCandidate> {
    available_utxos
        .iter()
        .map(|(outpoint, o)| UtxoCandidate {
            outpoint: *outpoint,
            txout: TxOut {
                value: o.value,
                script_pubkey: o.script_pubkey.clone(),
            },
            satisfaction_weight: TR_KEYSPEND_SATISFACTION_WEIGHT,
            is_segwit: true,
            is_ours: true,
        })
        .collect()
}

/// Builds the full [`UtxoCandidate`] list from wallet-owned and external UTXOs.
///
/// External UTXOs are validated and marked mandatory; see
/// [`candidate_from_external_utxo`] for the accepted script types.
fn build_candidates(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
    external_utxos: &[(OutPoint, TxOut)],
) -> Result<Vec<UtxoCandidate>> {
    let mut candidates = discovered_outputs_to_candidates(available_utxos);
    for (outpoint, txout) in external_utxos {
        candidates.push(candidate_from_external_utxo(*outpoint, txout.clone())?);
    }
    Ok(candidates)
}

/// Proposes coin selections for a normal (non-drain) transaction.
///
/// Runs the Changeless, LowestFee, and Greedy strategies independently and returns one
/// [`InputSelection`] per strategy that found a valid solution. The caller picks the preferred
/// selection and hands it to [`SpClient::create_transaction_from_selection`].
///
/// `external_utxos` are mandatory inputs that do not belong to this wallet (e.g. a counterparty's
/// UTXO in a collaborative transaction). They are always included in the selection regardless of
/// strategy. Only P2TR (key-path), P2WPKH, and P2PKH script types are accepted; any other type
/// returns an error, preventing a peer from understating the spending weight of their input.
///
/// `n_change_outputs` controls how many change outputs to budget for. Use `1` for the common case.
pub fn propose_coin_selections(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
    external_utxos: &[(OutPoint, TxOut)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
    n_change_outputs: usize,
) -> Result<Vec<InputSelection>> {
    let candidates = build_candidates(available_utxos, external_utxos)?;
    pick_utxos_for_fee_rate(candidates, recipients, n_change_outputs, fee_rate)
}

/// Proposes a coin selection for a drain transaction (spend all UTXOs).
///
/// Returns an [`InputSelection`] where **`selection.sent` is the total
/// amount available to be sent to the drain address** after fees
/// (`selection.change` is always zero for a drain).
///
/// ```ignore
/// let sel = propose_drain_selection(&utxos, &[], &addr, fee_rate)?;
/// let recipients = vec![Recipient { address: addr, amount: sel.sent }];
/// let unsigned = client.create_transaction_from_selection(&utxos, &[], recipients, sel, network)?;
/// ```
pub fn propose_drain_selection(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
    external_utxos: &[(OutPoint, TxOut)],
    recipient: &RecipientAddress,
    fee_rate: FeeRate,
) -> Result<InputSelection> {
    if matches!(recipient, RecipientAddress::Data(_)) {
        return Err(Error::msg("Draining to OP_RETURN not allowed"));
    }

    let candidates = build_candidates(available_utxos, external_utxos)?;

    // Amount::ZERO is a placeholder — only the output weight matters for fee
    // estimation here; the real amount is filled in by the caller.
    let placeholder = Recipient {
        address: recipient.clone(),
        amount: Amount::ZERO,
    };
    select_all_utxos_for_fee_rate(candidates, &[placeholder], fee_rate)
}

impl SpClient {
    /// Builds an unsigned silent-payment transaction from a previously chosen
    /// [`InputSelection`].
    ///
    /// **Normal transactions** (`selection.strategy != Strategy::Drain`):
    /// pass the original `recipients` without a change output; if
    /// `selection.change > 0` this method appends a change output addressed
    /// to the wallet's own SP change address automatically.
    ///
    /// **Drain transactions** (`selection.strategy == Strategy::Drain`):
    /// the caller must build the drain recipient with
    /// `amount = selection.sent` and include it in `recipients`; no extra
    /// change output is appended.
    ///
    /// In both cases the passed `recipients` must be the ones the selection
    /// was computed for: their total amount must equal `selection.sent` and
    /// their count `selection.n_sent_outputs`, otherwise an error is
    /// returned.
    ///
    /// `external_utxos` must be the same slice that was passed to the corresponding
    /// `propose_*` function. Any outpoint in the selection that is not found in
    /// `available_utxos` is resolved from `external_utxos` and stored as
    /// [`SpendingData::Legacy`]; an error is returned if an outpoint is absent from
    /// both.
    pub fn create_transaction_from_selection(
        &self,
        available_utxos: &[(OutPoint, DiscoveredOutput)],
        external_utxos: &[(OutPoint, TxOut)],
        mut recipients: Vec<Recipient>,
        selection: InputSelection,
        network: Network,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        let sp_network = sp_network_from_network(network);

        for r in &recipients {
            if let RecipientAddress::SpAddress(sp_address) = &r.address {
                if sp_address.network() != sp_network {
                    return Err(Error::msg(format!(
                        "Wrong network for address {}",
                        sp_address
                    )));
                }
            }
        }

        let mut change_indexes = Vec::new();
        let wallet_change =
            if selection.strategy != Strategy::Drain && selection.change > Amount::ZERO {
                let change_parts = super::coin_select::random_split(
                    selection.change,
                    selection.n_change_outputs,
                    Amount::from_sat(TR_DUST_RELAY_MIN_VALUE * 2),
                    &mut rand::thread_rng(),
                )?;
                for part in change_parts {
                    let change_address = self.sp_receiver.get_change_address();
                    change_indexes.push(recipients.len());
                    recipients.push(Recipient {
                        address: RecipientAddress::SpAddress(change_address.to_display_for_network(sp_network)),
                        amount: part,
                    });
                }
                selection.change
            } else {
                Amount::ZERO
            };

        let total_outputs_amt: Amount = recipients.iter().map(|r| r.amount).sum();
        if total_outputs_amt != selection.sent + selection.change
            || recipients.len() != selection.n_sent_outputs + selection.n_change_outputs
        {
            return Err(Error::msg(
                "Amount and/or number of outputs mismatch between recipients and selection",
            ));
        }

        let selected_utxos: Vec<SelectedUtxo> = selection
            .selected_utxos
            .iter()
            .map(|op| {
                if let Some((o, d)) = available_utxos.iter().find(|(o, _)| o == op) {
                    Ok(SelectedUtxo {
                        outpoint: *o,
                        spending_data: SpendingData::SilentPayment(d.clone()),
                    })
                } else if let Some((o, txout)) = external_utxos.iter().find(|(o, _)| o == op) {
                    Ok(SelectedUtxo {
                        outpoint: *o,
                        spending_data: SpendingData::Legacy(txout.clone()),
                    })
                } else {
                    Err(Error::msg(format!(
                        "outpoint {} not found in available_utxos or external_utxos",
                        op
                    )))
                }
            })
            .collect::<Result<_>>()?;

        let partial_secret = self.get_partial_secret_for_selected_utxos(&selected_utxos)?;

        Ok(SilentPaymentUnsignedTransaction {
            selected_utxos,
            recipients,
            partial_secret,
            unsigned_tx: None,
            network,
            change: wallet_change,
            change_indexes,
            fee: selection.fee,
            actual_fee_rate: selection.actual_fee_rate,
            strategy: selection.strategy,
        })
    }

    /// Resolves silent-payment placeholder outputs to their final script
    /// pubkeys and assembles the [`Transaction`] skeleton (no witnesses yet).
    pub fn finalize_transaction(
        mut unsigned_transaction: SilentPaymentUnsignedTransaction,
    ) -> Result<SilentPaymentUnsignedTransaction> {
        let tx_ins: Vec<TxIn> = unsigned_transaction
            .selected_utxos
            .iter()
            .map(|selected| TxIn {
                previous_output: selected.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();

        let sp_addresses: Vec<SilentPaymentAddress> = unsigned_transaction
            .recipients
            .iter()
            .filter_map(|r| match &r.address {
                RecipientAddress::SpAddress(sp_address) => {
                    Some(SilentPaymentAddress::from(*sp_address))
                }
                _ => None,
            })
            .collect();

        let sp_address2xonlypubkeys = silentpayments::sending::generate_recipient_pubkeys(
            sp_addresses,
            unsigned_transaction.partial_secret,
        )?;

        let tx_outs = unsigned_transaction
            .recipients
            .iter()
            .map(|recipient| match &recipient.address {
                RecipientAddress::SpAddress(s) => {
                    let pubkeys = sp_address2xonlypubkeys
                        .get(&SilentPaymentAddress::from(*s))
                        .ok_or(Error::msg("Unknown sp address"))?;

                    // we currently only allow having 1 output per silent payment address
                    // note: when changing this, it should also be accounted for in 'create_transaction_from_selection'
                    if pubkeys.len() == 1 {
                        let pubkey = pubkeys[0];
                        let script = ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked());
                        Ok(TxOut {
                            value: recipient.amount,
                            script_pubkey: script,
                        })
                    } else {
                        Err(Error::msg("multiple outputs not supported"))
                    }
                }
                RecipientAddress::LegacyAddress(unchecked_address) => {
                    let script = unchecked_address
                        .clone()
                        .require_network(unsigned_transaction.network)?
                        .script_pubkey();

                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    })
                }
                RecipientAddress::Data(data) => {
                    if recipient.amount > Amount::from_sat(0) {
                        return Err(Error::msg("Data output must have an amount of 0!"));
                    }
                    let data_len = data.len();
                    if data_len > DATA_CARRIER_SIZE {
                        return Err(Error::msg(format!(
                            "Can't embed data of length {}. Max length: {}",
                            data_len, DATA_CARRIER_SIZE
                        )));
                    }
                    let mut op_return = PushBytesBuf::with_capacity(data_len);
                    op_return.extend_from_slice(data)?;
                    let script = ScriptBuf::new_op_return(op_return);
                    Ok(TxOut {
                        value: recipient.amount,
                        script_pubkey: script,
                    })
                }
            })
            .collect::<Result<Vec<TxOut>>>()?;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: tx_outs,
        };
        unsigned_transaction.unsigned_tx = Some(tx);
        Ok(unsigned_transaction)
    }

    fn taproot_sighash<
        T: std::ops::Deref<Target = Transaction> + std::borrow::Borrow<Transaction>,
    >(
        hash_ty: bitcoin::TapSighashType,
        prevouts: &[TxOut],
        input_index: usize,
        cache: &mut SighashCache<T>,
        tapleaf_hash: Option<TapLeafHash>,
    ) -> Result<Message, Error> {
        let prevouts = Prevouts::All(prevouts);

        let sighash = match tapleaf_hash {
            Some(leaf_hash) => cache.taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                leaf_hash,
                hash_ty,
            )?,
            None => cache.taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)?,
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(msg)
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
            None => return Err(Error::msg("Missing unsigned transaction")),
        };

        let mut signed = to_sign.clone();

        let mut cache = SighashCache::new(to_sign);

        let prevouts: Vec<_> = unsigned_tx
            .selected_utxos
            .iter()
            .map(|selected| selected.spending_data.txout())
            .collect();

        let secp = Secp256k1::signing_only();
        let sighash_type = bitcoin::TapSighashType::Default; // We impose Default for now

        for (i, input) in to_sign.input.iter().enumerate() {
            let selected = unsigned_tx
                .selected_utxos
                .iter()
                .find(|s| s.outpoint == input.previous_output)
                .ok_or_else(|| {
                    Error::msg(format!("prevout for input {} not in selected utxos", i))
                })?;

            // Only SP-owned inputs carry a tweak this wallet can sign with;
            // skip external inputs before doing any sighash work.
            let SpendingData::SilentPayment(owned_output) = &selected.spending_data else {
                continue;
            };

            let tap_leaf_hash: Option<TapLeafHash> = None;

            let msg = Self::taproot_sighash(sighash_type, &prevouts, i, &mut cache, tap_leaf_hash)?;

            let sk = b_spend.add_tweak(&owned_output.tweak)?;

            let keypair = Keypair::from_secret_key(&secp, &sk);

            let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

            let mut witness = Witness::new();
            witness.push(
                Signature {
                    signature,
                    sighash_type,
                }
                .to_vec(),
            );

            signed.input[i].witness = witness;
        }

        Ok(signed)
    }

    pub fn get_partial_secret_for_selected_utxos(
        &self,
        selected_utxos: &[SelectedUtxo],
    ) -> Result<PartialSecret> {
        let b_spend = self.try_get_secret_spend_key()?;

        // Only SP-owned inputs contribute to the partial secret computation.
        let sp_inputs: Vec<_> = selected_utxos
            .iter()
            .filter_map(|u| match &u.spending_data {
                SpendingData::SilentPayment(o) => Some((u.outpoint, o)),
                SpendingData::Legacy(_) => None,
            })
            .collect();

        let outpoints = sp_inputs
            .iter()
            .map(|(outpoint, _)| {
                Ok(sp_utils::OutPoint::from_txid_and_vout(
                    outpoint.txid.to_string(),
                    outpoint.vout,
                )?)
            })
            .collect::<Result<Vec<sp_utils::OutPoint>>>()?;

        let input_privkeys = sp_inputs
            .iter()
            .map(|(_, output)| Ok((b_spend.add_tweak(&output.tweak)?, true)))
            .collect::<Result<Vec<_>>>()?;

        let partial_secret =
            sp_utils::sending::calculate_partial_secret(&input_privkeys, &outpoints)?;

        Ok(partial_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Scalar, SecretKey};
    use bitcoin::{Address, Txid};

    use crate::client::SpendKey;

    fn test_client() -> SpClient {
        let scan_sk = SecretKey::from_slice(&[0x11; 32]).expect("valid test key");
        let spend_sk = SecretKey::from_slice(&[0x22; 32]).expect("valid test key");
        SpClient::new(scan_sk, SpendKey::Secret(spend_sk), Network::Regtest).expect("client")
    }

    fn discovered_output(value_sat: u64) -> DiscoveredOutput {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        DiscoveredOutput {
            tweak: Scalar::ONE,
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
            label: None,
        }
    }

    fn wallet_utxos(values: &[u64]) -> Vec<(OutPoint, DiscoveredOutput)> {
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                (
                    OutPoint::new(Txid::all_zeros(), i as u32),
                    discovered_output(v),
                )
            })
            .collect()
    }

    fn legacy_address() -> Address<bitcoin::address::NetworkUnchecked> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x43; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        Address::p2tr_tweaked(tweaked, Network::Regtest)
            .as_unchecked()
            .clone()
    }

    fn payment_recipient(value_sat: u64) -> Recipient {
        Recipient {
            address: RecipientAddress::LegacyAddress(legacy_address()),
            amount: Amount::from_sat(value_sat),
        }
    }

    fn test_fee_rate() -> FeeRate {
        FeeRate::from_sat_per_vb(1.0)
    }

    fn external_p2tr_txout(value_sat: u64) -> TxOut {
        // Use a distinct key ([0x44; 32]) to distinguish from wallet/payment outputs.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x44; 32]).expect("valid test key");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        let tweaked = xonly.tap_tweak(&secp, None).0;
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        }
    }

    #[test]
    fn create_transaction_appends_change_for_normal_selection() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let recipients = vec![payment_recipient(50_000)];
        let selections =
            propose_coin_selections(&utxos, &[], &recipients, test_fee_rate(), 1)
                .expect("selection");
        let selection = selections
            .into_iter()
            .find(|s| s.change > Amount::ZERO)
            .expect("a selection with change");

        let unsigned = client
            .create_transaction_from_selection(
                &utxos,
                &[],
                recipients.clone(),
                selection,
                Network::Regtest,
            )
            .expect("transaction");

        assert_eq!(unsigned.recipients.len(), recipients.len() + 1);
        assert_eq!(unsigned.change_indexes, vec![recipients.len()]);
        assert_eq!(unsigned.change, unsigned.recipients.last().unwrap().amount);
    }

    #[test]
    fn create_transaction_rejects_amount_mismatch() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let recipients = vec![payment_recipient(50_000)];
        let selections =
            propose_coin_selections(&utxos, &[], &recipients, test_fee_rate(), 1)
                .expect("selection");

        let err = client
            .create_transaction_from_selection(
                &utxos,
                &[],
                vec![payment_recipient(49_999)],
                selections.into_iter().next().unwrap(),
                Network::Regtest,
            )
            .expect_err("amount mismatch must be rejected");
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn create_transaction_rejects_output_count_mismatch() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let recipients = vec![payment_recipient(50_000)];
        let selections =
            propose_coin_selections(&utxos, &[], &recipients, test_fee_rate(), 1)
                .expect("selection");

        // Same total amount as the selection, but split over two outputs.
        let err = client
            .create_transaction_from_selection(
                &utxos,
                &[],
                vec![payment_recipient(25_000), payment_recipient(25_000)],
                selections.into_iter().next().unwrap(),
                Network::Regtest,
            )
            .expect_err("output count mismatch must be rejected");
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn drain_flow_builds_transaction_without_change() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let drain_address = RecipientAddress::LegacyAddress(legacy_address());

        let selection =
            propose_drain_selection(&utxos, &[], &drain_address, test_fee_rate()).expect("selection");
        assert_eq!(selection.strategy, Strategy::Drain);
        assert_eq!(selection.change, Amount::ZERO);

        let recipients = vec![Recipient {
            address: drain_address,
            amount: selection.sent,
        }];
        let unsigned = client
            .create_transaction_from_selection(&utxos, &[], recipients, selection, Network::Regtest)
            .expect("transaction");

        assert_eq!(unsigned.recipients.len(), 1);
        assert_eq!(unsigned.change, Amount::ZERO);
        assert!(unsigned.change_indexes.is_empty());
        assert_eq!(
            unsigned.recipients[0].amount + unsigned.fee,
            Amount::from_sat(300_000)
        );
    }

    #[test]
    fn create_transaction_resolves_external_input_as_legacy() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000]);
        let ext_txout = external_p2tr_txout(50_000);
        let ext_outpoint = OutPoint::new(Txid::from_byte_array([0x01; 32]), 0);
        let external_utxos = vec![(ext_outpoint, ext_txout)];
        // Payment requires both inputs (100_000 + 50_000 - fees > 120_000).
        let recipients = vec![payment_recipient(120_000)];

        let selections =
            propose_coin_selections(&utxos, &external_utxos, &recipients, test_fee_rate(), 1)
                .expect("selection");
        let selection = selections.into_iter().next().unwrap();
        // External inputs are mandatory so the external outpoint must be selected.
        assert!(selection.selected_utxos.contains(&ext_outpoint));

        let unsigned = client
            .create_transaction_from_selection(
                &utxos,
                &external_utxos,
                recipients,
                selection,
                Network::Regtest,
            )
            .expect("transaction");

        let ext_selected = unsigned
            .selected_utxos
            .iter()
            .find(|u| u.outpoint == ext_outpoint)
            .expect("external input must be in selected_utxos");
        assert!(
            matches!(&ext_selected.spending_data, SpendingData::Legacy(_)),
            "external input must carry Legacy spending data",
        );

        let wallet_selected = unsigned
            .selected_utxos
            .iter()
            .find(|u| u.outpoint != ext_outpoint)
            .expect("wallet input must be in selected_utxos");
        assert!(
            matches!(&wallet_selected.spending_data, SpendingData::SilentPayment(_)),
            "wallet input must carry SilentPayment spending data",
        );
    }

    #[test]
    fn drain_with_external_input_counts_toward_sendable_amount() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000]);
        let ext_txout = external_p2tr_txout(50_000);
        let ext_outpoint = OutPoint::new(Txid::from_byte_array([0x01; 32]), 0);
        let external_utxos = vec![(ext_outpoint, ext_txout)];
        let drain_address = RecipientAddress::LegacyAddress(legacy_address());

        let sel_without =
            propose_drain_selection(&utxos, &[], &drain_address, test_fee_rate()).expect("without");
        let sel_with =
            propose_drain_selection(&utxos, &external_utxos, &drain_address, test_fee_rate())
                .expect("with");

        // The external input's value (minus its share of fees) must increase the sendable amount.
        assert!(sel_with.sent > sel_without.sent);
        assert!(sel_with.selected_utxos.contains(&ext_outpoint));

        let recipients = vec![Recipient {
            address: drain_address,
            amount: sel_with.sent,
        }];
        let unsigned = client
            .create_transaction_from_selection(
                &utxos,
                &external_utxos,
                recipients,
                sel_with,
                Network::Regtest,
            )
            .expect("transaction");

        assert!(unsigned
            .selected_utxos
            .iter()
            .any(|u| matches!(&u.spending_data, SpendingData::Legacy(_))));
        assert_eq!(unsigned.change, Amount::ZERO);
    }
}
