use std::collections::HashSet;

use anyhow::{Error, Result};
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::key::CompressedPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::seq::SliceRandom as _;
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxOut};
use psbt::extractor::SpExtractorExt as _;
use psbt::signer::{ShareMode, SpSignerExt as _};
use psbt_v2::Psbt;
use psbt_v2::{Constructor, Extractor, Finalizer, Input, Modifiable, Output, Signer, SpV0Info};
use silentpayments::Network as SpNetwork;
use spdk_core::scanner::DiscoveredOutput;

use super::coin_select::{pick_utxos_for_fee_rate, select_all_utxos_for_fee_rate};
use super::{DrainSelection, FeeRate, InputSelection, Recipient, RecipientAddress, SpClient};

const fn sp_network_from_network(network: Network) -> SpNetwork {
    match network {
        Network::Bitcoin => SpNetwork::Mainnet,
        Network::Testnet | Network::Testnet4 | Network::Signet => SpNetwork::Testnet,
        Network::Regtest => SpNetwork::Regtest,
    }
}

fn prevouts(available_utxos: &[(OutPoint, DiscoveredOutput)]) -> Result<Vec<(OutPoint, TxOut)>> {
    let mut seen = HashSet::with_capacity(available_utxos.len());
    let mut result = Vec::with_capacity(available_utxos.len());
    for (outpoint, o) in available_utxos {
        if !seen.insert(*outpoint) {
            return Err(Error::msg(format!("duplicate outpoint: {outpoint}")));
        }
        result.push((*outpoint, o.txout.clone()));
    }
    Ok(result)
}

/// Proposes coin selections for a normal (non-drain) transaction.
///
/// Runs the `Changeless`, `LowestFee`, and `FeeRateCap` strategies independently
/// and returns one [`InputSelection`] per strategy that found a valid solution.
/// If none of them succeed, falls back to `Greedy`.
///
/// The caller picks the preferred selection and hands it to
/// [`SpClient::create_transaction_from_selection`].
pub fn propose_coin_selections(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
    recipients: &[Recipient],
    fee_rate: FeeRate,
) -> Result<Vec<InputSelection>> {
    let utxos = prevouts(available_utxos)?;
    pick_utxos_for_fee_rate(&utxos, recipients, fee_rate)
}

/// Proposes a coin selection for a drain transaction (spend all UTXOs).
///
/// [`DrainSelection::sent`] is the amount available to send to the drain address after fees.
///
/// ```ignore
/// let sel = propose_drain_selection(&utxos, &addr, fee_rate)?;
/// let recipients = vec![Recipient { address: addr, amount: sel.sent() }];
/// let unsigned = client.create_drain_transaction_from_selection(&utxos, &recipients, &sel, network)?;
/// ```
pub fn propose_drain_selection(
    available_utxos: &[(OutPoint, DiscoveredOutput)],
    recipient: &RecipientAddress,
    fee_rate: FeeRate,
) -> Result<DrainSelection> {
    if matches!(recipient, RecipientAddress::Data(_)) {
        return Err(Error::msg("Draining to OP_RETURN not allowed"));
    }

    let utxos = prevouts(available_utxos)?;

    // Amount::ZERO is a placeholder — only the output weight matters for fee
    // estimation here; the real amount is filled in by the caller.
    let placeholder = Recipient {
        address: recipient.clone(),
        amount: Amount::ZERO,
    };
    select_all_utxos_for_fee_rate(&utxos, &[placeholder], fee_rate)
}

impl SpClient {
    fn check_recipient_networks(recipients: &[Recipient], network: Network) -> Result<()> {
        let sp_network = sp_network_from_network(network);
        for r in recipients {
            if let RecipientAddress::SpCode(sp_address) = &r.address
                && sp_address.network() != sp_network
            {
                return Err(Error::msg(format!(
                    "Wrong network for address {sp_address}"
                )));
            }
        }
        Ok(())
    }

    fn resolve_selected_utxos(
        available_utxos: &[(OutPoint, DiscoveredOutput)],
        selected: &[OutPoint],
    ) -> Result<Vec<(OutPoint, DiscoveredOutput)>> {
        let res = selected
            .iter()
            .map(|sel| {
                available_utxos
                    .iter()
                    .find(|(avail, _)| avail == sel)
                    .map(|(outpoint, output)| (*outpoint, output.clone()))
                    .ok_or_else(|| {
                        Error::msg(format!("outpoint {sel} not found in available_utxos"))
                    })
            })
            .collect::<Result<Vec<(OutPoint, DiscoveredOutput)>>>()?;
        if res.len() != selected.len() {
            return Err(Error::msg(
                "All selected outpoints are not in provided utxos",
            ));
        }
        Ok(res)
    }

    fn assemble_unsigned(
        &self,
        available_utxos: &[(OutPoint, DiscoveredOutput)],
        selected_outpoints: &[OutPoint],
        recipients: &[Recipient],
        network: Network,
    ) -> Result<Psbt> {
        Self::check_recipient_networks(recipients, network)?;
        let selected_utxos = Self::resolve_selected_utxos(available_utxos, selected_outpoints)?;
        let spend_pubkey = CompressedPublicKey(PublicKey::from(&self.spend_key()));

        // Inputs and outputs are fixed by coin selection. Freeze them here so a
        // later ECDH share cannot be computed against a different input set.
        let mut constructor = Constructor::<Modifiable>::default();
        for (outpoint, output) in &selected_utxos {
            constructor = constructor.input(input_for_utxo(spend_pubkey, outpoint, output));
        }
        for recipient in recipients {
            constructor = constructor.output(output_for_recipient(recipient, network)?)?;
        }
        Ok(constructor.no_more_inputs().no_more_outputs().psbt()?)
    }

    /// Builds an unsigned silent-payment PSBT from a payment [`InputSelection`].
    ///
    /// Pass the original `recipients` without a change output; if
    /// `selection.change() > 0` this method appends a change output
    /// addressed to the wallet's own SP change code, then shuffles the
    /// recipient order so change is not always last.
    ///
    /// Silent-payment outputs are returned with an empty `script_pubkey` and
    /// `sp_v0_info` set. [`Self::commit_sp_outputs`] derives the scripts.
    /// Fee, fee rate, and the coin-selection strategy are not stored on the PSBT;
    /// the fee is the difference between input and output amounts.
    ///
    /// The passed `recipients` must be the ones the selection was computed for:
    /// their total amount must equal `selection.sent()` and their count
    /// `selection.n_sent_outputs()`.
    pub fn create_transaction_from_selection(
        &self,
        available_utxos: &[(OutPoint, DiscoveredOutput)],
        mut recipients: Vec<Recipient>,
        selection: &InputSelection,
        network: Network,
    ) -> Result<Psbt> {
        let total_outputs_amt: Amount = recipients.iter().map(|r| r.amount).sum();
        if total_outputs_amt != selection.sent() {
            return Err(Error::msg(
                "Amount mismatch between recipients and selection",
            ));
        }

        let total_recipients_weights: u64 = recipients
            .iter()
            .map(Recipient::output_weight)
            .sum::<Result<_>>()?;

        if selection.weight_sum() != total_recipients_weights {
            return Err(Error::msg("Recipients and inputs selection mismatch"));
        }

        if recipients.len() != selection.n_sent_outputs() {
            return Err(Error::msg(
                "Number of outputs mismatch between recipients and selection",
            ));
        }

        // Check that there's no duplicate selection
        let selected_utxos = selection.selected_utxos();
        let mut selected_seen = HashSet::with_capacity(selected_utxos.len());
        for outpoint in selected_utxos {
            if !selected_seen.insert(outpoint) {
                return Err(Error::msg("Duplicate outpoint in selected_utxos"));
            }
        }

        if selection.change() > Amount::ZERO {
            recipients.push(Recipient {
                address: RecipientAddress::SpCode(self.sp_receiver.change_code()),
                amount: selection.change(),
            });
        }
        recipients.shuffle(&mut thread_rng());

        self.assemble_unsigned(available_utxos, selected_utxos, &recipients, network)
    }

    /// Builds an unsigned drain PSBT from a [`DrainSelection`].
    ///
    /// The caller must pass the drain recipient(s) with total amount equal to
    /// `selection.sent()`. No change output is appended.
    pub fn create_drain_transaction_from_selection(
        &self,
        available_utxos: &[(OutPoint, DiscoveredOutput)],
        recipients: &[Recipient],
        selection: &DrainSelection,
        network: Network,
    ) -> Result<Psbt> {
        let total_outputs_amt: Amount = recipients.iter().map(|r| r.amount).sum();
        if total_outputs_amt != selection.sent() {
            return Err(Error::msg(
                "Amount mismatch between recipients and selection",
            ));
        }

        let total_recipients_weights: u64 = recipients
            .iter()
            .map(Recipient::output_weight)
            .sum::<Result<_>>()?;

        if selection.weight_sum() != total_recipients_weights {
            return Err(Error::msg("Recipients and inputs selection mismatch"));
        }

        if recipients.len() != selection.n_sent_outputs() {
            return Err(Error::msg(
                "Number of outputs mismatch between recipients and selection",
            ));
        }

        self.assemble_unsigned(
            available_utxos,
            selection.selected_utxos(),
            recipients,
            network,
        )
    }

    /// Derives silent-payment output scripts and writes them onto `psbt`.
    ///
    /// BIP-375 requires the Signer to do this before adding any signature.
    /// Adds a global ECDH share (this wallet owns every input) when none is
    /// present, then commits the scripts. A PSBT with no silent-payment outputs
    /// is returned unchanged. Requires the spend secret when shares are missing.
    pub fn commit_sp_outputs(&self, mut psbt: Psbt) -> Result<Psbt> {
        let mut pending = false;
        let mut committed = false;
        for output in &psbt.outputs {
            if output.sp_v0_info.is_none() {
                continue;
            }
            if output.script_pubkey.is_empty() {
                pending = true;
            } else {
                committed = true;
            }
        }
        if pending && committed {
            return Err(Error::msg(
                "silent payment outputs are only partially derived",
            ));
        }
        if !pending {
            return Ok(psbt);
        }

        let secp = Secp256k1::new();
        let shares_present = !psbt.global.sp_ecdh_shares.is_empty()
            || psbt
                .inputs
                .iter()
                .any(|input| !input.sp_ecdh_shares.is_empty());
        if !shares_present {
            let spend_sk = self.try_secret_spend_key()?;
            let mut rng = OsRng;
            psbt.add_ecdh_shares(&secp, &mut rng, &spend_sk, ShareMode::Global)?;
        }
        psbt.commit_sp_outputs(&secp)?;
        Ok(psbt)
    }

    /// Signs every input this wallet can sign. Does not finalize witnesses.
    ///
    /// Silent-payment output scripts must already be set. BIP-375 forbids a
    /// signature while any of them is still empty.
    pub fn sign_inputs(&self, psbt: Psbt) -> Result<Psbt> {
        let spend_sk = self.try_secret_spend_key()?;
        let secp = Secp256k1::new();
        let (psbt, _) = Signer::new(psbt)?.sign_silent_payment_inputs(&spend_sk, &secp)?;
        Ok(psbt)
    }

    /// Builds each input's final scriptSig and witness from its signatures.
    ///
    /// This is the Input Finalizer. It clears the fields the Signer reads input
    /// public keys from, which is why [`Self::verify_sp_output_scripts`] recovers
    /// those keys from the witness.
    pub fn finalize_inputs(&self, psbt: Psbt) -> Result<Psbt> {
        let secp = Secp256k1::new();
        Ok(Finalizer::new(psbt)?.finalize(&secp)?)
    }

    /// Recomputes silent-payment output scripts from the finalized inputs and
    /// rejects a mismatch.
    ///
    /// BIP-375 assigns this to the Transaction Extractor. The input public keys
    /// are recovered from the final scriptSig and witness, so
    /// [`Self::finalize_inputs`] has to have run already.
    pub fn verify_sp_output_scripts(&self, psbt: &Psbt) -> Result<()> {
        let secp = Secp256k1::new();
        Ok(psbt.verify_sp_output_scripts(&secp)?)
    }

    /// Extracts the transaction. Does not repeat [`Self::verify_sp_output_scripts`].
    pub fn extract_transaction(&self, psbt: Psbt) -> Result<Transaction> {
        Ok(Extractor::new(psbt)?.extract_tx()?)
    }
}

fn input_for_utxo(
    spend_pubkey: CompressedPublicKey,
    outpoint: &OutPoint,
    output: &DiscoveredOutput,
) -> Input {
    let mut input = Input::new(outpoint);
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(output.txout.clone());
    // BIP-376: the map key is the untweaked spend key. The output key on the
    // prevout is `spend_pubkey + tweak·G`.
    input.sp_tweak = Some(output.tweak.to_be_bytes());
    input.sp_spend_bip32_derivations.insert(
        spend_pubkey,
        (Fingerprint::default(), DerivationPath::master()),
    );
    input
}

fn output_for_recipient(recipient: &Recipient, network: Network) -> Result<Output> {
    match &recipient.address {
        RecipientAddress::SpCode(code) => {
            let mut output = Output::new(TxOut {
                value: recipient.amount,
                script_pubkey: ScriptBuf::new(),
            });
            output.sp_v0_info = Some(SpV0Info::new(
                CompressedPublicKey(code.scan_key()),
                CompressedPublicKey(code.m_pubkey()),
            ));
            Ok(output)
        }
        RecipientAddress::LegacyAddress(unchecked_address) => {
            let script_pubkey = unchecked_address
                .clone()
                .require_network(network)?
                .script_pubkey();
            Ok(Output::new(TxOut {
                value: recipient.amount,
                script_pubkey,
            }))
        }
        RecipientAddress::Data(data) => {
            if recipient.amount > Amount::ZERO {
                return Err(Error::msg("Data output must have an amount of 0!"));
            }
            let mut op_return = PushBytesBuf::with_capacity(data.len());
            op_return.extend_from_slice(data)?;
            Ok(Output::new(TxOut {
                value: recipient.amount,
                script_pubkey: ScriptBuf::new_op_return(op_return),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::TapTweak as _;
    use bitcoin::secp256k1::{Keypair, Scalar, SecretKey};
    use bitcoin::{Address, Txid};

    use super::*;
    use crate::client::SpendKey;

    fn test_spend_key() -> SecretKey {
        SecretKey::from_slice(&[0x22; 32]).expect("valid test key")
    }

    fn test_client() -> SpClient {
        let scan_sk = SecretKey::from_slice(&[0x11; 32]).expect("valid test key");
        SpClient::new(
            scan_sk,
            SpendKey::Secret(test_spend_key()),
            Network::Regtest,
        )
        .expect("client")
    }

    // The output key must match `spend_sk + tweak`, otherwise the DLEQ proof
    // generated when committing silent-payment outputs cannot verify.
    fn discovered_output(spend_sk: &SecretKey, value_sat: u64) -> DiscoveredOutput {
        let secp = Secp256k1::new();
        let tweak = Scalar::ONE;
        let sk = spend_sk.add_tweak(&tweak).expect("valid tweak");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = keypair.x_only_public_key();
        DiscoveredOutput {
            tweak,
            txout: TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
            },
            label: None,
        }
    }

    fn wallet_utxos(values: &[u64]) -> Vec<(OutPoint, DiscoveredOutput)> {
        let spend_sk = test_spend_key();
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                (
                    OutPoint::new(
                        Txid::all_zeros(),
                        u32::try_from(i).expect("vout fits in u32"),
                    ),
                    discovered_output(&spend_sk, v),
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

    #[test]
    fn create_transaction_appends_change_for_normal_selection() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let recipients = vec![payment_recipient(50_000)];
        let selections =
            propose_coin_selections(&utxos, &recipients, test_fee_rate()).expect("selection");
        let selection = selections
            .into_iter()
            .find(|s| s.change() > Amount::ZERO)
            .expect("a selection with change");

        let psbt = client
            .create_transaction_from_selection(
                &utxos,
                recipients.clone(),
                &selection,
                Network::Regtest,
            )
            .expect("transaction");

        assert_eq!(psbt.outputs.len(), recipients.len() + 1);
        let change = psbt
            .outputs
            .iter()
            .find(|o| o.amount == selection.change() && o.sp_v0_info.is_some())
            .expect("change output");
        assert!(change.script_pubkey.is_empty());

        let psbt = client.commit_sp_outputs(psbt).expect("commit");
        let change_vout = psbt
            .outputs
            .iter()
            .position(|o| o.amount == selection.change() && o.sp_v0_info.is_some())
            .expect("change output");
        assert!(psbt.outputs[change_vout].script_pubkey.is_p2tr());

        let psbt = client.sign_inputs(psbt).expect("sign");
        let psbt = client.finalize_inputs(psbt).expect("finalize");
        client
            .verify_sp_output_scripts(&psbt)
            .expect("verify outputs");
        let tx = client.extract_transaction(psbt).expect("extract");
        assert_eq!(tx.output.len(), recipients.len() + 1);
        assert!(tx.output[change_vout].script_pubkey.is_p2tr());
        assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
    }

    #[test]
    fn create_transaction_rejects_amount_mismatch() {
        let client = test_client();
        let utxos = wallet_utxos(&[100_000, 200_000]);
        let recipients = vec![payment_recipient(50_000)];
        let selections =
            propose_coin_selections(&utxos, &recipients, test_fee_rate()).expect("selection");

        let err = client
            .create_transaction_from_selection(
                &utxos,
                vec![payment_recipient(49_999)],
                &selections[0],
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
            propose_coin_selections(&utxos, &recipients, test_fee_rate()).expect("selection");

        // Same total amount as the selection, but split over two outputs.
        let err = client
            .create_transaction_from_selection(
                &utxos,
                vec![payment_recipient(25_000), payment_recipient(25_000)],
                &selections[0],
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
            propose_drain_selection(&utxos, &drain_address, test_fee_rate()).expect("selection");

        let recipients = vec![Recipient {
            address: drain_address,
            amount: selection.sent(),
        }];
        let psbt = client
            .create_drain_transaction_from_selection(
                &utxos,
                &recipients,
                &selection,
                Network::Regtest,
            )
            .expect("transaction");

        assert_eq!(psbt.outputs.len(), 1);
        assert!(psbt.outputs[0].sp_v0_info.is_none());
        assert_eq!(psbt.outputs[0].amount, selection.sent());
        assert_eq!(
            psbt.outputs[0].amount + selection.fee(),
            Amount::from_sat(300_000)
        );

        let psbt = client.commit_sp_outputs(psbt).expect("commit");
        let psbt = client.sign_inputs(psbt).expect("sign");
        let psbt = client.finalize_inputs(psbt).expect("finalize");
        client
            .verify_sp_output_scripts(&psbt)
            .expect("verify outputs");
        let tx = client.extract_transaction(psbt).expect("extract");
        assert_eq!(tx.output.len(), 1);
        assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
    }
}
