use std::collections::{BTreeMap, HashMap, HashSet};

use bitcoin::absolute::Height;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use electrum_streaming_client::notification::Notification;
use electrum_streaming_client::{ElectrumScriptHash, Event, request};
use futures::channel::mpsc::{Receiver, channel};
use futures::{SinkExt as _, StreamExt as _};
use log::{debug, error, info, warn};
use silentpayments::receiving::Receiver as SpReceiver;
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, generate_script_pubkey_from_output_key,
};
use spdk_core::scanner::{DiscoveredOutput, ScanResult, Scanner};

use crate::client::FrigateClient;

pub struct FrigateScanner {
    client: FrigateClient,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    labels: Option<Vec<u32>>,
    owned_outpoints: HashSet<OutPoint>,
}

impl FrigateScanner {
    pub async fn new(
        host_url: String,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        labels: Option<Vec<u32>>,
        owned_outpoints: HashSet<OutPoint>,
    ) -> anyhow::Result<Self> {
        let client = FrigateClient::connect(&host_url).await?;
        Ok(Self {
            client,
            b_scan,
            sp_receiver,
            labels,
            owned_outpoints,
        })
    }

    /// Starts a scan and keeps listening for confirmed spends of discovered outputs.
    ///
    /// The scan receiver is closed when the historical scan reaches progress `1.0`. The spent
    /// receiver remains open for subsequent script-hash notifications.
    pub fn scan_blocks_with_spent_outputs(
        self,
        range: std::ops::RangeInclusive<Height>,
    ) -> (Receiver<ScanResult>, Receiver<HashSet<OutPoint>>) {
        self.start_scan(range, true)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "scan orchestration will be refactored later"
    )]
    fn start_scan(
        mut self,
        range: std::ops::RangeInclusive<Height>,
        monitor_spent: bool,
    ) -> (Receiver<ScanResult>, Receiver<HashSet<OutPoint>>) {
        let subscribe_params = request::SpSubscribe {
            scan_priv_key: self.b_scan,
            spend_pub_key: self.sp_receiver.receiving_code().m_pubkey(),
            start_height: Some(range.start().to_consensus_u32()),
            labels: self.labels,
        };

        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        );

        let (scan_tx, scan_rx) = channel(100_000);
        let (mut spent_tx, spent_rx) = channel(100_000);

        tokio::spawn(async move {
            let mut scan_tx = Some(scan_tx);
            let mut tracked_scripts: HashMap<ElectrumScriptHash, HashSet<OutPoint>> =
                HashMap::new();
            let mut inspected_txids: HashMap<ElectrumScriptHash, HashSet<Txid>> = HashMap::new();

            match self.client.subscribe(subscribe_params).await {
                Ok(sp_address) => info!("Subscribed to silent payments address {sp_address}"),
                Err(e) => {
                    error!("Unable to subscribe to silent payments: {e}");
                    return;
                }
            }

            while let Some(event) = self.client.events.next().await {
                let Event::Notification(notification) = event else {
                    continue;
                };

                match notification {
                    Notification::SpSubscribe(sp_subscribe_notification) => {
                        let histories = sp_subscribe_notification.history;
                        let progress = sp_subscribe_notification.progress;
                        let mut secrets_by_height: BTreeMap<u32, HashMap<Txid, PublicKey>> =
                            BTreeMap::new();

                        debug!("Received history {histories:#?}");
                        info!("Found a total of {} output(s)", histories.len());

                        for history in &histories {
                            if history.height == 0 {
                                debug!("Skipping mempool transaction {}", history.tx_hash);
                                continue;
                            }

                            secrets_by_height
                                .entry(history.height)
                                .or_default()
                                .insert(history.tx_hash, history.tweak_key);
                        }

                        for (height, tx_tweaks) in secrets_by_height {
                            let blk_header = match self.client.get_block_header(height).await {
                                Ok(header) => header,
                                Err(e) => {
                                    error!("Unable to fetch block header at height {height}: {e}");
                                    return;
                                }
                            };
                            let blkheight = match Height::from_consensus(height) {
                                Ok(height) => height,
                                Err(e) => {
                                    error!(
                                        "Invalid block height {height} received from Frigate: {e}"
                                    );
                                    return;
                                }
                            };

                            for (txid, tweak) in tx_tweaks {
                                let full_tx = match self.client.get_transaction(txid).await {
                                    Ok(full_tx) => full_tx,
                                    Err(e) => {
                                        warn!(
                                            "Skipping transaction {txid} after fetch failure: {e}"
                                        );
                                        continue;
                                    }
                                };
                                let discovered_outputs = match process_outputs(
                                    &full_tx.tx,
                                    &self.b_scan,
                                    &self.sp_receiver,
                                    &tweak,
                                ) {
                                    Ok(outputs) => outputs,
                                    Err(e) => {
                                        warn!("Skipping malformed transaction {txid}: {e}");
                                        continue;
                                    }
                                };

                                self.owned_outpoints.extend(discovered_outputs.keys());

                                if monitor_spent {
                                    subscribe_outputs(
                                        &mut self.client,
                                        &mut tracked_scripts,
                                        &discovered_outputs,
                                    )
                                    .await;
                                }

                                let scan_res = ScanResult {
                                    blkheight,
                                    blkhash: blk_header.header.block_hash(),
                                    discovered_inputs: HashSet::new(),
                                    discovered_outputs,
                                };

                                if let Some(sender) = scan_tx.as_mut() {
                                    if let Err(e) = sender.send(scan_res).await {
                                        error!(
                                            "Unable to send scan result: {e}; stopping scan output"
                                        );
                                        scan_tx = None;
                                        if !monitor_spent {
                                            return;
                                        }
                                    } else {
                                        info!("Scan result sent!");
                                    }
                                }
                            }
                        }

                        if progress >= 1.0f32 {
                            if !monitor_spent {
                                info!("Scan completed!");
                                break;
                            }

                            if scan_tx.take().is_some() {
                                info!("Scan completed, monitoring spent outputs");
                            }
                        }
                    }
                    Notification::ScriptHash(notification) if monitor_spent => {
                        let script_hash = notification.script_hash();
                        let spent = match confirmed_spent_outpoints(
                            &mut self.client,
                            script_hash,
                            &tracked_scripts,
                            &mut inspected_txids,
                        )
                        .await
                        {
                            Ok(spent) => spent,
                            Err(e) => {
                                error!(
                                    "Unable to inspect history for script hash {script_hash}: {e}"
                                );
                                continue;
                            }
                        };

                        if spent.is_empty() {
                            continue;
                        }

                        self.owned_outpoints
                            .retain(|outpoint| !spent.contains(outpoint));
                        for outpoints in tracked_scripts.values_mut() {
                            outpoints.retain(|outpoint| !spent.contains(outpoint));
                        }
                        tracked_scripts.retain(|_, outpoints| !outpoints.is_empty());

                        if let Err(e) = spent_tx.send(spent).await {
                            error!("Unable to send spent output update: {e}; stopping monitor");
                            return;
                        }
                    }
                    Notification::ScriptHash(_) => {
                        debug!("Ignoring script-hash notification after finite scan");
                    }
                    notification => {
                        debug!("Ignoring unsupported notification: {notification:?}");
                    }
                }
            }
        });

        (scan_rx, spent_rx)
    }
}

impl Scanner for FrigateScanner {
    fn scan_blocks(self, range: std::ops::RangeInclusive<Height>) -> Receiver<ScanResult> {
        let (scan_rx, spent_rx) = self.start_scan(range, false);
        drop(spent_rx);
        scan_rx
    }
}

async fn subscribe_outputs(
    client: &mut FrigateClient,
    tracked_scripts: &mut HashMap<ElectrumScriptHash, HashSet<OutPoint>>,
    discovered_outputs: &HashMap<OutPoint, DiscoveredOutput>,
) {
    for (outpoint, output) in discovered_outputs {
        let script_hash = ElectrumScriptHash::from(output.txout.script_pubkey.as_script());
        let first_output_for_script = !tracked_scripts.contains_key(&script_hash);
        tracked_scripts
            .entry(script_hash)
            .or_default()
            .insert(*outpoint);

        if !first_output_for_script {
            continue;
        }

        let request = request::ScriptHashSubscribe { script_hash };
        if let Err(e) = client.scripthash_subscribe(request).await {
            error!("Unable to subscribe to script hash {script_hash}: {e}");
        }
    }
}

async fn confirmed_spent_outpoints(
    client: &mut FrigateClient,
    script_hash: ElectrumScriptHash,
    tracked_scripts: &HashMap<ElectrumScriptHash, HashSet<OutPoint>>,
    inspected_txids: &mut HashMap<ElectrumScriptHash, HashSet<Txid>>,
) -> anyhow::Result<HashSet<OutPoint>> {
    let Some(owned_outpoints) = tracked_scripts.get(&script_hash) else {
        return Ok(HashSet::new());
    };

    let inspected_for_script = inspected_txids.entry(script_hash).or_default();
    let mut spent = HashSet::new();
    for history_entry in client.get_history(script_hash).await? {
        if history_entry.confirmation_height().is_none() {
            continue;
        }

        let txid = history_entry.txid();
        if inspected_for_script.contains(&txid) {
            continue;
        }

        let full_tx = client.get_transaction(txid).await?;
        for input in full_tx.tx.input {
            if owned_outpoints.contains(&input.previous_output) {
                spent.insert(input.previous_output);
            }
        }
        inspected_for_script.insert(txid);
    }

    Ok(spent)
}

fn process_outputs(
    tx: &Transaction,
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    tweak: &PublicKey,
) -> anyhow::Result<HashMap<OutPoint, DiscoveredOutput>> {
    let secret = calculate_ecdh_shared_secret(tweak, b_scan);
    let txid: Txid = tx.compute_txid();
    let outputs_to_check = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_idx, x)| x.script_pubkey.is_p2tr())
        .map(|(idx, txout)| {
            let output_key = XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
                .map_err(|e| anyhow::anyhow!("invalid Taproot output key at index {idx}: {e}"))?;
            let vout = u32::try_from(idx)
                .map_err(|e| anyhow::anyhow!("output index {idx} does not fit in u32: {e}"))?;
            Ok((vout, txout.value, output_key))
        })
        .collect::<anyhow::Result<Vec<(u32, bitcoin::Amount, XOnlyPublicKey)>>>()?;

    let output_keys: Vec<XOnlyPublicKey> = outputs_to_check
        .iter()
        .map(|(_, _, output_key)| *output_key)
        .collect();

    let ours = sp_receiver.scan_transaction(&secret, &output_keys)?;

    let mut res = HashMap::new();
    for (vout, value, output_key) in outputs_to_check {
        for (label, map) in &ours {
            if let Some(tweak) = map.get(&output_key) {
                let outpoint = OutPoint { txid, vout };
                let spk_bytes = generate_script_pubkey_from_output_key(output_key);
                let script_pubkey = ScriptBuf::from_bytes(spk_bytes.to_vec());

                res.insert(
                    outpoint,
                    DiscoveredOutput {
                        txout: TxOut {
                            value,
                            script_pubkey,
                        },
                        tweak: *tweak,
                        label: label.clone(),
                    },
                );
                break;
            }
        }
    }

    Ok(res)
}
