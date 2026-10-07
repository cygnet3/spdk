use std::collections::{HashMap, HashSet};

use bitcoin::absolute::Height;
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use electrum_streaming_client::notification::Notification;
use electrum_streaming_client::{Event, request};
use futures::channel::mpsc::{Receiver, channel};
use futures::{SinkExt as _, StreamExt as _};
use log::{debug, error, info};
use silentpayments::SharedSecret;
use silentpayments::receiving::{Label, Receiver as SpReceiver};
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, generate_script_pubkey_from_output_key,
};
use spdk_core::chain::UtxoData;
use spdk_core::scanner::{DiscoveredOutput, ScanResult, Scanner};

use crate::client::FrigateClient;

pub struct FrigateScanner {
    client: FrigateClient,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    labels: Option<Vec<u32>>,
}

impl FrigateScanner {
    pub const fn new(
        client: FrigateClient,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        labels: Option<Vec<u32>>,
    ) -> Self {
        Self {
            client,
            b_scan,
            sp_receiver,
            labels,
        }
    }
}

impl Scanner for FrigateScanner {
    fn scan_blocks(mut self, range: std::ops::RangeInclusive<Height>) -> Receiver<ScanResult> {
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

        let (mut tx, rx) = channel(100_000);

        tokio::spawn(async move {
            // Maybe later check if there's any current subscription and skip, just listen to
            // events.
            if let Ok(sp_address) = self.client.subscribe(subscribe_params).await {
                info!("Subscribed to silent payments address {sp_address}");
            } else {
                log::error!("Unable to subscribe");
            }

            while let Some(event) = self.client.events.next().await {
                if let Event::Notification(notification) = event {
                    match notification {
                        Notification::SpSubscribe(sp_subscribe_notification) => {
                            let histories = sp_subscribe_notification.history.clone();
                            let progress = sp_subscribe_notification.progress;

                            let mut secrets_by_height: HashMap<u32, HashMap<Txid, PublicKey>> =
                                HashMap::new();

                            debug!("Received history {histories:#?}");
                            info!("Found a total of {} output(s)", histories.len());

                            for h in &histories {
                                secrets_by_height
                                    .entry(h.height)
                                    .and_modify(|v| {
                                        v.insert(h.tx_hash, h.tweak_key);
                                    })
                                    .or_insert(HashMap::from([(h.tx_hash, h.tweak_key)]));
                            }

                            for history in secrets_by_height {
                                let blk_header =
                                    self.client.get_block_header(history.0).await.unwrap();

                                // Get now the outputs from the transaction belonging to the key
                                // we're scanning for.
                                // Once done just return the scan result

                                for tx_tweak in history.1 {
                                    let discovered_inputs = HashSet::<OutPoint>::new();
                                    let full_tx =
                                        self.client.get_transaction(tx_tweak.0).await.unwrap();
                                    let discovered_outputs = process_ouputs(
                                        &full_tx.tx,
                                        &self.b_scan,
                                        &self.sp_receiver,
                                        &[tx_tweak.1],
                                    )
                                    .unwrap();

                                    let scan_res = ScanResult {
                                        blkheight: Height::from_consensus(history.0).unwrap(),
                                        blkhash: blk_header.header.block_hash(),
                                        discovered_inputs,
                                        discovered_outputs,
                                    };

                                    match tx.send(scan_res).await {
                                        Ok(()) => info!("Scan result sent!"),
                                        Err(e) => log::error!("Unable to send scan result: {e}"),
                                    }
                                }
                            }

                            if progress >= 1.0f32 {
                                info!("Scanning completed!");
                                break;
                            }
                        }
                        _ => error!("Notification event not supported."),
                    }
                }
            }
        });

        rx
    }
}

fn process_ouputs(
    tx: &Transaction,
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    tweaks: &[PublicKey],
) -> anyhow::Result<HashMap<OutPoint, DiscoveredOutput>> {
    let secret_map = output_key_to_secret_map(b_scan, sp_receiver, tweaks.to_owned())?;
    let txid: Txid = tx.compute_txid();
    let outputs_to_check = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_idx, x)| x.script_pubkey.is_p2tr())
        .map(|(idx, txout)| {
            let output_key =
                XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..]).unwrap();
            UtxoData {
                txid,
                vout: u32::try_from(idx).unwrap(),
                value: txout.value,
                output_key,
                spent: false,
            }
        })
        .collect::<Vec<UtxoData>>();

    let output_keys: Vec<XOnlyPublicKey> = outputs_to_check
        .iter()
        .map(|utxo| utxo.output_key)
        .collect();

    let mut scan_res: Vec<(Option<Label>, UtxoData, Scalar)> = vec![];
    let secret = secret_map.into_values().last().unwrap();

    let ours = sp_receiver.scan_transaction(&secret, &output_keys)?;

    for utxo in outputs_to_check {
        if utxo.spent {
            continue;
        }

        for (label, map) in &ours {
            if let Some(scalar) = map.get(&utxo.output_key) {
                scan_res.push((label.clone(), utxo, *scalar));
                break;
            }
        }
    }

    let mut res = HashMap::new();
    for (label, utxo, tweak) in scan_res {
        let outpoint = OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        };

        let spk_bytes = generate_script_pubkey_from_output_key(utxo.output_key);
        let script_pubkey = ScriptBuf::from_bytes(spk_bytes.to_vec());

        let out = DiscoveredOutput {
            txout: TxOut {
                value: utxo.value,
                script_pubkey,
            },
            tweak,
            label,
        };

        res.insert(outpoint, out);
    }

    Ok(res)
}

// This is similar to the same function inside local scanner, may need to make it common
pub fn output_key_to_secret_map(
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    tweak_data_vec: Vec<PublicKey>,
) -> anyhow::Result<HashMap<XOnlyPublicKey, SharedSecret>> {
    let tweak_data_iterator = tweak_data_vec.into_iter();

    let items: anyhow::Result<Vec<_>> = tweak_data_iterator
        .map(|tweak| {
            let secret = calculate_ecdh_shared_secret(&tweak, b_scan);
            let output_keys = sp_receiver.generate_output_keys_from_shared_secret(&secret)?;

            Ok((secret, output_keys.into_values()))
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
