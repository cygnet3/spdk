use std::collections::{HashMap, HashSet};

use bitcoin::{OutPoint, Txid, absolute::Height, secp256k1::{PublicKey, SecretKey}};
use electrum_streaming_client::{Event, notification::Notification, request, response::TxTweak};
use futures::{SinkExt as _, StreamExt as _, channel::mpsc::{Receiver, channel}};
use log::{debug, info};
use spdk_core::scanner::{DiscoveredOutput, ScanResult, Scanner};
use silentpayments::receiving::Receiver as SpReceiver;

use crate::client::FrigateClient;

pub struct FrigateScanner {
    client: FrigateClient,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    labels: Option<Vec<u32>>
}

impl FrigateScanner {
    pub const fn new(
        client: FrigateClient,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        labels: Option<Vec<u32>>
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
            labels: self.labels
        };

        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        ); 

        let (mut tx, rx) = channel(100_000);

        tokio::spawn( async move {
            
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

                            let mut secrets_by_height: HashMap<u32, HashMap<Txid, PublicKey>> = HashMap::new();

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
                                let discovered_inputs = HashSet::<OutPoint>::new();
                                let discovered_outputs = HashMap::<OutPoint, DiscoveredOutput>::new();
                            
                                let blk_header = self.client.get_block_header(history.0).await.unwrap();
                                
                                let scan_res = ScanResult {
                                    blkheight: Height::from_consensus(history.0).unwrap(),
                                    blkhash: blk_header.header.block_hash(),
                                    discovered_inputs,
                                    discovered_outputs,
                                };

                                match tx.send(scan_res).await {
                                    Ok(()) => info!("Scan result sent!"),
                                    Err(e) => log::error!("Unable to send scan result: {e}")
                                }
                            }

                            if progress >= 1.0f32 {
                                info!("Scanning completed!");
                                break;
                            }

                            subscribe_to_owned_outpouts(&self.client, histories).await;
                        }
                        Notification::ScriptHash(_script_hash_notification) => todo!(),
                        _ => info!("Notification event not supported.")
                    }
                }
            }
        });

        rx
    }
}

async fn subscribe_to_owned_outpouts(_client: &FrigateClient, _tx_hash: Vec<TxTweak>) {}


