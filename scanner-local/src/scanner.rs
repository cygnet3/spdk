use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use anyhow::Result;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::{PublicKey, Scalar, SecretKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey};
use futures::channel::mpsc::{Receiver, Sender, channel};
use futures::{SinkExt as _, Stream, StreamExt as _, pin_mut};
use log::{info, warn};
use silentpayments::SharedSecret;
use silentpayments::receiving::{Label, Receiver as SpReceiver};
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, generate_script_pubkey_from_output_key,
};
use spdk_core::chain::{BoxedBlockData, BoxedChainBackend, UtxoData};
use spdk_core::scanner::{DiscoveredOutput, ScanResult, Scanner};
use tokio::task;

const BUFFER_SIZE: usize = 1000;

pub struct SpScanner {
    backend: BoxedChainBackend,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    owned_outpoints: HashSet<OutPoint>, // used to scan block inputs
    dust_limit: Amount,
    with_cutthrough: bool,
    keep_scanning: &'static AtomicBool,
}

impl SpScanner {
    pub fn new(
        backend: BoxedChainBackend,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        owned_outpoints: HashSet<OutPoint>,
        dust_limit: Amount,
        with_cutthrough: bool,
        keep_scanning: &'static AtomicBool,
    ) -> Self {
        Self {
            backend,
            b_scan,
            sp_receiver,
            owned_outpoints,
            dust_limit,
            with_cutthrough,
            keep_scanning,
        }
    }
}

impl Scanner for SpScanner {
    fn scan_blocks(self, range: RangeInclusive<Height>) -> Receiver<ScanResult> {
        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        );
        let start_time: Instant = Instant::now();

        let (tx, rx) = channel(BUFFER_SIZE);

        let dust_limit = self.dust_limit;
        let with_cutthrough = self.with_cutthrough;
        let b_scan = self.b_scan;
        let sp_receiver = self.sp_receiver;

        // get block data stream
        let block_data_stream =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        let backend = self.backend;
        let owned_outpoints = self.owned_outpoints;

        let keep_scanning = self.keep_scanning;

        task::spawn(async move {
            match process_block_data_stream(
                block_data_stream,
                backend,
                tx,
                b_scan,
                sp_receiver,
                owned_outpoints,
                keep_scanning,
            )
            .await
            {
                Ok(()) => info!(
                    "Blindbit scan complete in {} seconds",
                    start_time.elapsed().as_secs()
                ),
                Err(e) => warn!("Scan ended prematurely: {e}"),
            }
        });

        rx
    }
}

async fn process_block_data_stream(
    block_data_stream: impl Stream<Item = Result<BoxedBlockData>>,
    backend: BoxedChainBackend,
    mut tx: Sender<ScanResult>,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    mut owned_outpoints: HashSet<OutPoint>,
    keep_scanning: &AtomicBool,
) -> Result<()> {
    pin_mut!(block_data_stream);

    let mut tweak_count = 0;
    let mut block_count = 0;

    while let Some(blockdata) = block_data_stream.next().await {
        // if interrupt requested: stop scanning and return
        if !keep_scanning.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        let blockdata = blockdata?;
        let blkhash = blockdata.blkhash();
        let blkheight = blockdata.blkheight();

        tweak_count += blockdata.tweaks().len();
        block_count += 1;

        let (discovered_outputs, discovered_inputs) = process_block(
            &blockdata,
            &backend,
            &b_scan,
            &sp_receiver,
            &mut owned_outpoints,
        )
        .await?;

        tx.send(ScanResult {
            blkheight,
            blkhash,
            discovered_inputs,
            discovered_outputs,
        })
        .await?;
    }

    info!("Total number of tweaks processed: {tweak_count}");
    info!("Total number of blocks processed: {block_count}");

    Ok(())
}

async fn process_block(
    blockdata: &BoxedBlockData,
    backend: &BoxedChainBackend,
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    owned_outpoints: &mut HashSet<OutPoint>,
) -> Result<(HashMap<OutPoint, DiscoveredOutput>, HashSet<OutPoint>)> {
    let outs = process_block_outputs(blockdata, backend, b_scan, sp_receiver).await?;

    // after processing outputs, we add the found outputs to our list
    owned_outpoints.extend(outs.keys());

    let ins = process_block_inputs(backend, blockdata, owned_outpoints).await?;

    // after processing inputs, we remove the found inputs
    owned_outpoints.retain(|item| !ins.contains(item));

    Ok((outs, ins))
}

async fn process_block_outputs(
    blockdata: &BoxedBlockData,
    backend: &BoxedChainBackend,
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
) -> Result<HashMap<OutPoint, DiscoveredOutput>> {
    let mut res = HashMap::new();

    let tweaks = blockdata.tweaks();

    if !tweaks.is_empty() {
        let secrets_map = output_key_to_secret_map(b_scan, sp_receiver, tweaks)?;

        let candidate_keys: Vec<XOnlyPublicKey> = secrets_map.keys().copied().collect();

        let matched_outputs = blockdata.check_match_outputs(candidate_keys)?;

        //if match: fetch and scan utxos
        if matched_outputs {
            info!("matched outputs on: {}", blockdata.blkheight());
            let found =
                scan_utxos(backend, blockdata.blkheight(), secrets_map, sp_receiver).await?;

            if !found.is_empty() {
                for (label, utxo, tweak) in found {
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
            }
        }
    }
    Ok(res)
}

async fn process_block_inputs(
    backend: &BoxedChainBackend,
    blockdata: &BoxedBlockData,
    owned_outpoints: &HashSet<OutPoint>,
) -> Result<HashSet<OutPoint>> {
    let match_on_inputs = blockdata.check_match_inputs(owned_outpoints)?;

    if match_on_inputs {
        // if match: return the set of all outpoints that have been spent this block
        info!("matched inputs on: {}", blockdata.blkheight());
        backend
            .detect_spent_outpoints(
                blockdata.blkheight(),
                blockdata.blkhash(),
                owned_outpoints.clone(),
            )
            .await
    } else {
        // no match: return an empty set
        Ok(HashSet::new())
    }
}

async fn scan_utxos(
    backend: &BoxedChainBackend,
    blkheight: Height,
    secrets_map: HashMap<XOnlyPublicKey, SharedSecret>,
    sp_receiver: &SpReceiver,
) -> Result<Vec<(Option<Label>, UtxoData, Scalar)>> {
    let utxos = backend.utxos(blkheight).await?;

    let mut res: Vec<(Option<Label>, UtxoData, Scalar)> = vec![];

    // group utxos by the txid
    let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
    for utxo in utxos {
        txmap.entry(utxo.txid).or_default().push(utxo);
    }

    for utxos in txmap.into_values() {
        // check if we know the secret to any of the spks
        let mut secret = None;
        for utxo in &utxos {
            if let Some(s) = secrets_map.get(&utxo.output_key) {
                secret = Some(s);
                break;
            }
        }

        // skip this tx if no secret is found
        let Some(secret) = secret else { continue };

        let output_keys: Vec<XOnlyPublicKey> = utxos.iter().map(|utxo| utxo.output_key).collect();

        let ours = sp_receiver.scan_transaction(secret, &output_keys)?;

        for utxo in utxos {
            if utxo.spent {
                continue;
            }

            for (label, map) in &ours {
                if let Some(scalar) = map.get(&utxo.output_key) {
                    res.push((label.clone(), utxo, *scalar));
                    break;
                }
            }
        }
    }

    Ok(res)
}

pub fn output_key_to_secret_map(
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    tweak_data_vec: Vec<PublicKey>,
) -> Result<HashMap<XOnlyPublicKey, SharedSecret>> {
    // if using rayon feature, import the preludes
    #[cfg(feature = "rayon")]
    use rayon::prelude::*;

    // parallel iterator using rayon
    #[cfg(feature = "rayon")]
    let tweak_data_iterator = tweak_data_vec.into_par_iter();

    // regular iterator
    #[cfg(not(feature = "rayon"))]
    let tweak_data_iterator = tweak_data_vec.into_iter();

    let items: Result<Vec<_>> = tweak_data_iterator
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
