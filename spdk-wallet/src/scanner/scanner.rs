use std::{
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    sync::atomic::AtomicBool,
    time::Instant,
};

use anyhow::{Error, Result};
use backend_blindbit_v2::{
    BlindbitClient,
    structs::{BlockScanData, ComputeIndexTxItem, ShortenedXOnlyPubkey},
};
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Txid, XOnlyPublicKey,
    absolute::Height,
    bip158::BlockFilter,
    hashes::{Hash, sha256},
    secp256k1::{PublicKey, Scalar},
};
use futures::{Stream, StreamExt, pin_mut};
use log::info;
use silentpayments::{SharedSecret, receiving::Label};

use spdk_core::chain::{BlockData, ChainBackend, FilterData, UtxoData};
use spdk_core::updater::{DiscoveredOutput, Updater};

use crate::client::SpClient;

pub struct SpScanner<'a> {
    updater: Box<dyn Updater + Sync + Send>,
    backend: Box<dyn ChainBackend + Sync + Send>,
    blindbit_v2: BlindbitClient,
    client: SpClient,
    keep_scanning: &'a AtomicBool,     // used to interrupt scanning
    owned_scripts: HashSet<ScriptBuf>, // used to scan block inputs
}

impl<'a> SpScanner<'a> {
    pub fn new(
        client: SpClient,
        updater: Box<dyn Updater + Sync + Send>,
        backend: Box<dyn ChainBackend + Sync + Send>,
        owned_scripts: HashSet<ScriptBuf>,
        keep_scanning: &'a AtomicBool,
        blindbit_v2: BlindbitClient,
    ) -> Self {
        Self {
            client,
            updater,
            backend,
            owned_scripts,
            keep_scanning,
            blindbit_v2,
        }
    }

    pub async fn scan_blocks(
        &mut self,
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        );
        let start_time: Instant = Instant::now();

        // get block data stream
        let block_data_stream = self
            .blindbit_v2
            .get_block_data_for_range(range, dust_limit, with_cutthrough)
            .await;

        // process blocks using block data stream
        self.process_blocks(block_data_stream).await?;

        // time elapsed for the scan
        info!(
            "Blindbit scan complete in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    async fn process_blocks(
        &mut self,
        block_data_stream: impl Stream<Item = Result<BlockScanData>>,
    ) -> Result<()> {
        pin_mut!(block_data_stream);

        let mut tweak_count = 0;

        while let Some(blockdata) = block_data_stream.next().await {
            // stop scanning and return if interrupted
            if self.interrupt_requested() {
                break;
            }

            let blockdata = blockdata?;
            let blkhash = blockdata.block_identifier.block_hash;
            let blkheight = blockdata.block_identifier.block_height;

            tweak_count += blockdata.comp_index.len();

            let (discovered_outputs, discovered_inputs) = self.process_block(blockdata).await?;

            self.updater.record_block_scan_result(
                blkheight,
                blkhash,
                discovered_inputs,
                discovered_outputs,
            )?;
        }

        info!("Total number of tweaks processed: {tweak_count}");

        Ok(())
    }

    async fn process_block(
        &mut self,
        blockdata: BlockScanData,
    ) -> Result<(HashMap<OutPoint, DiscoveredOutput>, HashSet<OutPoint>)> {
        let BlockScanData {
            block_identifier,
            comp_index,
            spent_outputs: spent_spks,
        } = blockdata;

        let outs = self
            .process_block_outputs(block_identifier.block_height, comp_index)
            .await?;

        if !outs.is_empty() {
            info!("outs: {:?}", outs);
        }

        // after processing outputs, we add the found outputs to our list
        self.owned_scripts
            .extend(outs.values().map(|x| x.script_pubkey.clone()));

        let ins = self.process_block_inputs(spent_spks).await?;

        if !ins.is_empty() {
            info!("ins: {:?}", outs);
        }

        let ins = HashSet::new();

        // todo: instead of working with outpoints, we now need to work with spk's
        // after processing inputs, we remove the found inputs
        // self.owned_scripts.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    async fn process_block_outputs(
        &self,
        blkheight: Height,
        comp_index: Vec<ComputeIndexTxItem>,
    ) -> Result<HashMap<OutPoint, DiscoveredOutput>> {
        let mut res = HashMap::new();

        let matches = self.client.get_matches(comp_index);

        if !matches.is_empty() {
            info!("Found matches: {:?}", matches);
            let tweaks = matches.iter().map(|(_, t)| *t).collect();
            // note: doing some duplicate work here, can be made more efficient
            let secrets_map = self.client.get_script_to_secret_map(tweaks)?;
            let found = self.scan_utxos(blkheight, secrets_map).await?;

            if !found.is_empty() {
                for (label, utxo, tweak) in found {
                    let outpoint = OutPoint {
                        txid: utxo.txid,
                        vout: utxo.vout,
                    };

                    let out = DiscoveredOutput {
                        tweak,
                        value: utxo.value,
                        script_pubkey: utxo.scriptpubkey,
                        label,
                    };

                    res.insert(outpoint, out);
                }
            }
        }

        Ok(res)
    }

    async fn process_block_inputs(
        &self,
        spent_spks: Vec<ShortenedXOnlyPubkey>,
    ) -> Result<HashSet<ScriptBuf>> {
        let mut res = HashSet::new();

        for owned_scripts in &self.owned_scripts {
            if spent_spks.iter().any(|x| x.matches_script(owned_scripts)) {
                // mark this script has having been spent
                res.insert(owned_scripts.clone());
            }
        }

        Ok(res)
    }

    async fn scan_utxos(
        &self,
        blkheight: Height,
        secrets_map: HashMap<[u8; 34], SharedSecret>,
    ) -> Result<Vec<(Option<Label>, UtxoData, Scalar)>> {
        let utxos = self.backend.utxos(blkheight).await?;

        let mut res: Vec<(Option<Label>, UtxoData, Scalar)> = vec![];

        // group utxos by the txid
        let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
        for utxo in utxos {
            txmap.entry(utxo.txid).or_default().push(utxo);
        }

        for utxos in txmap.into_values() {
            // check if we know the secret to any of the spks
            let mut secret = None;
            for utxo in utxos.iter() {
                let spk = utxo.scriptpubkey.as_bytes();
                if let Some(s) = secrets_map.get(spk) {
                    secret = Some(s);
                    break;
                }
            }

            // skip this tx if no secret is found
            let secret = match secret {
                Some(secret) => secret,
                None => continue,
            };

            let output_keys: Result<Vec<XOnlyPublicKey>> = utxos
                .iter()
                .filter_map(|x| {
                    if x.scriptpubkey.is_p2tr() {
                        Some(
                            XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..])
                                .map_err(Error::new),
                        )
                    } else {
                        None
                    }
                })
                .collect();

            let ours = self
                .client
                .sp_receiver
                .scan_transaction(secret, &output_keys?)?;

            for utxo in utxos {
                if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                    continue;
                }

                match XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]) {
                    Ok(xonly) => {
                        for (label, map) in ours.iter() {
                            if let Some(scalar) = map.get(&xonly) {
                                res.push((label.clone(), utxo, *scalar));
                                break;
                            }
                        }
                    }
                    Err(_) => todo!(),
                }
            }
        }

        Ok(res)
    }

    // Check if this block contains relevant transactions
    fn check_block_outputs(
        created_utxo_filter: BlockFilter,
        blkhash: BlockHash,
        candidate_spks: Vec<&[u8; 34]>,
    ) -> Result<bool> {
        // check output scripts
        let output_keys: Vec<_> = candidate_spks
            .into_iter()
            .map(|spk| spk[2..].as_ref())
            .collect();

        // note: match will always return true for an empty query!
        if !output_keys.is_empty() {
            Ok(created_utxo_filter.match_any(&blkhash, &mut output_keys.into_iter())?)
        } else {
            Ok(false)
        }
    }

    // Check if this block contains relevant transactions
    fn check_block_inputs(
        &self,
        spent_filter: BlockFilter,
        blkhash: BlockHash,
        input_hashes: Vec<[u8; 8]>,
    ) -> Result<bool> {
        // note: match will always return true for an empty query!
        if !input_hashes.is_empty() {
            Ok(spent_filter.match_any(&blkhash, &mut input_hashes.into_iter())?)
        } else {
            Ok(false)
        }
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
