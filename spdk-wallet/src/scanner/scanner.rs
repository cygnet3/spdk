use std::{
    collections::{HashMap, HashSet},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use bitcoin::{
    Amount, OutPoint,
    absolute::Height,
    bip158::BlockFilter,
    secp256k1::PublicKey,
};
use futures::{Stream, StreamExt, pin_mut};
use log::info;

use spdk_core::chain::{BlockData, ChainBackend, FilterData};
use spdk_core::updater::{SimplifiedOutput, Updater};

use crate::{client::SpClient, scanner::logic::{check_block_inputs, check_block_outputs, find_owned_in_utxos, get_input_hashes}};

pub struct SpScanner<'a> {
    updater: Box<dyn Updater + Sync + Send>,
    backend: Box<dyn ChainBackend + Sync + Send>,
    client: SpClient,
    keep_scanning: &'a AtomicBool,      // used to interrupt scanning
    owned_outpoints: HashSet<OutPoint>, // used to scan block inputs
}

impl<'a> SpScanner<'a> {
    pub fn new(
        client: SpClient,
        updater: Box<dyn Updater + Sync + Send>,
        backend: Box<dyn ChainBackend + Sync + Send>,
        owned_outpoints: HashSet<OutPoint>,
        keep_scanning: &'a AtomicBool,
    ) -> Self {
        Self {
            client,
            updater,
            backend,
            owned_outpoints,
            keep_scanning,
        }
    }

    pub async fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        if start > end {
            bail!("bigger start than end: {} > {}", start, end);
        }

        info!("start: {} end: {}", start, end);
        let start_time: Instant = Instant::now();

        // get block data stream
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_stream =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        // process blocks using block data stream
        self.process_blocks(start, end, block_data_stream).await?;

        // time elapsed for the scan
        info!(
            "Blindbit scan complete in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    async fn process_blocks(
        &mut self,
        start: Height,
        end: Height,
        block_data_stream: impl Stream<Item = Result<BlockData>>,
    ) -> Result<()> {
        pin_mut!(block_data_stream);

        let mut update_time: Instant = Instant::now();

        while let Some(blockdata) = block_data_stream.next().await {
            let blockdata = blockdata?;
            let blkheight = blockdata.blkheight;
            let blkhash = blockdata.blkhash;

            // stop scanning and return if interrupted
            if self.interrupt_requested() {
                self.updater.save_to_persistent_storage()?;
                return Ok(());
            }

            let mut save_to_storage = false;

            // always save on last block or after 30 seconds since last save
            if blkheight == end || update_time.elapsed() > Duration::from_secs(30) {
                save_to_storage = true;
            }

            let (found_outputs, found_inputs) = self.process_block(blockdata).await?;

            if !found_outputs.is_empty() {
                save_to_storage = true;
                self.updater
                    .record_block_outputs(blkheight, blkhash, found_outputs)?;
            }

            if !found_inputs.is_empty() {
                save_to_storage = true;
                self.updater
                    .record_block_inputs(blkheight, blkhash, found_inputs)?;
            }

            // tell the updater we scanned this block
            self.updater.record_scan_progress(start, blkheight, end)?;

            if save_to_storage {
                self.updater.save_to_persistent_storage()?;
                update_time = Instant::now();
            }
        }

        Ok(())
    }

    async fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, SimplifiedOutput>, HashSet<OutPoint>)> {
        let BlockData {
            blkheight,
            tweaks,
            new_utxo_filter,
            spent_filter,
            ..
        } = blockdata;

        let outs = self
            .process_block_outputs(blkheight, tweaks, new_utxo_filter)
            .await?;

        // after processing outputs, we add the found outputs to our list
        self.owned_outpoints.extend(outs.keys());

        let ins = self.process_block_inputs(blkheight, spent_filter).await?;

        // after processing inputs, we remove the found inputs
        self.owned_outpoints.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    async fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, SimplifiedOutput>> {
        let mut res = HashMap::new();

        if !tweaks.is_empty() {
            let secrets_map = self.client.get_script_to_secret_map(tweaks)?;

            //last_scan = last_scan.max(n as u32);
            let candidate_spks: Vec<&[u8; 34]> = secrets_map.keys().collect();

            //get block gcs & check match
            let blkfilter = BlockFilter::new(&new_utxo_filter.data);
            let blkhash = new_utxo_filter.block_hash;

            let matched_outputs = check_block_outputs(blkfilter, blkhash, candidate_spks)?;

            //if match: fetch and scan utxos
            if matched_outputs {
                info!("matched outputs on: {}", blkheight);
                let utxos = self.backend.utxos(blkheight).await?;
                let found = find_owned_in_utxos(&self.client.sp_receiver, utxos, &secrets_map)?;

                if !found.is_empty() {
                    for (label, utxo, tweak) in found {
                        let outpoint = OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        };

                        let out = SimplifiedOutput {
                            tweak,
                            value: utxo.value,
                            script_pubkey: utxo.scriptpubkey,
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
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>> {
        let mut res = HashSet::new();

        let blkhash = spent_filter.block_hash;

        // first get the 8-byte hashes used to construct the input filter
        let input_hashes_map = get_input_hashes(&self.owned_outpoints, blkhash)?;

        // check against filter
        let blkfilter = BlockFilter::new(&spent_filter.data);
        let matched_inputs = check_block_inputs(
            blkfilter,
            blkhash,
            input_hashes_map.keys().cloned().collect(),
        )?;

        // if match: download spent data, collect the outpoints that are spent
        if matched_inputs {
            info!("matched inputs on: {}", blkheight);
            let spent = self.backend.spent_index(blkheight).await?.data;

            for spent in spent {
                let hex: &[u8] = spent.as_ref();

                if let Some(outpoint) = input_hashes_map.get(hex) {
                    res.insert(*outpoint);
                }
            }
        }
        Ok(res)
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
