use std::{
    collections::{HashMap, HashSet},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use bitcoin::{absolute::Height, bip158::BlockFilter, secp256k1::PublicKey, Amount, OutPoint};
use log::info;

use crate::{
    backend::{BlockData, FilterData, SyncChainBackend},
    client::{OwnedOutput, SpClient},
    updater::Updater,
};

use super::logic;

pub struct SpScanner<'a> {
    updater: Box<dyn Updater + Sync + Send>,
    backend: Box<dyn SyncChainBackend + Sync + Send>,
    client: SpClient,
    keep_scanning: &'a AtomicBool,
    owned_outpoints: HashSet<OutPoint>,
}

impl<'a> SpScanner<'a> {
    pub fn new(
        client: SpClient,
        updater: Box<dyn Updater + Sync + Send>,
        backend: Box<dyn SyncChainBackend + Sync + Send>,
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

    pub fn scan_blocks(
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

        // get block data iterator
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_iter =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        // process blocks using block data iterator
        self.process_blocks(start, end, block_data_iter)?;

        // time elapsed for the scan
        info!(
            "Blindbit scan complete in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    fn process_blocks(
        &mut self,
        start: Height,
        end: Height,
        block_data_iter: impl Iterator<Item = Result<BlockData>>,
    ) -> Result<()> {
        let mut update_time: Instant = Instant::now();

        for blockdata in block_data_iter {
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

            let (found_outputs, found_inputs) = self.process_block(blockdata)?;

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

    fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)> {
        let BlockData {
            blkheight,
            tweaks,
            new_utxo_filter,
            spent_filter,
            ..
        } = blockdata;

        let outs = self.process_block_outputs(blkheight, tweaks, new_utxo_filter)?;

        // after processing outputs, we add the found outputs to our list
        self.owned_outpoints.extend(outs.keys());

        let ins = self.process_block_inputs(blkheight, spent_filter)?;

        // after processing inputs, we remove the found inputs
        self.owned_outpoints.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>> {
        if tweaks.is_empty() {
            return Ok(HashMap::new());
        }

        let secrets_map = self.client.get_script_to_secret_map(tweaks)?;
        let candidate_spks: Vec<&[u8; 34]> = secrets_map.keys().collect();

        let blkfilter = BlockFilter::new(&new_utxo_filter.data);
        let blkhash = new_utxo_filter.block_hash;

        if !logic::check_block_outputs(blkfilter, blkhash, candidate_spks)? {
            return Ok(HashMap::new());
        }

        info!("matched outputs on: {}", blkheight);
        let utxos = self.backend.utxos(blkheight)?;
        let found = logic::find_owned_in_utxos(&self.client.sp_receiver, utxos, &secrets_map)?;

        Ok(logic::collect_found_outputs(blkheight, found))
    }

    fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>> {
        let blkhash = spent_filter.block_hash;

        let input_hashes_map = logic::get_input_hashes(&self.owned_outpoints, blkhash)?;

        let blkfilter = BlockFilter::new(&spent_filter.data);
        let matched_inputs = logic::check_block_inputs(
            blkfilter,
            blkhash,
            input_hashes_map.keys().cloned().collect(),
        )?;

        if !matched_inputs {
            return Ok(HashSet::new());
        }

        info!("matched inputs on: {}", blkheight);
        let spent = self.backend.spent_index(blkheight)?.data;

        Ok(logic::collect_spent_outpoints(spent, &input_hashes_map))
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
