use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use bitcoin::{BlockHash, OutPoint, absolute::Height};

use spdk_core::updater::{DiscoveredOutput, Updater};

pub struct UpdateResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

#[derive(Clone, Default)]
pub struct MockUpdater {
    pub updates: Arc<Mutex<Vec<UpdateResult>>>,
}

impl Updater for MockUpdater {
    fn record_block_scan_result(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        discovered_inputs: HashSet<OutPoint>,
        discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
    ) -> Result<()> {
        self.updates.lock().unwrap().push(UpdateResult {
            blkheight,
            blkhash,
            discovered_inputs,
            discovered_outputs,
        });

        Ok(())
    }
}
