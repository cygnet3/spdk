use std::collections::{HashMap, HashSet};

use bitcoin::{absolute::Height, BlockHash, OutPoint};

use anyhow::Result;

use super::DiscoveredOutput;

pub trait Updater {
    fn record_block_scan_result(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        discovered_inputs: HashSet<OutPoint>,
        discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
    ) -> Result<()>;
}
