use std::collections::{HashMap, HashSet};

use anyhow::Result;
use bitcoin::absolute::Height;
use bitcoin::{BlockHash, OutPoint};

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
