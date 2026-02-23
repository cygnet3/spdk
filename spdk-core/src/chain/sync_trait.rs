use std::ops::RangeInclusive;

use anyhow::Result;
use bitcoin::{absolute::Height, Amount};

use super::structs::{BlockData, SpentIndexData, UtxoData};

pub trait SyncChainBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Box<dyn Iterator<Item = Result<BlockData>> + Send>;

    fn spent_index(&self, block_height: Height) -> Result<SpentIndexData>;

    fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>>;

    fn block_height(&self) -> Result<Height>;
}
