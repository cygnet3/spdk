use std::ops::RangeInclusive;

use anyhow::Result;
use bitcoin::{absolute::Height, Amount};

use crate::{BlockData, SpentIndexData, UtxoData};

/// Iterator type for block data that conditionally includes `Send` bound.
///
/// - For native targets: includes `Send` bound for thread safety
/// - For WASM targets: omits `Send` since WASM is single-threaded
// For native targets, we require Send
#[cfg(not(target_arch = "wasm32"))]
pub type BlockDataIterator = Box<dyn Iterator<Item = Result<BlockData>> + Send>;

// For WASM targets, we don't require Send
#[cfg(target_arch = "wasm32")]
pub type BlockDataIterator = Box<dyn Iterator<Item = Result<BlockData>>>;

pub trait ChainBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> BlockDataIterator;

    fn spent_index(&self, block_height: Height) -> Result<SpentIndexData>;

    fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>>;

    fn block_height(&self) -> Result<Height>;
}
