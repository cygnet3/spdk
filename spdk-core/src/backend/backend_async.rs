use std::ops::RangeInclusive;
use std::pin::Pin;

use anyhow::Result;
use bitcoin::{absolute::Height, Amount};
use futures::Stream;

use crate::{BlockData, SpentIndexData, UtxoData};

/// Async stream type for block data that conditionally includes `Send` bound.
///
/// - For native targets: includes `Send` bound for thread safety
/// - For WASM targets: omits `Send` since WASM is single-threaded
// For native targets, we require Send
#[cfg(not(target_arch = "wasm32"))]
pub type BlockDataStream = Pin<Box<dyn Stream<Item = Result<BlockData>> + Send>>;

// For WASM targets, we don't require Send
#[cfg(target_arch = "wasm32")]
pub type BlockDataStream = Pin<Box<dyn Stream<Item = Result<BlockData>>>>;

/// Async version of ChainBackend for non-blocking I/O operations
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AsyncChainBackend: Send + Sync {
    /// Get a stream of block data for a range of blocks
    ///
    /// # Arguments
    /// * `range` - Range of block heights to fetch
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    ///
    /// # Returns
    /// * Stream of block data results
    fn get_block_data_stream(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> BlockDataStream;

    /// Get spent index data for a specific block height
    ///
    /// # Arguments
    /// * `block_height` - Block height to query
    ///
    /// # Returns
    /// * Spent index data for the block
    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData>;

    /// Get UTXOs for a specific block height
    ///
    /// # Arguments
    /// * `block_height` - Block height to query
    ///
    /// # Returns
    /// * Vector of UTXO data
    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>>;

    /// Get the current blockchain tip height
    ///
    /// # Returns
    /// * Current block height
    async fn block_height(&self) -> Result<Height>;
}
