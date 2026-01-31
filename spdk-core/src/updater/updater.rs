use std::collections::{HashMap, HashSet};

use bitcoin::{absolute::Height, BlockHash, OutPoint};

use crate::error::Result;

use crate::OwnedOutput;

/// Trait for persisting scan results and progress
///
/// This trait provides synchronous methods for recording scanning progress,
/// found outputs, and spent inputs. Implementations should handle persistence
/// to storage (database, file system, etc.).
///
/// For async operations, see `AsyncUpdater`.
pub trait Updater {
    /// Ask the updater to record the scanning progress.
    fn record_scan_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()>;

    /// Ask the updater to record the outputs found in a block.
    fn record_block_outputs(
        &mut self,
        height: Height,
        blkhash: BlockHash,
        found_outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()>;

    /// Ask the updater to record the inputs found in a block.
    fn record_block_inputs(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        found_inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    /// Ask the updater to save all recorded changes to persistent storage.
    fn save_to_persistent_storage(&mut self) -> Result<()>;
}

/// Async version of Updater for non-blocking I/O operations
/// Available by default, excluded when "sync" feature is enabled
#[cfg(feature = "async")]
#[async_trait::async_trait]
pub trait AsyncUpdater: Send + Sync {
    /// Ask the updater to record the scanning progress.
    ///
    /// # Arguments
    /// * `start` - Starting block height
    /// * `current` - Current block height being processed
    /// * `end` - Ending block height
    async fn record_scan_progress(
        &mut self,
        start: Height,
        current: Height,
        end: Height,
    ) -> Result<()>;

    /// Ask the updater to record the outputs found in a block.
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `blkhash` - Block hash
    /// * `found_outputs` - Map of found outputs
    async fn record_block_outputs(
        &mut self,
        height: Height,
        blkhash: BlockHash,
        found_outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()>;

    /// Ask the updater to record the inputs found in a block.
    ///
    /// # Arguments
    /// * `blkheight` - Block height
    /// * `blkhash` - Block hash
    /// * `found_inputs` - Set of spent inputs
    async fn record_block_inputs(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        found_inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    /// Ask the updater to save all recorded changes to persistent storage.
    async fn save_to_persistent_storage(&mut self) -> Result<()>;
}
