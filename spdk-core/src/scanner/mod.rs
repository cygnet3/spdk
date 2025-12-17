use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;

#[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
use anyhow::Error;
use anyhow::Result;
use bitcoin::{
    absolute::Height, bip158::BlockFilter, hashes::Hash as _, Amount, BlockHash, OutPoint, Txid,
    XOnlyPublicKey,
};
use silentpayments::receiving::Label;

#[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
use rayon::prelude::*;

use crate::{BlockData, ChainBackend, FilterData, OwnedOutput, OutputSpendStatus, SpClient, Updater, UtxoData};

/// Internal trait for synchronous scanning of silent payment blocks
///
/// This trait abstracts the core scanning functionality.
/// Consumers should use the concrete `SpScanner` type instead of implementing this trait.
pub(crate) trait SyncSpScannerTrait {
    /// Scan a range of blocks for silent payment outputs and inputs
    ///
    /// # Arguments
    /// * `start` - Starting block height (inclusive)
    /// * `end` - Ending block height (inclusive)
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()>;

    /// Process a single block's data
    ///
    /// # Arguments
    /// * `blockdata` - Block data containing tweaks and filters
    ///
    /// # Returns
    /// * `(found_outputs, found_inputs)` - Tuple of found outputs and spent inputs
    fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)>;

    /// Process block outputs to find owned silent payment outputs
    ///
    /// # Arguments
    /// * `blkheight` - Block height
    /// * `tweaks` - List of tweak public keys
    /// * `new_utxo_filter` - Filter data for new UTXOs
    ///
    /// # Returns
    /// * Map of outpoints to owned outputs
    fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<bitcoin::secp256k1::PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>>;

    /// Process block inputs to find spent outputs
    ///
    /// # Arguments
    /// * `blkheight` - Block height
    /// * `spent_filter` - Filter data for spent outputs
    ///
    /// # Returns
    /// * Set of spent outpoints
    fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>>;

    /// Get the block data iterator for a range of blocks
    ///
    /// # Arguments
    /// * `range` - Range of block heights
    /// * `dust_limit` - Minimum amount to consider
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    ///
    /// # Returns
    /// * Iterator of block data results
    fn get_block_data_iterator(
        &self,
        range: std::ops::RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> crate::BlockDataIterator;

    /// Check if scanning should be interrupted
    ///
    /// # Returns
    /// * `true` if scanning should stop, `false` otherwise
    fn should_interrupt(&self) -> bool;

    /// Save current state to persistent storage
    fn save_state(&mut self) -> Result<()>;

    /// Record found outputs for a block
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `block_hash` - Block hash
    /// * `outputs` - Found outputs
    fn record_outputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()>;

    /// Record spent inputs for a block
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `block_hash` - Block hash
    /// * `inputs` - Spent inputs
    fn record_inputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    /// Record scan progress
    ///
    /// # Arguments
    /// * `start` - Start height
    /// * `current` - Current height
    /// * `end` - End height
    fn record_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()>;

    /// Get the silent payment client
    fn client(&self) -> &SpClient;

    /// Get the chain backend
    fn backend(&self) -> &dyn ChainBackend;

    /// Get the updater
    fn updater(&mut self) -> &mut dyn Updater;

    // Helper methods with default implementations

    /// Process multiple blocks from an iterator
    ///
    /// This is a default implementation that can be overridden if needed
    fn process_blocks<I>(&mut self, start: Height, end: Height, block_data_iter: I) -> Result<()>
    where
        I: Iterator<Item = Result<BlockData>>,
    {
        use std::time::{Duration, Instant};

        let mut update_time = Instant::now();

        for blockdata_result in block_data_iter {
            let blockdata = blockdata_result?;
            let blkheight = blockdata.blkheight;
            let blkhash = blockdata.blkhash;

            // stop scanning and return if interrupted
            if self.should_interrupt() {
                self.save_state()?;
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
                self.record_outputs(blkheight, blkhash, found_outputs)?;
            }

            if !found_inputs.is_empty() {
                save_to_storage = true;
                self.record_inputs(blkheight, blkhash, found_inputs)?;
            }

            // tell the updater we scanned this block
            self.record_progress(start, blkheight, end)?;

            if save_to_storage {
                self.save_state()?;
                update_time = Instant::now();
            }
        }

        Ok(())
    }

    /// Helper method to process blocks sequentially
    ///
    /// # Arguments
    /// * `start` - Start height
    /// * `end` - End height
    /// * `block_data_iter` - Iterator of block data
    /// * `with_cutthrough` - Whether cutthrough is enabled (unused, kept for API compatibility)
    ///
    /// # Returns
    /// * Result indicating success or failure
    fn process_blocks_auto<I>(
        &mut self,
        start: Height,
        end: Height,
        block_data_iter: I,
        _with_cutthrough: bool,
    ) -> Result<()>
    where
        I: Iterator<Item = Result<BlockData>>,
    {
        // Always use sequential processing
        self.process_blocks(start, end, block_data_iter)
    }

    /// Scan UTXOs for a given block and secrets map
    ///
    /// This is a default implementation that can be overridden if needed
    fn scan_utxos(
        &self,
        blkheight: Height,
        secrets_map: HashMap<[u8; 34], bitcoin::secp256k1::PublicKey>,
    ) -> Result<Vec<(Option<Label>, UtxoData, bitcoin::secp256k1::Scalar)>> {
        let utxos = self.backend().utxos(blkheight)?;

        // group utxos by the txid
        let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
        for utxo in utxos {
            txmap.entry(utxo.txid).or_default().push(utxo);
        }

        let client = self.client();

        // Parallel transaction scanning on native platforms with parallel feature
        #[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
        let res: Vec<_> = txmap
            .into_par_iter()
            .filter_map(|(_, utxos)| {
                // check if we know the secret to any of the spks
                let secret = utxos.iter().find_map(|utxo| {
                    let spk = utxo.scriptpubkey.as_bytes();
                    secrets_map.get(spk)
                })?;

                let output_keys: Vec<XOnlyPublicKey> = utxos
                    .iter()
                    .filter_map(|x| {
                        if x.scriptpubkey.is_p2tr() {
                            XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..]).ok()
                        } else {
                            None
                        }
                    })
                    .collect();

                // CPU-intensive cryptographic operation
                let ours = client
                    .sp_receiver
                    .scan_transaction(secret, output_keys)
                    .ok()?;

                // Match UTXOs against our keys
                let matched: Vec<_> = utxos
                    .into_iter()
                    .filter(|utxo| utxo.scriptpubkey.is_p2tr() && !utxo.spent)
                    .filter_map(|utxo| {
                        let xonly =
                            XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]).ok()?;
                        ours.iter().find_map(|(label, map)| {
                            map.get(&xonly)
                                .map(|scalar| (label.clone(), utxo.clone(), *scalar))
                        })
                    })
                    .collect();

                if matched.is_empty() {
                    None
                } else {
                    Some(matched)
                }
            })
            .flatten()
            .collect();

        // Sequential fallback (WASM or no parallel feature)
        #[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
        let res: Vec<_> = {
            let mut result = Vec::new();
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

                let ours = client.sp_receiver.scan_transaction(secret, output_keys?)?;

                for utxo in utxos {
                    if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                        continue;
                    }

                    match XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]) {
                        Ok(xonly) => {
                            for (label, map) in ours.iter() {
                                if let Some(scalar) = map.get(&xonly) {
                                    result.push((label.clone(), utxo, *scalar));
                                    break;
                                }
                            }
                        }
                        Err(_) => todo!(),
                    }
                }
            }
            result
        };

        Ok(res)
    }

    /// Check if block contains relevant output transactions
    ///
    /// This is a default implementation that can be overridden if needed
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

    /// Get input hashes for owned outpoints
    fn get_input_hashes(&self, blkhash: BlockHash) -> Result<HashMap<[u8; 8], OutPoint>>;

    /// Check if block contains relevant input transactions
    ///
    /// This is a default implementation that can be overridden if needed
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
}

/// Internal trait for async scanning of silent payment blocks
///
/// This trait provides async methods for scanning silent payment blocks.
/// Consumers should use the concrete `SpScanner` type instead of implementing this trait.
#[cfg(feature = "async")]
#[async_trait::async_trait]
pub(crate) trait AsyncSpScannerTrait: Send + Sync {
    /// Scan a range of blocks for silent payment outputs and inputs
    ///
    /// # Arguments
    /// * `start` - Starting block height (inclusive)
    /// * `end` - Ending block height (inclusive)
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    async fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()>;

    /// Process a single block's data
    ///
    /// # Arguments
    /// * `blockdata` - Block data containing tweaks and filters
    ///
    /// # Returns
    /// * `(found_outputs, found_inputs)` - Tuple of found outputs and spent inputs
    async fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)>;

    /// Process block outputs to find owned silent payment outputs
    ///
    /// # Arguments
    /// * `blkheight` - Block height
    /// * `tweaks` - List of tweak public keys
    /// * `new_utxo_filter` - Filter data for new UTXOs
    ///
    /// # Returns
    /// * Map of outpoints to owned outputs
    async fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<bitcoin::secp256k1::PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>>;

    /// Process block inputs to find spent outputs
    ///
    /// # Arguments
    /// * `blkheight` - Block height
    /// * `spent_filter` - Filter data for spent outputs
    ///
    /// # Returns
    /// * Set of spent outpoints
    async fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>>;

    /// Get the block data stream for a range of blocks
    ///
    /// # Arguments
    /// * `range` - Range of block heights
    /// * `dust_limit` - Minimum amount to consider
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    ///
    /// # Returns
    /// * Stream of block data results
    fn get_block_data_stream(
        &self,
        range: std::ops::RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> crate::backend::BlockDataStream;

    /// Check if scanning should be interrupted
    ///
    /// # Returns
    /// * `true` if scanning should stop, `false` otherwise
    fn should_interrupt(&self) -> bool;

    /// Save current state to persistent storage
    async fn save_state(&mut self) -> Result<()>;

    /// Record found outputs for a block
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `block_hash` - Block hash
    /// * `outputs` - Found outputs
    async fn record_outputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()>;

    /// Record spent inputs for a block
    ///
    /// # Arguments
    /// * `height` - Block height
    /// * `block_hash` - Block hash
    /// * `inputs` - Spent inputs
    async fn record_inputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        inputs: HashSet<OutPoint>,
    ) -> Result<()>;

    /// Record scan progress
    ///
    /// # Arguments
    /// * `start` - Start height
    /// * `current` - Current height
    /// * `end` - End height
    async fn record_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()>;

    /// Get the silent payment client
    fn client(&self) -> &SpClient;

    /// Get the async chain backend
    fn backend(&self) -> &dyn crate::backend::AsyncChainBackend;

    /// Get the async updater
    fn updater(&mut self) -> &mut dyn crate::updater::AsyncUpdater;

    // Helper methods with default implementations

    /// Process multiple blocks from a stream
    ///
    /// This is a default implementation that can be overridden if needed
    async fn process_blocks(
        &mut self,
        start: Height,
        end: Height,
        mut block_data_stream: crate::backend::BlockDataStream,
    ) -> Result<()> {
        use futures::StreamExt;
        use std::time::{Duration, Instant};

        let mut update_time = Instant::now();

        while let Some(blockdata_result) = block_data_stream.next().await {
            let blockdata = blockdata_result?;
            let blkheight = blockdata.blkheight;
            let blkhash = blockdata.blkhash;

            // stop scanning and return if interrupted
            if self.should_interrupt() {
                self.save_state().await?;
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
                self.record_outputs(blkheight, blkhash, found_outputs)
                    .await?;
            }

            if !found_inputs.is_empty() {
                save_to_storage = true;
                self.record_inputs(blkheight, blkhash, found_inputs).await?;
            }

            // tell the updater we scanned this block
            self.record_progress(start, blkheight, end).await?;

            if save_to_storage {
                self.save_state().await?;
                update_time = Instant::now();
            }
        }

        Ok(())
    }

    /// Scan UTXOs for a given block and secrets map
    ///
    /// This is a default implementation that can be overridden if needed
    async fn scan_utxos(
        &self,
        blkheight: Height,
        secrets_map: HashMap<[u8; 34], bitcoin::secp256k1::PublicKey>,
    ) -> Result<Vec<(Option<Label>, UtxoData, bitcoin::secp256k1::Scalar)>> {
        let utxos = self.backend().utxos(blkheight).await?;

        // Group utxos by the txid
        let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
        for utxo in utxos {
            txmap.entry(utxo.txid).or_default().push(utxo);
        }

        let client = self.client();

        // Parallel transaction scanning on native platforms with parallel feature
        // This uses Rayon for CPU parallelism. Rayon uses its own thread pool internally,
        // so while this blocks the current async task, it doesn't block the entire runtime
        // on multi-threaded executors. The CPU work benefits significantly from parallelism.
        #[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
        let res = {
            use rayon::prelude::*;
            use std::sync::Arc;

            // Clone data needed for parallel processing
            let secrets_map = Arc::new(secrets_map);
            let client = Arc::new(client.clone());

            // Run CPU-intensive Rayon work
            // Rayon uses its own thread pool, so this parallelizes across CPU cores
            txmap
                .into_par_iter()
                .filter_map(|(_, utxos)| {
                    // check if we know the secret to any of the spks
                    let secret = utxos.iter().find_map(|utxo| {
                        let spk = utxo.scriptpubkey.as_bytes();
                        secrets_map.get(spk)
                    })?;

                    let output_keys: Vec<XOnlyPublicKey> = utxos
                        .iter()
                        .filter_map(|x| {
                            if x.scriptpubkey.is_p2tr() {
                                XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..]).ok()
                            } else {
                                None
                            }
                        })
                        .collect();

                    // CPU-intensive cryptographic operation
                    let ours = client
                        .sp_receiver
                        .scan_transaction(secret, output_keys)
                        .ok()?;

                    // Match UTXOs against our keys
                    let matched: Vec<_> = utxos
                        .into_iter()
                        .filter(|utxo| utxo.scriptpubkey.is_p2tr() && !utxo.spent)
                        .filter_map(|utxo| {
                            let xonly =
                                XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]).ok()?;
                            ours.iter().find_map(|(label, map)| {
                                map.get(&xonly)
                                    .map(|scalar| (label.clone(), utxo.clone(), *scalar))
                            })
                        })
                        .collect();

                    if matched.is_empty() {
                        None
                    } else {
                        Some(matched)
                    }
                })
                .flatten()
                .collect()
        };

        // Sequential fallback (WASM or no parallel feature)
        #[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
        let res: Vec<_> = {
            let mut result = Vec::new();
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
                                    .map_err(|e| anyhow::Error::new(e)),
                            )
                        } else {
                            None
                        }
                    })
                    .collect();

                let ours = client.sp_receiver.scan_transaction(secret, output_keys?)?;

                for utxo in utxos {
                    if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                        continue;
                    }

                    match XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]) {
                        Ok(xonly) => {
                            for (label, map) in ours.iter() {
                                if let Some(scalar) = map.get(&xonly) {
                                    result.push((label.clone(), utxo.clone(), *scalar));
                                    break;
                                }
                            }
                        }
                        Err(_) => todo!(),
                    }
                }
            }
            result
        };

        Ok(res)
    }

    /// Check if block contains relevant output transactions
    ///
    /// This is a default implementation that can be overridden if needed
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

    /// Get input hashes for owned outpoints
    async fn get_input_hashes(&self, blkhash: BlockHash) -> Result<HashMap<[u8; 8], OutPoint>>;

    /// Check if block contains relevant input transactions
    ///
    /// This is a default implementation that can be overridden if needed
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
}

// =============================================================================
// Concrete SpScanner Implementation
// =============================================================================

/// Public scanner implementation for silent payments
///
/// This type conditionally implements either synchronous or asynchronous scanning
/// based on the `async` feature flag. Consumers should use this type instead of
/// implementing the scanner traits directly.
///
/// # Type Parameters
/// * `B` - The chain backend type (sync or async depending on feature flags)
/// * `U` - The updater type (sync or async depending on feature flags)
#[cfg(not(feature = "async"))]
pub struct SpScanner<'a, B: ChainBackend, U: Updater> {
    client: SpClient,
    backend: B,
    updater: U,
    owned_outpoints: HashSet<OutPoint>,
    keep_scanning: &'a AtomicBool,
}

/// Public scanner implementation for silent payments (async variant)
///
/// This type conditionally implements either synchronous or asynchronous scanning
/// based on the `async` feature flag. Consumers should use this type instead of
/// implementing the scanner traits directly.
///
/// # Type Parameters
/// * `B` - The async chain backend type
/// * `U` - The async updater type
#[cfg(feature = "async")]
pub struct SpScanner<'a, B: crate::backend::AsyncChainBackend, U: crate::updater::AsyncUpdater> {
    client: SpClient,
    backend: B,
    updater: U,
    owned_outpoints: HashSet<OutPoint>,
    keep_scanning: &'a AtomicBool,
}

// Synchronous implementation
#[cfg(not(feature = "async"))]
impl<'a, B: ChainBackend, U: Updater> SpScanner<'a, B, U> {
    /// Create a new SpScanner instance
    ///
    /// # Arguments
    /// * `client` - The silent payment client
    /// * `backend` - The chain backend for blockchain data access
    /// * `updater` - The updater for tracking scan progress
    /// * `owned_outpoints` - Set of outpoints to track for spent detection
    /// * `keep_scanning` - Atomic bool reference for interrupting the scan
    pub fn new(
        client: SpClient,
        backend: B,
        updater: U,
        owned_outpoints: HashSet<OutPoint>,
        keep_scanning: &'a AtomicBool,
    ) -> Self {
        Self {
            client,
            backend,
            updater,
            owned_outpoints,
            keep_scanning,
        }
    }

    /// Scan a range of blocks for silent payment outputs and inputs
    ///
    /// # Arguments
    /// * `start` - Starting block height (inclusive)
    /// * `end` - Ending block height (inclusive)
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    pub fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        SyncSpScannerTrait::scan_blocks(self, start, end, dust_limit, with_cutthrough)
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(not(feature = "async"))]
impl<'a, B: ChainBackend, U: Updater> SyncSpScannerTrait for SpScanner<'a, B, U> {
    fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_iter = self.get_block_data_iterator(range, dust_limit, with_cutthrough);
        self.process_blocks_auto(start, end, block_data_iter, with_cutthrough)
    }

    fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)> {
        let blkheight = blockdata.blkheight;
        let tweaks = blockdata.tweaks;
        let new_utxo_filter = blockdata.new_utxo_filter;
        let spent_filter = blockdata.spent_filter;

        let found_outputs = self.process_block_outputs(blkheight, tweaks, new_utxo_filter)?;
        
        // Update owned outpoints with newly found outputs
        for outpoint in found_outputs.keys() {
            self.owned_outpoints.insert(*outpoint);
        }

        let found_inputs = self.process_block_inputs(blkheight, spent_filter)?;

        Ok((found_outputs, found_inputs))
    }

    fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<bitcoin::secp256k1::PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>> {
        if tweaks.is_empty() {
            return Ok(HashMap::new());
        }

        let secrets_map = self.client.get_script_to_secret_map(tweaks)?;
        if secrets_map.is_empty() {
            return Ok(HashMap::new());
        }

        let candidate_spks: Vec<_> = secrets_map.keys().collect();
        let filter = BlockFilter::new(&new_utxo_filter.data);
        let matched = Self::check_block_outputs(
            filter,
            new_utxo_filter.block_hash,
            candidate_spks,
        )?;

        if !matched {
            return Ok(HashMap::new());
        }

        let found_utxos = self.scan_utxos(blkheight, secrets_map)?;
        
        let mut outputs = HashMap::new();
        for (label, utxo, tweak) in found_utxos {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            let owned_output = OwnedOutput {
                blockheight: blkheight,
                tweak: tweak.to_be_bytes(),
                amount: utxo.value,
                script: utxo.scriptpubkey,
                label,
                spend_status: OutputSpendStatus::Unspent,
            };
            outputs.insert(outpoint, owned_output);
        }

        Ok(outputs)
    }

    fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>> {
        if self.owned_outpoints.is_empty() {
            return Ok(HashSet::new());
        }

        let input_hashes = self.get_input_hashes(spent_filter.block_hash)?;
        if input_hashes.is_empty() {
            return Ok(HashSet::new());
        }

        let filter = BlockFilter::new(&spent_filter.data);
        let matched = self.check_block_inputs(
            filter,
            spent_filter.block_hash,
            input_hashes.keys().copied().collect(),
        )?;

        if !matched {
            return Ok(HashSet::new());
        }

        // Get the actual spent inputs from spent index
        let spent_index = self.backend.spent_index(blkheight)?;
        let spent_inputs: HashSet<OutPoint> = spent_index
            .data
            .into_iter()
            .filter_map(|bytes| {
                if bytes.len() >= 36 {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&bytes[0..32]);
                    let hash = bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes);
                    let txid = Txid::from_raw_hash(hash);
                    let vout = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
                    let outpoint = OutPoint::new(txid, vout);
                    if self.owned_outpoints.contains(&outpoint) {
                        Some(outpoint)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(spent_inputs)
    }

    fn get_block_data_iterator(
        &self,
        range: std::ops::RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> crate::BlockDataIterator {
        self.backend.get_block_data_for_range(range, dust_limit, with_cutthrough)
    }

    fn should_interrupt(&self) -> bool {
        self.interrupt_requested()
    }

    fn save_state(&mut self) -> Result<()> {
        self.updater.save_to_persistent_storage()
    }

    fn record_outputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()> {
        self.updater.record_block_outputs(height, block_hash, outputs)
    }

    fn record_inputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        inputs: HashSet<OutPoint>,
    ) -> Result<()> {
        self.updater.record_block_inputs(height, block_hash, inputs)
    }

    fn record_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()> {
        self.updater.record_scan_progress(start, current, end)
    }

    fn client(&self) -> &SpClient {
        &self.client
    }

    fn backend(&self) -> &dyn ChainBackend {
        &self.backend
    }

    fn updater(&mut self) -> &mut dyn Updater {
        &mut self.updater
    }

    fn get_input_hashes(&self, _blkhash: BlockHash) -> Result<HashMap<[u8; 8], OutPoint>> {
        let mut input_hashes = HashMap::new();
        for outpoint in &self.owned_outpoints {
            let mut hash = [0u8; 8];
            hash.copy_from_slice(&outpoint.txid[..8]);
            input_hashes.insert(hash, *outpoint);
        }
        Ok(input_hashes)
    }
}

// Async implementation
#[cfg(feature = "async")]
impl<'a, B: crate::backend::AsyncChainBackend, U: crate::updater::AsyncUpdater> SpScanner<'a, B, U> {
    /// Create a new SpScanner instance
    ///
    /// # Arguments
    /// * `client` - The silent payment client
    /// * `backend` - The async chain backend for blockchain data access
    /// * `updater` - The async updater for tracking scan progress
    /// * `owned_outpoints` - Set of outpoints to track for spent detection
    /// * `keep_scanning` - Atomic bool reference for interrupting the scan
    pub fn new(
        client: SpClient,
        backend: B,
        updater: U,
        owned_outpoints: HashSet<OutPoint>,
        keep_scanning: &'a AtomicBool,
    ) -> Self {
        Self {
            client,
            backend,
            updater,
            owned_outpoints,
            keep_scanning,
        }
    }

    /// Scan a range of blocks for silent payment outputs and inputs
    ///
    /// # Arguments
    /// * `start` - Starting block height (inclusive)
    /// * `end` - Ending block height (inclusive)
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    pub async fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        AsyncSpScannerTrait::scan_blocks(self, start, end, dust_limit, with_cutthrough).await
    }

    fn interrupt_requested(&self) -> bool {
        !self
            .keep_scanning
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
impl<'a, B: crate::backend::AsyncChainBackend, U: crate::updater::AsyncUpdater> AsyncSpScannerTrait
    for SpScanner<'a, B, U>
{
    async fn scan_blocks(
        &mut self,
        start: Height,
        end: Height,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Result<()> {
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_stream = self.get_block_data_stream(range, dust_limit, with_cutthrough);
        self.process_blocks(start, end, block_data_stream).await
    }

    async fn process_block(
        &mut self,
        blockdata: BlockData,
    ) -> Result<(HashMap<OutPoint, OwnedOutput>, HashSet<OutPoint>)> {
        let blkheight = blockdata.blkheight;
        let tweaks = blockdata.tweaks;
        let new_utxo_filter = blockdata.new_utxo_filter;
        let spent_filter = blockdata.spent_filter;

        let found_outputs = self
            .process_block_outputs(blkheight, tweaks, new_utxo_filter)
            .await?;
        
        // Update owned outpoints with newly found outputs
        for outpoint in found_outputs.keys() {
            self.owned_outpoints.insert(*outpoint);
        }

        let found_inputs = self.process_block_inputs(blkheight, spent_filter).await?;

        Ok((found_outputs, found_inputs))
    }

    async fn process_block_outputs(
        &self,
        blkheight: Height,
        tweaks: Vec<bitcoin::secp256k1::PublicKey>,
        new_utxo_filter: FilterData,
    ) -> Result<HashMap<OutPoint, OwnedOutput>> {
        if tweaks.is_empty() {
            return Ok(HashMap::new());
        }

        let secrets_map = self.client.get_script_to_secret_map(tweaks)?;
        if secrets_map.is_empty() {
            return Ok(HashMap::new());
        }

        let candidate_spks: Vec<_> = secrets_map.keys().collect();
        let filter = BlockFilter::new(&new_utxo_filter.data);
        let matched = Self::check_block_outputs(
            filter,
            new_utxo_filter.block_hash,
            candidate_spks,
        )?;

        if !matched {
            return Ok(HashMap::new());
        }

        let found_utxos = self.scan_utxos(blkheight, secrets_map).await?;
        
        let mut outputs = HashMap::new();
        for (label, utxo, tweak) in found_utxos {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            let owned_output = OwnedOutput {
                blockheight: blkheight,
                tweak: tweak.to_be_bytes(),
                amount: utxo.value,
                script: utxo.scriptpubkey,
                label,
                spend_status: OutputSpendStatus::Unspent,
            };
            outputs.insert(outpoint, owned_output);
        }

        Ok(outputs)
    }

    async fn process_block_inputs(
        &self,
        blkheight: Height,
        spent_filter: FilterData,
    ) -> Result<HashSet<OutPoint>> {
        if self.owned_outpoints.is_empty() {
            return Ok(HashSet::new());
        }

        let input_hashes = self.get_input_hashes(spent_filter.block_hash).await?;
        if input_hashes.is_empty() {
            return Ok(HashSet::new());
        }

        let filter = BlockFilter::new(&spent_filter.data);
        let matched = self.check_block_inputs(
            filter,
            spent_filter.block_hash,
            input_hashes.keys().copied().collect(),
        )?;

        if !matched {
            return Ok(HashSet::new());
        }

        // Get the actual spent inputs from spent index
        let spent_index = self.backend.spent_index(blkheight).await?;
        let spent_inputs: HashSet<OutPoint> = spent_index
            .data
            .into_iter()
            .filter_map(|bytes| {
                if bytes.len() >= 36 {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&bytes[0..32]);
                    let hash = bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes);
                    let txid = Txid::from_raw_hash(hash);
                    let vout = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
                    let outpoint = OutPoint::new(txid, vout);
                    if self.owned_outpoints.contains(&outpoint) {
                        Some(outpoint)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(spent_inputs)
    }

    fn get_block_data_stream(
        &self,
        range: std::ops::RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> crate::backend::BlockDataStream {
        self.backend.get_block_data_stream(range, dust_limit, with_cutthrough)
    }

    fn should_interrupt(&self) -> bool {
        self.interrupt_requested()
    }

    async fn save_state(&mut self) -> Result<()> {
        self.updater.save_to_persistent_storage().await
    }

    async fn record_outputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        outputs: HashMap<OutPoint, OwnedOutput>,
    ) -> Result<()> {
        self.updater
            .record_block_outputs(height, block_hash, outputs)
            .await
    }

    async fn record_inputs(
        &mut self,
        height: Height,
        block_hash: BlockHash,
        inputs: HashSet<OutPoint>,
    ) -> Result<()> {
        self.updater.record_block_inputs(height, block_hash, inputs).await
    }

    async fn record_progress(&mut self, start: Height, current: Height, end: Height) -> Result<()> {
        self.updater.record_scan_progress(start, current, end).await
    }

    fn client(&self) -> &SpClient {
        &self.client
    }

    fn backend(&self) -> &dyn crate::backend::AsyncChainBackend {
        &self.backend
    }

    fn updater(&mut self) -> &mut dyn crate::updater::AsyncUpdater {
        &mut self.updater
    }

    async fn get_input_hashes(&self, _blkhash: BlockHash) -> Result<HashMap<[u8; 8], OutPoint>> {
        let mut input_hashes = HashMap::new();
        for outpoint in &self.owned_outpoints {
            let mut hash = [0u8; 8];
            hash.copy_from_slice(&outpoint.txid[..8]);
            input_hashes.insert(hash, *outpoint);
        }
        Ok(input_hashes)
    }
}
