use std::collections::{HashMap, HashSet};

#[cfg(not(all(not(target_arch = "wasm32"), feature = "parallel")))]
use anyhow::Error;
use anyhow::Result;
use bitcoin::{
    absolute::Height, bip158::BlockFilter, Amount, BlockHash, OutPoint, Txid, XOnlyPublicKey,
};
use silentpayments::receiving::Label;

#[cfg(all(not(target_arch = "wasm32"), feature = "parallel"))]
use rayon::prelude::*;

use crate::{BlockData, ChainBackend, FilterData, OwnedOutput, SpClient, Updater, UtxoData};

/// Trait for scanning silent payment blocks
///
/// This trait abstracts the core scanning functionality, allowing consumers
/// to implement it with their own constraints and requirements.
pub trait SpScanner {
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

/// Async version of SpScanner for non-blocking I/O operations
///
/// This trait provides async methods for scanning silent payment blocks,
/// allowing for concurrent operations and better integration with async ecosystems.
/// Particularly useful for WASM targets and UI applications.
#[cfg(feature = "async")]
#[async_trait::async_trait]
pub trait AsyncSpScanner: Send + Sync {
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
                                XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..])
                                    .ok()?;
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
