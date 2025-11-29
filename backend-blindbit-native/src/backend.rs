use std::ops::RangeInclusive;

use bitcoin::{absolute::Height, Amount};
use futures::executor::block_on;

use anyhow::Result;

use crate::client::{BlindbitClient, HttpClient};
use spdk_core::{BlockData, BlockDataIterator, ChainBackend, SpentIndexData, UtxoData};

/// Synchronous Blindbit backend implementation, generic over the HTTP client.
///
/// This uses `block_on` to convert async HTTP calls to synchronous operations.
/// For better performance, consider using `AsyncBlindbitBackend` with the `async` feature.
///
/// Consumers must provide their own HTTP client implementation by implementing the `HttpClient` trait.
pub struct BlindbitBackend<H: HttpClient> {
    client: BlindbitClient<H>,
}

impl<H: HttpClient> BlindbitBackend<H> {
    /// Create a new synchronous Blindbit backend with a custom HTTP client.
    ///
    /// # Arguments
    /// * `blindbit_url` - Base URL of the Blindbit server
    /// * `http_client` - HTTP client implementation
    pub fn new(blindbit_url: String, http_client: H) -> Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(blindbit_url, http_client)?,
        })
    }
}

impl<H: HttpClient + Clone + 'static> ChainBackend for BlindbitBackend<H> {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        mut range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> BlockDataIterator {
        let client = self.client.clone();

        // blindbit will return an error 500 for genesis block
        if *range.start() == 0 {
            range = RangeInclusive::new(1, *range.end());
        }

        // Convert range to iterator that fetches block data synchronously
        let iter = range.map(move |n| {
            let client = client.clone();
            block_on(async move {
                let blkheight = Height::from_consensus(n)?;
                let tweaks = match with_cutthrough {
                    true => client.tweaks(blkheight, dust_limit).await?,
                    false => client.tweak_index(blkheight, dust_limit).await?,
                };
                let new_utxo_filter = client.filter_new_utxos(blkheight).await?;
                let spent_filter = client.filter_spent(blkheight).await?;
                let blkhash = new_utxo_filter.block_hash;
                Ok(BlockData {
                    blkheight,
                    blkhash,
                    tweaks,
                    new_utxo_filter: new_utxo_filter.into(),
                    spent_filter: spent_filter.into(),
                })
            })
        });

        Box::new(iter)
    }

    fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        block_on(self.client.spent_index(block_height)).map(Into::into)
    }

    fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        Ok(block_on(self.client.utxos(block_height))?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    fn block_height(&self) -> Result<Height> {
        block_on(self.client.block_height())
    }
}
