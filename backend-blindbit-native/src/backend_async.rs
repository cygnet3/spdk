use std::{ops::RangeInclusive, pin::Pin, sync::Arc};

use bitcoin::{absolute::Height, Amount};
use futures::{stream, Stream, StreamExt};

use crate::client::{BlindbitClient, HttpClient};
use spdk_core::{AsyncChainBackend, BlockData, BlockDataStream, SpentIndexData, UtxoData};

const CONCURRENT_FILTER_REQUESTS: usize = 200;

/// Asynchronous Blindbit backend implementation, generic over the HTTP client.
///
/// This provides high-performance async methods with concurrent request handling.
/// Enable with the `async` feature flag.
///
/// Consumers must provide their own HTTP client implementation by implementing the `HttpClient` trait.
pub struct AsyncBlindbitBackend<H: HttpClient> {
    client: BlindbitClient<H>,
}

impl<H: HttpClient + Clone + 'static> AsyncBlindbitBackend<H> {
    /// Create a new async Blindbit backend with a custom HTTP client.
    ///
    /// # Arguments
    /// * `blindbit_url` - Base URL of the Blindbit server
    /// * `http_client` - HTTP client implementation
    pub fn new(blindbit_url: String, http_client: H) -> crate::error::Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(blindbit_url, http_client)?,
        })
    }

    /// Get block data for a range of blocks as a Stream (async iterator).
    ///
    /// This fetches blocks concurrently for better performance.
    ///
    /// # Arguments
    /// * `range` - Range of block heights to fetch
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    ///
    /// # Returns
    /// A Stream of BlockData results
    pub fn get_block_data_stream(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = spdk_core::error::Result<BlockData>> + Send + 'static>> {
        let client = Arc::new(self.client.clone());

        let res = stream::iter(range)
            .map(move |n| {
                let client = client.clone();

                async move {
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
                }
            })
            .buffered(CONCURRENT_FILTER_REQUESTS);

        Box::pin(res)
    }

    /// Get spent index data for a block height
    pub async fn spent_index(&self, block_height: Height) -> spdk_core::error::Result<SpentIndexData> {
        Ok(self.client.spent_index(block_height).await?.into())
    }

    /// Get UTXO data for a block height
    pub async fn utxos(&self, block_height: Height) -> spdk_core::error::Result<Vec<UtxoData>> {
        Ok(self
            .client
            .utxos(block_height)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Get the current block height from the server
    pub async fn block_height(&self) -> spdk_core::error::Result<Height> {
        Ok(self.client.block_height().await?)
    }
}

// Implement the AsyncChainBackend trait for AsyncBlindbitBackend
#[async_trait::async_trait]
impl<H: HttpClient + Clone + 'static> AsyncChainBackend for AsyncBlindbitBackend<H> {
    fn get_block_data_stream(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> BlockDataStream {
        self.get_block_data_stream(range, dust_limit, with_cutthrough)
    }

    async fn spent_index(&self, block_height: Height) -> spdk_core::error::Result<SpentIndexData> {
        self.spent_index(block_height).await
    }

    async fn utxos(&self, block_height: Height) -> spdk_core::error::Result<Vec<UtxoData>> {
        self.utxos(block_height).await
    }

    async fn block_height(&self) -> spdk_core::error::Result<Height> {
        self.block_height().await
    }
}
