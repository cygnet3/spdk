use std::{
    ops::RangeInclusive,
    sync::{mpsc, Arc},
};

use bitcoin::{absolute::Height, Amount};

#[cfg(feature = "rayon")]
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    ThreadPoolBuilder,
};

use crate::client::{BlindbitClient, HttpClient};
use spdk_core::{BlockData, ChainBackend, SpentIndexData, UtxoData};

const CONCURRENT_FILTER_REQUESTS: usize = 200;

pub struct BlindbitBackend<H: HttpClient> {
    client: BlindbitClient<H>,
}

impl<H: HttpClient + Clone + 'static> BlindbitBackend<H> {
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

    /// Get block data for a range of blocks as an Iterator
    ///
    /// This fetches blocks concurrently for better performance.
    ///
    /// # Arguments
    /// * `range` - Range of block heights to fetch
    /// * `dust_limit` - Minimum amount to consider (dust outputs are ignored)
    /// * `with_cutthrough` - Whether to use cutthrough optimization
    ///
    /// # Returns
    /// A Iterator of BlockData results
    pub fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> spdk_core::BlockDataIterator {
        #[cfg(feature = "rayon")]
        let iter = self.get_block_data_for_range_rayon(range, dust_limit, with_cutthrough);

        #[cfg(not(feature = "rayon"))]
        let iter = self.get_block_data_for_range_thread_pool(range, dust_limit, with_cutthrough);

        iter
    }

    #[cfg(not(feature = "rayon"))]
    pub fn get_block_data_for_range_thread_pool(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> spdk_core::BlockDataIterator {
        use crate::thread_pool::ThreadPool;

        let client = Arc::new(self.client.clone());

        let (sender, receiver) = mpsc::channel();

        let pool = ThreadPool::new(CONCURRENT_FILTER_REQUESTS);

        for height in range {
            let client = client.clone();
            let sender = sender.clone();

            pool.execute(move || {
                get_block_data_for_height(height, dust_limit, with_cutthrough, sender, client);
            });
        }
        Box::new(receiver.into_iter())
    }
    #[cfg(feature = "rayon")]
    pub fn get_block_data_for_range_rayon(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> spdk_core::BlockDataIterator {
        let client = Arc::new(self.client.clone());

        let (sender, receiver) = mpsc::channel();

        let pool = ThreadPoolBuilder::new()
            .num_threads(CONCURRENT_FILTER_REQUESTS)
            .build()
            .unwrap();

        pool.install(|| {
            range.into_par_iter().for_each(move |height| {
                let client = client.clone();
                let sender = sender.clone();

                get_block_data_for_height(height, dust_limit, with_cutthrough, sender, client);
            })
        });
        Box::new(receiver.into_iter())
    }

    /// Get spent index data for a block height
    pub fn spent_index(&self, block_height: Height) -> crate::error::Result<SpentIndexData> {
        Ok(self.client.spent_index(block_height)?.into())
    }

    /// Get UTXO data for a block height
    pub fn utxos(&self, block_height: Height) -> crate::error::Result<Vec<UtxoData>> {
        Ok(self
            .client
            .utxos(block_height)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Get the current block height from the server
    pub fn block_height(&self) -> crate::error::Result<Height> {
        self.client.block_height()
    }

    /// Get server info (network, supported modes, etc.)
    pub fn info(&self) -> crate::error::Result<crate::InfoResponse> {
        Ok(self.client.info()?)
    }
}

fn get_block_data_for_height<H>(
    height: u32,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    sender: mpsc::Sender<spdk_core::error::Result<BlockData>>,
    client: Arc<BlindbitClient<H>>,
) where
    H: HttpClient,
{
    let blkheight = match Height::from_consensus(height) {
        Ok(bh) => bh,
        Err(e) => {
            sender.send(Err(spdk_core::Error::from(e))).expect("closed");
            return;
        }
    };
    let tweaks = match with_cutthrough {
        true => client.tweaks(blkheight, dust_limit),
        false => client.tweak_index(blkheight, dust_limit),
    };
    let tweaks = match tweaks {
        Ok(t) => t,
        Err(e) => {
            sender.send(Err(spdk_core::Error::from(e))).expect("closed");
            return;
        }
    };
    let new_utxo_filter = match client.filter_new_utxos(blkheight) {
        Ok(f) => f,
        Err(e) => {
            sender.send(Err(spdk_core::Error::from(e))).expect("closed");
            return;
        }
    };
    let spent_filter = match client.filter_spent(blkheight) {
        Ok(f) => f,
        Err(e) => {
            sender.send(Err(spdk_core::Error::from(e))).expect("closed");
            return;
        }
    };
    let blkhash = new_utxo_filter.block_hash;
    sender
        .send(Ok(BlockData {
            blkheight,
            blkhash,
            tweaks,
            new_utxo_filter: new_utxo_filter.into(),
            spent_filter: spent_filter.into(),
        }))
        .expect("closed")
}

impl<H: HttpClient + Clone + 'static> ChainBackend for BlindbitBackend<H> {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Option<Amount>,
        with_cutthrough: bool,
    ) -> spdk_core::BlockDataIterator {
        self.get_block_data_for_range(range, dust_limit, with_cutthrough)
    }

    fn spent_index(&self, block_height: Height) -> spdk_core::error::Result<SpentIndexData> {
        Ok(self.spent_index(block_height)?)
    }

    fn utxos(&self, block_height: Height) -> spdk_core::error::Result<Vec<UtxoData>> {
        Ok(self.utxos(block_height)?)
    }

    fn block_height(&self) -> spdk_core::error::Result<Height> {
        Ok(self.block_height()?)
    }
}
