use std::ops::RangeInclusive;

use spdk_core::bitcoin::{Amount, absolute::Height};

use anyhow::Result;
use spdk_core::{BlockData, SpentIndexData, SyncChainBackend, UtxoData};

use crate::SyncBlindbitClient;

#[derive(Debug)]
pub struct SyncBlindbitBackend {
    client: SyncBlindbitClient,
}

impl SyncBlindbitBackend {
    pub fn new(blindbit_url: String) -> Result<Self> {
        Ok(Self {
            client: SyncBlindbitClient::new(blindbit_url)?,
        })
    }
}

impl SyncChainBackend for SyncBlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Box<dyn Iterator<Item = Result<BlockData>> + Send> {
        let client = self.client.clone();

        let iter = range.map(move |n| {
            let blkheight = Height::from_consensus(n)?;
            let tweaks = match with_cutthrough {
                true => client.tweaks(blkheight, dust_limit)?,
                false => client.tweak_index(blkheight, dust_limit)?,
            };
            let new_utxo_filter = client.filter_new_utxos(blkheight)?;
            let spent_filter = client.filter_spent(blkheight)?;
            let blkhash = new_utxo_filter.block_hash;
            Ok(BlockData {
                blkheight,
                blkhash,
                tweaks,
                new_utxo_filter: new_utxo_filter.into(),
                spent_filter: spent_filter.into(),
            })
        });

        Box::new(iter)
    }

    fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        self.client.spent_index(block_height).map(Into::into)
    }

    fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        Ok(self
            .client
            .utxos(block_height)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    fn block_height(&self) -> Result<Height> {
        self.client.block_height()
    }
}
