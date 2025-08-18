use std::{ops::RangeInclusive, pin::Pin};

use async_trait::async_trait;
use bitcoin::{absolute::Height, Amount};
use futures::{stream, Stream, StreamExt};

use anyhow::Result;

use crate::{BlockData, SpentIndexData, UtxoData};

use crate::backend::blindbit::client::wasm::WasmBlindbitClient;

use crate::backend::ChainBackendWasm;

pub struct WasmBlindbitBackend {
    client: WasmBlindbitClient,
}

impl WasmBlindbitBackend {
    pub fn new(blindbit_client: WasmBlindbitClient) -> Self {
        Self {
            client: blindbit_client,
        }
    }
}

#[async_trait(?Send)]
impl ChainBackendWasm for WasmBlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BlockData>>>> {
        let client = self.client.clone();

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
            .buffered(1); // Use buffered(1) for WASM to avoid concurrency issues

        Box::pin(res)
    }

    async fn spent_index(&self, block_height: Height) -> Result<SpentIndexData> {
        self.client.spent_index(block_height).await.map(Into::into)
    }

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        Ok(self
            .client
            .utxos(block_height)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn block_height(&self) -> Result<Height> {
        self.client.block_height().await
    }
}
