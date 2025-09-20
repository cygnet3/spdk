use std::{ops::RangeInclusive, sync::mpsc, thread};

use bitcoin::{absolute::Height, Amount};

use anyhow::Result;

use crate::{
    backend::blindbit::BlindbitClient, utils::ThreadPool, BlockData, ChainBackend, SpentIndexData,
    UtxoData,
};

const CONCURRENT_FILTER_REQUESTS: usize = 200;

#[derive(Debug)]
pub struct BlindbitBackend {
    client: BlindbitClient,
}

impl BlindbitBackend {
    pub fn new(blindbit_url: String) -> Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(blindbit_url)?,
        })
    }
}

macro_rules! request {
    ($result: expr, $sender: ident) => {
        match $result {
            Ok(r) => r,
            Err(e) => {
                $sender.send(Err(e)).unwrap();
                return;
            }
        }
    };
}

fn get_block_data(
    client: BlindbitClient,
    sender: mpsc::Sender<Result<BlockData>>,
    block_height: Height,
    dust_limit: Amount,
    with_cutthrough: bool,
) {
    //
    let tweaks = match with_cutthrough {
        true => request!(client.tweaks(block_height, dust_limit), sender),
        false => request!(client.tweak_index(block_height, dust_limit), sender),
    };
    let new_utxo_filter = request!(client.filter_new_utxos(block_height), sender);
    let spent_filter = request!(client.filter_spent(block_height), sender);
    let blkhash = new_utxo_filter.block_hash;
    sender
        .send(Ok(BlockData {
            blkheight: block_height,
            blkhash,
            tweaks,
            new_utxo_filter: new_utxo_filter.into(),
            spent_filter: spent_filter.into(),
        }))
        .unwrap()
}

impl ChainBackend for BlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for scanning,
    /// but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<u32>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> mpsc::Receiver<Result<BlockData>> {
        let client = self.client.clone();
        let (sender, receiver) = mpsc::channel::<Result<BlockData>>();

        thread::spawn(move || {
            let pool = ThreadPool::new(CONCURRENT_FILTER_REQUESTS);

            for block_height in range {
                let block_height = match Height::from_consensus(block_height) {
                    Ok(r) => r,
                    Err(e) => {
                        sender.send(Err(e.into())).unwrap();
                        // NOTE: as we return here, the pool will be dropped
                        return;
                    }
                };
                let client = client.clone();
                let sender = sender.clone();
                pool.execute(move || {
                    get_block_data(client, sender, block_height, dust_limit, with_cutthrough);
                });
            }
        });

        receiver
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
