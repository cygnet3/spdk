use std::ops::RangeInclusive;
use std::pin::Pin;

use bitcoin::{Amount, absolute::Height};
use futures::{Stream, StreamExt};

// use crate::oracle_grpc::{oracle_service_client::OracleServiceClient, }

use crate::oracle_grpc::RangedBlockHeightRequestFiltered;
use crate::oracle_grpc::oracle_service_client::OracleServiceClient;
use crate::structs::BlockScanData;

#[derive(Clone, Debug)]
pub struct BlindbitClient {
    host_url: String,
}

impl BlindbitClient {
    pub fn new(host_url: String) -> Self {
        Self { host_url }
    }

    pub async fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<BlockScanData>> + Send>> {
        let host_url = self.host_url.clone();
        println!("Connecting to oracle service at {host_url}...");

        let mut client = OracleServiceClient::connect(host_url).await.unwrap();

        let request = tonic::Request::new(RangedBlockHeightRequestFiltered {
            start: range.start().to_consensus_u32() as u64,
            end: range.end().to_consensus_u32() as u64,
            dustlimit: dust_limit.to_sat(),
            cut_through: with_cutthrough,
        });

        let stream = client
            .stream_block_scan_data_short(request)
            .await
            .unwrap()
            .into_inner();

        let mapped = stream.map(|response| Ok(response.unwrap().into()));

        Box::pin(mapped)
    }
}
