use std::{collections::HashSet, ops::RangeInclusive, pin::Pin, time::Duration};

use bitcoin::{
    Amount, BlockHash, OutPoint, Txid, absolute::Height,
};
use async_trait::async_trait;
use electrum_streaming_client::{AsyncClient, Event, request, response::{FullTx, HeaderResp}};
use futures::{Stream, channel::mpsc::UnboundedReceiver};

use spdk_core::chain::{BoxedBlockData, ChainBackend, UtxoData};
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};

pub struct FrigateClient {
    pub host_url: String,
    pub client: AsyncClient,
    pub events: UnboundedReceiver<Event>,
    pub worker: JoinHandle<Result<(), std::io::Error>>,
    pub request_timeout: Duration,
}


#[derive(Debug)]
pub enum FrigateError {
    Connection(String),
    Timeout(String),
    Request(String),
    Io(String),
}

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrigateError::Connection(msg) => write!(f, "connection error: {msg}"),
            FrigateError::Timeout(msg) => write!(f, "request timeout: {msg}"),
            FrigateError::Request(msg) => write!(f, "request error: {msg}"),
            FrigateError::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for FrigateError {}

impl FrigateClient {

    pub async fn connect(host_url: &str) -> Result<Self, FrigateError> {
        let stream = TcpStream::connect(host_url).await.map_err(|err| {
            FrigateError::Connection(format!("can't connect to socket '{host_url}': {err}"))
        })?;

        let (reader, writer) = stream.into_split();
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        let worker = tokio::spawn(async move {
            match worker.await {
                Ok(()) => {
                    Ok(())
                }
                Err(e) => {
                    Err(e)
                }
            }
        });

        Ok(Self {
            host_url: host_url.to_string(),
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Sets a custom request timeout for this client.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn get_block_header(&mut self, height: u32) -> Result<HeaderResp, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::Header { height }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Header request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Header request failed: {e}")))?;
        Ok(res)
    }

    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("GetTx request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("GetTx request failed: {e}")))?;
        Ok(res)
    }

    /// Send a request to the Frigate electrum server for version negotiation
    /// This is the first request that should be sent before subsequent one.
    pub async fn version(&mut self) -> Result<String, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::ServerVersion {
                client_name: "bdk-sp".into(),
                protocol_version: request::SupportedVersion::Range([
                    "1.3.2".into(),
                    "1.4.1".into(),
                ]),
            }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Version request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
        Ok(res.protocol_version)
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the given silent payment address
    /// Once the server receives the request notification will be sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    pub async fn subscribe(
        &mut self,
        subscribe_req: request::SpSubscribe,
    ) -> Result<String, FrigateError> {
        log::debug!("Sending subscribe event request...");
        
        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Subscribe request timed out".to_string()))?
        .map_err(|e| FrigateError::Request(format!("Subscribe request failed: {e}")))?;

        log::info!("Subscribed to silent payment address: {}", res);
        Ok(res)
    }

    pub async fn unsubscribe(
        &mut self,
        unsub_req: request::SpUnsubscribe,
    ) -> Result<(), FrigateError> {
        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_string()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        log::info!("Unsubscribed to silent payment address: {:?}", res);
        Ok(())
    }
}

#[async_trait]
impl ChainBackend for FrigateClient {
    fn get_block_data_for_range(
        &self,
        _range: RangeInclusive<Height>,
        _dust_limit: Amount,
        _with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = anyhow::Result<BoxedBlockData>> + Send>> {
        unimplemented!("Not needed for frigate implementation")
    }

    async fn detect_spent_outpoints(
        &self,
        _block_height: Height,
        _block_hash: BlockHash,
        _outpoints: HashSet<OutPoint>,
    ) -> anyhow::Result<HashSet<OutPoint>> {
        unimplemented!("Not needed for frigate implementation")
    }

    async fn utxos(&self, _block_height: Height) -> anyhow::Result<Vec<UtxoData>> {
        unimplemented!("Not needed for frigate implementation")
    }
}