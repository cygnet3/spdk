use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::{Amount, BlockHash, OutPoint, Txid};
use electrum_streaming_client::response::{FullTx, HeaderResp};
use electrum_streaming_client::{AsyncClient, Event, request};
use futures::Stream;
use futures::channel::mpsc::UnboundedReceiver;
use spdk_core::chain::{BoxedBlockData, ChainBackend, UtxoData};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[derive(Debug)]
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

type Result<T, E = FrigateError> = std::result::Result<T, E>;

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "connection error: {msg}"),
            Self::Timeout(msg) => write!(f, "request timeout: {msg}"),
            Self::Request(msg) => write!(f, "request error: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for FrigateError {}

impl FrigateClient {
    pub async fn connect(host_url: &str) -> Result<Self> {
        let stream = TcpStream::connect(host_url).await.map_err(|err| {
            FrigateError::Connection(format!("can't connect to socket '{host_url}': {err}"))
        })?;

        let (reader, writer) = stream.into_split();
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        let worker = tokio::spawn(async move {
            match worker.await {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            }
        });

        Ok(Self {
            host_url: host_url.to_owned(),
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Sets a custom request timeout for this client.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn get_block_header(&mut self, height: u32) -> Result<HeaderResp> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::Header { height }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Header request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Header request failed: {e}")))?;
        Ok(res)
    }

    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("GetTx request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("GetTx request failed: {e}")))?;
        Ok(res)
    }

    /// Send a request to the Frigate electrum server for version negotiation
    /// This is the first request that should be sent before subsequent one.
    pub async fn version(&mut self) -> Result<String> {
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
        .map_err(|_| FrigateError::Timeout("Version request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
        Ok(res.protocol_version)
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the
    /// given silent payment address Once the server receives the request notification will be
    /// sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    pub async fn subscribe(&mut self, subscribe_req: request::SpSubscribe) -> Result<String> {
        log::debug!("Sending subscribe event request...");

        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Subscribe request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Subscribe request failed: {e}")))?;

        log::info!("Subscribed to silent payment address: {res}");
        Ok(res)
    }

    pub async fn unsubscribe(&mut self, unsub_req: request::SpUnsubscribe) -> Result<()> {
        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_owned()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        log::info!("Unsubscribed to silent payment address: {res:?}");
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
