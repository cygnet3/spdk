use std::time::Duration;

use bitcoin::Txid;
use electrum_streaming_client::response::{FullTx, HeaderResp};
use electrum_streaming_client::{
    AsyncClient, ElectrumScriptHash, ElectrumScriptStatus, Event, request,
};
use futures::channel::mpsc::UnboundedReceiver;
use log::{debug, info};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[expect(unused, reason = "worker is used to keep the connection alive")]
pub struct FrigateClient {
    pub client: AsyncClient,
    pub events: UnboundedReceiver<Event>,
    pub worker: JoinHandle<Result<(), std::io::Error>>,
    pub request_timeout: Duration,
    protocol_version: Option<String>,
}

#[derive(Debug)]
pub enum FrigateError {
    Connection(String),
    Timeout(String),
    Request(String),
}

type Result<T, E = FrigateError> = std::result::Result<T, E>;

impl std::fmt::Display for FrigateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "connection error: {msg}"),
            Self::Timeout(msg) => write!(f, "request timeout: {msg}"),
            Self::Request(msg) => write!(f, "request error: {msg}"),
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

        let worker = tokio::spawn(worker);

        Ok(Self {
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
            protocol_version: None,
        })
    }

    /// Sets a custom request timeout for this client.
    #[expect(unused, reason = "tbd")]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn get_block_header(&mut self, height: u32) -> Result<HeaderResp> {
        self.version().await?;

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
        self.version().await?;

        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("GetTx request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("GetTx request failed: {e}")))?;
        Ok(res)
    }

    /// Negotiate the Frigate protocol version once and cache the result.
    ///
    /// The negotiation is sent as the first request on the connection. Later calls return the
    /// cached version without sending another request.
    pub async fn version(&mut self) -> Result<String> {
        if let Some(protocol_version) = &self.protocol_version {
            return Ok(protocol_version.clone());
        }

        debug!("Sending version request to Frigate server...");
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::ServerVersion {
                client_name: "spdk".into(),
                protocol_version: request::SupportedVersion::Range([
                    "1.3.2".into(),
                    "1.4.1".into(),
                ]),
            }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Version request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Version request failed: {e}")))?;
        self.protocol_version = Some(res.protocol_version.clone());
        Ok(res.protocol_version)
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the
    /// given silent payment address Once the server receives the request notification will be
    /// sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    pub async fn subscribe(&mut self, subscribe_req: request::SpSubscribe) -> Result<String> {
        self.version().await?;
        debug!("Sending subscribe event request...");

        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Subscribe request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Subscribe request failed: {e}")))?;

        info!("Subscribed to silent payment address: {res}");
        Ok(res)
    }

    #[expect(unused, reason = "tbd")]
    pub async fn unsubscribe(&mut self, unsub_req: request::SpUnsubscribe) -> Result<()> {
        self.version().await?;

        let res = timeout(self.request_timeout, self.client.send_request(unsub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Unsubscribe request timed out".to_owned()))?
            .map_err(|e| FrigateError::Request(format!("Unsubscribe request failed: {e}")))?;

        info!("Unsubscribed to silent payment address: {res:?}");
        Ok(())
    }

    pub async fn scripthash_subscribe(
        &mut self,
        sub_req: request::ScriptHashSubscribe,
    ) -> Result<Option<ElectrumScriptStatus>> {
        self.version().await?;
        let res = timeout(self.request_timeout, self.client.send_request(sub_req))
            .await
            .map_err(|_| FrigateError::Timeout("Script hash subscription timed out".to_owned()))?
            .map_err(|e| {
                FrigateError::Request(format!("Script hash subscription request failed: {e}"))
            })?;

        info!("Subscribed to script: {res:?}");
        Ok(res)
    }

    pub async fn get_history(
        &mut self,
        script_hash: ElectrumScriptHash,
    ) -> Result<Vec<electrum_streaming_client::response::Tx>> {
        self.version().await?;

        let res = timeout(
            self.request_timeout,
            self.client
                .send_request(request::GetHistory { script_hash }),
        )
        .await
        .map_err(|_| FrigateError::Timeout("Script history request timed out".to_owned()))?
        .map_err(|e| FrigateError::Request(format!("Script history request failed: {e}")))?;
        Ok(res)
    }
}
