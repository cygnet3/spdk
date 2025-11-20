mod backend;

// Async backend - available with "async" feature
#[cfg(feature = "async")]
mod backend_async;

mod client;

// Re-export backend functionality
pub use backend::BlindbitBackend;

#[cfg(feature = "async")]
pub use backend_async::AsyncBlindbitBackend;

pub use client::{BlindbitClient, HttpClient};

#[cfg(feature = "ureq-client")]
pub use client::UreqClient;

#[cfg(feature = "async")]
pub use async_trait;
#[cfg(feature = "async")]
pub use futures;
#[cfg(feature = "async")]
pub use futures_util;

// Re-export core types and traits (avoiding module name conflicts)
pub use spdk_core::{
    BlockData,
    BlockDataIterator,
    ChainBackend,
    // Re-exported external types
    FeeRate,
    FilterData,
    OutputSpendStatus,
    OwnedOutput,
    Recipient,
    RecipientAddress,
    SilentPaymentUnsignedTransaction,
    SpClient,
    SpScanner,
    SpendKey,
    SpentIndexData,
    Updater,
    UtxoData,
    // Constants
    DATA_CARRIER_SIZE,
    DUST_THRESHOLD,
    NUMS,
    PSBT_SP_ADDRESS_KEY,
    PSBT_SP_PREFIX,
    PSBT_SP_SUBTYPE,
    PSBT_SP_TWEAK_KEY,
};

// Async types and traits - available with "async" feature
#[cfg(feature = "async")]
pub use spdk_core::{AsyncChainBackend, AsyncSpScanner, AsyncUpdater, BlockDataStream};
