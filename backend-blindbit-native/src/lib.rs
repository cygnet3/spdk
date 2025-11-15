mod backend;
#[cfg(feature = "async")]
mod backend_async;
mod client;

// Re-export backend functionality based on features
#[cfg(feature = "sync")]
pub use backend::BlindbitBackend;

#[cfg(feature = "async")]
pub use backend_async::AsyncBlindbitBackend;

pub use client::{BlindbitClient, HttpClient};

#[cfg(feature = "ureq-client")]
pub use client::UreqClient;

pub use futures_util;
pub use async_trait;
pub use futures;

// Re-export core types and traits (avoiding module name conflicts)
pub use spdk_core::{
    BlockData, BlockDataIterator, ChainBackend, FilterData, OwnedOutput, OutputSpendStatus,
    Recipient, RecipientAddress, SilentPaymentUnsignedTransaction, SpClient, SpendKey,
    SpentIndexData, Updater, UtxoData,
    // Constants
    DATA_CARRIER_SIZE, DUST_THRESHOLD, NUMS, PSBT_SP_ADDRESS_KEY, PSBT_SP_PREFIX, PSBT_SP_SUBTYPE,
    PSBT_SP_TWEAK_KEY,
    // Re-exported external types
    FeeRate,
};
