#![allow(clippy::module_inception)]
mod backend;
mod client;

#[cfg(not(feature = "rayon"))]
mod thread_pool;

// Re-export backend functionality
pub use backend::BlindbitBackend;

pub use client::{BlindbitClient, HttpClient};

pub use client::UreqClient;

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
