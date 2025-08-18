mod client;
pub mod constants;

pub use bdk_coin_select::FeeRate;
pub use bitcoin;
pub use silentpayments;
pub use futures;

pub use client::*;

#[cfg(feature = "blindbit-backend")]
mod backend;
#[cfg(feature = "blindbit-backend")]
mod scanner;
#[cfg(feature = "blindbit-backend")]
mod updater;

#[cfg(feature = "blindbit-backend")]
pub use {
    backend::*,
    scanner::SpScanner,
    updater::Updater,
};
