#[cfg(all(feature = "async", feature = "sync"))]
compile_error!("Features `async` and `sync` are mutually exclusive. Use `--no-default-features --features sync` for a sync build.");

#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("Either feature `async` or `sync` must be enabled.");

mod backend;
mod client;
pub mod constants;
mod scanner;
mod updater;

pub use bdk_coin_select::FeeRate;
pub use bitcoin;
pub use silentpayments;

pub use backend::*;
pub use client::*;
pub use scanner::SpScanner;
pub use updater::Updater;
