#[cfg(all(feature = "async", feature = "sync"))]
compile_error!(
    "Features `async` and `sync` are mutually exclusive. Use `--no-default-features --features sync` for a sync build."
);

#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("Either feature `async` or `sync` must be enabled.");

pub mod api_structs;

#[cfg(feature = "async")]
mod backend;
#[cfg(feature = "async")]
mod client;

#[cfg(feature = "sync")]
mod sync_backend;
#[cfg(feature = "async")]
pub use backend::BlindbitBackend;
#[cfg(feature = "async")]
pub use client::BlindbitClient;

#[cfg(feature = "sync")]
pub use sync_backend::SyncBlindbitBackend;
#[cfg(feature = "sync")]
pub use sync_client::SyncBlindbitClient;
