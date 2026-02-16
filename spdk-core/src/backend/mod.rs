mod structs;

#[cfg(feature = "sync")]
mod sync_trait;
#[cfg(feature = "async")]
mod r#trait;

#[cfg(feature = "async")]
pub use r#trait::ChainBackend;
pub use structs::*;
#[cfg(feature = "sync")]
pub use sync_trait::SyncChainBackend;
