mod backend;

// Async backend - available by default, excluded when "sync" feature is enabled
#[cfg(feature = "async")]
mod backend_async;

pub use backend::{BlockDataIterator, ChainBackend};

#[cfg(feature = "async")]
pub use backend_async::{AsyncChainBackend, BlockDataStream};
