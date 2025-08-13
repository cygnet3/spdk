mod backend;
#[cfg(feature = "blindbit-backend")]
mod blindbit;
mod http_client;
mod structs;

#[cfg(target_arch = "wasm32")]
pub use backend::ChainBackendWasm;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::ChainBackend;

pub use structs::*;

#[cfg(feature = "blindbit-backend")]
#[cfg(not(target_arch = "wasm32"))]
pub use blindbit::backend::NativeBlindbitBackend;

#[cfg(feature = "blindbit-backend")]
#[cfg(target_arch = "wasm32")]
pub use blindbit::backend::WasmBlindbitBackend;

#[cfg(target_arch = "wasm32")]
#[cfg(feature = "blindbit-backend")]
pub use blindbit::client::client::WasmBlindbitClient;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "blindbit-backend")]
pub use blindbit::client::client::NativeBlindbitClient;
