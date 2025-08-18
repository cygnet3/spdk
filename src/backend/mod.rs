mod chain_backend;
mod blindbit;
mod http_client;
pub mod structs;

#[cfg(all(feature = "blindbit-wasm", target_arch = "wasm32"))]
pub use chain_backend::ChainBackendWasm;

#[cfg(all(feature = "blindbit-native", not(target_arch = "wasm32")))]
pub use chain_backend::ChainBackend;

pub use structs::*;

#[cfg(all(feature = "blindbit-native", not(target_arch = "wasm32")))]
pub use crate::backend::blindbit::backend::native::NativeBlindbitBackend;

#[cfg(all(feature = "blindbit-wasm", target_arch = "wasm32"))]
pub use crate::backend::blindbit::backend::wasm::WasmBlindbitBackend;

#[cfg(all(feature = "blindbit-wasm", target_arch = "wasm32"))]
pub use blindbit::client::wasm::WasmBlindbitClient;

#[cfg(all(feature = "blindbit-native", not(target_arch = "wasm32")))]
pub use blindbit::client::native::NativeBlindbitClient;
