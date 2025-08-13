pub mod backend;
pub mod client;

#[cfg(target_arch = "wasm32")]
pub use backend::WasmBlindbitBackend;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::NativeBlindbitBackend;

#[cfg(target_arch = "wasm32")]
pub use client::WasmBlindbitClient;

#[cfg(not(target_arch = "wasm32"))]
pub use client::NativeBlindbitClient;