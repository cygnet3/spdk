pub mod client;
pub mod structs;

#[cfg(target_arch = "wasm32")]
pub use client::WasmBlindbitClient;

#[cfg(not(target_arch = "wasm32"))]
pub use client::NativeBlindbitClient;

pub use client::BlindbitClient;
