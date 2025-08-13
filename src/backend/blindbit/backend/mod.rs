mod backend;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::NativeBlindbitBackend;
#[cfg(target_arch = "wasm32")]
pub use backend::WasmBlindbitBackend;
