mod backend;

#[cfg(target_arch = "wasm32")]
pub use backend::WasmBlindbitBackend;
#[cfg(not(target_arch = "wasm32"))]
pub use backend::NativeBlindbitBackend;
