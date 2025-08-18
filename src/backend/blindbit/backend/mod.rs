#[cfg(all(feature = "blindbit-native", not(target_arch = "wasm32")))]
pub mod native;
#[cfg(all(feature = "blindbit-wasm", target_arch = "wasm32"))]
pub mod wasm;
