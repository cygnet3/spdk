// HTTP Client module for both native and WASM targets
// This module provides a unified interface for HTTP operations

#[cfg(all(feature = "blindbit-native", not(target_arch = "wasm32")))]
pub mod native;

#[cfg(all(feature = "blindbit-wasm", target_arch = "wasm32"))]
pub mod wasm; 
