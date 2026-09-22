pub mod client;

// re-export traits for consumers who need to provide valid implementors
// re-export blindbit backend if enabled
#[cfg(feature = "backend-blindbit-v1")]
pub use backend_blindbit_v1;
// re-export libraries for consumers
pub use bip321;
pub use bitcoin;
// re-export local scanner if enabled
#[cfg(feature = "scanner-local")]
pub use scanner_local::SpScanner;
pub use silentpayments;
pub use spdk_core::{chain, scanner};
