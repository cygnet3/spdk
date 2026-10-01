pub mod client;

// re-export blindbit backend if enabled
#[cfg(feature = "backend-blindbit-v1")]
pub use backend_blindbit_v1;
// re-export libraries for consumers
pub use bip321;
pub use bitcoin;
// re-export local scanner if enabled
#[cfg(feature = "local-scanner")]
pub use local_scanner::SpScanner;
// BIP-375 extensions. The PSBT type and upstream roles come from psbt_v2.
pub use psbt::{extractor, signer};
pub use psbt_v2;
pub use silentpayments;
pub use spdk_core::{chain, scanner};
