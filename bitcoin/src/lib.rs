#[cfg(feature = "31")]
use bitcoin_31 as bitcoin;

#[cfg(feature = "32")]
use bitcoin_32 as bitcoin;

pub use bitcoin::*;
