//! BIP-375 I/O Library
//!
//! Provides file I/O operations for PSBTs with optional JSON metadata.

pub mod error;
pub mod file_io;
pub mod metadata;

pub use error::{IoError, Result};
pub use file_io::*;
pub use metadata::*;
