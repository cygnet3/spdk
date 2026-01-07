//! State persistence for wallet scanning.
//!
//! This module provides traits for persisting wallet state during blockchain scanning,
//! including found outputs, spent inputs, and scanning progress.
//!
//! ## Traits
//!
//! - [`Updater`] - Synchronous persistence interface
//! - [`AsyncUpdater`] - Asynchronous persistence interface (requires `async` feature)
//!
//! ## Feature Requirements
//!
//! - Requires the `client` feature (outputs depend on client types)
//! - [`AsyncUpdater`] requires the `async` feature
//!
//! Implementations should handle storage (database, file system, etc.) and
//! ensure atomic updates where necessary.

mod updater;

#[cfg(feature = "async")]
pub use updater::AsyncUpdater;
pub use updater::Updater;
