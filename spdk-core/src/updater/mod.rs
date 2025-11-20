mod updater;

#[cfg(feature = "async")]
pub use updater::AsyncUpdater;
pub use updater::Updater;
