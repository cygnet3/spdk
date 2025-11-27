mod dummy_updater;
mod updater;

pub use dummy_updater::DummyUpdater;
#[cfg(feature = "async")]
pub use updater::AsyncUpdater;
pub use updater::Updater;
