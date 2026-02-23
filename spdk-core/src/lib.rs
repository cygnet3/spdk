#[cfg(all(feature = "async", feature = "sync"))]
compile_error!("Features `async` and `sync` are mutually exclusive. Use `--no-default-features --features sync` for a sync build.");

#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("Either feature `async` or `sync` must be enabled.");

pub mod chain;
pub mod constants;
pub mod updater;
