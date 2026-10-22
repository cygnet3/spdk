#[expect(clippy::module_inception)]
mod client;
mod coin_select;
mod spend;
mod spend_key;
mod structs;

pub use client::SpClient;
pub use coin_select::{CoinSelectProposal, DrainSelection, Strategy};
pub use spend::{propose_coin_selections, propose_drain_selection};
pub use spend_key::SpendKey;
pub use structs::*;
