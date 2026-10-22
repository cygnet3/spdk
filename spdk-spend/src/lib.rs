mod client;
mod coin_select;
mod spend;
mod structs;

pub use client::SpClient;
pub use coin_select::{CoinSelectProposal, DrainSelection, Strategy};
pub use spend::{propose_coin_selections, propose_drain_selection};
pub use structs::*;
