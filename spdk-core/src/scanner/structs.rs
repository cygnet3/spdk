use std::collections::{HashMap, HashSet};

use bitcoin::absolute::Height;
use bitcoin::secp256k1::Scalar;
use bitcoin::{BlockHash, OutPoint, TxOut};
use silentpayments::receiving::Label;

#[derive(Debug)]
pub struct ScanResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredOutput {
    pub txout: TxOut,
    pub tweak: Scalar,
    pub label: Option<Label>,
}
