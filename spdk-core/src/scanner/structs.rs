use std::collections::{HashMap, HashSet};

use bitcoin::secp256k1::Scalar;
use bitcoin::{Amount, ScriptBuf};
use silentpayments::receiving::Label;

use bitcoin::{BlockHash, OutPoint, absolute::Height};

#[derive(Debug)]
pub struct ScanResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredOutput {
    pub tweak: Scalar,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub label: Option<Label>,
}
