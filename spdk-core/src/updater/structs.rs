use bitcoin::{absolute::Height, Amount, ScriptBuf};
use serde::{Deserialize, Serialize};
use silentpayments::receiving::Label;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spend_status: OutputSpendStatus,
}

type SpendingTxId = [u8; 32];
type MinedInBlock = [u8; 32];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum OutputSpendStatus {
    Unspent,
    Spent(SpendingTxId),
    Mined(MinedInBlock),
}
