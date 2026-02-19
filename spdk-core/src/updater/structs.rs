use bitcoin::{secp256k1::Scalar, Amount, ScriptBuf};
use silentpayments::receiving::Label;

#[derive(Debug, Clone)]
pub struct SimplifiedOutput {
    pub tweak: Scalar,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub label: Option<Label>,
}
