use bitcoin::{Amount, ScriptBuf, secp256k1::Scalar};
use silentpayments::receiving::Label;

#[derive(Debug, Clone)]
pub struct DiscoveredOutput {
    pub tweak: Scalar,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
    pub label: Option<Label>,
}
