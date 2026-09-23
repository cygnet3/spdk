use bitcoin::TxOut;
use bitcoin::secp256k1::Scalar;
use silentpayments::receiving::Label;

#[derive(Debug, Clone)]
pub struct DiscoveredOutput {
    pub txout: TxOut,
    pub tweak: Scalar,
    pub label: Option<Label>,
}
