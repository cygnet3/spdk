use bitcoin::{Amount, Txid, XOnlyPublicKey};

pub struct UtxoData {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
    pub output_key: XOnlyPublicKey,
    pub spent: bool,
}

pub struct SpentIndexData {
    pub data: Vec<Vec<u8>>,
}
