use crate::core::{Error, Psbt, Result};
use bitcoin::Transaction;
use psbt_v2::v2::Extractor;

pub trait ExtractorPsbtExt {
    fn extract_tx(self) -> Result<Transaction>;
}

impl ExtractorPsbtExt for Psbt {
    fn extract_tx(self) -> Result<Transaction> {
        let extract_tx = Extractor::new(self)
            .map_err(|_e| Error::InvalidPsbtState(format!("Psbt not finalized")))?
            .extract_tx()
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(extract_tx)
    }
}
