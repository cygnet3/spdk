use crate::{ChainBackend, OutputSpendStatus, OwnedOutput, SpClient, SpScanner, Updater};
use bitcoin::{
    absolute::Height,
    bip158::BlockFilter,
    hashes::{sha256, Hash},
    secp256k1::{self, All, PublicKey, SecretKey},
    OutPoint,
};
use silentpayments::SilentPaymentAddress;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

pub struct SpAccount<B, U>
where
    B: ChainBackend,
    U: Updater,
{
    backend: B,
    client: SpClient,
    updater: U,
    stop: Arc<AtomicBool>,
    owned_outpoints: HashSet<OutPoint>,
}

impl<B: ChainBackend, U: Updater> SpAccount<B, U> {
    pub fn new(backend: B, client: SpClient, updater: U, stop: Arc<AtomicBool>) -> Self {
        Self {
            backend,
            client,
            updater,
            stop,
            owned_outpoints: Default::default(),
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn get_sp_address(&self) -> SilentPaymentAddress {
        self.client.get_receiving_address()
    }

    pub fn outpoints(&self) -> Vec<OutPoint> {
        self.owned_outpoints.clone().into_iter().collect()
    }

    pub fn block_height(&self) -> crate::error::Result<Height> {
        self.backend.block_height()
    }

    pub fn scan_key(&self) -> SecretKey {
        self.client.get_scan_key()
    }

    pub fn spend_key(&self, secp: &secp256k1::Secp256k1<All>) -> PublicKey {
        match self.client.get_spend_key() {
            crate::SpendKey::Secret(secret_key) => secret_key.public_key(secp),
            crate::SpendKey::Public(pubkey) => pubkey,
        }
    }
}

impl<B: ChainBackend, U: Updater> SpScanner for SpAccount<B, U> {
    fn scan_blocks(
        &mut self,
        start: bitcoin::absolute::Height,
        end: bitcoin::absolute::Height,
        dust_limit: Option<bitcoin::Amount>,
        with_cutthrough: bool,
    ) -> crate::error::Result<()> {
        if start > end {
            return Err(crate::error::Error::InvalidRange(
                start.to_consensus_u32(),
                end.to_consensus_u32(),
            ));
        }

        log::info!("start: {} end: {}", start, end);
        let start_time: Instant = Instant::now();

        // get block data iterator
        let range = start.to_consensus_u32()..=end.to_consensus_u32();
        let block_data_stream =
            self.backend
                .get_block_data_for_range(range, dust_limit, with_cutthrough);

        // process blocks using block data stream
        self.process_blocks(start, end, block_data_stream)?;

        // time elapsed for the scan
        log::info!(
            "Blindbit scan completed in {} seconds",
            start_time.elapsed().as_secs()
        );

        Ok(())
    }

    fn process_block(
        &mut self,
        blockdata: crate::BlockData,
    ) -> crate::error::Result<(
        std::collections::HashMap<bitcoin::OutPoint, crate::OwnedOutput>,
        std::collections::HashSet<bitcoin::OutPoint>,
    )> {
        let crate::BlockData {
            blkheight,
            blkhash: _,
            tweaks,
            new_utxo_filter,
            spent_filter,
        } = blockdata;

        let outs = self.process_block_outputs(blkheight, tweaks, new_utxo_filter)?;

        // after processing outputs, we add the found outputs to our list
        self.owned_outpoints.extend(outs.keys());

        let ins = self.process_block_inputs(blkheight, spent_filter)?;

        // after processing inputs, we remove the found inputs
        self.owned_outpoints.retain(|item| !ins.contains(item));

        Ok((outs, ins))
    }

    fn process_block_outputs(
        &self,
        blkheight: bitcoin::absolute::Height,
        tweaks: Vec<bitcoin::secp256k1::PublicKey>,
        new_utxo_filter: crate::FilterData,
    ) -> crate::error::Result<std::collections::HashMap<bitcoin::OutPoint, crate::OwnedOutput>> {
        let mut res = HashMap::new();

        if !tweaks.is_empty() {
            let secrets_map = self.client.get_script_to_secret_map(tweaks)?;

            //last_scan = last_scan.max(n as u32);
            let candidate_spks: Vec<&[u8; 34]> = secrets_map.keys().collect();

            //get block gcs & check match
            let blkfilter = BlockFilter::new(&new_utxo_filter.data);
            let blkhash = new_utxo_filter.block_hash;

            let matched_outputs = Self::check_block_outputs(blkfilter, blkhash, candidate_spks)?;

            //if match: fetch and scan utxos
            if matched_outputs {
                log::info!("matched outputs on: {}", blkheight);
                let found = self.scan_utxos(blkheight, secrets_map)?;

                if !found.is_empty() {
                    for (label, utxo, tweak) in found {
                        let outpoint = OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        };

                        let out = OwnedOutput {
                            blockheight: blkheight,
                            tweak: tweak.to_be_bytes(),
                            amount: utxo.value,
                            script: utxo.scriptpubkey,
                            label,
                            spend_status: OutputSpendStatus::Unspent,
                        };

                        res.insert(outpoint, out);
                    }
                }
            }
        }
        Ok(res)
    }

    fn process_block_inputs(
        &self,
        blkheight: bitcoin::absolute::Height,
        spent_filter: crate::FilterData,
    ) -> crate::error::Result<std::collections::HashSet<bitcoin::OutPoint>> {
        let mut res = HashSet::new();

        let blkhash = spent_filter.block_hash;

        // first get the 8-byte hashes used to construct the input filter
        let input_hashes_map = self.get_input_hashes(blkhash)?;

        // check against filter
        let blkfilter = BlockFilter::new(&spent_filter.data);
        let matched_inputs = self.check_block_inputs(
            blkfilter,
            blkhash,
            input_hashes_map.keys().cloned().collect(),
        )?;

        // if match: download spent data, collect the outpoints that are spent
        if matched_inputs {
            log::info!("matched inputs on: {}", blkheight);
            let spent = self.backend.spent_index(blkheight)?.data;

            for spent in spent {
                let hex: &[u8] = spent.as_ref();

                if let Some(outpoint) = input_hashes_map.get(hex) {
                    res.insert(*outpoint);
                }
            }
        }
        Ok(res)
    }

    fn get_block_data_iterator(
        &self,
        range: std::ops::RangeInclusive<u32>,
        dust_limit: Option<bitcoin::Amount>,
        with_cutthrough: bool,
    ) -> crate::BlockDataIterator {
        self.backend
            .get_block_data_for_range(range, dust_limit, with_cutthrough)
    }

    fn should_interrupt(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn save_state(&mut self) -> crate::error::Result<()> {
        self.updater.save_to_persistent_storage()
    }

    fn record_outputs(
        &mut self,
        height: bitcoin::absolute::Height,
        block_hash: bitcoin::BlockHash,
        outputs: std::collections::HashMap<bitcoin::OutPoint, crate::OwnedOutput>,
    ) -> crate::error::Result<()> {
        self.updater
            .record_block_outputs(height, block_hash, outputs)
    }

    fn record_inputs(
        &mut self,
        height: bitcoin::absolute::Height,
        block_hash: bitcoin::BlockHash,
        inputs: std::collections::HashSet<bitcoin::OutPoint>,
    ) -> crate::error::Result<()> {
        self.updater.record_block_inputs(height, block_hash, inputs)
    }

    fn record_progress(
        &mut self,
        start: bitcoin::absolute::Height,
        current: bitcoin::absolute::Height,
        end: bitcoin::absolute::Height,
    ) -> crate::error::Result<()> {
        self.updater.record_scan_progress(start, current, end)
    }

    fn client(&self) -> &SpClient {
        &self.client
    }

    fn backend(&self) -> &dyn ChainBackend {
        &self.backend
    }

    fn updater(&mut self) -> &mut dyn Updater {
        &mut self.updater
    }

    fn get_input_hashes(
        &self,
        blkhash: bitcoin::BlockHash,
    ) -> crate::error::Result<std::collections::HashMap<[u8; 8], bitcoin::OutPoint>> {
        let mut map: HashMap<[u8; 8], OutPoint> = HashMap::new();

        for outpoint in &self.owned_outpoints {
            let mut arr = [0u8; 68];
            arr[..32].copy_from_slice(outpoint.txid.to_raw_hash().as_byte_array());
            arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
            arr[36..].copy_from_slice(&blkhash.to_byte_array());
            let hash = sha256::Hash::hash(&arr);

            let mut res = [0u8; 8];
            res.copy_from_slice(&hash[..8]);

            map.insert(res, *outpoint);
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{updater::DummyUpdater, SpentIndexData, UtxoData};
    use bitcoin::{absolute::Height, Amount, Network};
    use std::ops::RangeInclusive;

    /// Mock backend for testing stop flag behavior
    struct MockBackend;

    impl ChainBackend for MockBackend {
        fn get_block_data_for_range(
            &self,
            _range: RangeInclusive<u32>,
            _dust_limit: Option<Amount>,
            _with_cutthrough: bool,
        ) -> crate::BlockDataIterator {
            Box::new(std::iter::empty())
        }

        fn spent_index(&self, _block_height: Height) -> crate::error::Result<SpentIndexData> {
            Ok(SpentIndexData { data: vec![] })
        }

        fn utxos(&self, _block_height: Height) -> crate::error::Result<Vec<UtxoData>> {
            Ok(vec![])
        }

        fn block_height(&self) -> crate::error::Result<Height> {
            Ok(Height::from_consensus(100).expect("valid height"))
        }
    }

    fn create_test_sp_client() -> SpClient {
        let mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        SpClient::new_from_mnemonic(mnemonic, Network::Regtest).unwrap()
    }

    #[test]
    fn test_stop_flag_initial_state() {
        let stop = Arc::new(AtomicBool::new(false));
        let account = SpAccount::new(
            MockBackend,
            create_test_sp_client(),
            DummyUpdater::new(),
            stop.clone(),
        );

        // Initially should not be interrupted
        assert!(!account.should_interrupt());
    }

    #[test]
    fn test_stop_flag_after_external_set() {
        let stop = Arc::new(AtomicBool::new(false));
        let account = SpAccount::new(
            MockBackend,
            create_test_sp_client(),
            DummyUpdater::new(),
            stop.clone(),
        );

        // Set stop flag externally (simulating what bwk-sp does)
        stop.store(true, Ordering::Relaxed);

        // should_interrupt() should now return true
        assert!(account.should_interrupt());
    }

    #[test]
    fn test_stop_method_sets_flag() {
        let stop = Arc::new(AtomicBool::new(false));
        let account = SpAccount::new(
            MockBackend,
            create_test_sp_client(),
            DummyUpdater::new(),
            stop.clone(),
        );

        assert!(!account.should_interrupt());

        // Call the stop method
        account.stop();

        // Both the shared flag and should_interrupt should reflect the change
        assert!(stop.load(Ordering::Relaxed));
        assert!(account.should_interrupt());
    }

    #[test]
    fn test_shared_stop_flag_across_accounts() {
        // This test verifies the key use case: multiple SpAccounts sharing
        // the same stop flag (as in bwk-sp's continuous scan loop)
        let shared_stop = Arc::new(AtomicBool::new(false));

        let account1 = SpAccount::new(
            MockBackend,
            create_test_sp_client(),
            DummyUpdater::new(),
            shared_stop.clone(),
        );

        // Neither should be interrupted initially
        assert!(!account1.should_interrupt());

        // Setting the shared flag affects account1
        shared_stop.store(true, Ordering::Relaxed);
        assert!(account1.should_interrupt());

        // Create a new account with the same flag (simulates loop iteration)
        let account2 = SpAccount::new(
            MockBackend,
            create_test_sp_client(),
            DummyUpdater::new(),
            shared_stop.clone(),
        );

        // account2 should also see the stop signal immediately
        assert!(account2.should_interrupt());
    }
}
