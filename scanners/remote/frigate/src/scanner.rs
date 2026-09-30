use std::collections::HashSet;

use bitcoin::{OutPoint, absolute::Height, secp256k1::SecretKey};
use futures::channel::mpsc;
use spdk_core::{chain::BoxedChainBackend, scanner::{ScanResult, Scanner}};
use silentpayments::receiving::Receiver as SpReceiver;


struct FrigateScanner {
    backend: BoxedChainBackend,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    owned_outpoints: HashSet<OutPoint>,
}

impl FrigateScanner {
    pub fn new(
        backend: BoxedChainBackend,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        owned_outpoints: HashSet<OutPoint>) -> Self {
            Self {
                backend,
                b_scan,
                sp_receiver,
                owned_outpoints
            }
        }
}

impl Scanner for FrigateScanner {
    fn scan_blocks(self, range: std::ops::RangeInclusive<Height>) -> mpsc::Receiver<ScanResult> {
        todo!()
    }
}

// /
// / let backend = FrigateClient::connect("https://127.0.0.1:50001")?;
// / let scanner = FrigateSCanner::new(backend, b_scan, sp_receiver, owned_outpoints)?;
// / scanner.scan_outputs(start..=end)?;
// User can next then apply the results to the wallet view

