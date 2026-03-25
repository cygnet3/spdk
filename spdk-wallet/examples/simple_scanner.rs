use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, atomic::AtomicBool},
};

use backend_blindbit_v1::{BlindbitBackend, BlindbitClient};
use bitcoin::{Amount, BlockHash, Network, OutPoint, absolute::Height, secp256k1::SecretKey};
use spdk_core::updater::{DiscoveredOutput, Updater};
use spdk_wallet::{
    client::{SpClient, SpendKey},
    scanner::SpScanner,
};

// in this example, we use the public signet silentpayments.dev blindbit server
const BLINDBIT_BACKEND_URL: &str = "https://silentpayments.dev/blindbit/signet";
const NETWORK: Network = Network::Signet;

// scan range settings
const SCAN_START_HEIGHT: u32 = 200000;
const SCAN_END_HEIGHT: u32 = 200010;
const DUST_LIMIT: Amount = Amount::from_sat(546);
const WITH_CUTTHROUGH: bool = true;

// scan & spend key bytes, these should be randomly generated,
// but for this example we use simple byte arrays
const SCAN_SK_BYTES: [u8; 32] = [0x01; 32];
const SPEND_SK_BYTES: [u8; 32] = [0x02; 32];

#[derive(Debug)]
pub struct UpdateResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

#[derive(Clone)]
struct InMemoryUpdater {
    received_updates: Arc<Mutex<Vec<UpdateResult>>>,
}

impl InMemoryUpdater {
    fn new() -> Self {
        Self {
            received_updates: Default::default(),
        }
    }

    fn print_results(&self) {
        let updates = self.received_updates.lock().unwrap();

        for update in updates.iter() {
            println!("{update:#?}");
        }
    }
}

impl Updater for InMemoryUpdater {
    fn record_block_scan_result(
        &mut self,
        blkheight: Height,
        blkhash: BlockHash,
        discovered_inputs: HashSet<OutPoint>,
        discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
    ) -> anyhow::Result<()> {
        self.received_updates.lock().unwrap().push(UpdateResult {
            blkheight,
            blkhash,
            discovered_inputs,
            discovered_outputs,
        });

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scan_sk = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_sk = SecretKey::from_slice(&SPEND_SK_BYTES)?;

    // for a real scan, we can set this bool to false to interrupt the scan process
    // in this example, we keep it set to true
    let keep_scanning = AtomicBool::new(true);

    let backend = BlindbitBackend::new(BlindbitClient::new(BLINDBIT_BACKEND_URL)?);

    // we use a simple in-memory updater struct that stores all received updates in a vector
    let updater = InMemoryUpdater::new();

    let client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), NETWORK)?;

    println!("Receiving address for this key pair + network:");
    println!("{}", client.get_receiving_address());

    let mut scanner = SpScanner::new(
        client,
        Box::new(updater.clone()),
        Box::new(backend),
        HashSet::new(),
        &keep_scanning,
    );

    scanner
        .scan_blocks(
            SCAN_START_HEIGHT..=SCAN_END_HEIGHT,
            false,
            DUST_LIMIT,
            WITH_CUTTHROUGH,
        )
        .await?;

    // print all received updates
    updater.print_results();

    Ok(())
}
