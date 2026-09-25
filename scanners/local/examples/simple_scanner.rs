use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;

use backend_blindbit_v1::{BlindbitBackend, BlindbitClient};
use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, Network, OutPoint};
use local_scanner::SpScanner;
use spdk_core::scanner::{DiscoveredOutput, Scanner as _};
use spdk_wallet::client::{SpClient, SpendKey};

// in this example, we use the public signet silentpayments.dev blindbit server
const BLINDBIT_BACKEND_URL: &str = "https://silentpayments.dev/blindbit/signet";
const NETWORK: Network = Network::Signet;

// scan range settings
const SCAN_START_HEIGHT: u32 = 200_000;
const SCAN_END_HEIGHT: u32 = 200_010;
const DUST_LIMIT: Amount = Amount::from_sat(546);
const WITH_CUTTHROUGH: bool = true;

// scan & spend key bytes, these should be randomly generated,
// but for this example we use simple byte arrays
const SCAN_SK_BYTES: [u8; 32] = [0x01; 32];
const SPEND_SK_BYTES: [u8; 32] = [0x02; 32];

static KEEP_SCANNING: AtomicBool = AtomicBool::new(true);

#[derive(Debug)]
pub struct UpdateResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scan_sk = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_sk = SecretKey::from_slice(&SPEND_SK_BYTES)?;

    let backend = BlindbitBackend::new(BlindbitClient::new(BLINDBIT_BACKEND_URL)?);

    let client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), NETWORK)?;
    let sp_receiver = client.receiver();

    println!("Receiving code for this key pair + network:");
    println!("{}", client.receiving_code());

    let scanner = SpScanner::new(
        Box::new(backend),
        scan_sk,
        sp_receiver,
        HashSet::new(),
        DUST_LIMIT,
        WITH_CUTTHROUGH,
        &KEEP_SCANNING,
    );

    let start = Height::from_consensus(SCAN_START_HEIGHT)?;
    let end = Height::from_consensus(SCAN_END_HEIGHT)?;

    let mut rx = scanner.scan_blocks(start..=end);

    while let Ok(update) = rx.recv().await {
        // print all received updates
        println!("{update:#?}");
    }

    Ok(())
}
