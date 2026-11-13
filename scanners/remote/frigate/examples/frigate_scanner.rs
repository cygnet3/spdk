use std::collections::{HashMap, HashSet};

use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{BlockHash, Network, OutPoint};
use frigate::Scanner;
use spdk_core::scanner::{DiscoveredOutput, Scanner as _};
use spdk_wallet::client::{SpClient, SpendKey};

const NETWORK: Network = Network::Signet;
const FRIGATE_BACKEND_URL: &str = "100.81.213.115:50102";
// scan range settings
const SCAN_START_HEIGHT: u32 = 326_000;
const SCAN_END_HEIGHT: u32 = 326_595;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let scan_sk = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_sk = SecretKey::from_slice(&SPEND_SK_BYTES)?;

    let sp_client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), NETWORK)?;
    let sp_receiver = sp_client.receiver();

    let frigate_scanner = Scanner::new(
        FRIGATE_BACKEND_URL.to_owned(),
        scan_sk,
        sp_receiver,
        None,
        HashSet::new(),
    )
    .await?;

    println!("Receiving code for this key pair + network:");
    println!("{}", sp_client.receiving_code());

    let start = Height::from_consensus(SCAN_START_HEIGHT)?;
    let end = Height::from_consensus(SCAN_END_HEIGHT)?;

    // It's important to note that `scan_blocks` will not monitor scripts outputs.
    // Call `scan_blocks_with_spent_outputs` instead if you want to monitor spent outputs as well.
    let mut rx = frigate_scanner.scan_blocks(start..=end);

    while let Ok(update) = rx.recv().await {
        // print all received updates
        println!("{update:#?}");
    }

    Ok(())
}
