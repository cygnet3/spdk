use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, Network};
use spdk_wallet::client::{SpClient, SpendKey};
use spdk_wallet::scanner::SpScanner;

use crate::mock::chain::MockChainBackend;
use crate::mock::updater::MockUpdater;

mod mock;

const DUST_LIMIT: Amount = Amount::from_sat(546);

#[tokio::test]
async fn simple_scan_single_block() {
    let mock_backend = MockChainBackend {};

    let mock_update = MockUpdater::default();
    let updates = mock_update.updates.clone();

    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let spend_key = SpendKey::Secret(spend_sk);

    let network = Network::Bitcoin;
    let keep_scanning = AtomicBool::new(true);
    let owned_outpoints = HashSet::new();

    let client = SpClient::new(scan_sk, spend_key, network).unwrap();

    let mut scanner = SpScanner::new(
        client,
        Box::new(mock_update),
        Box::new(mock_backend),
        owned_outpoints,
        &keep_scanning,
    );

    let block_height: Height = Height::from_consensus(200000).unwrap();
    let block_hash: BlockHash = "0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c"
        .parse()
        .unwrap();

    scanner
        .scan_blocks(block_height, block_height, Amount::from_sat(546), true)
        .await
        .unwrap();

    let updates = updates.lock().unwrap();

    // assert that we received exactly 1 update
    assert!(updates.len() == 1);

    // block info is consistent
    assert_eq!(updates[0].blkheight, block_height);
    assert_eq!(updates[0].blkhash, block_hash);
    // update does not contain any relevant transaction info
    assert!(updates[0].discovered_inputs.is_empty());
    assert!(updates[0].discovered_outputs.is_empty());
}

#[tokio::test]
async fn simple_scan_multiple_blocks() {
    let mock_backend = MockChainBackend {};

    let mock_update = MockUpdater::default();
    let updates = mock_update.updates.clone();

    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let spend_key = SpendKey::Secret(spend_sk);

    let network = Network::Bitcoin;
    let keep_scanning = AtomicBool::new(true);
    let owned_outpoints = HashSet::new();

    let client = SpClient::new(scan_sk, spend_key, network).unwrap();

    let mut scanner = SpScanner::new(
        client,
        Box::new(mock_update),
        Box::new(mock_backend),
        owned_outpoints,
        &keep_scanning,
    );

    let first_block_height: Height = Height::from_consensus(200000).unwrap();
    let first_block_hash: BlockHash =
        "0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c"
            .parse()
            .unwrap();

    let second_block_height: Height = Height::from_consensus(200001).unwrap();
    let second_block_hash: BlockHash =
        "000000ad6bf1ea934186822de99a611924d94aff8fbcb1ad6be2c790c3b92ae1"
            .parse()
            .unwrap();

    scanner
        .scan_blocks(first_block_height, second_block_height, DUST_LIMIT, true)
        .await
        .unwrap();

    let updates = updates.lock().unwrap();

    // assert that we received 2 updates
    assert!(updates.len() == 2);

    // the first update relates to the first block
    assert_eq!(updates[0].blkheight, first_block_height);
    assert_eq!(updates[0].blkhash, first_block_hash);

    // the second update relates to the second block
    assert_eq!(updates[1].blkheight, second_block_height);
    assert_eq!(updates[1].blkhash, second_block_hash);
}
