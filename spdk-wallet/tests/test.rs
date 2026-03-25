use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use bitcoin::absolute::Height;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Scalar, SecretKey};
use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf};
use silentpayments::receiving::Label;
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
        .scan_blocks(
            block_height.to_consensus_u32()..=block_height.to_consensus_u32(),
            false,
            DUST_LIMIT,
            true,
        )
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
        .scan_blocks(
            first_block_height.to_consensus_u32()..=second_block_height.to_consensus_u32(),
            false,
            DUST_LIMIT,
            true,
        )
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

#[tokio::test]
async fn scan_single_block_with_output() {
    let expected_outpoint: OutPoint =
        "93a9b81f81244f8e6be29d8d6b0a9dbe6d6de6d2d4b018001ebf855bc870be88:0"
            .parse()
            .unwrap();

    let expected_tweak = Scalar::from_be_bytes(
        Vec::from_hex("78258954dccdba6597729dab70068bc4353ebd046f7156d9a3f8db8438b62aa5")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let expected_label: Option<Label> = None;
    let expected_value = Amount::from_sat(10000);

    // OP_PUSHNUM_1 OP_PUSHBYTES_32 dbd93fdd869e3522405749a594c2e3f4833ac98d0f4e70da6e7294f6623258c3
    let expected_script =
        ScriptBuf::from_hex("5120dbd93fdd869e3522405749a594c2e3f4833ac98d0f4e70da6e7294f6623258c3")
            .unwrap();

    let mock_backend = MockChainBackend {};

    let mock_update = MockUpdater::default();
    let updates = mock_update.updates.clone();

    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let spend_key = SpendKey::Secret(spend_sk);

    let network = Network::Signet;
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

    let block_height: u32 = 295125;

    scanner
        .scan_blocks(block_height..=block_height, false, DUST_LIMIT, true)
        .await
        .unwrap();

    let updates = updates.lock().unwrap();

    // first assert that we received exactly 1 update for this block
    assert!(updates.len() == 1);

    // update should contain a single output for this key pair
    let discovered_outputs = &updates[0].discovered_outputs;
    assert_eq!(discovered_outputs.len(), 1);

    let discovered_output = discovered_outputs.get(&expected_outpoint);

    assert!(discovered_output.is_some());

    assert_eq!(discovered_output.unwrap().script_pubkey, expected_script);
    assert_eq!(discovered_output.unwrap().tweak, expected_tweak);
    assert_eq!(discovered_output.unwrap().value, expected_value);
    assert_eq!(discovered_output.unwrap().label, expected_label);
}

#[tokio::test]
async fn scan_single_block_with_spent_input() {
    let owned_outpoint: OutPoint =
        "93a9b81f81244f8e6be29d8d6b0a9dbe6d6de6d2d4b018001ebf855bc870be88:0"
            .parse()
            .unwrap();

    let mock_backend = MockChainBackend {};

    let mock_update = MockUpdater::default();
    let updates = mock_update.updates.clone();

    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let spend_key = SpendKey::Secret(spend_sk);

    let network = Network::Signet;
    let keep_scanning = AtomicBool::new(true);
    let mut owned_outpoints = HashSet::new();

    owned_outpoints.insert(owned_outpoint);

    let client = SpClient::new(scan_sk, spend_key, network).unwrap();

    let mut scanner = SpScanner::new(
        client,
        Box::new(mock_update),
        Box::new(mock_backend),
        owned_outpoints,
        &keep_scanning,
    );

    let block_height: u32 = 295147;

    scanner
        .scan_blocks(block_height..=block_height, false, DUST_LIMIT, true)
        .await
        .unwrap();

    let updates = updates.lock().unwrap();

    // assert we received a single update
    assert!(updates.len() == 1);

    let discovered_inputs = &updates[0].discovered_inputs;

    // we discovered that our owned outpoint has been spent
    assert_eq!(discovered_inputs.len(), 1);

    let spent_outpoint = discovered_inputs.iter().next().unwrap();

    assert_eq!(*spent_outpoint, owned_outpoint);
}
