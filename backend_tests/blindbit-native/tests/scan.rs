use backend_blindbit_native::UreqClient;
use bitcoin::{
    bip32::ChildNumber,
    secp256k1::{self},
    Amount, OutPoint,
};
use blindbit_native::{
    clear_logs, generate_recipient_pubkey, generate_recipient_pubkey_segwit, scan, swap_to_sp,
    swap_to_sp_segwit, verify_recipient_pubkey, wait_until_sync_at_height,
};
use blindbitd::{BlindbitD, Conf, Storage};
use bwk_sign::{
    bwk_descriptor::{descriptor::DescriptorDerivator, tr_path, wpkh_path},
    HotSigner,
};
use bwk_utils::test::{self};
use spdk_core::{account::SpAccount, bip39, updater::DummyUpdater, SpClient};

/// Test scan with FullBasic storage (uses `/tweak-index`, no dust filtering)
#[test]
fn test_scan_full_basic() {
    let conf = Conf::with_storage(Storage::FullBasic);
    run_scan_test(conf, false);
}

/// Test scan with DustFilter storage (uses `/tweak-index`, with dust filtering)
#[test]
fn test_scan_dust_filter() {
    let conf = Conf::with_storage(Storage::DustFilter);
    run_scan_test(conf, false);
}

/// Test scan with DustFilterCutThrough storage (uses `/tweaks`, with cut-through)
#[test]
fn test_scan_cut_through() {
    let conf = Conf::with_storage(Storage::DustFilterCutThrough);
    run_scan_test(conf, true);
}

/// Helper function to run a scan test with the given configuration.
///
/// # Arguments
/// - `conf`: Server configuration specifying the storage strategy
/// - `with_cutthrough`: Whether to use the `/tweaks` endpoint (true) or `/tweak-index` (false)
#[allow(non_snake_case)]
fn run_scan_test(conf: Conf, with_cutthrough: bool) {
    println!("run_scan_test() conf: {:?}, with_cutthrough: {}", conf, with_cutthrough);
    let secp = secp256k1::Secp256k1::new();
    let network = bwk_sign::miniscript::bitcoin::Network::Regtest;
    let mut bbd = BlindbitD::with_conf(&conf).unwrap();

    let client = UreqClient::new();
    let backend = backend_blindbit_native::BlindbitBackend::new(bbd.url(), client).unwrap();
    let mut bitcoind_node = bbd.bitcoin().unwrap();
    let bitcoind = &mut bitcoind_node.client;

    let mnemonic = bip39::Mnemonic::generate(12).unwrap();
    let sp_client = SpClient::new_from_mnemonic(mnemonic.clone(), network).unwrap();
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, &mnemonic.to_string()).unwrap();
    let tr_derivator = tr_signer
        .descriptors()
        .into_iter()
        .next()
        .unwrap()
        .spk_derivator(network)
        .unwrap();
    let addr1 = tr_derivator.receive_at(0);
    let path = tr_path(network, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    // Receive account
    let path = path.child(ChildNumber::from_normal_idx(0).unwrap());
    // Index 0
    let path = path.child(ChildNumber::from_normal_idx(0).unwrap());
    let sk = tr_signer.private_key_at(&path);

    let updater = DummyUpdater::new();
    let mut sp_acc = SpAccount::new(backend, sp_client, updater);
    let sp_account = &mut sp_acc;

    test::generate_blocks(bitcoind, 120);
    wait_until_sync_at_height(sp_account, 120);

    let txid = test::send(bitcoind, addr1.clone(), 0.1).unwrap();
    test::generate_blocks(bitcoind, 2);
    let tx = test::get_tx(bitcoind, txid).unwrap();
    let tx_height = test::get_tx_height(bitcoind, txid);
    assert!(tx_height.is_some());
    let (index, txout) = test::txouts_for(&addr1, &tx).into_iter().next().unwrap();

    let sp_addr = sp_account.get_sp_address();
    let outpoint = OutPoint {
        txid,
        vout: index as u32,
    };
    let fees = Amount::from_sat(400);
    let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_addr, &secp).unwrap();
    assert!(verify_recipient_pubkey(
        sp_account.scan_key(),
        sp_account.spend_key(&secp),
        outpoint,
        &txout,
        recipient_pubkey,
        &secp
    ));
    let swap_tx = swap_to_sp(sk, outpoint, txout, recipient_pubkey, fees, &secp).unwrap();

    // broadcast
    let txid = bitcoind
        .send_raw_transaction(&swap_tx)
        .unwrap()
        .txid()
        .unwrap();
    test::generate_blocks(bitcoind, 2);
    let tx_height = test::get_tx_height(bitcoind, txid);
    assert!(tx_height.is_some());
    wait_until_sync_at_height(sp_account, 124);

    clear_logs(&mut bbd);

    scan(sp_account, 1, 124, 0, with_cutthrough).unwrap();

    let op = sp_account.outpoints().into_iter().next().unwrap();
    let expected_op = OutPoint { txid, vout: 0 };
    assert_eq!(op, expected_op);
}

/// Test scan with segwit (P2WPKH) input funding the SP wallet
#[test]
fn test_scan_segwit() {
    let conf = Conf::with_storage(Storage::FullBasic);
    run_scan_test_segwit(conf, false);
}

/// Helper function to run a scan test with segwit (P2WPKH) funding.
///
/// # Arguments
/// - `conf`: Server configuration specifying the storage strategy
/// - `with_cutthrough`: Whether to use the `/tweaks` endpoint (true) or `/tweak-index` (false)
#[allow(non_snake_case)]
fn run_scan_test_segwit(conf: Conf, with_cutthrough: bool) {
    println!(
        "run_scan_test_segwit() conf: {:?}, with_cutthrough: {}",
        conf, with_cutthrough
    );
    let secp = secp256k1::Secp256k1::new();
    let network = bwk_sign::miniscript::bitcoin::Network::Regtest;
    let mut bbd = BlindbitD::with_conf(&conf).unwrap();

    let client = UreqClient::new();
    let backend = backend_blindbit_native::BlindbitBackend::new(bbd.url(), client).unwrap();
    let mut bitcoind_node = bbd.bitcoin().unwrap();
    let bitcoind = &mut bitcoind_node.client;

    let mnemonic = bip39::Mnemonic::generate(12).unwrap();
    let sp_client = SpClient::new_from_mnemonic(mnemonic.clone(), network).unwrap();

    // Use WPKH signer instead of taproot
    let wpkh_signer =
        HotSigner::new_wpkh_from_mnemonics(network, &mnemonic.to_string()).unwrap();
    let wpkh_derivator = wpkh_signer
        .descriptors()
        .into_iter()
        .next()
        .unwrap()
        .spk_derivator(network)
        .unwrap();
    let addr1 = wpkh_derivator.receive_at(0);

    // Use BIP84 path for segwit
    let path = wpkh_path(network, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    // Receive account
    let path = path.child(ChildNumber::from_normal_idx(0).unwrap());
    // Index 0
    let path = path.child(ChildNumber::from_normal_idx(0).unwrap());
    let sk = wpkh_signer.private_key_at(&path);

    let updater = DummyUpdater::new();
    let mut sp_acc = SpAccount::new(backend, sp_client, updater);
    let sp_account = &mut sp_acc;

    test::generate_blocks(bitcoind, 120);
    wait_until_sync_at_height(sp_account, 120);

    // Fund the segwit address
    let txid = test::send(bitcoind, addr1.clone(), 0.1).unwrap();
    test::generate_blocks(bitcoind, 2);
    let tx = test::get_tx(bitcoind, txid).unwrap();
    let tx_height = test::get_tx_height(bitcoind, txid);
    assert!(tx_height.is_some());
    let (index, txout) = test::txouts_for(&addr1, &tx).into_iter().next().unwrap();

    let sp_addr = sp_account.get_sp_address();
    let outpoint = OutPoint {
        txid,
        vout: index as u32,
    };
    let fees = Amount::from_sat(400);

    // Use segwit-specific functions
    let recipient_pubkey = generate_recipient_pubkey_segwit(sk, outpoint, sp_addr).unwrap();
    let swap_tx = swap_to_sp_segwit(sk, outpoint, txout, recipient_pubkey, fees, &secp).unwrap();

    // broadcast
    let txid = bitcoind
        .send_raw_transaction(&swap_tx)
        .unwrap()
        .txid()
        .unwrap();
    test::generate_blocks(bitcoind, 2);
    let tx_height = test::get_tx_height(bitcoind, txid);
    assert!(tx_height.is_some());
    wait_until_sync_at_height(sp_account, 124);

    clear_logs(&mut bbd);

    scan(sp_account, 1, 124, 0, with_cutthrough).unwrap();

    let op = sp_account.outpoints().into_iter().next().unwrap();
    let expected_op = OutPoint { txid, vout: 0 };
    assert_eq!(op, expected_op);
}
