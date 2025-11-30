use std::{thread, time::Duration};

use backend_blindbit_native::UreqClient;
use bitcoin::{
    absolute::{self, Height},
    bip32::ChildNumber,
    hashes::Hash,
    key::TapTweak,
    secp256k1::{self, All, PublicKey, SecretKey},
    sighash,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use blindbitd::BlindbitD;
use bwk_sign::{
    bwk_descriptor::{descriptor::DescriptorDerivator, tr_path},
    HotSigner,
};
use bwk_utils::test::{
    self,
    corepc_node::anyhow::{self},
};
use spdk_core::{
    account::SpAccount, bip39, silentpayments::SilentPaymentAddress, updater::DummyUpdater,
    ChainBackend, SpClient, SpScanner, Updater,
};

fn get_taproot_pubkey(txout: &TxOut) -> XOnlyPublicKey {
    let script_bytes = txout.script_pubkey.as_bytes();
    assert_eq!(script_bytes[0], 0x51); // OP_1
    assert_eq!(script_bytes[1], 0x20); // 32 bytes
    bitcoin::key::XOnlyPublicKey::from_slice(&script_bytes[2..34]).expect("valid output key")
}

#[allow(non_snake_case)]
fn generate_recipient_pubkey(
    // internal key (not tweaked)
    sk: SecretKey,
    // outpoint to spend
    outpoint: OutPoint,
    // prevout
    txout: &TxOut,
    sp_addr: SilentPaymentAddress,
    secp: &secp256k1::Secp256k1<All>,
) -> Option<XOnlyPublicKey> {
    // tweak the key
    let keypair = secp256k1::Keypair::from_secret_key(secp, &sk);
    #[allow(deprecated)]
    let keypair = keypair.tap_tweak(secp, None).to_inner();
    let taproot_pubkey = get_taproot_pubkey(txout);

    // check the secret key we pass to calculate_partial_secret() is the one related to
    // the txout script_pubkey
    let (sp_pk, _parity) = keypair.x_only_public_key();
    assert_eq!(taproot_pubkey, sp_pk);

    // process partial secret
    let sp_sk = keypair.secret_key();

    let input_keys = vec![(sp_sk, true /* is taproot */)];
    let outpoints = vec![(outpoint.txid.to_string(), outpoint.vout)];
    let partial_secret = spdk_core::silentpayments::utils::sending::calculate_partial_secret(
        &input_keys,
        &outpoints,
    )
    .ok()?;

    // generate recipient pubkey
    spdk_core::silentpayments::sending::generate_recipient_pubkeys(vec![sp_addr], partial_secret)
        .ok()?
        .into_iter()
        .next()
        .and_then(|(_addr, k)| k.into_iter().next())
}

#[allow(non_snake_case)]
fn verify_recipient_pubkey(
    b_scan: SecretKey,
    B_spend: PublicKey,
    // outpoint to spend
    outpoint: OutPoint,
    // prevout
    txout: &TxOut,
    recipient_pubkey: XOnlyPublicKey,
    secp: &secp256k1::Secp256k1<All>,
) -> bool {
    // Extract the taproot output key from the input being spent
    let A = get_taproot_pubkey(txout);
    let A_pubkey = A.public_key(bitcoin::key::Parity::Even);

    // Calculate input_hash = hash(outpoint || A)
    let input_hash = spdk_core::silentpayments::utils::hash::calculate_input_hash(
        &[(outpoint.txid.to_string(), outpoint.vout)],
        A_pubkey,
    )
    .unwrap();

    // Calculate tweak_data = input_hash·A
    let tweak_data = A_pubkey.mul_tweak(secp, &input_hash).unwrap();

    // Calculate ecdh_shared_secret = tweak_data·b_scan
    let ecdh_shared_secret =
        spdk_core::silentpayments::utils::receiving::calculate_ecdh_shared_secret(
            &tweak_data,
            &b_scan,
        );

    // Calculate t_0 = hash(ecdh_shared_secret || 0)
    use spdk_core::silentpayments::utils::common::calculate_t_n;
    let t_0 = calculate_t_n(&ecdh_shared_secret, 0).unwrap();

    // Calculate P_0 = B_spend + t_0·G
    use spdk_core::silentpayments::utils::common::calculate_P_n;
    let B_spend_pubkey = B_spend;
    let P_0 = calculate_P_n(&B_spend_pubkey, t_0.into()).unwrap();

    // Compare with recipient_pubkey
    let (P_0_xonly, _) = P_0.x_only_public_key();
    P_0_xonly == recipient_pubkey
}

fn swap_to_sp(
    sk: SecretKey,
    outpoint: OutPoint,
    txout: TxOut,
    recipient_pubkey: XOnlyPublicKey,
    fees: bitcoin::Amount,
    secp: &secp256k1::Secp256k1<All>,
) -> Option<bitcoin::Transaction /* Signed */> {
    const DUST: u64 = 330;

    // craft tx
    let script = ScriptBuf::new_p2tr_tweaked(recipient_pubkey.dangerous_assume_tweaked());
    if txout.value < (fees + Amount::from_sat(DUST)) {
        return None;
    }
    let value = txout.value - fees;
    let output = vec![TxOut {
        value,
        script_pubkey: script,
    }];
    let input = vec![TxIn {
        previous_output: outpoint,
        script_sig: Default::default(),
        sequence: Sequence::ZERO,
        witness: Default::default(),
    }];
    let mut tx = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output,
    };

    // tweak the key
    let keypair = secp256k1::Keypair::from_secret_key(secp, &sk);
    #[allow(deprecated)]
    let keypair = keypair.tap_tweak(secp, None).to_inner();

    // process sighash
    let mut cache = sighash::SighashCache::new(tx.clone());
    let sighash_type = sighash::TapSighashType::Default;
    let txouts = vec![txout.clone()];
    let prevouts = sighash::Prevouts::All(&txouts);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .ok()?;
    let sighash = secp256k1::Message::from_digest_slice(&sighash.as_raw_hash().to_byte_array())
        .expect("Sighash is always 32 bytes.");

    // sign
    let signature = secp.sign_schnorr_no_aux_rand(&sighash, &keypair);
    let sig = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    // craft & add witness
    let witness = Witness::p2tr_key_spend(&sig);
    tx.input[0].witness = witness;

    Some(tx)
}

fn clear_logs(bbd: &mut BlindbitD) {
    while let Ok(_log) = bbd.logs.try_recv() {
        //
    }
}

fn dump_logs(bbd: &mut BlindbitD) {
    while let Ok(log) = bbd.logs.try_recv() {
        println!("{log}");
    }
}

fn wait_until_sync_at_height<B, U>(sp_account: &mut SpAccount<B, U>, height: u32)
where
    B: ChainBackend,
    U: Updater,
{
    loop {
        if let Ok(sync_height) = sp_account.block_height() {
            if sync_height.to_consensus_u32() >= height {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn scan<B, U>(
    sp_account: &mut SpAccount<B, U>,
    start: u32,
    stop: u32,
    dust: u64,
    with_cutthrough: bool,
) -> Result<(), anyhow::Error>
where
    B: ChainBackend,
    U: Updater,
{
    let dust_limit = (dust > 0).then_some(Amount::from_sat(dust));
    sp_account.scan_blocks(
        Height::from_consensus(start).unwrap(),
        Height::from_consensus(stop).unwrap(),
        dust_limit,
        with_cutthrough,
    )
}

#[allow(non_snake_case)]
#[test]
fn integration() {
    let secp = secp256k1::Secp256k1::new();
    let network = bwk_sign::miniscript::bitcoin::Network::Regtest;
    let mut bbd = BlindbitD::new().unwrap();

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

    // brodcast
    let txid = bitcoind
        .send_raw_transaction(&swap_tx)
        .unwrap()
        .txid()
        .unwrap();
    test::generate_blocks(bitcoind, 2);
    let tx_height = test::get_tx_height(bitcoind, txid);
    assert!(tx_height.is_some());
    wait_until_sync_at_height(sp_account, 124);

    // thread::sleep(Duration::from_secs(1));
    clear_logs(&mut bbd);

    // BUG: if dust == Some(_) && with_cutthrough == false => error 400
    // BUG: if dust == _) && with_cutthrough == true => no tweak is returned
    scan(sp_account, 1, 124, 0, false).unwrap();

    let op = sp_account.outpoints().into_iter().next().unwrap();
    let expected_op = OutPoint { txid, vout: 0 };
    assert_eq!(op, expected_op);
}
