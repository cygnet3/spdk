use std::{thread, time::Duration};

use bitcoin::{
    absolute::{self, Height},
    hashes::Hash,
    key::TapTweak,
    secp256k1::{self, All, PublicKey, SecretKey},
    sighash,
    transaction::Version,
    Address, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use blindbitd::BlindbitD;
use bwk_utils::test::{
    self,
    corepc_node::{self},
    get_tx,
};
use rand::random_range;
use spdk_core::{
    account::SpAccount,
    silentpayments::{
        utils::receiving::{calculate_tweak_data, get_pubkey_from_input},
        SilentPaymentAddress,
    },
    ChainBackend, SpScanner, Updater,
};

pub fn get_taproot_pubkey(txout: &TxOut) -> XOnlyPublicKey {
    let script_bytes = txout.script_pubkey.as_bytes();
    assert_eq!(script_bytes[0], 0x51); // OP_1
    assert_eq!(script_bytes[1], 0x20); // 32 bytes
    bitcoin::key::XOnlyPublicKey::from_slice(&script_bytes[2..34]).expect("valid output key")
}

#[allow(non_snake_case)]
pub fn generate_recipient_pubkey(
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
pub fn verify_recipient_pubkey(
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

pub fn swap_to_sp(
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

pub fn clear_logs(bbd: &mut BlindbitD) {
    while let Ok(_log) = bbd.logs.try_recv() {
        //
    }
}

pub fn dump_logs(bbd: &mut BlindbitD) {
    while let Ok(log) = bbd.logs.try_recv() {
        println!("{log}");
    }
}

pub fn wait_until_sync_at_height<B, U>(sp_account: &mut SpAccount<B, U>, height: u32)
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

pub fn scan<B, U>(
    sp_account: &mut SpAccount<B, U>,
    start: u32,
    stop: u32,
    dust: u64,
    with_cutthrough: bool,
) -> Result<(), spdk_core::Error>
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

pub fn get_tr_address(bitcoind: &mut corepc_node::Client) -> Address {
    bitcoind
        .get_new_address(None, Some(corepc_node::AddressType::Bech32m))
        .unwrap()
        .address()
        .unwrap()
        .assume_checked()
}

pub fn inputs_pubkeys_outpoint_from_tx(
    tx: &bitcoin::Transaction,
    bitcoind: &mut corepc_node::Client,
) -> (Vec<PublicKey>, Vec<OutPoint>) {
    let mut pubkeys = vec![];
    let mut ops = vec![];
    for inp in &tx.input {
        let prev_tx = get_tx(bitcoind, inp.previous_output.txid).unwrap();
        let prev_txout = prev_tx.output[inp.previous_output.vout as usize].clone();
        let script_pub_key = prev_txout.script_pubkey.as_bytes();
        let script_sig = inp.script_sig.as_bytes();
        let txinwitness = inp.witness.to_vec();
        if let Ok(Some(pk)) = get_pubkey_from_input(script_sig, &txinwitness, script_pub_key) {
            pubkeys.push(pk);
        }
        ops.push(inp.previous_output);
    }

    (pubkeys, ops)
}

pub fn generate_sp_candidate(
    bitcoind: &mut corepc_node::Client,
) -> (Option<PublicKey /* tweak_data */>, TxOut, OutPoint) {
    let addr = get_tr_address(bitcoind);
    let txid = test::send_sats(bitcoind, addr.clone(), random_range(10_001..1_000_000)).unwrap();
    let tx = test::get_tx(bitcoind, txid).unwrap();
    test::generate_blocks(bitcoind, random_range(1..5));
    let (index, txout) = test::txouts_for(&addr, &tx).into_iter().next().unwrap();
    let op = OutPoint {
        txid,
        vout: index as u32,
    };

    let (pks, ops) = inputs_pubkeys_outpoint_from_tx(&tx, bitcoind);
    let ops = ops
        .into_iter()
        .map(|op| (op.txid.to_string(), op.vout))
        .collect::<Vec<_>>();
    let inputs_pks = pks.iter().collect::<Vec<_>>();
    (calculate_tweak_data(&inputs_pks, &ops).ok(), txout, op)
}
