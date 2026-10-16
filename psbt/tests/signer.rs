//! Integration tests for the signer role.
//!
//! Covers:
//!   1. Regression for `collect_scan_keys` off-by-one (was passing 67-byte array to a 33-byte key
//!      parser, making the entire SP path non-functional).
//!   2. Regression for multi-signer skipping non-eligible inputs in `derive_sp_output_scripts`.
//!   3. BIP-352 n-counter correctness: two outputs to the same scan key produce distinct keys.
//!   4. Unit tests for `extract_eligible_input_pubkey` covering all declared script types.
//!   5. Multi-signer `derive_sp_output_scripts` with mixed eligible/non-eligible inputs (regression
//!      for the `is_partial` detection bug).
//!   6. `SigningSession::get_silent_payment_sigs` produces a valid Schnorr signature over an SP
//!      input.
//!   7. Receiver-verified end-to-end: the recipient can scan the derived SP outputs (single-signer
//!      with an SP input, and two-party multi-signer aggregation).
//!   8. Inputs the signer and the receiver disagree on: an uncompressed P2PKH key, and a non-P2TR
//!      funding UTXO given only as `witness_utxo`.

use std::collections::HashSet;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use psbt::signer::{
    ShareMode, SpOutputVerifier, SpSignerError, SpSignerExt, extract_eligible_input_pubkey,
};
use psbt_v2::{
    Constructor, Creator, Extractor, Finalizer, Input, InputsOnlyModifiable, Output, Psbt,
    SignError, Signer, SpV0Info,
};
use secp256k1::{Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, rand};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{PublicTweakData, get_pubkey_from_input};
use silentpayments::utils::{NUMS_H, OutPoint as SpOutPoint};
use silentpayments::{Network, SpVersion, TransactionInputs, TransactionSharedSecret};

// ── test helpers ──────────────────────────────────────────────────────────────

fn secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
}

fn rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

fn sk(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

fn pk(secp: &Secp256k1<secp256k1::All>, byte: u8) -> PublicKey {
    sk(byte).public_key(secp)
}

fn p2wpkh_script(secp: &Secp256k1<secp256k1::All>, secret: &SecretKey) -> ScriptBuf {
    let compressed = bitcoin::CompressedPublicKey(secret.public_key(secp));
    ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash())
}

fn p2tr_script(secp: &Secp256k1<secp256k1::All>, secret: &SecretKey) -> ScriptBuf {
    let (xonly, _) = secret.x_only_public_key(secp);
    ScriptBuf::new_p2tr(secp, xonly, None)
}

/// Build an `Output` with `sp_v0_info` set to `scan_key(33) | spend_key(33)`.
/// `script_pubkey` is left empty — `set_sp_scriptpubkey` will fill it.
fn sp_output(scan: &PublicKey, spend: &PublicKey) -> Output {
    let mut output = Output::new(TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: ScriptBuf::new(),
    });
    output.sp_v0_info = Some(SpV0Info::new(
        CompressedPublicKey(*scan),
        CompressedPublicKey(*spend),
    ));
    output
}

/// Record `txout` as this input's funding output.
///
/// `previous_txid` is replaced with the txid of a previous transaction that
/// pays `txout` at `spent_output_index`. A witness-only UTXO is not verifiable
/// for non-P2TR spends, so both UTXO forms are set and kept consistent.
/// The txid of the `OutPoint` passed to [`Input::new`] is not preserved.
fn set_verified_funding_utxo(input: &mut Input, txout: TxOut) {
    let vout = input.spent_output_index as usize;
    let mut output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        };
        vout
    ];
    output.push(txout.clone());
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output,
    };
    input.previous_txid = tx.compute_txid();
    input.witness_utxo = Some(txout);
    input.non_witness_utxo = Some(tx);
}

/// Build a P2WPKH `Input` with a verifiable funding UTXO and `bip32_derivations`
/// populated so that `extract_eligible_input_pubkey` can identify and return the key.
fn p2wpkh_input(secp: &Secp256k1<secp256k1::All>, outpoint: OutPoint, secret: &SecretKey) -> Input {
    let public = secret.public_key(secp);
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: p2wpkh_script(secp, secret),
        },
    );
    input.bip32_derivations.insert(
        bitcoin::PublicKey::new(public),
        (Fingerprint::default(), DerivationPath::default()),
    );
    input
}

/// Build a P2PKH `Input` funded to the compressed encoding of `secret`'s public key.
fn p2pkh_input(
    secp: &Secp256k1<secp256k1::All>,
    outpoint: OutPoint,
    secret: &SecretKey,
) -> Input {
    let public = bitcoin::PublicKey::new(secret.public_key(secp));
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2pkh(&public.pubkey_hash()),
        },
    );
    input
        .bip32_derivations
        .insert(public, (Fingerprint::default(), DerivationPath::default()));
    input
}

/// Build a P2SH-P2WPKH `Input`: the funding script commits to a P2WPKH redeem script for `secret`.
fn p2sh_p2wpkh_input(
    secp: &Secp256k1<secp256k1::All>,
    outpoint: OutPoint,
    secret: &SecretKey,
) -> Input {
    let redeem_script = p2wpkh_script(secp, secret);
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2sh(&redeem_script.script_hash()),
        },
    );
    input.bip32_derivations.insert(
        bitcoin::PublicKey::new(secret.public_key(secp)),
        (Fingerprint::default(), DerivationPath::default()),
    );
    input.redeem_script = Some(redeem_script);
    input
}

/// Build a P2PKH `Input` funded to the *uncompressed* encoding of `secret`'s public key, with
/// that uncompressed key in `bip32_derivations`.
fn p2pkh_uncompressed_input(
    secp: &Secp256k1<secp256k1::All>,
    outpoint: OutPoint,
    secret: &SecretKey,
) -> Input {
    let public = bitcoin::PublicKey::new_uncompressed(secret.public_key(secp));
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2pkh(&public.pubkey_hash()),
        },
    );
    input
        .bip32_derivations
        .insert(public, (Fingerprint::default(), DerivationPath::default()));
    input
}

/// A `scriptSig` spending [`p2pkh_uncompressed_input`]: a placeholder signature and the
/// uncompressed key. BIP-352 key extraction does not check the signature.
fn p2pkh_uncompressed_script_sig(
    secp: &Secp256k1<secp256k1::All>,
    secret: &SecretKey,
) -> ScriptBuf {
    ScriptBuf::builder()
        .push_slice([0u8; 71])
        .push_key(&bitcoin::PublicKey::new_uncompressed(
            secret.public_key(secp),
        ))
        .into_script()
}

fn outpoint(vout: u32) -> OutPoint {
    OutPoint::new(
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::all_zeros()),
        vout,
    )
}

/// Build a PSBT with the given outputs and inputs via psbt_v2's Creator/Constructor.
fn new_psbt(outputs: Vec<Output>, outpoints: Vec<OutPoint>) -> Psbt {
    let mut constructor = Creator::new().constructor_modifiable();
    for output in outputs {
        constructor = constructor.output(output).unwrap();
    }
    let psbt = constructor.psbt().unwrap();

    let mut constructor = Constructor::<InputsOnlyModifiable>::new(psbt).unwrap();
    for outpoint in outpoints {
        constructor = constructor.input(Input::new(&outpoint));
    }
    constructor.psbt().unwrap()
}

/// Build an SP P2TR `Input`: the funding output key is `spend_sk + tweak·G` (placed
/// directly, without a BIP-341 tweak), with `sp_tweak` and the BIP-376
/// `sp_spend_bip32_derivations` entry (keyed by the *untweaked* spend key) populated.
fn sp_p2tr_input(
    secp: &Secp256k1<secp256k1::All>,
    outpoint: OutPoint,
    spend_sk: &SecretKey,
    tweak: [u8; 32],
) -> Input {
    let tweaked = spend_sk
        .add_tweak(&Scalar::from_be_bytes(tweak).unwrap())
        .unwrap();
    let (xonly, _) = tweaked.x_only_public_key(secp);
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
    });
    input.sp_tweak = Some(tweak);
    input.sp_spend_bip32_derivations.insert(
        CompressedPublicKey(spend_sk.public_key(secp)),
        (Fingerprint::default(), DerivationPath::default()),
    );
    input
}

/// Sign input 0 as a BIP-376 silent payment input and write the signature.
fn sign_sp_input(psbt: Psbt, spend_sk: &SecretKey, secp: &Secp256k1<secp256k1::All>) -> Psbt {
    let mut signer = Signer::new(psbt).unwrap();
    let verifier = SpOutputVerifier { secp };
    let sigs = signer
        .session(&verifier, &[0], |mut session| {
            let inputs = session.signable_inputs().unwrap();
            vec![session
                .get_silent_payment_sigs(&inputs, 0, spend_sk, secp)
                .unwrap()]
        })
        .unwrap();
    signer.apply(sigs).unwrap()
}

/// Rebuild the sender-side `TransactionInputs` exactly as `compute_sp_outputs` does.
fn transaction_inputs_for(psbt: &Psbt) -> TransactionInputs {
    let mut inputs = TransactionInputs::with_capacity(psbt.global.input_count);
    for (vin, input) in psbt.inputs.iter().enumerate() {
        let outpoint = SpOutPoint::from_txid_and_vout(
            &input.previous_txid.to_string(),
            input.spent_output_index,
        )
        .unwrap();
        let spk = input
            .funding_utxo_untrusted()
            .unwrap()
            .script_pubkey
            .to_bytes();
        let pubkey = extract_eligible_input_pubkey(input, vin).unwrap();
        inputs.push(outpoint, spk, pubkey);
    }
    inputs
}

/// Receiver-side verification: the recipient holding `scan_sk` must find every SP output
/// of the PSBT via the public tweak data. This is the assertion that distinguishes a
/// *correct* derived output key from merely *a* P2TR key.
fn assert_receiver_scan_finds_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
) {
    let inputs = transaction_inputs_for(psbt);
    assert_receiver_scan_finds_outputs_from(secp, psbt, &inputs, scan_sk, spend_pk);
}

/// Like [`assert_receiver_scan_finds_outputs`], with the receiver's input set supplied by the
/// caller instead of rebuilt from the PSBT fields the signer reads.
fn assert_receiver_scan_finds_outputs_from(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    inputs: &TransactionInputs,
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
) {
    let tweak_data = PublicTweakData::new(secp, inputs).unwrap();
    let shared_secret =
        TransactionSharedSecret::new_from_public_tweak_data(secp, &tweak_data, scan_sk).unwrap();
    let receiver = Receiver::new(
        SpVersion::ZERO,
        scan_sk.public_key(secp),
        *spend_pk,
        Label::new(*scan_sk, 0),
        Network::Regtest,
    )
    .unwrap();

    let sp_output_keys: Vec<XOnlyPublicKey> = psbt
        .outputs
        .iter()
        .filter(|o| o.sp_v0_info.is_some())
        .map(|o| {
            assert!(o.script_pubkey.is_p2tr(), "SP output must be P2TR");
            XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..]).unwrap()
        })
        .collect();
    assert!(!sp_output_keys.is_empty());

    let found = receiver
        .scan_transaction(&shared_secret, &sp_output_keys)
        .unwrap();
    let found_keys: HashSet<&XOnlyPublicKey> = found.values().flat_map(|m| m.keys()).collect();
    for key in &sp_output_keys {
        assert!(
            found_keys.contains(key),
            "receiver must find SP output {key}"
        );
    }
}

// ── 1. Single-signer round-trip ───────────────────────────────────────────────

/// Full single-signer flow: share generation → output computation → script assignment.
///
/// Before the `collect_scan_keys` fix this always errored because `from_slice` was
/// called with all 67 bytes of the address array instead of the 33-byte scan key.
#[test]
fn test_single_signer_e2e() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    assert!(!psbt.global.sp_ecdh_shares.is_empty());
    assert!(!psbt.global.sp_dleq_proofs.is_empty());

    let scripts = psbt.derive_sp_output_scripts(&secp).unwrap();
    assert_eq!(scripts.len(), 1);

    psbt.commit_sp_outputs(&secp).unwrap();

    let sp_out = psbt
        .outputs
        .iter()
        .find(|o| o.sp_v0_info.is_some())
        .unwrap();
    assert!(
        sp_out.script_pubkey.is_p2tr(),
        "SP output must be a P2TR scriptPubKey"
    );

    // Stronger than "is P2TR": the recipient must be able to scan the output.
    let scan_sk = sk(2);
    assert_receiver_scan_finds_outputs(&secp, &psbt, &scan_sk, &spend_pk);
}

/// A PSBT with no SP outputs must be a no-op: no shares written, no error.
#[test]
fn test_single_signer_no_sp_outputs_is_noop() {
    let secp = secp();
    let spend_sk = sk(1);
    let regular_out = Output::new(TxOut {
        value: Amount::from_sat(9_000),
        script_pubkey: p2wpkh_script(&secp, &spend_sk),
    });

    let mut psbt = new_psbt(vec![regular_out], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    let covered = psbt
        .add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    assert!(
        covered.is_empty() && psbt.global.sp_ecdh_shares.is_empty(),
        "no shares expected when there are no SP outputs"
    );
}

// ── 2. n-counter correctness ──────────────────────────────────────────────────

/// Two outputs to the same scan key must receive *distinct* output keys, derived
/// with BIP-352 counter n=0 and n=1 respectively.
///
/// The concrete check is that the two xonly keys in the result Vec differ.
#[test]
fn test_two_outputs_same_scan_key_produce_distinct_keys() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    // Two identical SP addresses in the same PSBT.
    let mut psbt = new_psbt(
        vec![
            sp_output(&scan_pk, &spend_pk),
            sp_output(&scan_pk, &spend_pk),
        ],
        vec![outpoint(0)],
    );
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    let scripts = psbt.derive_sp_output_scripts(&secp).unwrap();

    // One index-keyed script per SP output; the two outputs share an address but
    // must get distinct keys derived with n=0 and n=1 respectively.
    assert_eq!(scripts.len(), 2, "one script per SP output");
    assert_eq!(scripts[0].0, 0);
    assert_eq!(scripts[1].0, 1);
    assert_ne!(
        scripts[0].1, scripts[1].1,
        "n=0 and n=1 must be distinct keys"
    );
}

/// Two outputs to *different* scan keys each get one entry in the result map,
/// and the single-signer produces one global share per scan key.
#[test]
fn test_two_outputs_different_scan_keys() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk_a = pk(&secp, 2);
    let scan_pk_b = pk(&secp, 4);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![
            sp_output(&scan_pk_a, &spend_pk),
            sp_output(&scan_pk_b, &spend_pk),
        ],
        vec![outpoint(0)],
    );
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    assert_eq!(
        psbt.global.sp_ecdh_shares.len(),
        2,
        "one share per scan key"
    );

    let scripts = psbt.derive_sp_output_scripts(&secp).unwrap();
    assert_eq!(scripts.len(), 2, "one script per SP output");
}

// ── 3. Multi-signer eligible-input filtering ──────────────────────────────────

/// `multi_signer_generate_ecdh_shares` must only produce shares for SP-eligible inputs
/// and silently skip non-eligible ones.
///
/// Before the `eligible_vins` fix, the subsequent `compute_sp_outputs` call would panic
/// because it iterated over every vin including non-eligible ones and failed to find a
/// share for them.
#[test]
fn test_multi_signer_share_generation_skips_non_eligible_input() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );

    // Input 0: eligible P2WPKH owned by spend_sk.
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    // Input 1: non-eligible empty-script input (BIP-352 excludes it from ECDH).
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut nonelig,
        TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: ScriptBuf::default(), // empty → not eligible
        },
    );
    psbt.inputs[1] = nonelig;

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Partial)
        .unwrap();

    assert!(
        !psbt.inputs[0].sp_ecdh_shares.is_empty(),
        "eligible input must have a share"
    );
    assert!(
        psbt.inputs[1].sp_ecdh_shares.is_empty(),
        "non-eligible input must not receive a share"
    );
}

/// `single_signer_generate_ecdh_shares` followed by `compute_sp_outputs` must work
/// correctly even when one of the inputs is not BIP-352 eligible.
///
/// The global share is computed over the eligible input keys only; the non-eligible
/// input is pushed into `TransactionInputs` with `pubkey = None` and skipped when
/// computing the eligible pubkeys sum and input hash.
#[test]
fn test_single_signer_ignores_non_eligible_input() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );

    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut nonelig,
        TxOut {
            value: Amount::from_sat(3_000),
            script_pubkey: ScriptBuf::default(),
        },
    );
    psbt.inputs[1] = nonelig;

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    let scripts = psbt.derive_sp_output_scripts(&secp).unwrap();
    assert_eq!(scripts.len(), 1);
    psbt.commit_sp_outputs(&secp).unwrap();

    let sp_out = psbt
        .outputs
        .iter()
        .find(|o| o.sp_v0_info.is_some())
        .unwrap();
    assert!(sp_out.script_pubkey.is_p2tr());
}

// ── 4. extract_eligible_input_pubkey unit tests ───────────────────────────────

/// P2WPKH input with `bip32_derivations` populated → returns the correct pubkey.
#[test]
fn test_extract_p2wpkh_with_derivation_returns_pubkey() {
    let secp = secp();
    let secret = sk(1);
    let public = secret.public_key(&secp);
    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2wpkh_script(&secp, &secret),
        },
    );
    input.bip32_derivations.insert(
        bitcoin::PublicKey::new(public),
        (Fingerprint::default(), DerivationPath::default()),
    );

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert_eq!(result, Some(public));
}

/// P2WPKH input without `bip32_derivations` → returns `Ok(None)`: the pubkey cannot
/// be named, so lenient callers skip the input and strict ones (ShareMode::Global,
/// output derivation) turn the `None` into an error themselves.
#[test]
fn test_extract_p2wpkh_missing_derivation_returns_none() {
    let secp = secp();
    let secret = sk(1);
    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2wpkh_script(&secp, &secret),
        },
    );
    // Deliberately omit bip32_derivations.
    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert!(
        result.is_none(),
        "must return None when bip32_derivations is absent for a P2WPKH input"
    );
}

/// A P2TR output that really is NUMS_H tweaked by `tap_merkle_root` must return `Ok(None)`.
///
/// BIP-352 §3 excludes script-path-only outputs. The claim is accepted only when the
/// merkle root reproduces the funding scriptPubKey.
#[test]
fn test_extract_p2tr_nums_h_internal_key_returns_none() {
    let secp = secp();
    let nums = XOnlyPublicKey::from_slice(&NUMS_H).unwrap();
    let merkle_root = bitcoin::TapNodeHash::from_byte_array([1u8; 32]);
    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, nums, Some(merkle_root)),
    });
    input.tap_internal_key = Some(nums);
    input.tap_merkle_root = Some(merkle_root);

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert!(
        result.is_none(),
        "a NUMS_H script-path output must be non-contributing"
    );
}

/// An input whose `witness_utxo` has a non-eligible scriptPubKey must return `Ok(None)`.
#[test]
fn test_extract_non_eligible_script_returns_none() {
    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::default(), // empty → not eligible
        },
    );

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert!(result.is_none());
}

/// P2SH input where the redeem script is NOT P2WPKH → must return `Ok(None)`.
#[test]
fn test_extract_p2sh_non_wpkh_redeem_returns_none() {
    let secp = secp();
    let secret = sk(1);
    // Redeem script: a P2TR (not a P2WPKH).  Any non-P2WPKH redeem is excluded.
    let non_wpkh_redeem = p2tr_script(&secp, &secret);
    let p2sh_script = ScriptBuf::new_p2sh(&non_wpkh_redeem.script_hash());

    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2sh_script,
        },
    );
    input.redeem_script = Some(non_wpkh_redeem);

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert!(
        result.is_none(),
        "P2SH with non-P2WPKH redeem must be ineligible"
    );
}

/// P2SH input with no redeem script set → must error: it may be P2SH-P2WPKH, which the
/// receiver counts once it reads the redeem script from the final scriptSig.
#[test]
fn test_extract_p2sh_missing_redeem_script_errors() {
    let secp = secp();
    let secret = sk(1);
    let p2wpkh = p2wpkh_script(&secp, &secret);
    let p2sh_script = ScriptBuf::new_p2sh(&p2wpkh.script_hash());

    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2sh_script,
        },
    );
    // redeem_script intentionally absent.

    let result = extract_eligible_input_pubkey(&input, 3);
    assert!(
        matches!(result, Err(SpSignerError::MissingRedeemScript { vin: 3 })),
        "got {result:?}"
    );
}

/// The funding script is P2SH-P2WPKH, but the declared redeem script is something else and is not
/// P2WPKH. Without a hash check this input is skipped; the receiver spends the real redeem script
/// and counts the key.
#[test]
fn test_extract_p2sh_mismatched_redeem_script_errors() {
    let secp = secp();
    let secret = sk(1);
    let p2sh_script = ScriptBuf::new_p2sh(&p2wpkh_script(&secp, &secret).script_hash());

    let mut input = Input::new(&outpoint(0));
    set_verified_funding_utxo(
        &mut input,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2sh_script,
        },
    );
    input.redeem_script = Some(p2tr_script(&secp, &sk(2)));

    let result = extract_eligible_input_pubkey(&input, 2);
    assert!(
        matches!(result, Err(SpSignerError::RedeemScriptMismatch { vin: 2 })),
        "got {result:?}"
    );
}

#[test]
fn test_multi_signer_compute_sp_outputs_with_non_eligible_input() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );

    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut nonelig,
        TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: ScriptBuf::default(),
        },
    );
    psbt.inputs[1] = nonelig;

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Partial)
        .unwrap();

    // The non-eligible input requires no share; derivation must succeed from the
    // eligible input's partial share alone.
    psbt.derive_sp_output_scripts(&secp).unwrap();
}

/// P2TR input with `sp_tweak` set (SP spend): the BIP-352 input pubkey is the
/// even-lifted output key from the funding scriptPubKey — for an SP output that
/// is `B_spend + tweak·G` by construction. Per BIP-376 the
/// `sp_spend_bip32_derivations` map key is the *untweaked* spend key and is only
/// used for signer key lookup; it must not be read here.
#[test]
fn test_extract_p2tr_sp_tweak_reads_output_key_from_prevout() {
    let secp = secp();
    let spend = sk(1);
    let tweak = Scalar::from_be_bytes(sk(2).secret_bytes()).unwrap();
    let tweaked = spend.add_tweak(&tweak).unwrap();
    let (xonly, _) = tweaked.x_only_public_key(&secp);

    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        // SP outputs place the derived key directly, without a BIP-341 tweak.
        script_pubkey: ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
    });
    input.sp_tweak = Some(sk(2).secret_bytes());
    // BIP-376: the map key is the untweaked spend key B_spend.
    input.sp_spend_bip32_derivations.insert(
        CompressedPublicKey(spend.public_key(&secp)),
        (Fingerprint::default(), DerivationPath::default()),
    );

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert_eq!(result, Some(xonly.public_key(Parity::Even)));
}

/// An SP input without `sp_spend_bip32_derivations` still yields its output key:
/// the field is a key-lookup aid (BIP-376 SHOULD), not an input to the ECDH
/// extraction. Its presence is enforced by validation, not by this function.
#[test]
fn test_extract_p2tr_sp_tweak_without_derivation_map() {
    let secp = secp();
    let tweaked = sk(1)
        .add_tweak(&Scalar::from_be_bytes(sk(2).secret_bytes()).unwrap())
        .unwrap();
    let (xonly, _) = tweaked.x_only_public_key(&secp);

    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
    });
    input.sp_tweak = Some(sk(2).secret_bytes());

    let result = extract_eligible_input_pubkey(&input, 0).unwrap();
    assert_eq!(result, Some(xonly.public_key(Parity::Even)));
}

// ── 6. sign_sp_inputs ─────────────────────────────────────────────────────────

/// Signing an SP input must produce a Schnorr signature that verifies against the
/// output key from the funding scriptPubKey, over the key-spend sighash of the
/// unsigned transaction.
///
/// BIP-375 forbids adding signatures while any silent-payment output still has an
/// empty scriptPubKey, so this test uses a plain (non-SP) output.
#[test]
fn test_sign_sp_inputs_produces_valid_taproot_sig() {
    let secp = secp();
    let spend_sk = sk(1);
    let tweak_bytes = sk(7).secret_bytes();

    let payment_output = Output::new(TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: p2wpkh_script(&secp, &sk(9)),
    });
    let mut psbt = new_psbt(vec![payment_output], vec![outpoint(0)]);
    psbt.inputs[0] = sp_p2tr_input(&secp, outpoint(0), &spend_sk, tweak_bytes);

    let psbt = sign_sp_input(psbt, &spend_sk, &secp);

    let tweaked = spend_sk
        .add_tweak(&Scalar::from_be_bytes(tweak_bytes).unwrap())
        .unwrap();
    let (output_key, _) = tweaked.x_only_public_key(&secp);

    let sig = psbt.inputs[0]
        .tap_key_sig
        .expect("tap_key_sig must be set after signing");

    // Verify the signature against the sighash of the unsigned transaction.
    // (`Psbt::unsigned_tx` is private upstream; rebuild it from the PSBT fields.)
    let tx = bitcoin::Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt
            .global
            .fallback_lock_time
            .unwrap_or(bitcoin::absolute::LockTime::ZERO),
        input: psbt
            .inputs
            .iter()
            .map(|i| bitcoin::TxIn {
                previous_output: OutPoint::new(i.previous_txid, i.spent_output_index),
                script_sig: ScriptBuf::new(),
                sequence: i.sequence.unwrap_or(Sequence::MAX),
                witness: bitcoin::Witness::new(),
            })
            .collect(),
        output: psbt
            .outputs
            .iter()
            .map(|o| TxOut {
                value: o.amount,
                script_pubkey: o.script_pubkey.clone(),
            })
            .collect(),
    };
    let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sig.sighash_type)
        .unwrap();
    secp.verify_schnorr(&sig.signature, &Message::from(sighash), &output_key)
        .unwrap();
}

// ── 7. Receiver-verified end-to-end ──────────────────────────────────────────

/// Full single-signer flow spending *from* an SP input (P2TR with `sp_tweak`):
/// share generation must resolve the tweaked key, and the recipient must be able
/// to scan the derived output. Exercises the taproot branch of
/// `resolve_owned_eligible_key` / `NormalizedSecretKey` that P2WPKH-only tests miss.
#[test]
fn test_single_signer_sp_input_receiver_can_scan() {
    let secp = secp();
    let input_spend_sk = sk(1);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);
    let tweak_bytes = sk(7).secret_bytes();

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = sp_p2tr_input(&secp, outpoint(0), &input_spend_sk, tweak_bytes);

    psbt.add_ecdh_shares(&secp, &mut rng(), &input_spend_sk, ShareMode::Global)
        .unwrap();
    let scripts = psbt.derive_sp_output_scripts(&secp).unwrap();
    assert_eq!(scripts.len(), 1);
    psbt.commit_sp_outputs(&secp).unwrap();

    assert_receiver_scan_finds_outputs(&secp, &psbt, &scan_sk, &spend_pk);
}

/// An SP input has no `tap_internal_key` (BIP-352 outputs have no internal
/// key), so the finalizer must build the key-path witness from `tap_key_sig`
/// alone. Regression test: rust-psbt's `construct_tap_witness` used to gate
/// the key-spend path on `tap_internal_key`, making every SP spend
/// unfinalizable ("failed to finalize input at index N") even though the
/// signature was present and valid.
#[test]
fn test_sp_input_finalizes_without_tap_internal_key() {
    let secp = secp();
    let spend_sk = sk(1);
    let tweak_bytes = sk(7).secret_bytes();

    let payment_output = Output::new(TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: p2wpkh_script(&secp, &sk(9)),
    });
    let mut psbt = new_psbt(vec![payment_output], vec![outpoint(0)]);
    psbt.inputs[0] = sp_p2tr_input(&secp, outpoint(0), &spend_sk, tweak_bytes);
    assert!(
        psbt.inputs[0].tap_internal_key.is_none(),
        "SP inputs must not carry an internal key"
    );

    let psbt = sign_sp_input(psbt, &spend_sk, &secp);
    let sig = psbt.inputs[0].tap_key_sig.expect("tap_key_sig set");

    let finalized = Finalizer::new(psbt)
        .expect("finalizer")
        .finalize(&secp)
        .expect("SP input must finalize");
    let witness = finalized.inputs[0]
        .final_script_witness
        .as_ref()
        .expect("final witness set");
    assert_eq!(witness.to_vec(), vec![sig.to_vec()]);

    let tx = Extractor::new(finalized)
        .expect("Transaction finalized")
        .extract_tx()
        .expect("extract tx");
    assert_eq!(tx.input[0].witness.to_vec(), vec![sig.to_vec()]);
}

/// True two-party flow: each signer contributes per-input shares for their own
/// input only, the PSBTs are merged (manually — no Combiner role exists yet), and
/// the recipient can scan the resulting SP output.
#[test]
fn test_multi_signer_two_parties_receiver_can_scan() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);
    let bob_tweak = sk(8).secret_bytes();

    let base = {
        let mut psbt = new_psbt(
            vec![sp_output(&scan_pk, &spend_pk)],
            vec![outpoint(0), outpoint(1)],
        );
        // Alice: plain P2WPKH input. Bob: SP P2TR input (taproot share path).
        psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &alice_sk);
        psbt.inputs[1] = sp_p2tr_input(&secp, outpoint(1), &bob_sk, bob_tweak);
        psbt
    };

    let mut psbt_alice = base.clone();
    psbt_alice
        .add_ecdh_shares(&secp, &mut rng(), &alice_sk, ShareMode::Partial)
        .unwrap();
    let mut psbt_bob = base;
    psbt_bob
        .add_ecdh_shares(&secp, &mut rng(), &bob_sk, ShareMode::Partial)
        .unwrap();

    // Each signer must contribute to their own input only.
    assert!(!psbt_alice.inputs[0].sp_ecdh_shares.is_empty());
    assert!(psbt_alice.inputs[1].sp_ecdh_shares.is_empty());
    assert!(psbt_bob.inputs[0].sp_ecdh_shares.is_empty());
    assert!(!psbt_bob.inputs[1].sp_ecdh_shares.is_empty());

    // No Combiner role exists yet: merge the per-input fields manually.
    psbt_alice.inputs[1].sp_ecdh_shares = psbt_bob.inputs[1].sp_ecdh_shares.clone();
    psbt_alice.inputs[1].sp_dleq_proofs = psbt_bob.inputs[1].sp_dleq_proofs.clone();

    psbt_alice.commit_sp_outputs(&secp).unwrap();

    assert_receiver_scan_finds_outputs(&secp, &psbt_alice, &scan_sk, &spend_pk);
}

/// BIP-375 "Computing the Output Scripts": when a scan key has both a global
/// share and per-input shares, the global share takes precedence and the
/// partials are ignored — even a per-input share that could never verify on its
/// own (here: no DLEQ proof at all). `add_ecdh_shares` never produces the mix,
/// so build it by hand, as a combiner merging redundant fields would.
#[test]
fn test_mixed_share_state_global_precedence() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    let expected = psbt.derive_sp_output_scripts(&secp).unwrap();

    // Simulate a combiner merging in a redundant (and proof-less) per-input share.
    let (&scan_key, &share) = psbt.global.sp_ecdh_shares.iter().next().unwrap();
    psbt.inputs[0].sp_ecdh_shares.insert(scan_key, share);

    assert_eq!(
        psbt.derive_sp_output_scripts(&secp).unwrap(),
        expected,
        "per-input shares must be ignored when a global share exists"
    );
}

/// When a global share fails verification but every eligible input carries a
/// valid partial share, derivation falls back to the partials. Verified partial
/// proofs bind each share to its input's key, so the fallback necessarily
/// recovers the same secret an honest global share would have produced.
#[test]
fn test_invalid_global_share_falls_back_to_partials() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let base = {
        let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
        psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
        psbt
    };

    // Reference: partials only.
    let mut psbt_partial = base.clone();
    psbt_partial
        .add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Partial)
        .unwrap();
    let expected = psbt_partial.derive_sp_output_scripts(&secp).unwrap();

    // Mixed: valid partials + a global share whose proof is corrupted.
    let mut psbt_mixed = base;
    psbt_mixed
        .add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt_mixed.inputs[0].sp_ecdh_shares = psbt_partial.inputs[0].sp_ecdh_shares.clone();
    psbt_mixed.inputs[0].sp_dleq_proofs = psbt_partial.inputs[0].sp_dleq_proofs.clone();
    for proof in psbt_mixed.global.sp_dleq_proofs.values_mut() {
        proof.0[0] ^= 1;
    }

    assert_eq!(
        psbt_mixed.derive_sp_output_scripts(&secp).unwrap(),
        expected,
        "fallback to verified partials must recover the same scripts"
    );
}

// ── 8. Signer/receiver disagreement ──────────────────────────────────────────

/// BIP-352 only takes compressed keys from P2PKH inputs. A P2PKH output committing to an
/// uncompressed key does not contribute to the ECDH, so the signer must not return a key for it.
#[test]
fn test_extract_p2pkh_uncompressed_key_is_not_contributing() {
    let secp = secp();
    let secret = sk(1);
    let input = p2pkh_uncompressed_input(&secp, outpoint(0), &secret);

    assert_eq!(
        extract_eligible_input_pubkey(&input, 0).unwrap(),
        None,
        "an uncompressed P2PKH key must not be added to the input key sum"
    );
}

/// Alice spends a P2WPKH input and Bob an uncompressed P2PKH input; each adds a partial share
/// for their own input. The receiver reads Bob's key from his finalized `scriptSig` and skips it,
/// so the outputs committed before signing must be derived from Alice's key alone.
#[test]
fn test_uncompressed_p2pkh_cosigner_receiver_can_scan() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let bob_keys = bitcoin::PrivateKey::new_uncompressed(bob_sk, bitcoin::NetworkKind::Test);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);

    let base = {
        let mut psbt = new_psbt(
            vec![sp_output(&scan_pk, &spend_pk)],
            vec![outpoint(0), outpoint(1)],
        );
        psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &alice_sk);
        psbt.inputs[1] = p2pkh_uncompressed_input(&secp, outpoint(1), &bob_sk);
        psbt
    };

    let mut psbt = base.clone();
    psbt.add_ecdh_shares(&secp, &mut rng(), &alice_sk, ShareMode::Partial)
        .unwrap();
    let mut psbt_bob = base;
    // Bob's input does not contribute, so an uncompressed key yields no share.
    let _ = psbt_bob.add_ecdh_shares(&secp, &mut rng(), &bob_keys, ShareMode::Partial);
    psbt.inputs[1].sp_ecdh_shares = psbt_bob.inputs[1].sp_ecdh_shares.clone();
    psbt.inputs[1].sp_dleq_proofs = psbt_bob.inputs[1].sp_dleq_proofs.clone();

    psbt.commit_sp_outputs(&secp).unwrap();

    let mut receiver_inputs = TransactionInputs::with_capacity(2);
    let alice = &psbt.inputs[0];
    receiver_inputs.push(
        SpOutPoint::from_txid_and_vout(&alice.previous_txid.to_string(), alice.spent_output_index)
            .unwrap(),
        p2wpkh_script(&secp, &alice_sk).to_bytes(),
        Some(alice_sk.public_key(&secp)),
    );
    let bob = &psbt.inputs[1];
    let bob_spk = bob.witness_utxo.as_ref().unwrap().script_pubkey.clone();
    let bob_key = get_pubkey_from_input(
        p2pkh_uncompressed_script_sig(&secp, &bob_sk).as_bytes(),
        &[],
        bob_spk.as_bytes(),
    )
    .unwrap();
    assert_eq!(bob_key, None, "receiver skips an uncompressed P2PKH key");
    receiver_inputs.push(
        SpOutPoint::from_txid_and_vout(&bob.previous_txid.to_string(), bob.spent_output_index)
            .unwrap(),
        bob_spk.to_bytes(),
        bob_key,
    );

    assert_receiver_scan_finds_outputs_from(&secp, &psbt, &receiver_inputs, &scan_sk, &spend_pk);
}

/// Bob's input is P2SH-P2WPKH but he leaves out `redeem_script` and adds no share. The receiver
/// will read the redeem script from his final scriptSig and count his key, so deriving the outputs
/// from Alice's share alone must fail.
#[test]
fn test_derive_rejects_p2sh_cosigner_without_redeem_script() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &alice_sk);
    let mut bob = Input::new(&outpoint(1));
    bob.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut bob,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2sh(&p2wpkh_script(&secp, &bob_sk).script_hash()),
        },
    );
    psbt.inputs[1] = bob;

    psbt.add_ecdh_shares(&secp, &mut rng(), &alice_sk, ShareMode::Partial)
        .unwrap();

    let result = psbt.derive_sp_output_scripts(&secp);
    assert!(
        matches!(result, Err(SpSignerError::MissingRedeemScript { vin: 1 })),
        "got {result:?}"
    );
}

/// Same as a missing redeem script, except Bob declares a redeem script that does not hash to his
/// P2SH output and is not P2WPKH. Deriving from Alice's share alone must fail.
#[test]
fn test_derive_rejects_p2sh_cosigner_with_mismatched_redeem_script() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &alice_sk);
    let mut bob = Input::new(&outpoint(1));
    bob.sequence = Some(Sequence::MAX);
    set_verified_funding_utxo(
        &mut bob,
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::new_p2sh(&p2wpkh_script(&secp, &bob_sk).script_hash()),
        },
    );
    bob.redeem_script = Some(p2tr_script(&secp, &sk(5)));
    psbt.inputs[1] = bob;

    psbt.add_ecdh_shares(&secp, &mut rng(), &alice_sk, ShareMode::Partial)
        .unwrap();

    let result = psbt.derive_sp_output_scripts(&secp);
    assert!(
        matches!(result, Err(SpSignerError::RedeemScriptMismatch { vin: 1 })),
        "got {result:?}"
    );
}

/// Alice and Bob each add a partial share for their own input, and the outputs are committed.
fn committed_two_party_psbt(
    secp: &Secp256k1<secp256k1::All>,
    alice: (Input, &SecretKey),
    bob: (Input, &SecretKey),
) -> Psbt {
    let scan_pk = pk(secp, 2);
    let spend_pk = pk(secp, 3);
    let mut base = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );
    base.inputs[0] = alice.0;
    base.inputs[1] = bob.0;

    let mut psbt = base.clone();
    psbt.add_ecdh_shares(secp, &mut rng(), alice.1, ShareMode::Partial)
        .unwrap();
    let mut psbt_bob = base;
    psbt_bob
        .add_ecdh_shares(secp, &mut rng(), bob.1, ShareMode::Partial)
        .unwrap();
    psbt.inputs[1].sp_ecdh_shares = psbt_bob.inputs[1].sp_ecdh_shares.clone();
    psbt.inputs[1].sp_dleq_proofs = psbt_bob.inputs[1].sp_dleq_proofs.clone();
    psbt.commit_sp_outputs(secp).unwrap();
    psbt
}

/// Bob's P2WPKH funding output is only given as `witness_utxo`. Alice signs a SegWit v0 input,
/// whose signature does not commit to Bob's script, so she must refuse. Bob vouches for his own
/// input, so signing both is accepted.
#[test]
fn test_verify_before_signing_rejects_unverified_prevout() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let mut bob = p2wpkh_input(&secp, outpoint(1), &bob_sk);
    bob.non_witness_utxo = None;
    let psbt = committed_two_party_psbt(
        &secp,
        (p2wpkh_input(&secp, outpoint(0), &alice_sk), &alice_sk),
        (bob, &bob_sk),
    );

    let result = psbt.verify_before_signing(&secp, &[0]);
    assert!(
        matches!(result, Err(SpSignerError::UnverifiedPrevout { vin: 1 })),
        "got {result:?}"
    );
    psbt.verify_before_signing(&secp, &[0, 1]).unwrap();
}

/// Same unverified funding output for Bob, but Alice signs a P2TR input: her signature commits to
/// every prevout script, so a misreported script only invalidates it.
#[test]
fn test_verify_before_signing_accepts_unverified_prevout_when_signing_p2tr() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let mut bob = p2wpkh_input(&secp, outpoint(1), &bob_sk);
    bob.non_witness_utxo = None;
    let psbt = committed_two_party_psbt(
        &secp,
        (
            sp_p2tr_input(&secp, outpoint(0), &alice_sk, sk(7).secret_bytes()),
            &alice_sk,
        ),
        (bob, &bob_sk),
    );

    psbt.verify_before_signing(&secp, &[0]).unwrap();
}

/// A PSBT that comes back with a silent payment output script that does not follow from the
/// shares must not be signed.
#[test]
fn test_verify_before_signing_rejects_tampered_output_script() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();
    psbt.verify_before_signing(&secp, &[0]).unwrap();

    psbt.outputs[0].script_pubkey = p2tr_script(&secp, &sk(9));
    let result = psbt.verify_before_signing(&secp, &[0]);
    assert!(
        matches!(
            result,
            Err(SpSignerError::OutputScriptMismatch { index: 0 })
        ),
        "got {result:?}"
    );
}

/// A compressed P2PKH key matches its script and is what the receiver extracts from the scriptSig.
#[test]
fn test_compressed_p2pkh_contributes_and_receiver_can_scan() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);
    let input = p2pkh_input(&secp, outpoint(0), &spend_sk);

    assert_eq!(
        extract_eligible_input_pubkey(&input, 0).unwrap(),
        Some(spend_sk.public_key(&secp))
    );

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = input;
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();

    let spk = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    let script_sig = ScriptBuf::builder()
        .push_slice([0u8; 71])
        .push_key(&bitcoin::PublicKey::new(spend_sk.public_key(&secp)))
        .into_script();
    let pubkey = get_pubkey_from_input(script_sig.as_bytes(), &[], spk.as_bytes()).unwrap();
    assert_eq!(pubkey, Some(spend_sk.public_key(&secp)));

    let mut inputs = TransactionInputs::with_capacity(1);
    inputs
        .push(
            SpOutPoint::from_txid_and_vout(
                &psbt.inputs[0].previous_txid.to_string(),
                psbt.inputs[0].spent_output_index,
            )
            .unwrap(),
            spk.to_bytes(),
            pubkey,
        );
    assert_receiver_scan_finds_outputs_from(&secp, &psbt, &inputs, &scan_sk, &spend_pk);
}

/// A P2SH-P2WPKH input contributes its compressed key, and the receiver recovers the same key
/// from the redeem script and witness.
#[test]
fn test_p2sh_p2wpkh_contributes_and_receiver_can_scan() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);
    let input = p2sh_p2wpkh_input(&secp, outpoint(0), &spend_sk);

    assert_eq!(
        extract_eligible_input_pubkey(&input, 0).unwrap(),
        Some(spend_sk.public_key(&secp))
    );

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = input;
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();

    let redeem = psbt.inputs[0].redeem_script.clone().unwrap();
    let spk = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    let script_sig = ScriptBuf::builder()
        .push_slice(<&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap())
        .into_script();
    let witness = vec![
        vec![0u8; 72],
        spend_sk.public_key(&secp).serialize().to_vec(),
    ];
    let pubkey = get_pubkey_from_input(script_sig.as_bytes(), &witness, spk.as_bytes()).unwrap();
    assert_eq!(pubkey, Some(spend_sk.public_key(&secp)));

    let mut inputs = TransactionInputs::with_capacity(1);
    inputs
        .push(
            SpOutPoint::from_txid_and_vout(
                &psbt.inputs[0].previous_txid.to_string(),
                psbt.inputs[0].spent_output_index,
            )
            .unwrap(),
            spk.to_bytes(),
            pubkey,
        );
    assert_receiver_scan_finds_outputs_from(&secp, &psbt, &inputs, &scan_sk, &spend_pk);
}

/// The signer owns both inputs. Global mode must leave the uncompressed P2PKH key out of the sum,
/// which is what the receiver does when it reads that scriptSig.
#[test]
fn test_global_share_skips_owned_uncompressed_p2pkh() {
    let secp = secp();
    let spend_sk = sk(1);
    let uncompressed_sk = sk(4);
    let scan_sk = sk(2);
    let scan_pk = scan_sk.public_key(&secp);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(
        vec![sp_output(&scan_pk, &spend_pk)],
        vec![outpoint(0), outpoint(1)],
    );
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    psbt.inputs[1] = p2pkh_uncompressed_input(&secp, outpoint(1), &uncompressed_sk);
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();

    let mut inputs = TransactionInputs::with_capacity(2);
    let eligible = &psbt.inputs[0];
    inputs
        .push(
            SpOutPoint::from_txid_and_vout(
                &eligible.previous_txid.to_string(),
                eligible.spent_output_index,
            )
            .unwrap(),
            p2wpkh_script(&secp, &spend_sk).to_bytes(),
            Some(spend_sk.public_key(&secp)),
        );
    let skipped = &psbt.inputs[1];
    let skipped_spk = skipped
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .clone();
    let skipped_key = get_pubkey_from_input(
        p2pkh_uncompressed_script_sig(&secp, &uncompressed_sk).as_bytes(),
        &[],
        skipped_spk.as_bytes(),
    )
    .unwrap();
    assert_eq!(skipped_key, None);
    inputs
        .push(
            SpOutPoint::from_txid_and_vout(
                &skipped.previous_txid.to_string(),
                skipped.spent_output_index,
            )
            .unwrap(),
            skipped_spk.to_bytes(),
            skipped_key,
        );
    assert_receiver_scan_finds_outputs_from(&secp, &psbt, &inputs, &scan_sk, &spend_pk);
}

/// An uncompressed P2PKH input is the only one. Global mode has no key to sum.
#[test]
fn test_global_share_rejects_only_uncompressed_p2pkh() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2pkh_uncompressed_input(&secp, outpoint(0), &spend_sk);

    let result = psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global);
    assert!(result.is_err(), "got {result:?}");
    assert!(psbt.global.sp_ecdh_shares.is_empty());
}

/// An empty silent-payment script has not been derived, so it must not be signed.
#[test]
fn test_verify_before_signing_rejects_empty_output_script() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();
    psbt.outputs[0].script_pubkey = ScriptBuf::new();

    let result = psbt.verify_before_signing(&secp, &[0]);
    assert!(
        matches!(
            result,
            Err(SpSignerError::OutputScriptMismatch { index: 0 })
        ),
        "got {result:?}"
    );
}

/// A signed-input index past the end of the PSBT is rejected.
#[test]
fn test_verify_before_signing_rejects_out_of_range_index() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt = new_psbt(vec![sp_output(&scan_pk, &spend_pk)], vec![outpoint(0)]);
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    psbt.add_ecdh_shares(&secp, &mut rng(), &spend_sk, ShareMode::Global)
        .unwrap();
    psbt.commit_sp_outputs(&secp).unwrap();

    let result = psbt.verify_before_signing(&secp, &[9]);
    assert!(
        matches!(result, Err(SpSignerError::MalformedInput { vin: 9, .. })),
        "got {result:?}"
    );
}

/// The session was opened for input 0 only. Minting a signable input 1 must fail.
#[test]
fn test_session_rejects_signing_outside_declared_inputs() {
    let secp = secp();
    let alice_sk = sk(1);
    let bob_sk = sk(4);
    let psbt = committed_two_party_psbt(
        &secp,
        (p2wpkh_input(&secp, outpoint(0), &alice_sk), &alice_sk),
        (p2wpkh_input(&secp, outpoint(1), &bob_sk), &bob_sk),
    );
    let mut signer = Signer::new(psbt).unwrap();
    let verifier = SpOutputVerifier { secp: &secp };
    let result = signer.session(&verifier, &[0], |session| {
        session.signable_input(1).map(|_| ())
    });
    assert!(
        matches!(
            result,
            Ok(Err(SignError::NotInSignedInputs { index: 1 }))
        ),
        "got {result:?}"
    );
}
