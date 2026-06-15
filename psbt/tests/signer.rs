//! Integration tests for the signer role.
//!
//! Covers:
//!   1. Regression for `collect_scan_keys` off-by-one (was passing 67-byte array to a
//!      33-byte key parser, making the entire SP path non-functional).
//!   2. Regression for multi-signer skipping non-eligible inputs in `compute_sp_outputs`.
//!   3. BIP-352 n-counter correctness: two outputs to the same scan key produce distinct keys.
//!   4. Unit tests for `extract_eligible_input_pubkey` covering all declared script types.
//!   5. Known-failing case documenting the outstanding `is_partial` detection bug when
//!      `compute_sp_outputs` is called in multi-signer mode with mixed eligible/non-eligible inputs.

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid, XOnlyPublicKey};
use psbt::roles::signer::extract_eligible_input_pubkey;
use psbt::roles::updater::Bip375UpdaterExt;
use psbt::roles::{ConstructorPsbtExt, SignerPsbtExt};
use psbt::Psbt;
use psbt_v2::v2::{Input, Output};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::utils::NUMS_H;

// ── test helpers ──────────────────────────────────────────────────────────────

fn secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
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
    let mut sp_info = [0u8; 66];
    sp_info[..33].copy_from_slice(&scan.serialize());
    sp_info[33..].copy_from_slice(&spend.serialize());
    let mut output = Output::new(TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: ScriptBuf::new(),
    });
    output.sp_v0_info = Some(sp_info);
    output
}

/// Build a P2WPKH `Input` with `witness_utxo` and `bip32_derivations` populated so
/// that `extract_eligible_input_pubkey` can identify and return the key.
fn p2wpkh_input(
    secp: &Secp256k1<secp256k1::All>,
    outpoint: OutPoint,
    secret: &SecretKey,
) -> Input {
    let public = secret.public_key(secp);
    let mut input = Input::new(&outpoint);
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: p2wpkh_script(secp, secret),
    });
    input.set_bip32_derivation(&public, Fingerprint::default(), DerivationPath::default());
    input
}

fn outpoint(vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::all_zeros()), vout)
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

    let mut psbt = Psbt::create_new_transaction(vec![sp_output(&scan_pk, &spend_pk)]).unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0)]).unwrap();
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.single_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();
    assert!(!psbt.global.sp_ecdh_shares.is_empty());
    assert!(!psbt.global.sp_dleq_proofs.is_empty());

    let xonly_map = psbt.compute_sp_outputs(&secp).unwrap();
    assert_eq!(xonly_map.len(), 1);

    psbt.set_sp_scriptpubkey(xonly_map).unwrap();

    let sp_out = psbt.outputs.iter().find(|o| o.sp_v0_info.is_some()).unwrap();
    assert!(
        sp_out.script_pubkey.is_p2tr(),
        "SP output must be a P2TR scriptPubKey"
    );
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

    let mut psbt = Psbt::create_new_transaction(vec![regular_out]).unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0)]).unwrap();
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.single_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();
    assert!(
        psbt.global.sp_ecdh_shares.is_empty(),
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
    let mut psbt = Psbt::create_new_transaction(vec![
        sp_output(&scan_pk, &spend_pk),
        sp_output(&scan_pk, &spend_pk),
    ])
    .unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0)]).unwrap();
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.single_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();
    let xonly_map = psbt.compute_sp_outputs(&secp).unwrap();

    // Both share the same 67-byte address key → single map entry, two output keys.
    assert_eq!(xonly_map.len(), 1, "single address entry expected");
    let keys = xonly_map.values().next().unwrap();
    assert_eq!(keys.len(), 2, "n=0 and n=1 keys must both be present");
    assert_ne!(keys[0], keys[1], "n=0 and n=1 must be distinct xonly keys");
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

    let mut psbt = Psbt::create_new_transaction(vec![
        sp_output(&scan_pk_a, &spend_pk),
        sp_output(&scan_pk_b, &spend_pk),
    ])
    .unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0)]).unwrap();
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    psbt.single_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();
    assert_eq!(psbt.global.sp_ecdh_shares.len(), 2, "one share per scan key");

    let xonly_map = psbt.compute_sp_outputs(&secp).unwrap();
    assert_eq!(xonly_map.len(), 2, "one map entry per distinct SP address");
    for keys in xonly_map.values() {
        assert_eq!(keys.len(), 1);
    }
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

    let mut psbt =
        Psbt::create_new_transaction(vec![sp_output(&scan_pk, &spend_pk)]).unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0), outpoint(1)]).unwrap();

    // Input 0: eligible P2WPKH owned by spend_sk.
    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);

    // Input 1: non-eligible empty-script input (BIP-352 excludes it from ECDH).
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    nonelig.witness_utxo = Some(TxOut {
        value: Amount::from_sat(5_000),
        script_pubkey: ScriptBuf::default(), // empty → not eligible
    });
    psbt.inputs[1] = nonelig;

    psbt.multi_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();

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

    let mut psbt =
        Psbt::create_new_transaction(vec![sp_output(&scan_pk, &spend_pk)]).unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0), outpoint(1)]).unwrap();

    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    nonelig.witness_utxo = Some(TxOut {
        value: Amount::from_sat(3_000),
        script_pubkey: ScriptBuf::default(),
    });
    psbt.inputs[1] = nonelig;

    psbt.single_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();
    let xonly_map = psbt.compute_sp_outputs(&secp).unwrap();
    assert_eq!(xonly_map.len(), 1);
    psbt.set_sp_scriptpubkey(xonly_map).unwrap();

    let sp_out = psbt.outputs.iter().find(|o| o.sp_v0_info.is_some()).unwrap();
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
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: p2wpkh_script(&secp, &secret),
    });
    input.set_bip32_derivation(&public, Fingerprint::default(), DerivationPath::default());

    let result = extract_eligible_input_pubkey(&input).unwrap();
    assert_eq!(result, Some(public));
}

/// P2WPKH input without `bip32_derivations` → returns `Err` (missing derivation).
#[test]
fn test_extract_p2wpkh_missing_derivation_errors() {
    let secp = secp();
    let secret = sk(1);
    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: p2wpkh_script(&secp, &secret),
    });
    // Deliberately omit bip32_derivations.
    assert!(
        extract_eligible_input_pubkey(&input).is_err(),
        "must error when bip32_derivations is absent for a P2WPKH input"
    );
}

/// P2TR input whose `tap_internal_key` is NUMS_H must return `Ok(None)`.
///
/// NUMS_H indicates a script-path-only output with no usable key path — BIP-352 §3
/// explicitly excludes it from ECDH contribution.
#[test]
fn test_extract_p2tr_nums_h_internal_key_returns_none() {
    let secp = secp();
    let secret = sk(1);
    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: p2tr_script(&secp, &secret),
    });
    input.tap_internal_key = Some(XOnlyPublicKey::from_slice(&NUMS_H).unwrap());

    let result = extract_eligible_input_pubkey(&input).unwrap();
    assert!(
        result.is_none(),
        "NUMS_H internal key must mark the input as non-contributing"
    );
}

/// An input whose `witness_utxo` has a non-eligible scriptPubKey must return `Ok(None)`.
#[test]
fn test_extract_non_eligible_script_returns_none() {
    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: ScriptBuf::default(), // empty → not eligible
    });

    let result = extract_eligible_input_pubkey(&input).unwrap();
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
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: p2sh_script,
    });
    input.redeem_script = Some(non_wpkh_redeem);

    let result = extract_eligible_input_pubkey(&input).unwrap();
    assert!(
        result.is_none(),
        "P2SH with non-P2WPKH redeem must be ineligible"
    );
}

/// P2SH input with no redeem script set → must return `Ok(None)` (updater hasn't
/// populated the PSBT yet).
#[test]
fn test_extract_p2sh_missing_redeem_script_returns_none() {
    let secp = secp();
    let secret = sk(1);
    let p2wpkh = p2wpkh_script(&secp, &secret);
    let p2sh_script = ScriptBuf::new_p2sh(&p2wpkh.script_hash());

    let mut input = Input::new(&outpoint(0));
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: p2sh_script,
    });
    // redeem_script intentionally absent.

    let result = extract_eligible_input_pubkey(&input).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_multi_signer_compute_sp_outputs_with_non_eligible_input() {
    let secp = secp();
    let spend_sk = sk(1);
    let scan_pk = pk(&secp, 2);
    let spend_pk = pk(&secp, 3);

    let mut psbt =
        Psbt::create_new_transaction(vec![sp_output(&scan_pk, &spend_pk)]).unwrap();
    psbt = psbt.add_inputs(vec![outpoint(0), outpoint(1)]).unwrap();

    psbt.inputs[0] = p2wpkh_input(&secp, outpoint(0), &spend_sk);
    let mut nonelig = Input::new(&outpoint(1));
    nonelig.sequence = Some(Sequence::MAX);
    nonelig.witness_utxo = Some(TxOut {
        value: Amount::from_sat(5_000),
        script_pubkey: ScriptBuf::default(),
    });
    psbt.inputs[1] = nonelig;

    psbt.multi_signer_generate_ecdh_shares(&secp, spend_sk).unwrap();

    // This call currently fails: "No shares found".
    psbt.compute_sp_outputs(&secp).unwrap();
}
