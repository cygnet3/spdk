//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.
//!
//! This module handles both regular P2WPKH signing and Silent Payment P2TR signing:
//! - **P2PKH inputs**: Signs with ECDSA (legacy) → `partial_sigs`
//! - **P2WPKH inputs**: Signs with ECDSA (SegWit v0) → `partial_sigs`
//! - **P2TR inputs**: Signs with Schnorr (Taproot v1) → `tap_key_sig`, with optional SP tweak

use std::collections::HashMap;

use crate::core::utils::{to_psbt_dleq, to_rust_dleq};
use crate::core::{Error, Input, Psbt, Result};
use crate::roles::Bip375UpdaterExt;
use bitcoin::key::TweakedPublicKey;
use bitcoin::CompressedPublicKey;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::receiving::is_eligible;
use silentpayments::utils::sending::{
    GlobalSenderEcdhShare, NormalizedSecretKey, PartialSenderEcdhShare,
};
use silentpayments::utils::OutPoint;
use silentpayments::utils::NUMS_H;
use silentpayments::{NonEmptyArray, SpVersion, TransactionSharedSecret};
use silentpayments::{SilentPaymentKeyMaterial, TransactionInputs};

pub trait SignerPsbtExt {
    /// Single-signer share creation (BIP-375 global path).
    ///
    /// The caller must hold the spending key for *every* eligible input. For each recipient scan
    /// key, this writes one global ECDH share `C = a * B_scan` (raw, without the BIP-352 input
    /// hash) into `global.sp_ecdh_shares` plus the matching BIP-374 DLEQ proof into
    /// `global.sp_dleq_proofs`. No per-input fields are written.
    fn single_signer_generate_ecdh_shares(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<()>;
    /// Multi-signer share creation (BIP-375 per-input path).
    ///
    /// Contributes one per-input ECDH share `C = a_i * B_scan` (raw) plus a per-input DLEQ proof
    /// for every input this signer can resolve a key for (taproot SP inputs whose
    /// `spend_key + sp_tweak` matches the funding output). Inputs owned by other parties are left
    /// untouched, and no global fields are written.
    fn multi_signer_generate_ecdh_shares(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<()>;
    fn compute_sp_outputs(
        &self,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>>>;
    fn set_sp_scriptpubkey(
        &mut self,
        xonly_map: HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>>,
    ) -> Result<()>;
    fn sign_sp_inputs(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<Vec<XOnlyPublicKey>>;
}

impl SignerPsbtExt for Psbt {
    fn single_signer_generate_ecdh_shares(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<()> {
        let sp_v0_info = collect_sp_v0_keys(self)?;
        let scan_keys = collect_scan_keys(&sp_v0_info)?;
        if scan_keys.is_empty() {
            return Ok(());
        }

        // A single signer owns every eligible input, so resolving any one of them is mandatory.
        let mut summed_keys: Vec<NormalizedSecretKey> = Vec::new();
        for (vin, input) in self.inputs.iter().enumerate() {
            let funding_utxo = input
                .funding_utxo()
                .map_err(|_| Error::Other(format!("Input {vin} missing funding utxo")))?;
            if !is_eligible(funding_utxo.script_pubkey.as_bytes()) {
                continue;
            }
            let input_key =
                resolve_owned_eligible_key(secp, input, &spend_key)?.ok_or_else(|| {
                    Error::Other(format!(
                        "Single signer cannot resolve the spending key for eligible input {vin}"
                    ))
                })?;
            let is_taproot = funding_utxo.script_pubkey.is_p2tr();
            summed_keys.push(NormalizedSecretKey::new(secp, input_key, is_taproot));
        }

        for scan_key in &scan_keys {
            let aux_rand: [u8; 32] = rand::random();
            let keys = NonEmptyArray::new(&summed_keys).map_err(|e| Error::Other(e.to_string()))?;
            let global_share =
                GlobalSenderEcdhShare::new_from_summed_keys(secp, scan_key.0, keys, &aux_rand)
                    .map_err(|e| Error::Other(e.to_string()))?;
            self.global.sp_ecdh_shares.insert(
                *scan_key,
                CompressedPublicKey(*global_share.as_ecdh_shared_secret()),
            );
            self.global
                .sp_dleq_proofs
                .insert(*scan_key, to_psbt_dleq(*global_share.dleq_proof()));
        }

        Ok(())
    }

    fn multi_signer_generate_ecdh_shares(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<()> {
        let sp_v0_info = collect_sp_v0_keys(self)?;
        let scan_keys = collect_scan_keys(&sp_v0_info)?;
        if scan_keys.is_empty() {
            return Ok(());
        }

        for (vin, input) in self.inputs.iter_mut().enumerate() {
            // Only contribute shares for inputs this signer actually owns.
            let Some(input_key) = resolve_owned_eligible_key(secp, input, &spend_key)? else {
                continue;
            };
            let funding_utxo = input
                .funding_utxo()
                .map_err(|_| Error::Other(format!("Input {vin} missing funding utxo")))?;
            let is_taproot = funding_utxo.script_pubkey.is_p2tr();
            let normalized = NormalizedSecretKey::new(secp, input_key, is_taproot);

            for scan_key in &scan_keys {
                let aux_rand: [u8; 32] = rand::random();
                let partial = PartialSenderEcdhShare::new(
                    secp,
                    scan_key.0,
                    vin,
                    &normalized,
                    &aux_rand,
                )
                .map_err(|e| Error::Other(e.to_string()))?;
                input.sp_ecdh_shares.insert(
                    *scan_key,
                    CompressedPublicKey(*partial.as_ecdh_shared_secret()),
                );
                input
                    .sp_dleq_proofs
                    .insert(*scan_key, to_psbt_dleq(*partial.dleq_proof()));
            }
        }

        Ok(())
    }

    fn compute_sp_outputs(
        &self,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>>> {
        let sp_addresses_bytes = collect_sp_v0_keys(self)?;
        let scan_keys = collect_scan_keys(&sp_addresses_bytes)?;
        let mut scan_key_to_shared_secret: HashMap<PublicKey, TransactionSharedSecret> =
            HashMap::with_capacity(scan_keys.len());
        let has_global = !self.global.sp_ecdh_shares.is_empty();
        let has_partial = self
            .inputs
            .iter()
            .any(|input| !input.sp_ecdh_shares.is_empty());
        if !has_global && !has_partial {
            return Err(Error::InvalidPsbtState("No shares found".to_string()));
        }
        let mut transaction_inputs = TransactionInputs::with_capacity(self.global.input_count);
        for input in self.inputs.iter() {
            let outpoint = OutPoint::from_txid_and_vout(
                input.previous_txid.to_string(),
                input.spent_output_index,
            )
            .map_err(|e| Error::Other(e.to_string()))?;
            let spk = &input
                .funding_utxo()
                .map_err(|e| Error::Other(e.to_string()))?
                .script_pubkey;
            let pubkey = extract_eligible_input_pubkey(input)?;
            transaction_inputs.push(outpoint, spk.to_bytes(), pubkey);
        }
        let eligible_vins = transaction_inputs.eligible_vins();
        for scan_key in scan_keys.iter() {
            if let Some(shared_secret) = self.global.sp_ecdh_shares.get(scan_key) {
                // We must have a dleq proof
                let dleq_proof = self.global.sp_dleq_proofs.get(scan_key).ok_or_else(|| {
                    Error::InvalidPsbtState(format!(
                        "No dleq proof found for global share {scan_key}"
                    ))
                })?;
                let global_secret = GlobalSenderEcdhShare::new_unchecked(
                    scan_key.0,
                    shared_secret.0,
                    to_rust_dleq(*dleq_proof),
                );
                let shared_secret = TransactionSharedSecret::new_from_global_share(
                    secp,
                    &global_secret,
                    &transaction_inputs,
                )
                .map_err(|e| Error::Other(e.to_string()))?;
                scan_key_to_shared_secret.insert(scan_key.0, shared_secret);
            } else {
                let mut partial_shares = Vec::with_capacity(self.global.input_count);
                for (vin, input) in self.inputs.iter().enumerate() {
                    if !eligible_vins.contains(&vin) {
                        continue;
                    }
                    let Some(shared_secret) = input.sp_ecdh_shares.get(scan_key) else {
                        return Err(Error::InvalidPsbtState(format!(
                            "No shared secret found for input {vin} and scan key {scan_key}"
                        )));
                    };
                    let dleq_proof = input.sp_dleq_proofs.get(scan_key).ok_or_else(|| {
                        Error::InvalidPsbtState(format!(
                            "No dleq proof found for input {vin} and scan key {scan_key}"
                        ))
                    })?;
                    let partial_share = PartialSenderEcdhShare::new_unchecked(
                        scan_key.0,
                        vin,
                        shared_secret.0,
                        to_rust_dleq(*dleq_proof),
                    );
                    partial_shares.push(partial_share);
                }
                let shared_secret = TransactionSharedSecret::new_from_partial_shares(
                    secp,
                    scan_key.0,
                    NonEmptyArray::new(&partial_shares).map_err(|e| Error::Other(e.to_string()))?,
                    &transaction_inputs,
                )
                .map_err(|e| Error::Other(e.to_string()))?;
                scan_key_to_shared_secret.insert(scan_key.0, shared_secret);
            }
        }
        let res_map = generate_recipient_pubkeys(
            secp,
            sp_addresses_bytes
                .into_iter()
                .filter_map(|x| x)
                .collect::<Vec<SilentPaymentKeyMaterial>>()
                .as_slice(),
            &scan_key_to_shared_secret,
        ).map_err(|e| Error::Other(e.to_string()))?;
        Ok(res_map)
    }

    fn set_sp_scriptpubkey(
        &mut self,
        mut xonly_map: HashMap<SilentPaymentKeyMaterial, Vec<XOnlyPublicKey>>,
    ) -> Result<()> {
        let mut update_outputs = self.outputs.clone();
        for output in update_outputs.iter_mut() {
            if let Some(sp_info) = output.sp_v0_info.as_ref() {
                // Find the matching pubkey
                let key = sp_info_to_key_material(sp_info.as_slice())?;
                if let Some(xonly_keys) = xonly_map.get_mut(&key) {
                    if xonly_keys.is_empty() {
                        return Err(Error::Other(format!("Not enough keys")));
                    };
                    let xonly_key = xonly_keys.remove(0);
                    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly_key);
                    let script = ScriptBuf::new_p2tr_tweaked(tweaked);
                    output.script_pubkey = script;
                } else {
                    return Err(Error::InvalidPsbtState(format!(
                        "sp_info {:?} doesn't exit in provided map",
                        key
                    )));
                }
            } else {
                // not a sp output
                continue;
            }
        }
        // Check that we used all provided key
        for (_address, xonly_keys) in xonly_map {
            if !xonly_keys.is_empty() {
                return Err(Error::InvalidPsbtState(format!(
                    "Failed to use all provided keys"
                )));
            }
        }

        // Now replace the initial outputs
        self.outputs = update_outputs;

        // Make the psbt non modifiable
        self.global.tx_modifiable_flags = 0u8;

        Ok(())
    }

    fn sign_sp_inputs(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<Vec<XOnlyPublicKey>> {
        let signed_xonly_keys = self
            .sign_silent_payment_inputs(&spend_key, secp)
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(signed_xonly_keys)
    }
}

fn collect_scan_keys(
    sp_v0_info: &[Option<SilentPaymentKeyMaterial>],
) -> Result<Vec<CompressedPublicKey>> {
    sp_v0_info
        .iter()
        .filter_map(|x| {
            let Some(x) = x else {
                return None;
            };
            Some(CompressedPublicKey::from_slice(&x.scan_key().serialize()).map_err(|e| Error::Other(e.to_string())))
        })
        .collect()
}

/// Build the v0 key material from the 66-byte `sp_v0_info` blob (scan key ‖ spend key,
/// both compressed).
fn sp_info_to_key_material(sp_info: &[u8]) -> Result<SilentPaymentKeyMaterial> {
    if sp_info.len() != 66 {
        return Err(Error::InvalidFieldData(format!(
            "Invalid SP info length: {}",
            sp_info.len()
        )));
    }
    let scan_key = PublicKey::from_slice(&sp_info[..33]).map_err(|e| Error::Other(e.to_string()))?;
    let m_pubkey =
        PublicKey::from_slice(&sp_info[33..]).map_err(|e| Error::Other(e.to_string()))?;
    Ok(SilentPaymentKeyMaterial::new(
        SpVersion::ZERO,
        scan_key,
        m_pubkey,
    ))
}

/// Collect the recipient keys from the SP outputs of the PSBT and preserve the index (put None if output is not SP).
fn collect_sp_v0_keys(psbt: &Psbt) -> Result<Vec<Option<SilentPaymentKeyMaterial>>> {
    let mut res: Vec<Option<SilentPaymentKeyMaterial>> =
        Vec::with_capacity(psbt.global.output_count);
    let mut sorted_outputs: Vec<_> = psbt.outputs.iter().enumerate().collect();
    sorted_outputs.sort_by(|(index_a, output_a), (index_b, output_b)| {
        output_a
            .sp_v0_info
            .cmp(&output_b.sp_v0_info)
            .then(index_a.cmp(index_b))
    });
    for (i, output) in sorted_outputs {
        let Some(sp_info) = output.sp_v0_info.as_ref() else {
            res.push(None);
            continue;
        };
        let key_material = sp_info_to_key_material(sp_info.as_slice()).map_err(|e| match e {
            Error::InvalidFieldData(_) => Error::InvalidFieldData(format!(
                "Output {} has invalid SP info length: {}",
                i,
                sp_info.len()
            )),
            other => other,
        })?;
        res.push(Some(key_material));
    }
    Ok(res)
}

/// Extract the BIP-352 input public key from PSBT fields populated by the Updater.
///
/// Returns `Some(pubkey)` for each eligible script type:
/// - **P2TR with `sp_tweak`**: reads the tweaked spend key from `sp_spend_bip32_derivations`.
/// - **P2TR without `sp_tweak`**: reads `tap_internal_key`, promoted to even parity (BIP-352 §3).
/// - **P2WPKH / P2PKH**: reads from `bip32_derivations`.
/// - **P2SH-P2WPKH**: checks that `redeem_script` is P2WPKH, then reads from `bip32_derivations`.
///
/// Returns `Ok(None)` when the input is not eligible or when the required PSBT fields have not
/// been populated by the Updater yet.
pub fn extract_eligible_input_pubkey(
    input: &Input,
) -> Result<Option<PublicKey>> {
    let funding_utxo = input
        .funding_utxo()
        .map_err(|_| Error::Other("Input missing funding utxo".to_string()))?;
    let spk = &funding_utxo.script_pubkey;

    if !is_eligible(spk.as_bytes()) {
        return Ok(None);
    }

    if spk.is_p2tr() {
        if input.sp_tweak.is_some() {
            // SP tweaked output: the tweaked spend key is what BIP-352 uses for ECDH.
            let (pubkey, _, _) = input.get_sp_spend_bip32_derivation().ok_or_else(|| {
                Error::Other("P2TR SP input missing sp_spend_bip32_derivation".to_string())
            })?;
            Ok(Some(pubkey))
        } else {
            // BIP-352 §3: use the taproot **output key** (from the scriptPubKey), not the
            // internal key. The sender signs with the tweaked private key and the receiver
            // reads the same key from the scriptPubKey.
            //
            // Exception (BIP-352 §3): if the internal key is NUMS_H the output has no
            // key path, so there is no private key to contribute — skip this input.
            if let Some(internal_key) = input.tap_internal_key {
                if internal_key.serialize() == NUMS_H {
                    return Ok(None);
                }
            }
            let output_xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])?;
            Ok(Some(output_xonly.public_key(Parity::Even)))
        }
    } else if spk.is_p2wpkh() || spk.is_p2pkh() {
        let (pubkey, _, _) = input
            .get_bip32_derivation()
            .ok_or_else(|| Error::Other("Input missing bip32_derivation".to_string()))?;
        Ok(Some(pubkey))
    } else if spk.is_p2sh() {
        let Some(redeem_script) = input.redeem_script.as_ref() else {
            return Ok(None);
        };
        if !redeem_script.is_p2wpkh() {
            return Ok(None);
        }
        let (pubkey, _, _) = input.get_bip32_derivation().ok_or_else(|| {
            Error::Other("P2SH-P2WPKH input missing bip32_derivation".to_string())
        })?;
        Ok(Some(pubkey))
    } else {
        Ok(None)
    }
}

/// Resolve the private key for an eligible input owned by `spend_key`.
///
/// Calls [`extract_eligible_input_pubkey`] to read the public key declared by the Updater, then
/// checks whether `spend_key` (with `sp_tweak` applied for SP P2TR inputs) produces that key.
///
/// For P2TR the comparison is x-only (parity-agnostic); for ECDSA types the full compressed
/// public key must match.
///
/// Returns `Ok(None)` for inputs that are not eligible or not owned by `spend_key`.
fn resolve_owned_eligible_key(
    secp: &Secp256k1<secp256k1::All>,
    input: &Input,
    spend_key: &SecretKey,
) -> Result<Option<SecretKey>> {
    let Some(input_pubkey) = extract_eligible_input_pubkey(input)? else {
        return Ok(None);
    };

    let funding_utxo = input
        .funding_utxo()
        .map_err(|_| Error::Other("Input missing funding utxo".to_string()))?;

    let candidate = if let Some(tweak_bytes) = input.sp_tweak {
        let tweak = Scalar::from_be_bytes(tweak_bytes)
            .map_err(|_| Error::Other("Invalid sp_tweak: not a valid scalar".to_string()))?;
        spend_key
            .add_tweak(&tweak)
            .map_err(|_| Error::Other("Failed to apply sp_tweak to spend key".to_string()))?
    } else {
        *spend_key
    };

    // P2TR: compare x-only (parity-agnostic, since BIP-352 normalises to even).
    // ECDSA types: compare full compressed keys (parity is part of the commitment).
    let owns = if funding_utxo.script_pubkey.is_p2tr() {
        candidate.x_only_public_key(secp).0 == input_pubkey.x_only_public_key().0
    } else {
        candidate.public_key(secp) == input_pubkey
    };

    if owns {
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
}
