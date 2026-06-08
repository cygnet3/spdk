//! Receiving utility functions.
use crate::{
    Error, InputsHash, Result,
    utils::{
        common::{eligible_input_pubkey_refs, NonEmptyArray, OutPoint},
        script::{is_p2pkh, is_p2sh, is_p2wpkh},
    },
};

pub use crate::utils::script::{is_eligible, is_p2tr};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::{Parity::Even, Secp256k1, Verification, XOnlyPublicKey};
use secp256k1::{PublicKey};

use super::{COMPRESSED_PUBKEY_SIZE, NUMS_H};

/// Public tweak data for a transaction: `input_hash * sum(eligible input pubkeys)`.
///
/// Indexing servers can publish this value so recipients can derive a
/// [`TransactionSharedSecret`](crate::TransactionSharedSecret) locally without revealing their scan private key.
pub struct PublicTweakData(PublicKey);

impl PublicTweakData {
    /// Construct tweak data from a value obtained from a trusted external source.
    ///
    /// Prefer [`Self::new`] when computing from chain data directly.
    pub fn new_unchecked(tweak_data: PublicKey) -> Self {
        Self(tweak_data)
    }

    /// Calculate the tweak data of a transaction: `input_hash * sum(eligible input pubkeys)`.
    ///
    /// Uses the same inputs as [`InputsHash::new`]. Combine with
    /// [`TransactionSharedSecret::new_from_public_tweak_data`](crate::TransactionSharedSecret::new_from_public_tweak_data)
    /// to obtain the shared secret used by [`Receiver::scan_transaction`](crate::receiving::Receiver::scan_transaction).
    ///
    /// # Arguments
    ///
    /// * `outpoints` - outpoints of all inputs spent by the transaction.
    /// * `script_pubkeys` - For each outpoint, the prevout script pubkey and its extracted pubkey
    ///   if the input is silent-payment eligible. Pass `None` when no pubkey could be extracted.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// * `outpoints` and `script_pubkeys` differ in length or are empty.
    /// * No eligible input pubkeys could be extracted.
    /// * Elliptic curve computation results in an invalid public key.
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        outpoints: NonEmptyArray<OutPoint>,
        script_pubkeys: NonEmptyArray<(Vec<u8>, Option<PublicKey>)>,
    ) -> Result<Self> {
        let eligible_pubkeys = eligible_input_pubkey_refs(script_pubkeys.as_inner())?;
        let summed_pubkeys = PublicKey::combine_keys(&eligible_pubkeys)?;
        let input_hash = InputsHash::new(outpoints, script_pubkeys)?;
        Ok(Self(summed_pubkeys.mul_tweak(secp, input_hash.as_inner())?))
    }

    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }
}

/// Get the public keys from a set of input data.
///
/// # Arguments
///
/// * `script_sig` - The script signature as a byte array.
/// * `txinwitness` - The witness data.
/// * `script_pub_key` - The scriptpubkey from the output spent. This requires looking up the previous output.
///
/// # Returns
///
/// If no errors occur, this function will optionally return a [PublicKey] if this input is silent payment-eligible.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided Vin data is incorrect.
pub fn get_pubkey_from_input(
    script_sig: &[u8],
    txinwitness: &[Vec<u8>],
    script_pub_key: &[u8],
) -> Result<Option<PublicKey>> {
    if is_p2pkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (true, false) => {
                let spk_hash = &script_pub_key[3..23];
                for i in (COMPRESSED_PUBKEY_SIZE..=script_sig.len()).rev() {
                    if let Some(pubkey_bytes) = script_sig.get(i - COMPRESSED_PUBKEY_SIZE..i) {
                        let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
                        if pubkey_hash.to_byte_array() == spk_hash {
                            return Ok(Some(PublicKey::from_slice(pubkey_bytes)?));
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2pkh".to_owned(),
                ))
            }
            (false, _) => {
                return Err(Error::InvalidVin(
                    "non empty witness for spending a p2pkh".to_owned(),
                ))
            }
        }
    } else if is_p2sh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, false) => {
                let redeem_script = &script_sig[1..];
                if is_p2wpkh(redeem_script) {
                    if let Some(value) = txinwitness.last() {
                        match (
                            PublicKey::from_slice(value),
                            value.len() == COMPRESSED_PUBKEY_SIZE,
                        ) {
                            (Ok(pubkey), true) => {
                                return Ok(Some(pubkey));
                            }
                            (_, false) => {
                                return Ok(None);
                            }
                            // Not sure how we could get an error here, so just return none for now
                            // if the pubkey cant be parsed
                            (Err(_), _) => {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2sh".to_owned(),
                ))
            }
            (true, false) => return Ok(None),
        }
    } else if is_p2wpkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                if let Some(value) = txinwitness.last() {
                    match (
                        PublicKey::from_slice(value),
                        value.len() == COMPRESSED_PUBKEY_SIZE,
                    ) {
                        (Ok(pubkey), true) => {
                            return Ok(Some(pubkey));
                        }
                        (_, false) => {
                            return Ok(None);
                        }
                        // Not sure how we could get an error here, so just return none for now
                        // if the pubkey cant be parsed
                        (Err(_), _) => {
                            return Ok(None);
                        }
                    }
                } else {
                    return Err(Error::InvalidVin("Empty witness".to_owned()));
                }
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    } else if is_p2tr(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                // check for the optional annex
                let annex = match txinwitness.last().and_then(|value| value.first()) {
                    Some(&0x50) => 1,
                    Some(_) => 0,
                    None => return Err(Error::InvalidVin("Empty or invalid witness".to_owned())),
                };

                // Check for script path
                let stack_size = txinwitness.len();
                if stack_size > annex && txinwitness[stack_size - annex - 1][1..33] == NUMS_H {
                    return Ok(None);
                }

                // Return the pubkey from the script pubkey
                return XOnlyPublicKey::from_slice(&script_pub_key[2..34])
                    .map_err(Error::Secp256k1Error)
                    .map(|x_only_public_key| {
                        Some(PublicKey::from_x_only_public_key(x_only_public_key, Even))
                    });
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    }
    Ok(None)
}
