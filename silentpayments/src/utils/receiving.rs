//! Receiving utility functions.
use crate::{
    Error, Result, utils::{
        hash::OUTPOINTS_LEN, is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh
    }
};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::{Parity::Even, Secp256k1, Verification, XOnlyPublicKey, ecdh::shared_secret_point};
use secp256k1::{PublicKey, SecretKey};

use super::{hash::calculate_input_hash, COMPRESSED_PUBKEY_SIZE, NUMS_H};

/// Calculate the tweak data of a transaction.
///
/// This is useful in combination with the [calculate_ecdh_shared_secret] function, but can also be used
/// by indexing servers that don't have access to the recipient scan key.
///
/// # Arguments
///
/// * `secp` - Secp256k1 context used for elliptic curve operations.
/// * `input_pub_keys` - The list of public keys that are used as input for this transaction. Only the public keys for inputs that are silent payment eligible should be given.
/// * `outpoints_head` - The first prevout outpoint used as input for this transaction in serialized form.
/// * `outpoints_tail` - The remaining prevout outpoints used as input for this transaction in serialized form.
///
/// # Returns
///
/// This function returns the tweak data for this transaction. The tweak data is an intermediary result that can be used to calculate the final shared secret.
///
/// # Errors
///
/// This function will error if:
///
/// * The input public keys array is of length zero, or the summing results in an invalid key.
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_tweak_data<C: Verification>(
    secp: &Secp256k1<C>,
    input_pub_keys: &[&PublicKey],
    outpoints_head: &[u8; OUTPOINTS_LEN],
    outpoints_tail: &[[u8; OUTPOINTS_LEN]]
) -> Result<PublicKey> {
    let A_sum = PublicKey::combine_keys(input_pub_keys)?;
    let input_hash = calculate_input_hash(&outpoints_head, &outpoints_tail, A_sum);

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

/// Calculate the shared secret of a transaction.
///
/// # Arguments
///
/// * `tweak_data` - The tweak data of the transaction, see `calculate_tweak_data`.
/// * `b_scan` - The scan private key used by the wallet.
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See [`Receiver::scan_transaction`](crate::receiving::Receiver::scan_transaction).
pub fn calculate_ecdh_shared_secret(tweak_data: &PublicKey, b_scan: &SecretKey) -> PublicKey {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    ss_bytes[1..].copy_from_slice(&shared_secret_point(&tweak_data, &b_scan));

    PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
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
    txinwitness: &Vec<Vec<u8>>,
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
