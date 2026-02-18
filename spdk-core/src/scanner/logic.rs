use std::collections::{HashMap, HashSet};

use anyhow::{Error, Result};
use bitcoin::{
    BlockHash, OutPoint, Txid, XOnlyPublicKey, absolute::Height, bip158::BlockFilter, hashes::{Hash, sha256}, hex::DisplayHex, secp256k1::{PublicKey, Scalar}
};
use silentpayments::receiving::{Label, Receiver};

use crate::{
    backend::UtxoData,
    client::{OutputSpendStatus, OwnedOutput},
};

/// Check if a block's created-UTXO filter matches any of our candidate scriptpubkeys.
pub(crate) fn check_block_outputs(
    created_utxo_filter: BlockFilter,
    blkhash: BlockHash,
    candidate_spks: Vec<&[u8; 34]>,
) -> Result<bool> {
    let output_keys: Vec<_> = candidate_spks
        .into_iter()
        .map(|spk| spk[2..].as_ref())
        .collect();

    // note: match will always return true for an empty query!
    if !output_keys.is_empty() {
        Ok(created_utxo_filter.match_any(&blkhash, &mut output_keys.into_iter())?)
    } else {
        Ok(false)
    }
}

/// Compute 8-byte input hashes for our owned outpoints against a given block hash.
pub(crate) fn get_input_hashes(
    owned_outpoints: &HashSet<OutPoint>,
    blkhash: BlockHash,
) -> Result<HashMap<[u8; 8], OutPoint>> {
    let mut map: HashMap<[u8; 8], OutPoint> = HashMap::new();

    for outpoint in owned_outpoints {
        let mut arr = [0u8; 68];
        arr[..32].copy_from_slice(&outpoint.txid.to_raw_hash().to_byte_array());
        arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
        arr[36..].copy_from_slice(&blkhash.to_byte_array());
        let hash = sha256::Hash::hash(&arr);

        let mut res = [0u8; 8];
        res.copy_from_slice(&hash[..8]);

        map.insert(res, *outpoint);
    }

    Ok(map)
}

/// Check if a block's spent filter matches any of our input hashes.
pub(crate) fn check_block_inputs(
    spent_filter: BlockFilter,
    blkhash: BlockHash,
    input_hashes: Vec<[u8; 8]>,
) -> Result<bool> {
    // note: match will always return true for an empty query!
    if !input_hashes.is_empty() {
        Ok(spent_filter.match_any(&blkhash, &mut input_hashes.into_iter())?)
    } else {
        Ok(false)
    }
}

/// Given fetched UTXOs and a secret map, find which ones belong to us.
pub(crate) fn find_owned_in_utxos(
    sp_receiver: &Receiver,
    utxos: Vec<UtxoData>,
    secrets_map: &HashMap<[u8; 34], PublicKey>,
) -> Result<Vec<(Option<Label>, UtxoData, Scalar)>> {
    let mut res: Vec<(Option<Label>, UtxoData, Scalar)> = vec![];

    // group utxos by the txid
    let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
    for utxo in utxos {
        txmap.entry(utxo.txid).or_default().push(utxo);
    }

    for utxos in txmap.into_values() {
        // check if we know the secret to any of the spks
        let mut secret = None;
        for utxo in utxos.iter() {
            let spk = utxo.scriptpubkey.as_bytes();
            if let Some(s) = secrets_map.get(spk) {
                secret = Some(s);
                break;
            }
        }

        // skip this tx if no secret is found
        let secret = match secret {
            Some(secret) => secret,
            None => continue,
        };

        let output_keys: Result<Vec<XOnlyPublicKey>> = utxos
            .iter()
            .filter_map(|x| {
                if x.scriptpubkey.is_p2tr() {
                    Some(
                        XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..])
                            .map_err(Error::new),
                    )
                } else {
                    None
                }
            })
            .collect();

        let ours = sp_receiver.scan_transaction(secret, output_keys?)?;

        for utxo in utxos {
            if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                continue;
            }

            match XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..]) {
                Ok(xonly) => {
                    for (label, map) in ours.iter() {
                        if let Some(scalar) = map.get(&xonly) {
                            res.push((label.clone(), utxo, *scalar));
                            break;
                        }
                    }
                }
                Err(_) => {
                    // This should never happen, but we log it just in case
                    log::error!("Failed to parse XOnlyPublicKey from utxo.scriptpubkey: {}", utxo.scriptpubkey.as_bytes().as_hex());
                },
            }
        }
    }

    Ok(res)
}

/// Convert found (label, utxo, tweak) tuples into a map of outpoints to owned outputs.
pub(crate) fn collect_found_outputs(
    blkheight: Height,
    found: Vec<(Option<Label>, UtxoData, Scalar)>,
) -> HashMap<OutPoint, OwnedOutput> {
    let mut res = HashMap::new();

    for (label, utxo, tweak) in found {
        let outpoint = OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        };

        let out = OwnedOutput {
            blockheight: blkheight,
            tweak: tweak.to_be_bytes(),
            amount: utxo.value,
            script: utxo.scriptpubkey,
            label,
            spend_status: OutputSpendStatus::Unspent,
        };

        res.insert(outpoint, out);
    }

    res
}

/// Match spent index data against our input hashes to find spent outpoints.
pub(crate) fn collect_spent_outpoints(
    spent_data: Vec<Vec<u8>>,
    input_hashes_map: &HashMap<[u8; 8], OutPoint>,
) -> HashSet<OutPoint> {
    let mut res = HashSet::new();

    for spent in spent_data {
        let hex: &[u8] = spent.as_ref();
        if let Some(outpoint) = input_hashes_map.get(hex) {
            res.insert(*outpoint);
        }
    }

    res
}
