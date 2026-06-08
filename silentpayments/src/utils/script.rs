//! Script template matching for silent payment-eligible inputs (BIP352).

use super::{OP_0, OP_1, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_20, OP_PUSHBYTES_32};

/// Check if a script_pub_key is taproot.
pub fn is_p2tr(spk: &[u8]) -> bool {
    matches!(spk, [OP_1, OP_PUSHBYTES_32, ..] if spk.len() == 34)
}

pub(crate) fn is_p2wpkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_0, OP_PUSHBYTES_20, ..] if spk.len() == 22)
}

pub(crate) fn is_p2sh(spk: &[u8]) -> bool {
    matches!(spk, [OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUAL] if spk.len() == 23)
}

pub(crate) fn is_p2pkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_DUP, OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUALVERIFY, OP_CHECKSIG] if spk.len() == 25)
}

/// Check if a script_pub_key is silent payment-eligible (BIP352 shared secret derivation).
/// This is supposed to help as a kind of quick sanity check, but the real check must be done by the caller
/// that have access to bitcoin crate and more context.
pub fn is_eligible(spk: &[u8]) -> bool {
    is_p2pkh(spk) || is_p2wpkh(spk) || is_p2sh(spk) || is_p2tr(spk)
}
