//! PSBT Updater Role
//!
//! Adds additional information like BIP32 derivation paths.

use crate::psbt::core::{Error, Result, SilentPaymentPsbt};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::TapLeafHash;
use bitcoin::EcdsaSighashType;
use psbt_v2::PsbtSighashType;

/// BIP32 derivation information
pub struct Bip32Derivation {
    /// Master fingerprint (4 bytes)
    pub master_fingerprint: [u8; 4],
    /// Derivation path
    pub path: Vec<u32>,
}

impl Bip32Derivation {
    /// Create a new BIP32 derivation
    pub fn new(master_fingerprint: [u8; 4], path: Vec<u32>) -> Self {
        Self {
            master_fingerprint,
            path,
        }
    }
}

/// Add BIP32 derivation information for an input
pub fn add_input_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    pubkey: &secp256k1::PublicKey,
    derivation: &Bip32Derivation,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let fingerprint = Fingerprint::from(derivation.master_fingerprint);
    let path: DerivationPath = derivation
        .path
        .iter()
        .map(|&i| ChildNumber::from(i))
        .collect();

    input.bip32_derivations.insert(*pubkey, (fingerprint, path));

    Ok(())
}

/// Add BIP32 derivation information for an output
pub fn add_output_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    output_index: usize,
    pubkey: &secp256k1::PublicKey,
    derivation: &Bip32Derivation,
) -> Result<()> {
    let output = psbt
        .outputs
        .get_mut(output_index)
        .ok_or(Error::InvalidOutputIndex(output_index))?;

    let fingerprint = Fingerprint::from(derivation.master_fingerprint);
    let path: DerivationPath = derivation
        .path
        .iter()
        .map(|&i| ChildNumber::from(i))
        .collect();

    output
        .bip32_derivations
        .insert(*pubkey, (fingerprint, path));

    Ok(())
}

/// Add Taproot BIP32 derivation information for an input (PSBT_IN_TAP_BIP32_DERIVATION)
///
/// Use this for P2TR inputs
/// The leaf_hashes parameter specifies which tap leaves this key is used in;
/// pass an empty vec for key-path spending.
pub fn add_input_tap_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    xonly_pubkey: &XOnlyPublicKey,
    leaf_hashes: Vec<TapLeafHash>,
    derivation: &Bip32Derivation,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let fingerprint = Fingerprint::from(derivation.master_fingerprint);
    let path: DerivationPath = derivation
        .path
        .iter()
        .map(|&i| ChildNumber::from(i))
        .collect();

    input
        .tap_key_origins
        .insert(*xonly_pubkey, (leaf_hashes, (fingerprint, path)));

    Ok(())
}

/// Add Taproot BIP32 derivation information for an output (PSBT_OUT_TAP_BIP32_DERIVATION)
///
/// Use this for P2TR outputs.
pub fn add_output_tap_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    output_index: usize,
    xonly_pubkey: &XOnlyPublicKey,
    leaf_hashes: Vec<TapLeafHash>,
    derivation: &Bip32Derivation,
) -> Result<()> {
    let output = psbt
        .outputs
        .get_mut(output_index)
        .ok_or(Error::InvalidOutputIndex(output_index))?;

    let fingerprint = Fingerprint::from(derivation.master_fingerprint);
    let path: DerivationPath = derivation
        .path
        .iter()
        .map(|&i| ChildNumber::from(i))
        .collect();

    output
        .tap_key_origins
        .insert(*xonly_pubkey, (leaf_hashes, (fingerprint, path)));

    Ok(())
}

/// Add Silent Payment spend BIP32 derivation for an input (PSBT_IN_SP_SPEND_BIP32_DERIVATION)
///
/// Use this for Silent Payment inputs (those with PSBT_IN_SP_TWEAK).
/// The spend key is the untweaked key that, when combined with the SP tweak,
/// produces the key locking the output.
pub fn add_input_sp_spend_bip32_derivation(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    spend_pubkey: &secp256k1::PublicKey,
    derivation: &Bip32Derivation,
) -> Result<()> {
    use crate::psbt::Bip375PsbtExt;

    psbt.set_input_sp_spend_bip32_derivation(
        input_index,
        spend_pubkey,
        derivation.master_fingerprint,
        derivation.path.clone(),
    )
}

/// Add sighash type for an input
pub fn add_input_sighash_type(
    psbt: &mut SilentPaymentPsbt,
    input_index: usize,
    sighash_type: u32,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let sighash = EcdsaSighashType::from_consensus(sighash_type);
    input.sighash_type = Some(PsbtSighashType::from(sighash));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::roles::creator::create_psbt;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_add_input_bip32_derivation() {
        let mut psbt = create_psbt(1, 1);
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);

        let derivation = Bip32Derivation::new([0xAA, 0xBB, 0xCC, 0xDD], vec![0x8000002C]);

        add_input_bip32_derivation(&mut psbt, 0, &pubkey, &derivation).unwrap();

        // Verify derivation was added
        let input = &psbt.inputs[0];
        assert!(input.bip32_derivations.contains_key(&pubkey));

        let (fp, path) = input.bip32_derivations.get(&pubkey).unwrap();
        assert_eq!(fp.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_add_input_tap_bip32_derivation() {
        let mut psbt = create_psbt(1, 1);
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);
        let (xonly, _parity) = pubkey.x_only_public_key();

        let derivation = Bip32Derivation::new([0xAA, 0xBB, 0xCC, 0xDD], vec![0x80000056]); // m/86'

        add_input_tap_bip32_derivation(&mut psbt, 0, &xonly, vec![], &derivation).unwrap();

        let input = &psbt.inputs[0];
        assert!(input.tap_key_origins.contains_key(&xonly));

        let (leaf_hashes, (fp, path)) = input.tap_key_origins.get(&xonly).unwrap();
        assert!(leaf_hashes.is_empty());
        assert_eq!(fp.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_add_sighash_type() {
        let mut psbt = create_psbt(1, 1);

        add_input_sighash_type(&mut psbt, 0, 0x01).unwrap(); // SIGHASH_ALL

        let input = &psbt.inputs[0];
        assert!(input.sighash_type.is_some());
        assert_eq!(input.sighash_type.unwrap().to_u32(), 0x01);
    }
}
