//! BIP-375 Type Definitions
//!
//! Core types for silent payments in PSBTs.

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut};
use secp256k1::{PublicKey, SecretKey};
use silentpayments::SilentPaymentAddress;

// ============================================================================
// Core BIP-352/BIP-375 Protocol Types
// ============================================================================

/// ECDH share for a silent payment output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhShareData {
    /// Scan public key this share is for (33 bytes)
    pub scan_key: PublicKey,
    /// ECDH share value (33 bytes compressed public key)
    pub share: PublicKey,
    /// Optional DLEQ proof (64 bytes)
    pub dleq_proof: Option<[u8; 64]>,
}

impl EcdhShareData {
    /// Create a new ECDH share
    pub fn new(scan_key: PublicKey, share: PublicKey, dleq_proof: Option<[u8; 64]>) -> Self {
        Self {
            scan_key,
            share,
            dleq_proof,
        }
    }

    /// Create an ECDH share without a DLEQ proof
    pub fn without_proof(scan_key: PublicKey, share: PublicKey) -> Self {
        Self::new(scan_key, share, None)
    }

    /// Serialize share data (scan_key || share)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&self.scan_key.serialize());
        bytes.extend_from_slice(&self.share.serialize());
        bytes
    }

    /// Deserialize share data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::Error> {
        if bytes.len() != 66 {
            return Err(super::Error::InvalidEcdhShare(format!(
                "Invalid length: expected 66 bytes, got {}",
                bytes.len()
            )));
        }

        let scan_key = PublicKey::from_slice(&bytes[0..33])
            .map_err(|e| super::Error::InvalidEcdhShare(e.to_string()))?;
        let share = PublicKey::from_slice(&bytes[33..66])
            .map_err(|e| super::Error::InvalidEcdhShare(e.to_string()))?;

        Ok(Self {
            scan_key,
            share,
            dleq_proof: None,
        })
    }
}

// ============================================================================
// PSBT Construction Helper Types
// ============================================================================

/// Input data for PSBT construction
///
/// Combines bitcoin primitives with optional signing key for BIP-375 workflows.
/// This is a construction helper, not part of the serialized PSBT format.
#[derive(Debug, Clone)]
pub struct PsbtInput {
    /// The previous output being spent
    pub outpoint: OutPoint,
    /// The UTXO being spent (value + script)
    pub witness_utxo: TxOut,
    /// Sequence number for this input
    pub sequence: Sequence,
    /// Optional private key for signing (not serialized)
    pub private_key: Option<SecretKey>,
}

impl PsbtInput {
    /// Create a new PSBT input
    pub fn new(
        outpoint: OutPoint,
        witness_utxo: TxOut,
        sequence: Sequence,
        private_key: Option<SecretKey>,
    ) -> Self {
        Self {
            outpoint,
            witness_utxo,
            sequence,
            private_key,
        }
    }
}

/// Output data for PSBT construction
///
/// Either a regular bitcoin output or a silent payment output.
/// For silent payments, the script is computed during finalization.
#[derive(Debug, Clone)]
pub enum PsbtOutput {
    /// Regular bitcoin output with known script
    Regular(TxOut),
    /// Silent payment output (script computed during finalization)
    SilentPayment {
        /// Amount to send
        amount: Amount,
        /// Silent payment address
        address: SilentPaymentAddress,
        /// Optional label (useful for detecting change outputs)
        label: Option<u32>,
    },
}

impl PsbtOutput {
    /// Create a regular output
    pub fn regular(amount: Amount, script_pubkey: ScriptBuf) -> Self {
        Self::Regular(TxOut {
            value: amount,
            script_pubkey,
        })
    }

    /// Create a silent payment output
    pub fn silent_payment(amount: Amount, address: SilentPaymentAddress, label: Option<u32>) -> Self {
        Self::SilentPayment { amount, address, label }
    }

    /// Check if this is a silent payment output
    pub fn is_silent_payment(&self) -> bool {
        matches!(self, Self::SilentPayment { .. })
    }

    /// Get the amount
    pub fn amount(&self) -> Amount {
        match self {
            Self::Regular(txout) => txout.value,
            Self::SilentPayment { amount, .. } => *amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use silentpayments::Network;

    #[test]
    fn test_silent_payment_address_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let addr = SilentPaymentAddress::new(scan_key, spend_key, Network::Regtest, 0).unwrap();
        let bytes: Vec<u8> = addr.to_string().into_bytes();
        let decoded = SilentPaymentAddress::try_from(String::from_utf8(bytes).unwrap()).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_ecdh_share_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let ecdh = EcdhShareData::without_proof(scan_key, share);
        let bytes = ecdh.to_bytes();
        let decoded = EcdhShareData::from_bytes(&bytes).unwrap();

        assert_eq!(ecdh.scan_key, decoded.scan_key);
        assert_eq!(ecdh.share, decoded.share);
    }
}
