//! Sending utility functions.
//!
//! The typical flow for a single signer is:
//!
//! 1. Normalize input private keys with [`NormalizedSecretKey`].
//! 2. Build an [`InputsHash`] from outpoints and eligible input public keys.
//! 3. Create a [`GlobalSenderEcdhShare`] (single spender) or [`PartialSenderEcdhShare`]s (per input - collaborative transaction).
//! 4. Call [`GlobalSenderEcdhShare::apply_input_hash`] / [`PartialSenderEcdhShare::apply_input_hash`].
//! 5. Convert to a [`TransactionSharedSecret`](crate::TransactionSharedSecret) and pass to [`generate_recipient_pubkeys`](crate::sending::generate_recipient_pubkeys).
use std::collections::HashSet;

use crate::utils::common::{ecdh_multiply, InputsHash, NonEmptyArray};
use crate::{Error, Result};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

/// Guarantees that the secret key is producing even xonly public key if output spent is taproot
/// by negating the secret key if necessary
#[derive(Debug, Clone)]
pub struct NormalizedSecretKey(SecretKey);

impl NormalizedSecretKey {
    pub fn new<C: Signing>(secp: &Secp256k1<C>, secret_key: SecretKey, is_taproot: bool) -> Self {
        let (_, parity) = secret_key.x_only_public_key(&secp);

        if is_taproot && parity == secp256k1::Parity::Odd {
            return Self(secret_key.negate());
        }

        Self(secret_key)
    }

    pub fn as_inner(&self) -> &SecretKey {
        &self.0
    }

    pub fn into_inner(self) -> SecretKey {
        self.0
    }
}

impl<'a> NonEmptyArray<'a, NormalizedSecretKey> {
    pub fn sum_keys(&self) -> Result<SecretKey> {
        let (head, tail) = self.as_inner().split_first().expect("Is non-empty");
        let result = tail
            .iter()
            .try_fold(*head.as_inner(), |acc, item| acc.add_tweak(&(*item.as_inner()).into()))?;
        Ok(result)
    }
}

/// ECDH share for a single eligible input: `a_i * B_scan` (before input hash).
///
/// Used in multi-signer flows where each party contributes one input.
/// Apply the input hash before combining into a [`GlobalSenderEcdhShare`].
pub struct PartialSenderEcdhShare {
    recipient_scan_key: PublicKey,
    input_vin: usize,
    ecdh_shared_secret: PublicKey,
    dleq_proof: Option<PublicKey>, // TODO: implement DLEQ proof
    input_hash_applied: bool,
}

impl PartialSenderEcdhShare {
    pub fn new(
        recipient_scan_key: PublicKey,
        input_vin: usize,
        private_key: NormalizedSecretKey,
    ) -> Result<Self> {
        let shared_secret = ecdh_multiply(&recipient_scan_key, private_key.as_inner())?;
        Ok(Self {
            recipient_scan_key,
            input_vin,
            ecdh_shared_secret: shared_secret,
            dleq_proof: None,
            input_hash_applied: false,
        })
    }

    pub fn apply_input_hash<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        input_hash: InputsHash,
    ) -> Result<()> {
        if self.input_hash_applied {
            return Err(Error::GenericError(
                "Input hash already applied".to_owned(),
            ));
        }
        self.ecdh_shared_secret = self
            .ecdh_shared_secret
            .mul_tweak(secp, input_hash.as_inner())?;
        self.input_hash_applied = true;
        Ok(())
    }

    pub fn recipient_scan_key(&self) -> &PublicKey {
        &self.recipient_scan_key
    }

    pub fn input_vin(&self) -> usize {
        self.input_vin
    }

    pub fn as_ecdh_shared_secret(&self) -> &PublicKey {
        &self.ecdh_shared_secret
    }
}

/// ECDH share for all eligible inputs combined.
///
/// Built either by summing private keys first ([`Self::new_from_summed_keys`])
/// or by summing hashed partial shares ([`Self::from_partial_shares`]).
pub struct GlobalSenderEcdhShare {
    recipient_scan_key: PublicKey,
    ecdh_shared_secret: PublicKey,
    dleq_proof: Option<PublicKey>, // TODO: implement DLEQ proof
    input_hash_applied: bool,
}

impl GlobalSenderEcdhShare {
    pub fn new_from_summed_keys(
        recipient_scan_key: PublicKey,
        summed_keys: NonEmptyArray<NormalizedSecretKey>,
    ) -> Result<Self> {
        let secret_key = summed_keys.sum_keys()?;
        let shared_secret = ecdh_multiply(&recipient_scan_key, &secret_key)?;
        Ok(Self {
            recipient_scan_key,
            ecdh_shared_secret: shared_secret,
            dleq_proof: None,
            input_hash_applied: false,
        })
    }

    pub fn from_partial_shares(
        partial_shares: NonEmptyArray<PartialSenderEcdhShare>,
    ) -> Result<Self> {
        let mut vin_seen: HashSet<usize> = HashSet::new();
        let recipient_scan_key = partial_shares.as_inner()[0].recipient_scan_key;
        let mut shares_to_sum: Vec<&PublicKey> =
            Vec::with_capacity(partial_shares.as_inner().len());

        for share in partial_shares.as_inner() {
            if share.recipient_scan_key != recipient_scan_key {
                return Err(Error::GenericError(
                    format!("Multiple recipient scan keys found: {} and {}", share.recipient_scan_key, recipient_scan_key),
                ));
            }
            if vin_seen.contains(&share.input_vin) {
                return Err(Error::GenericError(
                    format!("Input vin {} already seen", share.input_vin),
                ));
            }
            if !share.input_hash_applied {
                return Err(Error::GenericError(
                    format!("No input hash applied for input vin {}", share.input_vin),
                ));
            }
            vin_seen.insert(share.input_vin);
            shares_to_sum.push(&share.ecdh_shared_secret);
        }

        // TODO check the dleq proofs
        let shared_secret = PublicKey::combine_keys(shares_to_sum.as_slice())?;
        Ok(Self {
            recipient_scan_key,
            ecdh_shared_secret: shared_secret,
            dleq_proof: None,
            input_hash_applied: true,
        })
    }

    pub fn apply_input_hash<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        input_hash: InputsHash,
    ) -> Result<()> {
        if self.input_hash_applied {
            return Err(Error::GenericError(
                "Input hash already applied".to_owned(),
            ));
        }
        self.ecdh_shared_secret = self
            .ecdh_shared_secret
            .mul_tweak(secp, input_hash.as_inner())?;
        self.input_hash_applied = true;
        Ok(())
    }

    pub fn recipient_scan_key(&self) -> &PublicKey {
        &self.recipient_scan_key
    }

    pub fn as_ecdh_shared_secret(&self) -> &PublicKey {
        &self.ecdh_shared_secret
    }

    pub fn into_ecdh_shared_secret(self) -> PublicKey {
        self.ecdh_shared_secret
    }

    pub(crate) fn is_input_hash_applied(&self) -> bool {
        self.input_hash_applied
    }
}
