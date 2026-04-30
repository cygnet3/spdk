//! Sending utility functions.
use std::marker::PhantomData;

use crate::{Error, Result, utils::hash::OUTPOINTS_LEN};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, ecdh::shared_secret_point};

use super::hash::calculate_input_hash;

/// Typestate marker: keys are not normalized yet.
#[derive(Clone, Copy, Debug)]
pub struct Raw;
/// Typestate marker: taproot parity normalization was applied.
#[derive(Clone, Copy, Debug)]
pub struct Normalized;
/// Typestate marker: BIP-352 input hash was applied.
#[derive(Clone, Copy, Debug)]
pub struct InputHashApplied;

/// A typed secret key wrapper used to model derivation stages.
#[derive(Clone, Copy, Debug)]
pub struct TypedSecretKey<State> {
    key: SecretKey,
    _state: PhantomData<State>,
}

impl<State> TypedSecretKey<State> {
    pub fn into_inner(self) -> SecretKey {
        self.key
    }

    pub fn as_inner(&self) -> &SecretKey {
        &self.key
    }
}

impl TypedSecretKey<Normalized> {
    fn from_inner(key: SecretKey) -> Self {
        Self {
            key,
            _state: PhantomData,
        }
    }
}

impl TypedSecretKey<Raw> {
    pub fn new(key: SecretKey) -> Self {
        Self {
            key,
            _state: PhantomData,
        }
    }

    /// Normalize this key for BIP-352 usage.
    ///
    /// For non-taproot inputs the key is unchanged.
    /// For taproot inputs with odd-y pubkeys, the negated key is returned.
    pub fn normalize_for_input<C: secp256k1::Signing>(
        self,
        secp: &Secp256k1<C>,
        is_taproot: bool,
    ) -> TypedSecretKey<Normalized> {
        let (_, parity) = self.key.x_only_public_key(secp);
        let key = if is_taproot && parity == secp256k1::Parity::Odd {
            self.key.negate()
        } else {
            self.key
        };

        TypedSecretKey {
            key,
            _state: PhantomData,
        }
    }
}

impl TypedSecretKey<Normalized> {
    /// Apply BIP-352 input hash to this normalized key.
    pub fn apply_input_hash<C: Signing>(self, secp: &Secp256k1<C>, outpoints_head: &[u8; 36], outpoints_tail: &[[u8; 36]]) -> Result<SecretKey> {
        let input_hash = calculate_input_hash(outpoints_head, outpoints_tail, self.as_inner().public_key(secp));
        Ok(self.key.mul_tweak(&input_hash)?)
    }
}

/// Non-empty normalized key collection.
#[derive(Clone, Debug)]
pub struct NonEmptyNormalizedKeys {
    head: TypedSecretKey<Normalized>,
    tail: Vec<TypedSecretKey<Normalized>>,
}

impl NonEmptyNormalizedKeys {
    pub fn from_vec(keys: Vec<TypedSecretKey<Normalized>>) -> Result<Self> {
        let mut iter = keys.into_iter();
        let head = iter
            .next()
            .ok_or_else(|| Error::GenericError("No input provided".to_owned()))?;
        Ok(Self {
            head,
            tail: iter.collect(),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &TypedSecretKey<Normalized>> {
        std::iter::once(&self.head).chain(self.tail.iter())
    }

    /// Sum already-normalized keys into an aggregated normalized key.
    pub fn sum_normalized_keys(self) -> Result<TypedSecretKey<Normalized>> {
        let result = self.tail
            .iter()
            .try_fold(self.head.key, |acc, item| acc.add_tweak(&(*item.as_inner()).into()))?;

        Ok(TypedSecretKey::from_inner(result))
    }
}

/// Build normalized keys from raw `(SecretKey, is_taproot)` pairs.
pub fn normalize_input_keys<C: Signing>(
    secp: &Secp256k1<C>,
    input_keys: &[(SecretKey, bool)],
) -> Result<NonEmptyNormalizedKeys> {
    if input_keys.is_empty() {
        return Err(Error::GenericError("No input provided".to_owned()));
    }

    let normalized = input_keys
        .iter()
        .map(|(key, is_taproot)| TypedSecretKey::new(*key).normalize_for_input(secp, *is_taproot))
        .collect::<Vec<_>>();
    NonEmptyNormalizedKeys::from_vec(normalized)
}

/// Compute the transaction-level partial secret used for output derivation.
///
/// # Arguments
///
/// * `secp` - Secp256k1 context used for key arithmetic.
/// * `input_keys` - Input key metadata as `(SecretKey, is_taproot)` tuples.
///   Taproot keys are parity-normalized before aggregation.
/// * `outpoints` - Serialized outpoints used to compute the BIP-352 input hash.
///
/// # Returns
///
/// This function returns the partial secret, which represents the sum of all (eligible) input keys multiplied with the input hash.
///
/// # Errors
///
/// This function will error if:
///
/// * `input_keys` is empty, or key aggregation produces an invalid key.
/// * `outpoints` is empty or cannot be hashed into a valid tweak.
pub fn calculate_partial_secret<C: Signing>(
    secp: &Secp256k1<C>,
    input_keys: &[(SecretKey, bool)],
    outpoints: &[[u8; OUTPOINTS_LEN]],
) -> Result<SecretKey> {
    // First check for empty outpoints
    let (outpoints_head, outpoints_tail) = outpoints.split_first().ok_or(Error::GenericError("Empty outpoints".to_string()))?;
    let normalized = normalize_input_keys(secp, input_keys)?;
    let a_sum = normalized.sum_normalized_keys()?;

    a_sum.apply_input_hash(secp, outpoints_head, outpoints_tail)
}

/// Compute the ECDH shared secret point for a scan key and partial secret.
///
/// [`generate_recipient_pubkeys`](crate::sending::generate_recipient_pubkeys)
/// expects this result per derivation input.
///
/// # Arguments
///
/// * `B_scan` - Recipient scan public key.
/// * `partial_secret` - Result from [`calculate_partial_secret`].
///
/// # Returns
///
/// Returns the full public key point `partial_secret * B_scan`.
pub fn calculate_ecdh_shared_secret(B_scan: &PublicKey, partial_secret: &SecretKey) -> PublicKey {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    ss_bytes[1..].copy_from_slice(&shared_secret_point(B_scan, partial_secret));

    PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
}
