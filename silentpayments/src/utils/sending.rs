//! Sending utility functions.
use std::marker::PhantomData;

use crate::{
    utils::{
        common::{InputHashApplied, Normalized, Raw, SharedSecret},
        hash::OUTPOINTS_LEN,
    },
    Error, Result,
};
use secp256k1::{
    ecdh::shared_secret_point, PublicKey, Secp256k1, SecretKey, Signing, Verification,
};

use super::hash::calculate_input_hash;

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

    pub fn from_inner(key: &SecretKey) -> Self {
        Self {
            key: *key,
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
    pub fn calculate_ecdh_shared_secret(self, B_scan: &PublicKey) -> SharedSecret<Raw> {
        let mut ss_bytes = [0u8; 65];
        ss_bytes[0] = 0x04;
        ss_bytes[1..].copy_from_slice(&shared_secret_point(B_scan, self.as_inner()));
        SharedSecret::<Raw>::try_from(&ss_bytes).expect("guaranteed to be a point on the curve")
    }

    /// Apply BIP-352 input hash to this normalized key.
    pub fn apply_input_hash<C: Signing>(
        self,
        secp: &Secp256k1<C>,
        outpoints_head: &[u8; 36],
        outpoints_tail: &[[u8; 36]],
    ) -> Result<TypedSecretKey<InputHashApplied>> {
        let A_sum: PublicKey = self.as_inner().public_key(secp);
        let input_hash = calculate_input_hash(outpoints_head, outpoints_tail, &A_sum);
        let tweaked_key = self.key.mul_tweak(&input_hash)?;
        Ok(TypedSecretKey::<InputHashApplied>::from_inner(&tweaked_key))
    }
}

impl TypedSecretKey<InputHashApplied> {
    pub fn calculate_ecdh_shared_secret(
        self,
        B_scan: &PublicKey,
    ) -> SharedSecret<InputHashApplied> {
        let mut ss_bytes = [0u8; 65];
        ss_bytes[0] = 0x04;
        ss_bytes[1..].copy_from_slice(&shared_secret_point(B_scan, self.as_inner()));
        SharedSecret::<InputHashApplied>::try_from(&ss_bytes)
            .expect("guaranteed to be a point on the curve")
    }
}

/// Non-empty normalized key collection.
#[derive(Clone, Debug)]
pub struct NonEmptyNormalizedKeys {
    head: TypedSecretKey<Normalized>,
    tail: Vec<TypedSecretKey<Normalized>>,
}

impl NonEmptyNormalizedKeys {
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        head: &(SecretKey, bool),
        tail: &[(SecretKey, bool)],
    ) -> Self {
        let head = TypedSecretKey::<Raw>::from_inner(&head.0).normalize_for_input(secp, head.1);
        if tail.is_empty() {
            return Self { head, tail: vec![] };
        } else {
            let mut normalized_tail = Vec::with_capacity(tail.len());
            normalized_tail.extend(tail.iter().map(|(key, is_taproot)| {
                TypedSecretKey::<Raw>::from_inner(key).normalize_for_input(secp, *is_taproot)
            }));

            Self {
                head,
                tail: normalized_tail,
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &TypedSecretKey<Normalized>> {
        std::iter::once(&self.head).chain(self.tail.iter())
    }

    /// Sum already-normalized keys into an aggregated normalized key.
    pub fn sum_normalized_keys(self) -> Result<TypedSecretKey<Normalized>> {
        let result = self.tail.iter().try_fold(self.head.key, |acc, item| {
            acc.add_tweak(&(*item.as_inner()).into())
        })?;

        Ok(TypedSecretKey::<Normalized>::from_inner(&result))
    }
}

impl SharedSecret<Raw> {
    pub fn apply_input_hash<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        A_sum: &PublicKey,
        outpoints_head: &[u8; 36],
        outpoints_tail: &[[u8; 36]],
    ) -> Result<SharedSecret<InputHashApplied>> {
        let input_hash = calculate_input_hash(outpoints_head, outpoints_tail, A_sum);
        let tweaked_key = self.into_inner().mul_tweak(secp, &input_hash)?;
        Ok(SharedSecret::<InputHashApplied>::from_inner(&tweaked_key))
    }
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
) -> Result<TypedSecretKey<InputHashApplied>> {
    // First check for empty outpoints
    let (outpoints_head, outpoints_tail) = outpoints
        .split_first()
        .ok_or(Error::GenericError("Empty outpoints".to_string()))?;
    let (input_keys_head, input_keys_tail) = input_keys
        .split_first()
        .ok_or(Error::GenericError("Empty input keys".to_string()))?;
    let normalized = NonEmptyNormalizedKeys::new(secp, input_keys_head, input_keys_tail);
    let a_sum = normalized.sum_normalized_keys()?;

    a_sum.apply_input_hash(secp, outpoints_head, outpoints_tail)
}
