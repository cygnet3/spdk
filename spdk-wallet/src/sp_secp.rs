// `from_public_key` is available for call sites that need bitcoin PublicKey from SP keys.
#![allow(dead_code)]

//! Convert between bitcoin's secp256k1 0.29 types and silentpayments' 0.33 types.
//!
//! Both crates currently coexist: `bitcoin` 0.32 still depends on secp 0.29, while
//! the workspace `secp256k1` (nymius fork) is 0.33. Keys are interchangeable via
//! their serializations.

use bitcoin::secp256k1::{
    PublicKey as BtcPublicKey, Scalar as BtcScalar, SecretKey as BtcSecretKey,
};
use silentpayments::secp256k1::{
    PublicKey as SpPublicKey, Scalar as SpScalar, SecretKey as SpSecretKey,
    XOnlyPublicKey as SpXOnlyPublicKey,
};

pub fn secret_key(sk: &BtcSecretKey) -> SpSecretKey {
    SpSecretKey::from_secret_bytes(sk.secret_bytes()).expect("valid secret key")
}

pub fn public_key(pk: &BtcPublicKey) -> SpPublicKey {
    SpPublicKey::from_slice(&pk.serialize()).expect("valid public key")
}

pub fn from_public_key(pk: &SpPublicKey) -> BtcPublicKey {
    BtcPublicKey::from_slice(&pk.serialize()).expect("valid public key")
}

pub fn xonly(pk: &bitcoin::XOnlyPublicKey) -> SpXOnlyPublicKey {
    SpXOnlyPublicKey::from_byte_array(pk.serialize()).expect("valid x-only key")
}

pub fn from_xonly(pk: SpXOnlyPublicKey) -> bitcoin::XOnlyPublicKey {
    bitcoin::XOnlyPublicKey::from_slice(&pk.to_byte_array()).expect("valid x-only key")
}

pub fn from_scalar(s: SpScalar) -> BtcScalar {
    BtcScalar::from_be_bytes(s.to_be_bytes()).expect("valid scalar")
}
