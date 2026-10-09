use anyhow::Error;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey),
}

impl Drop for SpendKey {
    fn drop(&mut self) {
        if let Self::Secret(sk) = self {
            // Erase the key material before dropping.
            // secp256k1::SecretKey does not implement Zeroize (its inner
            // array is private); non_secure_erase() is the zeroize-documented
            // erase path (volatile C-level memset, cannot be optimized away).
            sk.non_secure_erase();
        }
    }
}

impl TryInto<SecretKey> for SpendKey {
    type Error = anyhow::Error;
    fn try_into(self) -> std::prelude::v1::Result<SecretKey, Error> {
        match self {
            Self::Secret(k) => Ok(k),
            Self::Public(_) => Err(Error::msg("Can't take SecretKey from Public")),
        }
    }
}

impl From<&SpendKey> for PublicKey {
    fn from(value: &SpendKey) -> Self {
        match value {
            SpendKey::Secret(k) => {
                let secp = Secp256k1::signing_only();
                k.public_key(&secp)
            }
            SpendKey::Public(p) => *p,
        }
    }
}

impl From<SpendKey> for PublicKey {
    fn from(value: SpendKey) -> Self {
        (&value).into()
    }
}
