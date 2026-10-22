use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// A spend key that can be either a secret key (full wallet) or a public key (watch-only).
#[derive(Debug, PartialEq, Eq, Clone)]
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

#[cfg(feature = "bip392")]
impl From<&bip392::Sp> for SpendKey {
    fn from(descriptor: &bip392::Sp) -> Self {
        match descriptor.spend_secret() {
            Some(secret) => Self::Secret(secret),
            None => Self::Public(descriptor.spend_pubkey()),
        }
    }
}
