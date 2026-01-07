#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::protocol::utils::hash::SharedSecretHash;
use crate::protocol::Result;
#[cfg(any(feature = "sending", feature = "receiving"))]
use bitcoin_hashes::Hash;
use bitcoin::secp256k1::PublicKey;
#[cfg(any(feature = "sending", feature = "receiving"))]
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey};

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_t_n(ecdh_shared_secret: &PublicKey, k: u32) -> Result<SecretKey> {
    let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}
