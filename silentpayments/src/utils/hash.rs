use crate::{
    utils::common::{OutPoint, SharedSecret},
    Error,
};
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};
use secp256k1::{PublicKey, Scalar, SecretKey};

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);

    pub(crate) struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub(crate) struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

impl InputsHash {
    pub(crate) fn from_outpoint_and_A_sum(
        smallest_outpoint: &OutPoint,
        A_sum: PublicKey,
    ) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint.0);
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub(crate) fn from_b_scan_and_m(b_scan: SecretKey, m: u32) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &SharedSecret, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.0.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub(crate) fn calculate_input_hash(
    outpoints_data: &[OutPoint],
    A_sum: PublicKey,
) -> Result<Scalar, Error> {
    if outpoints_data.is_empty() {
        return Err(Error::GenericError("No outpoints provided".to_owned()));
    }
    let smallest_outpoint = outpoints_data
        .iter()
        .min()
        .expect("must be present if array is non-empty");
    Ok(InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum).to_scalar())
}
