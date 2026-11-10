#![allow(non_snake_case)]

use bitcoin::consensus::deserialize;
use bitcoin::{ScriptBuf, Txid, Witness, XOnlyPublicKey};
use secp256k1::schnorr::Signature;
use secp256k1::{Scalar, SecretKey};
use serde::{Deserialize, Deserializer};
use serde_with::{DisplayFromStr, FromInto, serde_as};
use silentpayments::SilentPaymentCode;

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingKeyMaterial {
    pub scan_priv_key: SecretKey,
    pub spend_priv_key: SecretKey,
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKeyStruct {
    pub hex: ScriptBuf,
}

#[derive(Debug, Deserialize)]
pub struct PrevoutData {
    pub scriptPubKey: ScriptPubKeyStruct,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingVinData {
    pub txid: Txid,
    pub vout: u32,
    pub scriptSig: ScriptBuf,
    #[serde(deserialize_with = "deserialize_witness")]
    pub txinwitness: Witness,
    pub prevout: PrevoutData,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub vin: Vec<ReceivingVinData>,
    pub key_material: ReceivingKeyMaterial,
    pub labels: Vec<u32>,
    pub outputs: Vec<XOnlyPublicKey>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    #[serde(rename = "addresses")]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub codes: Vec<SilentPaymentCode>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub vin: Vec<SendingVinData>,
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub recipients: Vec<SilentPaymentCode>,
}

#[derive(Debug, Deserialize)]
pub struct SendingVinData {
    pub txid: Txid,
    pub vout: u32,
    pub scriptSig: ScriptBuf,
    #[serde(deserialize_with = "deserialize_witness")]
    pub txinwitness: Witness,
    pub prevout: PrevoutData,
    pub private_key: SecretKey,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<Vec<String>>,
}

#[serde_as]
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct OutputWithSignature {
    pub pub_key: XOnlyPublicKey,
    #[serde_as(deserialize_as = "FromInto<SecretKey>")]
    pub priv_key_tweak: Scalar,
    pub signature: Signature,
}

fn deserialize_witness<'de, D>(deserializer: D) -> Result<Witness, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;
    let bytes = hex::decode(buf).map_err(serde::de::Error::custom)?;

    if bytes.is_empty() {
        Ok(Witness::new())
    } else {
        deserialize(&bytes).map_err(serde::de::Error::custom)
    }
}
