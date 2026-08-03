#![allow(unused)]
use bitcoin::{
    BlockHash, Txid, XOnlyPublicKey, absolute::Height, hashes::Hash, secp256k1::PublicKey,
};

use crate::oracle_grpc;

// first 8 bytes of an output x-only pubkeys
#[derive(Clone, Debug)]
pub struct ShortenedXOnlyPubkey([u8; 8]);

#[derive(Clone, Debug)]
pub struct BlockScanData {
    pub block_identifier: BlockIdentifier,
    pub comp_index: Vec<ComputeIndexTxItem>,
    pub spent_outputs: Vec<ShortenedXOnlyPubkey>,
}

impl From<oracle_grpc::BlockScanDataShortResponse> for BlockScanData {
    fn from(value: oracle_grpc::BlockScanDataShortResponse) -> Self {
        Self {
            block_identifier: value.block_identifier.unwrap().into(),
            comp_index: value.comp_index.into_iter().map(Into::into).collect(),
            spent_outputs: ShortenedXOnlyPubkey::from_vec(value.spent_outputs),
        }
    }
}

impl ShortenedXOnlyPubkey {
    pub fn matches(&self, other: XOnlyPublicKey) -> bool {
        self.0 == other.serialize()[..8]
    }

    pub fn from_vec(vec: Vec<u8>) -> Vec<Self> {
        let iter = vec.chunks_exact(8);

        if !iter.remainder().is_empty() {
            // todo: this should throw a deserialize error
        }

        iter.map(|chunk| ShortenedXOnlyPubkey(chunk.try_into().unwrap()))
            .collect()
    }
}

impl From<&[u8; 8]> for ShortenedXOnlyPubkey {
    fn from(value: &[u8; 8]) -> Self {
        Self(*value)
    }
}

#[derive(Clone, Debug)]
pub struct BlockIdentifier {
    pub block_hash: BlockHash,
    pub block_height: Height,
}

impl From<oracle_grpc::BlockIdentifier> for BlockIdentifier {
    fn from(value: oracle_grpc::BlockIdentifier) -> Self {
        Self {
            block_hash: BlockHash::from_slice(&value.block_hash).unwrap(),
            block_height: Height::from_consensus(value.block_height as u32).unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ComputeIndexTxItem {
    pub txid: Txid,
    pub tweak: PublicKey,
    pub outputs_short: Vec<ShortenedXOnlyPubkey>,
}

impl From<oracle_grpc::ComputeIndexTxItem> for ComputeIndexTxItem {
    fn from(value: oracle_grpc::ComputeIndexTxItem) -> Self {
        Self {
            txid: Txid::from_slice(&value.txid).unwrap(),
            tweak: PublicKey::from_slice(&value.tweak).unwrap(),
            outputs_short: ShortenedXOnlyPubkey::from_vec(value.outputs_short),
        }
    }
}
