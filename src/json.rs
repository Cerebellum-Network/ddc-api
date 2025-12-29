#![allow(clippy::from_over_into)]

use core::str;

use codec::{Decode, Encode};
use ddc_primitives::{BucketId, EhdEra, NodePubKey, TcaEra};
use scale_info::prelude::string::String;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, TryFromInto};
use sp_std::{collections::btree_map::BTreeMap, prelude::*};

/// DDC aggregation era
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AggregationEraResponse {
    pub id: TcaEra,
    pub status: String,
    pub start: i64,
    pub end: i64,
    pub processing_time: i64,
    pub nodes_total: u32,
    pub nodes_processed: u32,
    pub records_processed: u32,
    pub records_applied: u32,
    pub records_discarded: u32,
    pub attempt: u32,
}

/// Json response wrapped with a signature.
#[serde_as]
#[derive(
    Debug, Serialize, Deserialize, Clone, Hash, Ord, PartialOrd, PartialEq, Eq, Encode, Decode,
)]
pub struct SignedJsonResponse<T> {
    pub payload: T,
    #[serde_as(as = "Base64")]
    pub signer: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
}

#[derive(
    Debug, Serialize, Deserialize, Clone, Hash, Encode, Decode, Ord, PartialOrd, PartialEq, Eq,
)]
pub struct EHDEra {
    pub id: u32,
    pub status: String,
    pub era_start: Option<TcaEra>,
    pub era_end: Option<TcaEra>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Encode, Decode)]
pub struct IsGCollectorResponse {
    #[serde(rename = "isGroupingCollector")]
    pub is_g_collector: bool,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct GCollectorsResponse {
    #[serde(rename = "keys")]
    #[serde_as(as = "Vec<TryFromInto<String>>")]
    pub nodes_keys: Vec<NodePubKey>,
}

pub type PathId = String;

#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode, PartialOrd, Ord, Eq, PartialEq)]
pub struct InspSummary {
    pub era: EhdEra,
    pub verified_paths: BTreeMap<PathId, VerifiedPath>,
    pub unverified_paths: BTreeMap<PathId, UnverifiedPath>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode, PartialOrd, Ord, Eq, PartialEq)]
pub struct VerifiedPath {
    pub result_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode, PartialOrd, Ord, Eq, PartialEq)]
pub struct UnverifiedPath {
    pub result_hash: String,
    pub exception: InspPathException,
}

#[derive(Debug, Clone, Deserialize, Serialize, Encode, Decode, PartialOrd, Ord, Eq, PartialEq)]
pub enum InspPathException {
    MultipleExceptions {
        /// Serialized exceptions of `InspPathException` type as SCALE encoded bytes. 
        /// We do not use recursive type here as the inspection module depends on a different type. 
        exceptions: Vec<Vec<u8>>,
    },
    NodeARsSigUnverified {
        node_key: NodePubKey,
        tca_id: TcaEra,
        bad_leaves_ids: Vec<u64>,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    BucketARsSigUnverified {
        bucket_id: BucketId,
        node_key: NodePubKey,
        tca_id: TcaEra,
        bad_leaves_ids: Vec<u64>,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    NodeARsUnavailable {
        node_key: NodePubKey,
        tca_id: TcaEra,
        leaves_ids: Vec<u64>,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    BucketARsUnavailable {
        bucket_id: BucketId,
        node_key: NodePubKey,
        tca_id: TcaEra,
        leaves_ids: Vec<u64>,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    NodeAggregateMalformed {
        node_key: NodePubKey,
        tca_id: TcaEra,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    BucketAggregateMalformed {
        bucket_id: BucketId,
        tca_id: TcaEra,
        unverified_usage: Vec<u8>,
        unverified_usage_collector: NodePubKey,
        unverified_usage_signature: Vec<u8>,
    },
    NodeCumulativeUsageUnavailable {
        node_key: NodePubKey,
        tca_id: TcaEra,
        accessible_unverified_usage: Vec<u8>,
    },
    BucketCumulativeUsageUnavailable {
        bucket_id: BucketId,
        node_key: Option<NodePubKey>,
        tca_id: TcaEra,
        accessible_unverified_usage: Vec<u8>,
    },
}
