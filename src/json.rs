#![allow(clippy::from_over_into)]

use core::str;

use codec::{Decode, Encode};
use ddc_primitives::{NodePubKey, TcaEra};
use scale_info::prelude::string::String;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, TryFromInto};
use sp_std::prelude::*;

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

#[derive(Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct NodeAggregateResponse {
    pub node_id: String,
    pub stored_bytes: i64,
    pub transferred_bytes: u64,
    pub number_of_puts: u64,
    pub number_of_gets: u64,
    pub number_of_computes: u64,
    pub cpu_used: u64,
    pub gpu_used: u64,
    pub ram_used: u64,
}

