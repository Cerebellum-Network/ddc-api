#![allow(clippy::from_over_into)]

// TODO: Remove this once migration to Protobuf is fully completed, as JSON is deprecated
use codec::{Decode, Encode};
use ddc_primitives::{NodePubKey, TcaEra};
use scale_info::prelude::string::String;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as, TryFromInto};
use sp_std::prelude::*;

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

