use core::str;

use codec::{Decode, Encode};
use ddc_primitives::{
    traits::{ClusterManager, NodeManager},
    BucketId, ClusterId, EhdEra, NodeParams, NodePubKey, StorageNodeParams, TcaEra,
};
use proto::{inspection::endpoint_itm_table::Variant as ItmTableVariant, inspection::ItmTable};
use scale_info::{
    prelude::{format, string::String},
    TypeInfo,
};
use serde::{Deserialize, Serialize};
use sp_runtime::offchain::{http, Duration};
use sp_std::{collections::btree_map::BTreeMap, prelude::*};

use crate::{
    client::DdcClient,
    json,
    proto::{self},
};

pub const RESPONSE_TIMEOUT: u64 = 20000;
pub const MAX_RETRIES_COUNT: u32 = 3;
pub const BUCKETS_AGGREGATES_FETCH_BATCH_SIZE: usize = 100;

#[allow(dead_code)]
pub const NODES_AGGREGATES_FETCH_BATCH_SIZE: usize = 10;

#[derive(Debug, Encode, Decode, Clone, TypeInfo, PartialEq)]
pub enum ApiError {
    NodeRetrievalError,
    FailedToFetchCollectors { cluster_id: ClusterId },
    FailedToFetchCollectorNode { cluster_id: ClusterId },
    FailedToFetchBucketChallenge,
    FailedToFetchNodeChallenge,
    FailedToFetchBucketAggregate,
    FailedToFetchTraversedEHD,
    FailedToFetchTraversedPHD,
    FailedToFetchTraversedNodeAggregate,
    FailedToFetchTraversedBucketSubAggregate,
    FailedToFetchEra,
    FailedToFetchGCollectors { cluster_id: ClusterId },
    FailedToFetchGCollectorNode { cluster_id: ClusterId },
    Unexpected,
    FailedToFetchPathsExceptions,
    FailedToFetchSyncNode { cluster_id: ClusterId },
    FailedToFetchInspSummary { cluster_id: ClusterId },
    FailedToFetchInspectedEras { cluster_id: ClusterId },
    FailedToFetchProcessedEras { cluster_id: ClusterId },
}

#[derive(
    Debug, Clone, Encode, Decode, Deserialize, Serialize, PartialOrd, Ord, TypeInfo, Eq, PartialEq,
)]
pub struct ApiResponse<R> {
    pub response: R,
    pub signed_by: Option<SignedBy>,
}

#[derive(
    Debug, Clone, Encode, Decode, Deserialize, Serialize, PartialOrd, Ord, TypeInfo, Eq, PartialEq,
)]
pub struct SignedBy {
    pub signer: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Fetch grouping collectors nodes of a cluster.
/// Parameters:
/// - `cluster_id`: Cluster id of a cluster.
pub fn get_g_collectors_nodes<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
) -> Result<Vec<(NodePubKey, StorageNodeParams)>, ApiError> {
    let mut g_collectors = Vec::new();

    let collectors = get_collectors_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)?;
    for (node_key, node_params) in collectors {
        if check_grouping_collector(&node_params).map_err(|_| ApiError::NodeRetrievalError)? {
            g_collectors.push((node_key, node_params))
        }
    }

    Ok(g_collectors)
}

/// Fetch G-Collector node.
///
/// Parameters:
/// - `cluster_id`: Cluster id of a cluster.
pub fn get_g_collector_node<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
) -> Result<(NodePubKey, StorageNodeParams), http::Error> {
    // todo(yahortsaryk): replace G-Collector with Sync node once it is supported at DDC
    let g_collectors = get_g_collectors_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)
        .map_err(|_| http::Error::Unknown)?;
    let Some(g_collector) = g_collectors.first() else {
        log::warn!("⚠️ No Grouping Collector found in cluster {:?}", cluster_id);
        return Err(http::Error::Unknown);
    };

    Ok(g_collector.clone())
}

pub fn get_sync_node<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
) -> Result<(NodePubKey, StorageNodeParams), http::Error> {
    // todo(yahortsaryk): replace G-Collector with Sync node once it is supported at DDC
    get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id)
}

/// Fetch customer usage.
///
/// Parameters:
/// - `node_params`: Requesting DDC node
pub fn check_grouping_collector(node_params: &StorageNodeParams) -> Result<bool, http::Error> {
    let host = str::from_utf8(&node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url: String = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let response = client.check_grouping_collector()?;
    Ok(response.is_g_collector)
}

/// Fetch collectors nodes of a cluster.
/// Parameters:
/// - `cluster_id`: Cluster id of a cluster.
pub fn get_collectors_nodes<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
) -> Result<Vec<(NodePubKey, StorageNodeParams)>, ApiError> {
    let mut collectors = Vec::new();
    let nodes = CM::get_nodes(cluster_id).map_err(|_| ApiError::NodeRetrievalError)?;
    for node_pub_key in nodes {
        if let Ok(NodeParams::StorageParams(storage_params)) = NM::get_node_params(&node_pub_key) {
            collectors.push((node_pub_key, storage_params));
        }
    }

    Ok(collectors)
}

/// Fetch collectors nodes of a cluster.
/// Parameters:
/// - `cluster_id`: Cluster id of a cluster.
/// - `collector_key`: Collector node key
pub fn get_collector_node<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    collector_key: NodePubKey,
) -> Result<(NodePubKey, StorageNodeParams), ApiError> {
    let mut collectors = Vec::new();
    let nodes = CM::get_nodes(cluster_id).map_err(|_| ApiError::NodeRetrievalError)?;
    for node_pub_key in nodes {
        if let Ok(NodeParams::StorageParams(storage_params)) = NM::get_node_params(&node_pub_key) {
            collectors.push((node_pub_key, storage_params));
        }
    }
    let (collector_key, collector_params) = collectors
        .into_iter()
        .find(|(key, _)| *key == collector_key)
        .ok_or(ApiError::FailedToFetchCollectorNode {
            cluster_id: *cluster_id,
        })?;

    Ok((collector_key, collector_params))
}

pub fn fetch_bucket_challenge_response<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tcaa_id: TcaEra,
    collector_key: NodePubKey,
    node_key: NodePubKey,
    bucket_id: BucketId,
    tree_node_ids: Vec<u64>,
    verify_sig: bool,
) -> Result<ApiResponse<proto::activity::ChallengeResponse>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host = str::from_utf8(&collector_params.host)
        .map_err(|_| ApiError::FailedToFetchBucketChallenge)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig,
    );

    match client.challenge_bucket_sub_aggregate(
        tcaa_id,
        bucket_id,
        &Into::<String>::into(node_key.clone()),
        tree_node_ids,
    ) {
        Ok(res) => Ok(res),
        Err(_) => {
            log::warn!(
                "Collector from cluster {:?} is unavailable while challenging bucket sub-aggregate or responded unexpectedly. Key: {:?}, Host: {:?}",
                cluster_id,
                collector_key,
                String::from_utf8_lossy(&collector_params.host)
            );
            Err(ApiError::FailedToFetchBucketChallenge)
        }
    }
}

pub fn fetch_node_challenge_response<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tcaa_id: TcaEra,
    collector_key: NodePubKey,
    node_key: NodePubKey,
    tree_node_ids: Vec<u64>,
    verify_sig: bool,
) -> Result<ApiResponse<proto::activity::ChallengeResponse>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::FailedToFetchNodeChallenge)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig,
    );

    match client.challenge_node_aggregate(tcaa_id, &Into::<String>::into(node_key), tree_node_ids) {
        Ok(res) => Ok(res),
        Err(_) => {
            log::warn!(
                "Collector from cluster {:?} is unavailable while challenging node aggregate or responded unexpectedly. Key: {:?}, Host: {:?}",
                cluster_id,
                collector_key,
                String::from_utf8_lossy(&collector_params.host)
            );
            Err(ApiError::FailedToFetchNodeChallenge)
        }
    }
}

/// Fetch customer usage.
///
/// Parameters:
/// - `cluster_id`: cluster id of a cluster
/// - `tcaa_id`: time capsule era
/// - `collector_key`: collector to fetch Bucket aggregates from
pub fn fetch_bucket_aggregates<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tcaa_id: TcaEra,
    collector_key: NodePubKey,
) -> Result<Vec<json::BucketAggregateResponse>, ApiError> {
    let (_, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host = str::from_utf8(&collector_params.host)
        .map_err(|_| ApiError::FailedToFetchBucketAggregate)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        true,
    );

    let mut buckets_aggregates = Vec::new();
    let mut prev_token = None;

    loop {
        let api_response= client
            .buckets_aggregates(
                tcaa_id,
                prev_token,
                Some(BUCKETS_AGGREGATES_FETCH_BATCH_SIZE as u32),
            )
            .map_err(|_| ApiError::FailedToFetchBucketAggregate)?;

        let response = api_response.response;
        let response_len = response.len();

        prev_token = response.last().map(|a| a.bucket_id);

        buckets_aggregates.extend(response);

        if response_len < BUCKETS_AGGREGATES_FETCH_BATCH_SIZE {
            break;
        }
    }

    return Ok(buckets_aggregates);
}

/// Traverse EHD record.
///
/// Parameters:
/// - `cluster_id`: cluster id of a cluster
/// - `era`: EHD era
/// - `tree_node_id` - merkle tree node identifier
/// - `tree_levels_count` - merkle tree levels to request
pub fn fetch_traversed_era_historical_document<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    tree_node_id: u32,
    tree_levels_count: u32,
) -> Result<Vec<json::EHDTreeNode>, ApiError> {
    let (g_collector_key, g_collector_params) =
        get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchGCollectorNode {
                cluster_id: *cluster_id,
            }
        })?;
    let host = str::from_utf8(&g_collector_params.host)
        .map_err(|_| ApiError::FailedToFetchTraversedEHD)?;

    let base_url = format!("http://{}:{}", host, g_collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    let traversed_ehd = client.traverse_era_historical_document(
        *cluster_id,
        era,
        g_collector_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|_| {
        log::error!(
            "⚠️  G-Collector from cluster {:?} is unavailable while fetching EHD record or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            g_collector_key,
            String::from_utf8(g_collector_params.host)
        );
        ApiError::FailedToFetchTraversedEHD
    })?;
    // proceed with the first available EHD record for the prototype
    Ok(traversed_ehd)
}

/// Traverse PHD record.
///
/// Parameters:
/// - `cluster_id`: cluster id of a cluster
/// - `era`: EHD era
/// - `collector`: Collector node key
/// - `tree_node_id` - merkle tree node identifier
/// - `tree_levels_count` - merkle tree levels to request
pub fn fetch_traversed_partial_historical_document<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    collector_key: NodePubKey,
    tree_node_id: u32,
    tree_levels_count: u32,
) -> Result<Vec<json::PHDTreeNode>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::FailedToFetchTraversedPHD)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    let traversed_phd = client.traverse_partial_historical_document(
        era,
        collector_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|_| {
        log::error!(
            "⚠️  Collector from cluster {:?} is unavailable while fetching PHD record or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8(collector_params.host)
        );
        ApiError::FailedToFetchTraversedPHD
    })?;

    Ok(traversed_phd)
}

pub fn fetch_traversed_node_aggregate<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tca_id: TcaEra,
    collector_key: NodePubKey,
    node_key: NodePubKey,
    tree_node_id: u64,
    tree_levels_count: u16,
    verify_sig: bool,
) -> Result<ApiResponse<Vec<json::MerkleTreeNodeResponse>>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host = str::from_utf8(&collector_params.host)
        .map_err(|_| ApiError::FailedToFetchTraversedNodeAggregate)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig,
    );

    let traversed_node_aggregate = client.traverse_node_aggregate(
        tca_id,
        node_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|_| {
        log::error!(
            "⚠️  Collector from cluster {:?} is unavailable while fetching Node aggregate or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8(collector_params.host)
        );
        ApiError::FailedToFetchTraversedNodeAggregate
    })?;

    Ok(traversed_node_aggregate)
}

pub fn fetch_traversed_bucket_sub_aggregate<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tca_id: TcaEra,
    collector_key: NodePubKey,
    bucket_id: BucketId,
    node_key: NodePubKey,
    tree_node_id: u64,
    tree_levels_count: u16,
    verify_sig: bool,
) -> Result<ApiResponse<Vec<json::MerkleTreeNodeResponse>>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host = str::from_utf8(&collector_params.host)
        .map_err(|_| ApiError::FailedToFetchTraversedBucketSubAggregate)?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig, // no response signature verification for now
    );

    let traversed_bucket_sub_aggregate = client.traverse_bucket_sub_aggregate(
        tca_id,
        bucket_id,
        node_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|_| {
        log::error!(
            "⚠️  Collector from cluster {:?} is unavailable while fetching Bucket aggregate or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8(collector_params.host)
        );
        ApiError::FailedToFetchTraversedBucketSubAggregate
    })?;

    Ok(traversed_bucket_sub_aggregate)
}

/// Fetch EHD merkle root node.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `era`: EHD era
pub fn get_ehd_root<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<json::EHDTreeNode, ApiError> {
    fetch_traversed_era_historical_document::<AccountId, BlockNumber, CM, NM>(
        cluster_id, era, 1, 1,
    )?
    .first()
    .ok_or(ApiError::FailedToFetchTraversedEHD)
    .cloned()
}

/// Fetch PHD merkle root node.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `era`: EHD era
/// - `collector`: Collector node key
pub fn get_phd_root<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    collector: NodePubKey,
) -> Result<json::PHDTreeNode, ApiError> {
    fetch_traversed_partial_historical_document::<AccountId, BlockNumber, CM, NM>(
        cluster_id, era, collector, 1, 1,
    )?
    .first()
    .ok_or(ApiError::FailedToFetchTraversedPHD)
    .cloned()
}

/// Fetch processed EHD eras.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
#[allow(dead_code)]
pub fn fetch_processed_eras_for_cluster<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    prev: Option<EhdEra>,
    limit: Option<u32>,
) -> Result<Vec<json::EHDEra>, ApiError> {
    let (_, node_params) =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchSyncNode {
                cluster_id: *cluster_id,
            }
        })?;

    fetch_processed_eras(&node_params, prev, limit).map_err(|_| ApiError::FailedToFetchProcessedEras {
        cluster_id: *cluster_id,
    })
}

/// Fetch processed payment era era
///
/// Parameters:
/// - `node_params`: Sync node parameters
pub fn fetch_processed_eras(
    node_params: &StorageNodeParams,
    prev: Option<EhdEra>,
    limit: Option<u32>,
) -> Result<Vec<json::EHDEra>, http::Error> {
    let host = str::from_utf8(&node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        true,
    );

    let api_response = client.payment_eras(prev, limit)?;
    Ok(api_response.response
        .into_iter()
        .filter(|e| e.status == "EHD_PROCESSED")
        .collect::<Vec<_>>())
}

/// Fetch inspected EHD eras.
///
/// Parameters:
/// - `node_params`: DAC node parameters
#[allow(dead_code)]
pub fn fetch_inspected_eras_for_cluster<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    prev: Option<EhdEra>,
    limit: Option<u32>,
) -> Result<Vec<json::EHDEra>, ApiError> {
    let (_, node_params) =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchSyncNode {
                cluster_id: *cluster_id,
            }
        })?;

    fetch_inspected_eras(&node_params, prev, limit).map_err(|_| ApiError::FailedToFetchInspectedEras {
        cluster_id: *cluster_id,
    })
}

/// Fetch processed payment era era
///
/// Parameters:
/// - `node_params`: Sync node parameters
pub fn fetch_inspected_era<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<json::EHDEra, ApiError> {
    let ehd_eras = fetch_inspected_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(cluster_id, Some(era - 1), None)?;
    ehd_eras
        .iter()
        .find(|ehd| ehd.id == era)
        .ok_or(ApiError::FailedToFetchEra)
        .cloned()
}

/// Fetch processed payment era era
///
/// Parameters:
/// - `node_params`: Sync node parameters
pub fn fetch_processed_era<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    prev: Option<EhdEra>,
    limit: Option<u32>,
) -> Result<json::EHDEra, ApiError> {
    let ehd_eras = fetch_processed_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(cluster_id, prev, limit)?;
    ehd_eras
        .iter()
        .find(|ehd| ehd.id == era)
        .ok_or(ApiError::FailedToFetchEra)
        .cloned()
}

/// Fetch inspected EHD eras.
///
/// Parameters:
/// - `node_params`: Sync node parameters
#[allow(dead_code)]
pub fn fetch_inspected_eras(
    node_params: &StorageNodeParams,
    prev: Option<EhdEra>,
    limit: Option<u32>,
) -> Result<Vec<json::EHDEra>, http::Error> {
    let host = str::from_utf8(&node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        true,
    );

    let api_response = client.payment_eras(prev, limit)?;
    Ok(api_response.response
        .into_iter()
        .filter(|e| e.status == "EHD_INSPECTED")
        .collect::<Vec<_>>())
}

pub fn fetch_inspection_exceptions<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<BTreeMap<String, BTreeMap<String, json::InspPathException>>, ApiError> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)
        .map_err(|_| ApiError::FailedToFetchSyncNode {
            cluster_id: *cluster_id,
        })?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| ApiError::Unexpected)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .fetch_inspection_exceptions(era)
        .map_err(|_| ApiError::FailedToFetchPathsExceptions)
}

pub fn get_inspection_state<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<proto::inspection::EndpointItmGetPathsState, http::Error> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client.get_inspection_state(era)
}

pub fn submit_inspection_report<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    report_json_str: String, // todo(yahortsaryk): add .proto definition for `InspEraReport` type
) -> Result<proto::inspection::EndpointItmPostPath, http::Error> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client.submit_inspection_report(report_json_str)
}

pub fn submit_assignments_table<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    table_json_str: String, /* todo(yahortsaryk): add .proto definition for
                             * `InspAssignmentsTable` type */
    inspector_hex: String,
) -> Result<proto::inspection::EndpointItmSubmit, http::Error> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client.submit_assignments_table(era, table_json_str, inspector_hex)
}

pub fn get_assignments_table<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<String, http::Error> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let table_response: proto::inspection::EndpointItmTable = client
        .get_assignments_table(era)
        .map_err(|_| http::Error::Unknown)?;

    // todo(yahortsaryk): move the below pattern matching to `InspTaskAssigner`
    match table_response.variant {
        Some(ItmTableVariant::Table(ItmTable {
            json_string,
            inspector_key: _key,
        })) => {
            // todo(yahortsaryk):  add .proto definition for `InspAssignmentsTable` type
            Ok(json_string)
        }
        _ => {
            // todo(yahortsaryk): handle other `EndpointItmTable` variants
            Err(http::Error::Unknown)
        }
    }
}

pub fn post_itm_lease<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
    inspector_hex: String,
) -> Result<proto::inspection::EndpointItmLease, http::Error> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client.post_itm_lease(era, inspector_hex)
}

pub fn get_inspection_summary<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<json::InspSummary, ApiError> {
    let (_, sync_node_params) = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)
        .map_err(|_| ApiError::FailedToFetchSyncNode {
            cluster_id: *cluster_id,
        })?;

    let host = str::from_utf8(&sync_node_params.host).map_err(|_| ApiError::Unexpected)?;
    let base_url = format!("http://{}:{}", host, sync_node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    client
        .get_inspection_summary(era)
        .map_err(|_| ApiError::FailedToFetchInspSummary {
            cluster_id: *cluster_id,
        })
}
