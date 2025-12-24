use core::str;

use codec::{Decode, Encode};
use ddc_primitives::{
    traits::{ClusterManager, NodeManager},
    BucketId, ClusterId, EhdEra, NodeParams, NodePubKey, StorageNodeParams, TcaEra,
};
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

#[macro_export]
macro_rules! log {
    ($level:tt, $pattern:expr $(, $values:expr)* $(,)?) => {
        log::$level!(
            target: $crate::LOG_TARGET,
            concat!("🔁 ", $pattern) $(, $values)*
        )
    };
}

pub const RESPONSE_TIMEOUT: u64 = 20000;
pub const MAX_RETRIES_COUNT: u32 = 3;
pub const BUCKETS_AGGREGATES_FETCH_BATCH_SIZE: usize = 100;

#[allow(dead_code)]
pub const NODES_AGGREGATES_FETCH_BATCH_SIZE: usize = 10;

#[derive(Debug, Encode, Decode, Clone, TypeInfo, PartialEq)]
pub enum ApiError {
    HttpClientError {
        cluster_id: ClusterId,
        host: Vec<u8>,
    },
    NodeHostParseError {
        cluster_id: ClusterId,
        node_key: NodePubKey,
        host: Vec<u8>,
    },
    FailedToFetchCollector {
        cluster_id: ClusterId,
        node_key: NodePubKey,
    },
    FailedToFetchCollectors {
        cluster_id: ClusterId,
    },
    FailedToFetchGCollectors {
        cluster_id: ClusterId,
    },
    FailedToFetchBucketChallenge {
        cluster_id: ClusterId,
        tca_id: TcaEra,
        bucket_id: BucketId,
        node_key: NodePubKey,
    },
    FailedToFetchNodeChallenge {
        cluster_id: ClusterId,
        tca_id: TcaEra,
        node_key: NodePubKey,
    },
    FailedToFetchBucketAggregates {
        cluster_id: ClusterId,
        tca_id: TcaEra,
    },
    FailedToFetchTraversedEHD {
        cluster_id: ClusterId,
        era: EhdEra,
        tree_node_id: u32,
        tree_levels_count: u32,
    },
    FailedToFetchTraversedPHD {
        cluster_id: ClusterId,
        era: EhdEra,
        tree_node_id: u32,
        tree_levels_count: u32,
    },
    FailedToFetchTraversedNodeAggregate {
        cluster_id: ClusterId,
        tca_id: TcaEra,
        node_key: NodePubKey,
        tree_node_id: u64,
        tree_levels_count: u16,
    },
    FailedToFetchTraversedBucketSubAggregate {
        cluster_id: ClusterId,
        tca_id: TcaEra,
        bucket_id: BucketId,
        node_key: NodePubKey,
        tree_node_id: u64,
        tree_levels_count: u16,
    },
    FailedToFetchEra {
        cluster_id: ClusterId,
        era: EhdEra,
    },
    FailedToFetchPathsExceptions {
        cluster_id: ClusterId,
        era: EhdEra,
    },
    FailedToFetchSyncNodes {
        cluster_id: ClusterId,
    },
    FailedToFetchInspSummary {
        cluster_id: ClusterId,
        era: EhdEra,
    },
    FailedToFetchInspectedEras {
        cluster_id: ClusterId,
    },
    FailedToFetchProcessedEras {
        cluster_id: ClusterId,
    },
    FailedToFetchInspectionDryRunParams {
        cluster_id: ClusterId,
    },
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
    let mut g_collectors_keys = Vec::new();

    for (node_key, node_params) in collectors {
        if g_collectors_keys.is_empty() {
            if let Ok(keys) = get_grouping_collectors_keys(cluster_id, &node_key, &node_params) {
                g_collectors_keys.extend(keys);
            } else {
                continue;
            }
        }
        
        if g_collectors_keys.contains(&node_key) {
            g_collectors.push((node_key, node_params))
        }
    }

    if g_collectors_keys.is_empty() {
        return Err(ApiError::FailedToFetchGCollectors {
            cluster_id: *cluster_id,
        });
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
) -> Result<(NodePubKey, StorageNodeParams), ApiError> {
    // todo(yahortsaryk): replace G-Collector with Sync node once it is supported at DDC
    let g_collectors = get_g_collectors_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)
        .map_err(|_| ApiError::FailedToFetchGCollectors {
            cluster_id: *cluster_id,
        })?;
    let Some(g_collector) = g_collectors.first() else {
        log!(
            error,
            "❌ No Grouping Collector found in cluster {:?}",
            cluster_id
        );
        return Err(ApiError::FailedToFetchGCollectors {
            cluster_id: *cluster_id,
        });
    };

    Ok(g_collector.clone())
}

pub struct SyncNode {
    pub dry_run: bool,
    pub key: NodePubKey,
    pub params: StorageNodeParams,
}

pub fn get_sync_node<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
) -> Result<SyncNode, ApiError> {
    
    let dry_run_params = CM::get_inspection_dry_run_params(cluster_id).map_err(|_| ApiError::FailedToFetchInspectionDryRunParams {
        cluster_id: *cluster_id,
    })?;

    if let Some(params) = dry_run_params {
        Ok(SyncNode {
            dry_run: params.enabled,
            key: params.sync_node_key,
            params: params.sync_node_params,
        })
    } else {
        // todo(yahortsaryk): replace G-Collector with Sync node once it is supported at DDC
        get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id)
        .map(|(key, params)| SyncNode {
            dry_run: false,
            key,
            params,
        })
    }
}

/// Fetch customer usage.
///
/// Parameters:
/// - `node_params`: Requesting DDC node
pub fn check_grouping_collector(
    cluster_id: &ClusterId,
    node_key: &NodePubKey,
    node_params: &StorageNodeParams,
) -> Result<bool, ApiError> {
    let host = str::from_utf8(&node_params.host).map_err(|_| ApiError::NodeHostParseError {
        cluster_id: *cluster_id,
        node_key: node_key.clone(),
        host: node_params.host.clone(),
    })?;
    let base_url: String = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let response = client
        .check_grouping_collector()
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: node_params.host.clone(),
        })?;
    Ok(response.is_g_collector)
}

pub fn get_grouping_collectors_keys(
    cluster_id: &ClusterId,
    node_key: &NodePubKey,
    node_params: &StorageNodeParams,
) -> Result<Vec<NodePubKey>, ApiError> {
    let host = str::from_utf8(&node_params.host).map_err(|_| ApiError::NodeHostParseError {
        cluster_id: *cluster_id,
        node_key: node_key.clone(),
        host: node_params.host.clone(),
    })?;
    let base_url: String = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let response = client
        .get_grouping_collectors()
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: node_params.host.clone(),
        })?;
        
    Ok(response.nodes_keys)
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
    let nodes = CM::get_nodes(cluster_id).map_err(|_| ApiError::FailedToFetchCollectors {
        cluster_id: *cluster_id,
    })?;
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
    let nodes = CM::get_nodes(cluster_id).map_err(|_| ApiError::FailedToFetchCollector {
        cluster_id: *cluster_id,
        node_key: collector_key.clone(),
    })?;
    for node_pub_key in nodes {
        if let Ok(NodeParams::StorageParams(storage_params)) = NM::get_node_params(&node_pub_key) {
            collectors.push((node_pub_key, storage_params));
        }
    }
    let (collector_key, collector_params) = collectors
        .into_iter()
        .find(|(key, _)| *key == collector_key)
        .ok_or(ApiError::FailedToFetchCollector {
            cluster_id: *cluster_id,
            node_key: collector_key,
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
    tca_id: TcaEra,
    collector_key: NodePubKey,
    node_key: NodePubKey,
    bucket_id: BucketId,
    tree_node_ids: Vec<u64>,
    verify_sig: bool,
) -> Result<ApiResponse<proto::activity::ChallengeResponse>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key.clone(),
            host: collector_params.host.clone(),
        })?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig,
    );

    match client.challenge_bucket_sub_aggregate(
        tca_id,
        bucket_id,
        &Into::<String>::into(node_key.clone()),
        tree_node_ids,
    ) {
        Ok(res) => Ok(res),
        Err(_) => {
            log!(error,
                "❌ Collector from cluster {:?} is unavailable while challenging bucket sub-aggregate or responded unexpectedly. Key: {:?}, Host: {:?}",
                cluster_id,
                collector_key,
                String::from_utf8_lossy(&collector_params.host)
            );
            Err(ApiError::FailedToFetchBucketChallenge {
                cluster_id: *cluster_id,
                tca_id,
                bucket_id,
                node_key: node_key.clone(),
            })
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
    tca_id: TcaEra,
    collector_key: NodePubKey,
    node_key: NodePubKey,
    tree_node_ids: Vec<u64>,
    verify_sig: bool,
) -> Result<ApiResponse<proto::activity::ChallengeResponse>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key.clone(),
            host: collector_params.host.clone(),
        })?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        verify_sig,
    );

    match client.challenge_node_aggregate(
        tca_id,
        &Into::<String>::into(node_key.clone()),
        tree_node_ids,
    ) {
        Ok(res) => Ok(res),
        Err(_) => {
            log!(error,
                "❌ Collector from cluster {:?} is unavailable while challenging node aggregate or responded unexpectedly. Key: {:?}, Host: {:?}",
                cluster_id,
                collector_key,
                String::from_utf8_lossy(&collector_params.host)
            );
            Err(ApiError::FailedToFetchNodeChallenge {
                cluster_id: *cluster_id,
                tca_id,
                node_key: node_key,
            })
        }
    }
}

/// Fetch customer usage.
///
/// Parameters:
/// - `cluster_id`: cluster id of a cluster
/// - `tca_id`: time capsule era
/// - `collector_key`: collector to fetch Bucket aggregates from
pub fn fetch_bucket_aggregates<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    tca_id: TcaEra,
    collector_key: NodePubKey,
) -> Result<Vec<proto::activity_tree::BucketAggregate>, ApiError> {
    let (_, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key.clone())?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key,
            host: collector_params.host.clone(),
        })?;

    let base_url = format!("http://{}:{}", host, collector_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let mut buckets_aggregates: Vec<proto::activity_tree::BucketAggregate> = Vec::new();
    let mut prev_token = None;

    loop {
        let api_response = client
            .buckets_aggregates(
                tca_id,
                prev_token,
                Some(BUCKETS_AGGREGATES_FETCH_BATCH_SIZE as u32),
            )
            .map_err(|_| ApiError::FailedToFetchBucketAggregates {
                cluster_id: *cluster_id,
                tca_id,
            })?;

        let response = api_response.response;
        let response_len = response.buckets.len();

        prev_token = response.buckets.last().map(|a| a.bucket_id);

        buckets_aggregates.extend(response.buckets);

        if response_len < BUCKETS_AGGREGATES_FETCH_BATCH_SIZE {
            break;
        }
    }

    Ok(buckets_aggregates)
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
) -> Result<ApiResponse<proto::activity_tree::PhdTreeTraversalResponse>, ApiError> {
    let (collector_key, collector_params) =
        get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key.clone(),
            host: collector_params.host.clone(),
        })?;

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
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching PHD record (proto) or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host)
        );
        ApiError::FailedToFetchTraversedPHD {
            cluster_id: *cluster_id,
            era,
            tree_node_id,
            tree_levels_count,
        }
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
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key.clone(),
            host: collector_params.host.clone(),
        })?;

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
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching Node aggregate or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host)
        );
        ApiError::FailedToFetchTraversedNodeAggregate {
            cluster_id: *cluster_id,
            tca_id,
            node_key: node_key.clone(),
            tree_node_id,
            tree_levels_count,
        }
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
    let host =
        str::from_utf8(&collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: collector_key.clone(),
            host: collector_params.host.clone(),
        })?;

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
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching Bucket aggregate or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host)
        );
        ApiError::FailedToFetchTraversedBucketSubAggregate {
            cluster_id: *cluster_id,
            tca_id,
            bucket_id,
            node_key: node_key.clone(),
            tree_node_id,
            tree_levels_count,
        }
    })?;

    Ok(traversed_bucket_sub_aggregate)
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
) -> Result<ApiResponse<proto::activity_tree::EhdTreeTraversalResponse>, ApiError> {
    let (g_collector_key, g_collector_params) =
        get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchGCollectors {
                cluster_id: *cluster_id,
            }
        })?;
    let host =
        str::from_utf8(&g_collector_params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: g_collector_key.clone(),
            host: g_collector_params.host.clone(),
        })?;

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
        log!(error,
            "❌ G-Collector from cluster {:?} is unavailable while fetching EHD record or responded with unexpected body. Key: {:?} Host: {:?}",
            cluster_id,
            g_collector_key,
            String::from_utf8_lossy(&g_collector_params.host)
        );
        ApiError::FailedToFetchTraversedEHD {
            cluster_id: *cluster_id,
            era,
            tree_node_id,
            tree_levels_count,
        }
    })?;
    
    Ok(traversed_ehd)
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
) -> Result<ApiResponse<proto::activity_tree::EhdTreeTraversedNode>, ApiError> {
    let api_response = fetch_traversed_era_historical_document::<AccountId, BlockNumber, CM, NM>(
        cluster_id, era, 1, 1,
    )?;
    
    let first_node = api_response.response.nodes
        .into_iter()
        .next()
        .ok_or(ApiError::FailedToFetchTraversedEHD {
            cluster_id: *cluster_id,
            era,
            tree_node_id: 1,
            tree_levels_count: 1,
        })?;
    
    Ok(ApiResponse {
        response: first_node,
        signed_by: api_response.signed_by,
    })
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
) -> Result<ApiResponse<proto::activity_tree::PhdTreeTraversedNode>, ApiError> {
    let api_response = fetch_traversed_partial_historical_document::<AccountId, BlockNumber, CM, NM>(
        cluster_id, era, collector, 1, 1,
    )?;

    let first_node = api_response.response.nodes
        .into_iter()
        .next()
        .ok_or(ApiError::FailedToFetchTraversedPHD {
            cluster_id: *cluster_id,
            era,
            tree_node_id: 1,
            tree_levels_count: 1,
        })?;

    Ok(ApiResponse {
        response: first_node,
        signed_by: api_response.signed_by,
    })
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

    let sync_node = get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    if sync_node.dry_run {
        // note(yahortsaryk): to prevent interference between production DDC network and stage DDC network during dry-run, we fetch processed eras from pre-configured Sync Node.
        let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
        let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
        let client = DdcClient::new(
            &base_url,
            Duration::from_millis(RESPONSE_TIMEOUT),
            MAX_RETRIES_COUNT,
            false, // no response signature verification for now
        );

        let api_response = client.processed_eras(prev, limit, sync_node.dry_run).map_err(|_| ApiError::FailedToFetchProcessedEras {
            cluster_id: *cluster_id,
        })?;

        Ok(api_response.response)

    } else {
        // note(yahortsaryk): processed eras always have corresponding EHD stored at global collector side, not sync node side. Global Collectors and Sync Node can be different quorums of nodes.
        let (_, g_collector_params) = get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchGCollectors {
                cluster_id: *cluster_id,
            }
        })?;

        fetch_processed_eras(&g_collector_params, prev, limit).map_err(|_| {
            ApiError::FailedToFetchProcessedEras {
                cluster_id: *cluster_id,
            }
        })
    }
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
        false,
    );

    let api_response = client.activity_eras(prev, limit)?;
    Ok(api_response
        .response
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
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchSyncNodes {
                cluster_id: *cluster_id,
            }
        })?;

    fetch_inspected_eras(&sync_node.params, prev, limit, sync_node.dry_run).map_err(|_| {
        ApiError::FailedToFetchInspectedEras {
            cluster_id: *cluster_id,
        }
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
    let ehd_eras = fetch_inspected_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(
        cluster_id,
        Some(era - 1),
        None,
    )?;
    ehd_eras
        .iter()
        .find(|ehd| ehd.id == era)
        .ok_or(ApiError::FailedToFetchEra {
            cluster_id: *cluster_id,
            era,
        })
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
    let ehd_eras = fetch_processed_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(
        cluster_id, prev, limit,
    )?;
    ehd_eras
        .iter()
        .find(|ehd| ehd.id == era)
        .ok_or(ApiError::FailedToFetchEra {
            cluster_id: *cluster_id,
            era,
        })
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
    dry_run: bool,
) -> Result<Vec<json::EHDEra>, http::Error> {
    let host = str::from_utf8(&node_params.host).map_err(|_| http::Error::Unknown)?;
    let base_url = format!("http://{}:{}", host, node_params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    let api_response = client.inspected_eras(prev, limit, dry_run)?;
    Ok(api_response
        .response
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
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchSyncNodes {
                cluster_id: *cluster_id,
            }
        })?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .fetch_inspection_exceptions(era, sync_node.dry_run)
        .map_err(|_| ApiError::FailedToFetchPathsExceptions {
            cluster_id: *cluster_id,
            era,
        })
}

pub fn get_inspection_state<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<proto::inspection::EndpointItmGetPathsState, ApiError> {
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .get_inspection_state(era, sync_node.dry_run)
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: sync_node.params.host.clone(),
        })
}

pub fn submit_inspection_report<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    report_json_str: String, // todo(yahortsaryk): add .proto definition for `InspEraReport` type
) -> Result<proto::inspection::EndpointItmPostPath, ApiError> {
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .submit_inspection_report(report_json_str, sync_node.dry_run)
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: sync_node.params.host.clone(),
        })
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
) -> Result<proto::inspection::EndpointItmSubmit, ApiError> {
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .submit_assignments_table(era, table_json_str, inspector_hex, sync_node.dry_run)
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: sync_node.params.host.clone(),
        })
}

pub fn get_assignments_table<
    AccountId,
    BlockNumber,
    CM: ClusterManager<AccountId, BlockNumber>,
    NM: NodeManager<AccountId>,
>(
    cluster_id: &ClusterId,
    era: EhdEra,
) -> Result<proto::inspection::EndpointItmTable, ApiError> {
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    client
        .get_assignments_table(era, sync_node.dry_run)
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: sync_node.params.host.clone(),
        })
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
) -> Result<proto::inspection::EndpointItmLease, ApiError> {
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id)?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false, // no response signature verification for now
    );

    client
        .post_itm_lease(era, inspector_hex, sync_node.dry_run)
        .map_err(|_| ApiError::HttpClientError {
            cluster_id: *cluster_id,
            host: sync_node.params.host.clone(),
        })
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
    let sync_node =
        get_sync_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|_| {
            ApiError::FailedToFetchSyncNodes {
                cluster_id: *cluster_id,
            }
        })?;

    let host =
        str::from_utf8(&sync_node.params.host).map_err(|_| ApiError::NodeHostParseError {
            cluster_id: *cluster_id,
            node_key: sync_node.key.clone(),
            host: sync_node.params.host.clone(),
        })?;
    let base_url = format!("http://{}:{}", host, sync_node.params.http_port);
    let client = DdcClient::new(
        &base_url,
        Duration::from_millis(RESPONSE_TIMEOUT),
        MAX_RETRIES_COUNT,
        false,
    );

    client
        .get_inspection_summary(era, sync_node.dry_run)
        .map_err(|_| ApiError::FailedToFetchInspSummary {
            cluster_id: *cluster_id,
            era,
        })
}
