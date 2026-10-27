use core::str;

use codec::{Decode, Encode};
use ddc_primitives::StorageNodeMode;
use ddc_primitives::{
	traits::{ClusterManager, NodeManager},
	BucketId, ClusterId, EhdEra, NodeParams, NodePubKey, StorageNodeParams, TcaEra,
};
use polkadot_sdk::sp_runtime::offchain::{http, Duration};
use polkadot_sdk::sp_std::prelude::*;
use scale_info::{
	prelude::{format, string::String},
	TypeInfo,
};
use serde::{Deserialize, Serialize};

use crate::{
	client::DdcClient,
	proto::{self},
	shared_memory::{dry_run_shared_memory_node, SharedMemoryNode},
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
	FailedToFetchBucketAggregates {
		cluster_id: ClusterId,
		tca_id: TcaEra,
	},
	FailedToFetchNodeAggregate {
		cluster_id: ClusterId,
		tca_id: TcaEra,
		node_key: NodePubKey,
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
	FailedToFetchSharedMemoryNodes {
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
	FailedToFetchRecordsRange {
		cluster_id: ClusterId,
		tca_id: TcaEra,
		node_key: NodePubKey,
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
		return Err(ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id });
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
	let g_collectors = get_g_collectors_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)
		.map_err(|e| {
			log!(error, "❌ Failed to fetch G-Collectors for cluster {:?}: {:?}", cluster_id, e);
			ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
		})?;
	let Some(g_collector) = g_collectors.first() else {
		log!(error, "❌ No Grouping Collector found in cluster {:?}", cluster_id);
		return Err(ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id });
	};

	Ok(g_collector.clone())
}

pub fn get_grouping_collectors_keys(
	cluster_id: &ClusterId,
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
) -> Result<Vec<NodePubKey>, ApiError> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse node host for node {:?} in cluster {:?}: {:?}",
			node_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: node_key.clone(),
			host: node_params.host.clone(),
		}
	})?;
	let base_url: String = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let api_response = client.get_grouping_collectors().map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch grouping collectors from node {:?} in cluster {:?}: {:?}",
			node_key,
			cluster_id,
			e
		);
		ApiError::HttpClientError { cluster_id: *cluster_id, host: node_params.host.clone() }
	})?;

	api_response
		.response
		.keys
		.into_iter()
		.map(|s| {
			NodePubKey::try_from(s).map_err(|_| ApiError::HttpClientError {
				cluster_id: *cluster_id,
				host: node_params.host.clone(),
			})
		})
		.collect()
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
	let nodes = CM::get_nodes(cluster_id).map_err(|e| {
		log!(error, "❌ Failed to fetch collectors for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchCollectors { cluster_id: *cluster_id }
	})?;
	for node_pub_key in nodes {
		if let Ok(NodeParams::StorageParams(node_params)) = NM::get_node_params(&node_pub_key) {
			if node_params.mode == StorageNodeMode::Compute {
				continue;
			}
			collectors.push((node_pub_key, node_params));
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
	let nodes = CM::get_nodes(cluster_id).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch collector {:?} for cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::FailedToFetchCollector {
			cluster_id: *cluster_id,
			node_key: collector_key.clone(),
		}
	})?;
	for node_pub_key in nodes {
		if let Ok(NodeParams::StorageParams(storage_params)) = NM::get_node_params(&node_pub_key) {
			collectors.push((node_pub_key, storage_params));
		}
	}
	let (collector_key, collector_params) =
		collectors.into_iter().find(|(key, _)| *key == collector_key).ok_or(
			ApiError::FailedToFetchCollector { cluster_id: *cluster_id, node_key: collector_key },
		)?;

	Ok((collector_key, collector_params))
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
) -> Result<(Vec<proto::activity_tree::BucketAggregate>, Vec<u8>), ApiError> {
	let (_, collector_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key.clone())?;
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key,
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let mut buckets_aggregates: Vec<proto::activity_tree::BucketAggregate> = Vec::new();
	let mut prev_token = None;
	let mut last_sig: Vec<u8> = Vec::new();

	loop {
		let api_response = client
			.buckets_aggregates(
				tca_id,
				prev_token,
				Some(BUCKETS_AGGREGATES_FETCH_BATCH_SIZE as u32),
			)
			.map_err(|e| {
				log!(
					error,
					"❌ Failed to fetch bucket aggregates for cluster {:?}, tca {:?}: {:?}",
					cluster_id,
					tca_id,
					e
				);
				ApiError::FailedToFetchBucketAggregates { cluster_id: *cluster_id, tca_id }
			})?;

		if let Some(signed_by) = &api_response.signed_by {
			last_sig = signed_by.signature.clone();
		}

		let response = api_response.response;
		let response_len = response.buckets.len();

		prev_token = response.buckets.last().map(|a| a.bucket_id);

		buckets_aggregates.extend(response.buckets);

		if response_len < BUCKETS_AGGREGATES_FETCH_BATCH_SIZE {
			break;
		}
	}

	Ok((buckets_aggregates, last_sig))
}

pub fn fetch_bucket_aggregate<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	tca_id: TcaEra,
	collector_key: NodePubKey,
	bucket_id: BucketId,
) -> Result<(Option<proto::activity_tree::BucketAggregate>, Vec<u8>), ApiError> {
	let (_, collector_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key.clone())?;
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key,
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let api_response = client.bucket_aggregate(tca_id, bucket_id).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch bucket aggregate for bucket {:?} in cluster {:?}, tca {:?}: {:?}",
			bucket_id,
			cluster_id,
			tca_id,
			e
		);
		ApiError::FailedToFetchBucketAggregates { cluster_id: *cluster_id, tca_id }
	})?;

	let sig = api_response.signed_by.map(|signed_by| signed_by.signature).unwrap_or_default();

	let aggregate = api_response
		.response
		.buckets
		.into_iter()
		.find(|a| a.bucket_id == bucket_id as u64);

	Ok((aggregate, sig))
}

pub fn fetch_node_aggregate<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	tca_id: TcaEra,
	collector_key: NodePubKey,
	node_key: NodePubKey,
) -> Result<(Option<proto::activity_tree::NodeAggregate>, Vec<u8>), ApiError> {
	let (_, collector_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key.clone())?;
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key,
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let api_response = client.node_aggregate(tca_id, node_key.clone()).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch node aggregate for node {:?} in cluster {:?}, tca {:?}: {:?}",
			node_key,
			cluster_id,
			tca_id,
			e
		);
		ApiError::FailedToFetchNodeAggregate {
			cluster_id: *cluster_id,
			tca_id,
			node_key: node_key.clone(),
		}
	})?;

	let sig = api_response.signed_by.map(|signed_by| signed_by.signature).unwrap_or_default();

	let node_aggregate = api_response.response.nodes.into_iter().next();

	Ok((node_aggregate, sig))
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
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let traversed_phd = client.traverse_partial_historical_document(
        era,
        tree_node_id,
        tree_levels_count,
    ).map_err(|e| {
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching PHD record (proto) or responded with unexpected body. Key: {:?} Host: {:?}, Error: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host),
            e
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
) -> Result<ApiResponse<proto::activity::ActivityTreeTraversalResponse>, ApiError> {
	let (collector_key, collector_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let traversed_node_aggregate = client.traverse_node_aggregate(
        tca_id,
        node_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|e| {
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching Node aggregate or responded with unexpected body. Key: {:?} Host: {:?}, Error: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host),
            e
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

/// Fetch activity records in a RecordId range directly from a Data Node.
///
/// Parameters:
/// - `cluster_id`: cluster id (used to resolve the node's host)
/// - `tca_id`: TCA era
/// - `node_key`: Data Node public key — determines which node serves the request
/// - `bucket_id`: optional bucket scope (cross-bucket scan if None)
/// - `record_id_gte` / `record_id_lte`: inclusive recordId range bounds
/// - `cursor`: optional resume token from a previous page's next_cursor
/// - `limit`: optional cap; the Data Node enforces its own max
pub fn fetch_records_range<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	tca_id: TcaEra,
	node_key: NodePubKey,
	bucket_id: Option<BucketId>,
	record_id_gte: &[u8],
	record_id_lte: &[u8],
	cursor: Option<&[u8]>,
	limit: Option<u32>,
	indexes: Option<&[u64]>,
) -> Result<ApiResponse<proto::activity::GetRecordsResponse>, ApiError> {
	let (node_key, node_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, node_key)?;
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse node host for {:?} in cluster {:?}: {:?}",
			node_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: node_key.clone(),
			host: node_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	client
        .fetch_records_range(tca_id, node_key.as_ref(), bucket_id, record_id_gte, record_id_lte, cursor, limit, indexes)
        .map_err(|e| {
            log!(error,
                "❌ Data node {:?} (cluster {:?}) unavailable while fetching records range. Host: {:?}, Error: {:?}",
                node_key,
                cluster_id,
                String::from_utf8_lossy(&node_params.host),
                e
            );
            ApiError::FailedToFetchRecordsRange {
                cluster_id: *cluster_id,
                tca_id,
                node_key: node_key.clone(),
            }
        })
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
) -> Result<ApiResponse<proto::activity::ActivityTreeTraversalResponse>, ApiError> {
	let (collector_key, collector_params) =
		get_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, collector_key)?;
	let host = str::from_utf8(&collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse collector host for node {:?} in cluster {:?}: {:?}",
			collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let traversed_bucket_sub_aggregate = client.traverse_bucket_sub_aggregate(
        tca_id,
        bucket_id,
        node_key.clone(),
        tree_node_id,
        tree_levels_count,
    ).map_err(|e| {
        log!(error,
            "❌ Collector from cluster {:?} is unavailable while fetching Bucket aggregate or responded with unexpected body. Key: {:?} Host: {:?}, Error: {:?}",
            cluster_id,
            collector_key,
            String::from_utf8_lossy(&collector_params.host),
            e
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
	let (g_collector_key, g_collector_params) = get_g_collector_node::<
		AccountId,
		BlockNumber,
		CM,
		NM,
	>(cluster_id)
	.map_err(|e| {
		log!(error, "❌ Failed to fetch G-Collector node for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
	})?;
	let host = str::from_utf8(&g_collector_params.host).map_err(|e| {
		log!(
			error,
			"❌ Failed to parse G-Collector host for node {:?} in cluster {:?}: {:?}",
			g_collector_key,
			cluster_id,
			e
		);
		ApiError::NodeHostParseError {
			cluster_id: *cluster_id,
			node_key: g_collector_key.clone(),
			host: g_collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, g_collector_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

	let traversed_ehd = client.traverse_era_historical_document(
        era,
        tree_node_id,
        tree_levels_count,
    ).map_err(|e| {
        log!(error,
            "❌ G-Collector from cluster {:?} is unavailable while fetching EHD record or responded with unexpected body. Key: {:?} Host: {:?}, Error: {:?}",
            cluster_id,
            g_collector_key,
            String::from_utf8_lossy(&g_collector_params.host),
            e
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

	let first_node = api_response.response.nodes.into_iter().next().ok_or(
		ApiError::FailedToFetchTraversedEHD {
			cluster_id: *cluster_id,
			era,
			tree_node_id: 1,
			tree_levels_count: 1,
		},
	)?;

	Ok(ApiResponse { response: first_node, signed_by: api_response.signed_by })
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

	let first_node = api_response.response.nodes.into_iter().next().ok_or(
		ApiError::FailedToFetchTraversedPHD {
			cluster_id: *cluster_id,
			era,
			tree_node_id: 1,
			tree_levels_count: 1,
		},
	)?;

	Ok(ApiResponse { response: first_node, signed_by: api_response.signed_by })
}

/// Fetch node TCA merkle root node.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `tca_id`: TCA era
/// - `collector_key`: Collector node key
/// - `node_key`: Node key
pub fn get_node_tca_root<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	tca_id: TcaEra,
	collector_key: NodePubKey,
	node_key: NodePubKey,
) -> Result<ApiResponse<proto::activity::ActivityTreeTraversedNode>, ApiError> {
	let api_response = fetch_traversed_node_aggregate::<AccountId, BlockNumber, CM, NM>(
		cluster_id,
		tca_id,
		collector_key,
		node_key.clone(),
		1,
		1,
	)?;

	let first_node = api_response.response.nodes.into_iter().next().ok_or(
		ApiError::FailedToFetchTraversedNodeAggregate {
			cluster_id: *cluster_id,
			tca_id,
			node_key: node_key.clone(),
			tree_node_id: 1,
			tree_levels_count: 1,
		},
	)?;

	Ok(ApiResponse { response: first_node, signed_by: api_response.signed_by })
}

/// Fetch bucket TCA merkle root node.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `tca_id`: TCA era
/// - `collector_key`: Collector node key
/// - `bucket_id`: Bucket Id
/// - `node_key`: Node key
pub fn get_bucket_tca_root<
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
) -> Result<ApiResponse<proto::activity::ActivityTreeTraversedNode>, ApiError> {
	let api_response = fetch_traversed_bucket_sub_aggregate::<AccountId, BlockNumber, CM, NM>(
		cluster_id,
		tca_id,
		collector_key,
		bucket_id,
		node_key.clone(),
		1,
		1,
	)?;

	let first_node = api_response.response.nodes.into_iter().next().ok_or(
		ApiError::FailedToFetchTraversedBucketSubAggregate {
			cluster_id: *cluster_id,
			tca_id,
			bucket_id,
			node_key: node_key.clone(),
			tree_node_id: 1,
			tree_levels_count: 1,
		},
	)?;

	Ok(ApiResponse { response: first_node, signed_by: api_response.signed_by })
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
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, ApiError> {
	// Era statuses are the G-Collector's; a dry-run sync node serves its own instead.
	let configured = dry_run_shared_memory_node::<AccountId, BlockNumber, CM>(cluster_id)?;
	if let Some(dry_run_node) = configured.filter(|node| node.dry_run) {
		let host = str::from_utf8(&dry_run_node.params.host).map_err(|e| {
			log!(
				error,
				"❌ Failed to parse dry-run node host for node {:?} in cluster {:?}: {:?}",
				dry_run_node.key,
				cluster_id,
				e
			);
			ApiError::NodeHostParseError {
				cluster_id: *cluster_id,
				node_key: dry_run_node.key.clone(),
				host: dry_run_node.params.host.clone(),
			}
		})?;
		let base_url = format!("http://{}:{}", host, dry_run_node.params.http_port);
		let client =
			DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

		return client.dry_run_processed_eras(cursor, limit).map(|r| r.response).map_err(|e| {
			log!(
				error,
				"❌ Failed to fetch dry-run processed eras for cluster {:?}: {:?}",
				cluster_id,
				e
			);
			ApiError::FailedToFetchProcessedEras { cluster_id: *cluster_id }
		});
	}

	let (_, g_collector_params) =
		get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|e| {
			log!(
				error,
				"❌ Failed to fetch G-Collector node for cluster {:?}: {:?}",
				cluster_id,
				e
			);
			ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
		})?;
	fetch_processed_eras(&g_collector_params, cursor, limit).map_err(|e| {
		log!(error, "❌ Failed to fetch processed eras for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchProcessedEras { cluster_id: *cluster_id }
	})
}

/// Fetch processed payment eras from global collector via /activity/processed-eras.
pub fn fetch_processed_eras(
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for processed eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);
	Ok(client.processed_eras(cursor, limit)?.response)
}

/// Fetch inspected EHD eras of a cluster from its G-Collector, or from the
/// dry-run sync node during a dry-run.
#[allow(dead_code)]
pub fn fetch_inspected_eras_for_cluster<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, ApiError> {
	// Era statuses are the G-Collector's; a dry-run sync node serves its own instead.
	let configured = dry_run_shared_memory_node::<AccountId, BlockNumber, CM>(cluster_id)?;
	if let Some(dry_run_node) = configured.filter(|node| node.dry_run) {
		let host = str::from_utf8(&dry_run_node.params.host).map_err(|e| {
			log!(
				error,
				"❌ Failed to parse dry-run node host for node {:?} in cluster {:?}: {:?}",
				dry_run_node.key,
				cluster_id,
				e
			);
			ApiError::NodeHostParseError {
				cluster_id: *cluster_id,
				node_key: dry_run_node.key.clone(),
				host: dry_run_node.params.host.clone(),
			}
		})?;
		let base_url = format!("http://{}:{}", host, dry_run_node.params.http_port);
		let client =
			DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);

		return client.dry_run_inspected_eras(cursor, limit).map(|r| r.response).map_err(|e| {
			log!(
				error,
				"❌ Failed to fetch dry-run inspected eras for cluster {:?}: {:?}",
				cluster_id,
				e
			);
			ApiError::FailedToFetchInspectedEras { cluster_id: *cluster_id }
		});
	}

	let (_, g_collector_params) =
		get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id).map_err(|e| {
			log!(
				error,
				"❌ Failed to fetch G-Collector node for cluster {:?}: {:?}",
				cluster_id,
				e
			);
			ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
		})?;
	fetch_inspected_eras(&g_collector_params, cursor, limit).map_err(|e| {
		log!(error, "❌ Failed to fetch inspected eras for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchInspectedEras { cluster_id: *cluster_id }
	})
}

/// Fetch a single inspected era by id.
pub fn fetch_inspected_era<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<proto::era::Era, ApiError> {
	let after = era.saturating_sub(1).to_be_bytes().to_vec();
	let page = fetch_inspected_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(
		cluster_id,
		Some(&after),
		None,
	)?;
	page.records
		.into_iter()
		.find(|e| e.id == era)
		.ok_or(ApiError::FailedToFetchEra { cluster_id: *cluster_id, era })
}

/// Fetch a single processed era by id.
pub fn fetch_processed_era<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::era::Era, ApiError> {
	let page = fetch_processed_eras_for_cluster::<AccountId, BlockNumber, CM, NM>(
		cluster_id, cursor, limit,
	)?;
	page.records
		.into_iter()
		.find(|e| e.id == era)
		.ok_or(ApiError::FailedToFetchEra { cluster_id: *cluster_id, era })
}

/// Fetch inspected EHD eras from a node via /activity/inspected-eras.
#[allow(dead_code)]
pub fn fetch_inspected_eras(
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for inspected eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);
	Ok(client.inspected_eras(cursor, limit)?.response)
}

/// Fetch a single page of `/activity/tcas`. `cursor` is the opaque token
/// returned from the previous page (`None` for the first page). `limit`
/// caps the number of records; the server also enforces its own max.
pub fn fetch_tcas_page(
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetTcasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for TCAs: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);
	let api_response = client.tcas(cursor, limit)?;
	Ok(api_response.response)
}

/// Walks `/activity/tcas` page by page until `next_cursor` is absent.
/// Concatenates all records into a single Vec. Intended for callers that
/// genuinely need a full enumeration; prefer fetch_tcas_page where the
/// caller can persist a cursor across calls.
pub fn fetch_tcas_all(
	node_params: &StorageNodeParams,
	page_limit: Option<u32>,
) -> Result<Vec<proto::era::Tca>, http::Error> {
	let mut out: Vec<proto::era::Tca> = Vec::new();
	let mut cursor: Option<Vec<u8>> = None;
	loop {
		let page = fetch_tcas_page(node_params, cursor.as_deref(), page_limit)?;
		out.extend(page.records.into_iter());
		match page.next_cursor {
			Some(c) if !c.is_empty() => cursor = Some(c),
			_ => return Ok(out),
		}
	}
}

/// Same as fetch_tcas_page for `/activity/eras`.
pub fn fetch_eras_page(
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client =
		DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT);
	let api_response = client.eras(cursor, limit)?;
	Ok(api_response.response)
}

/// Walks `/activity/eras` page by page until `next_cursor` is absent.
pub fn fetch_eras_all(
	node_params: &StorageNodeParams,
	page_limit: Option<u32>,
) -> Result<Vec<proto::era::Era>, http::Error> {
	let mut out: Vec<proto::era::Era> = Vec::new();
	let mut cursor: Option<Vec<u8>> = None;
	loop {
		let page = fetch_eras_page(node_params, cursor.as_deref(), page_limit)?;
		out.extend(page.records.into_iter());
		match page.next_cursor {
			Some(c) if !c.is_empty() => cursor = Some(c),
			_ => return Ok(out),
		}
	}
}

// ============================================================================
// Inspection API Functions (inspection protobuf types)
// ============================================================================
// These functions use the new etcd-based sync quorum API with full protobuf
// serialization. They correspond to the inspection_router endpoints.

/// Runs one operation on the inspectors' shared memory: the cluster's sync
/// store. Which replica answers is a storage detail; replicas are tried in key
/// order, each at its registry endpoint, and when none answers the cluster is
/// asked again in the same tick. A configured dry-run sync node is the only
/// one tried.
fn with_shared_memory<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
	R,
>(
	cluster_id: &ClusterId,
	operation: &str,
	mut call: impl FnMut(&DdcClient) -> Result<R, http::Error>,
) -> Result<R, ApiError> {
	if let Some(node) = dry_run_shared_memory_node::<AccountId, BlockNumber, CM>(cluster_id)? {
		return try_shared_memory_replicas(cluster_id, operation, &[node], &mut call);
	}

	let nodes = crate::shared_memory::discovered_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(
		cluster_id,
	)?;
	if let Ok(result) = try_shared_memory_replicas(cluster_id, operation, &nodes, &mut call) {
		return Ok(result);
	}

	log!(warn, "No cached shared-memory replica of cluster {:?} answered; discovering again", cluster_id);
	let nodes =
		crate::shared_memory::rediscover_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)?;
	try_shared_memory_replicas(cluster_id, operation, &nodes, &mut call)
}

fn try_shared_memory_replicas<R>(
	cluster_id: &ClusterId,
	operation: &str,
	nodes: &[SharedMemoryNode],
	call: &mut impl FnMut(&DdcClient) -> Result<R, http::Error>,
) -> Result<R, ApiError> {
	let mut last_error = ApiError::FailedToFetchSharedMemoryNodes { cluster_id: *cluster_id };
	for node in nodes {
		let host = match str::from_utf8(&node.params.host) {
			Ok(host) => host,
			Err(e) => {
				log!(
					error,
					"❌ Failed to parse dry-run node host for node {:?} in cluster {:?}: {:?}",
					node.key,
					cluster_id,
					e
				);
				last_error = ApiError::NodeHostParseError {
					cluster_id: *cluster_id,
					node_key: node.key.clone(),
					host: node.params.host.clone(),
				};
				continue;
			},
		};
		let base_url = format!("http://{}:{}", host, node.params.http_port);
		let client =
			DdcClient::new(&base_url, Duration::from_millis(RESPONSE_TIMEOUT), MAX_RETRIES_COUNT)
				.with_dry_run(node.dry_run);

		match call(&client) {
			Ok(result) => return Ok(result),
			Err(e) => {
				log!(
					error,
					"❌ Failed to {} at shared-memory replica {:?} of cluster {:?}: {:?}",
					operation,
					node.key,
					cluster_id,
					e
				);
				last_error =
					ApiError::HttpClientError { cluster_id: *cluster_id, host: node.params.host.clone() };
			},
		}
	}
	Err(last_error)
}

pub fn post_itm_lease<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	request: &proto::inspection::LeaseRequest,
) -> Result<proto::inspection::LeaseResult, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, "post ITM lease", |client| {
		client.post_itm_lease(request)
	})
}

pub fn submit_assignments_table<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	request: &proto::inspection::PostAssignmentTableRequest,
) -> Result<proto::inspection::PostAssignmentTableResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		"submit assignments table",
		|client| client.submit_assignments_table(request),
	)
}

pub fn get_assignments_table<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<proto::inspection::GetAssignmentTableResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, "get assignments table", |client| {
		client.get_assignments_table(era)
	})
}

pub fn submit_inspection_result<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	request: &proto::inspection::PostInspectionResultRequest,
) -> Result<proto::inspection::PostInspectionResultResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		"submit inspection result",
		|client| client.submit_inspection_result(request),
	)
}

pub fn get_inspection_state<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<proto::inspection::InspectionState, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, "get inspection state", |client| {
		client.get_inspection_state(era)
	})
}

pub fn get_inspection_receipt<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<proto::inspection::InspectionReceipt, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, "get inspection receipt", |client| {
		client.get_inspection_receipt(era)
	})
	.map_err(|e| match e {
		ApiError::HttpClientError { .. } => {
			ApiError::FailedToFetchInspSummary { cluster_id: *cluster_id, era }
		},
		other => other,
	})
}

pub fn get_quorum_info<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<proto::inspection::InspSyncQuorumInfo, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, "get quorum info", |client| {
		client.get_quorum_info(era)
	})
}
