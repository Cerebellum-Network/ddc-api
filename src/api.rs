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
	client::{DdcClient, ReadBackError},
	proto::{self},
	read_auth::ReadSigner,
	shared_memory::SharedMemoryNode,
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
	FailedToFetchRecordsRange {
		cluster_id: ClusterId,
		tca_id: TcaEra,
		node_key: NodePubKey,
	},
	FailedToFetchSealedEHD {
		cluster_id: ClusterId,
		era: EhdEra,
	},
	FailedToFetchSealedPHD {
		cluster_id: ClusterId,
		era: EhdEra,
		node_key: NodePubKey,
	},
	/// The shared memory served an inspection receipt, state or table that names another
	/// cluster or era than the one asked for.
	AnotherEraOrCluster {
		cluster_id: ClusterId,
		era: EhdEra,
	},
}

/// Refuses an inspection receipt, state or table whose own cluster and era are not the ones
/// asked for. The fetcher is the only place that holds both: settlement takes its era from the
/// receipt itself, so a check further on would compare the receipt with itself.
fn require_era_and_cluster(
	cluster_id: &ClusterId,
	era: EhdEra,
	served_cluster: &[u8],
	served_era: EhdEra,
) -> Result<(), ApiError> {
	if served_cluster != cluster_id.as_bytes() || served_era != era {
		log!(
			error,
			"❌ Shared memory served cluster 0x{} era {}, asked for cluster {:?} era {}",
			hex::encode(served_cluster),
			served_era,
			cluster_id,
			era
		);
		return Err(ApiError::AnotherEraOrCluster { cluster_id: *cluster_id, era });
	}
	Ok(())
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
	discovery_timeout: Duration,
) -> Result<Vec<(NodePubKey, StorageNodeParams)>, ApiError> {
	let mut g_collectors = Vec::new();

	let collectors = get_collectors_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)?;
	let mut g_collectors_keys = Vec::new();

	for (node_key, node_params) in collectors {
		if g_collectors_keys.is_empty() {
			if let Ok(keys) =
				get_grouping_collectors_keys(cluster_id, &node_key, &node_params, discovery_timeout)
			{
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
	discovery_timeout: Duration,
) -> Result<(NodePubKey, StorageNodeParams), ApiError> {
	let g_collectors = get_g_collectors_nodes::<AccountId, BlockNumber, CM, NM>(
		cluster_id,
		discovery_timeout,
	)
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
	timeout: Duration,
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
	let client = DdcClient::new(node_key.clone(), &base_url, timeout, MAX_RETRIES_COUNT);

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
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
			node_key: collector_key.clone(),
			host: collector_params.host.clone(),
		}
	})?;

	let base_url = format!("http://{}:{}", host, collector_params.http_port);
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
	let client = DdcClient::new(
		node_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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
	>(cluster_id, Duration::from_millis(RESPONSE_TIMEOUT))
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
	let client = DdcClient::new(
		g_collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

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

/// Fetch the era's sealed EHD envelope from the G-Collector, as the bytes it
/// signed, together with the key of the G-Collector that was asked.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `era`: EHD era
pub fn get_sealed_ehd<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
) -> Result<(NodePubKey, ApiResponse<Vec<u8>>), ApiError> {
	let (g_collector_key, g_collector_params) =
		get_g_collector_node::<AccountId, BlockNumber, CM, NM>(
			cluster_id,
			Duration::from_millis(RESPONSE_TIMEOUT),
		)?;
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
	let client = DdcClient::new(
		g_collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

	let sealed_ehd = client.get_sealed_ehd(era).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch sealed EHD for era {:?} from G-Collector {:?} in cluster {:?}: {:?}",
			era,
			g_collector_key,
			cluster_id,
			e
		);
		ApiError::FailedToFetchSealedEHD { cluster_id: *cluster_id, era }
	})?;

	Ok((g_collector_key, sealed_ehd))
}

/// Fetch a collector's sealed PHD envelope of the era, as the bytes it signed.
///
/// Parameters:
/// - `cluster_id`: Cluster Id
/// - `era`: EHD era
/// - `collector_key`: Collector node key
pub fn get_sealed_phd<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	era: EhdEra,
	collector_key: NodePubKey,
) -> Result<ApiResponse<Vec<u8>>, ApiError> {
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
	let client = DdcClient::new(
		collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);

	client.get_sealed_phd(era).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch sealed PHD for era {:?} from collector {:?} in cluster {:?}: {:?}",
			era,
			collector_key,
			cluster_id,
			e
		);
		ApiError::FailedToFetchSealedPHD { cluster_id: *cluster_id, era, node_key: collector_key }
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
	let (g_collector_key, g_collector_params) = get_g_collector_node::<
		AccountId,
		BlockNumber,
		CM,
		NM,
	>(cluster_id, Duration::from_millis(RESPONSE_TIMEOUT))
	.map_err(|e| {
		log!(error, "❌ Failed to fetch G-Collector node for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
	})?;
	fetch_processed_eras(&g_collector_key, &g_collector_params, cursor, limit).map_err(|e| {
		log!(error, "❌ Failed to fetch processed eras for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchProcessedEras { cluster_id: *cluster_id }
	})
}

/// Fetch processed payment eras from global collector via /activity/processed-eras.
pub fn fetch_processed_eras(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for processed eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client = DdcClient::new(
		node_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);
	Ok(client.processed_eras(cursor, limit)?.response)
}

/// Fetch inspected EHD eras of a cluster from its G-Collector. `discovery_timeout` bounds
/// only the grouping-collectors request that resolves the G-Collector; the eras request
/// keeps `RESPONSE_TIMEOUT`.
pub fn fetch_inspected_eras_for_cluster<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
	discovery_timeout: Duration,
) -> Result<proto::activity::GetErasResponse, ApiError> {
	let (g_collector_key, g_collector_params) = get_g_collector_node::<
		AccountId,
		BlockNumber,
		CM,
		NM,
	>(cluster_id, discovery_timeout)
	.map_err(|e| {
		log!(error, "❌ Failed to fetch G-Collector node for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
	})?;
	fetch_inspected_eras(&g_collector_key, &g_collector_params, cursor, limit).map_err(|e| {
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
		Duration::from_millis(RESPONSE_TIMEOUT),
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

/// Statuses of an era that inspection is done with. The newest such era is the
/// anchor the inspection cursor moves forward from.
const INSPECTED_ERA_STATUSES: [proto::era::EraStatus; 2] =
	[proto::era::EraStatus::EraInspected, proto::era::EraStatus::EraPaid];

/// Statuses of the first non-empty era above the anchor: inspected when
/// processed, waited for while still in progress. An empty era is stepped over.
/// Leaving out in-progress would step over an era still being finalized, which
/// would then fall below the anchor and never be inspected.
const NEXT_ERA_STATUSES: [proto::era::EraStatus; 2] =
	[proto::era::EraStatus::EraProcessed, proto::era::EraStatus::EraInProgress];

/// Records asked for when reading the anchor. One would do, but two returned
/// newest first prove the node applied the filter and the order, where a node
/// that ignores them lists the oldest eras first.
const ANCHOR_PROBE_LIMIT: u32 = 2;

/// Records asked for when reading the era after the anchor.
const NEXT_ERA_LIMIT: u32 = 1;

/// The era to inspect next: the first era above the newest ERA_INSPECTED or
/// ERA_PAID one that is not ERA_EMPTY, if it is ERA_PROCESSED. None while that
/// era is still ERA_IN_PROGRESS or there is none. With no inspected era yet it
/// is the oldest such era. Eras below the anchor are never reached.
pub fn next_era_to_inspect(client: &DdcClient) -> Result<Option<EhdEra>, http::Error> {
	let list = |cursor: Option<&[u8]>,
	            limit: u32,
	            statuses: &[proto::era::EraStatus],
	            newest_first: bool| {
		client
			.eras_with_status(cursor, Some(limit), statuses, newest_first)
			.map(|r| r.response.records)
	};

	let anchors = list(None, ANCHOR_PROBE_LIMIT, &INSPECTED_ERA_STATUSES, true)?;
	let filtered = anchors.iter().all(|era| has_status(era, &INSPECTED_ERA_STATUSES)) &&
		anchors.windows(2).all(|pair| pair[0].id > pair[1].id);
	if !filtered {
		log!(error, "❌ Era listing ignored the status filter or order; the node predates them");
		return Err(http::Error::Unknown);
	}
	let anchor = anchors.first().map(|era| era.id);

	let cursor = anchor.map(|id| id.to_be_bytes().to_vec());
	let next = list(cursor.as_deref(), NEXT_ERA_LIMIT, &NEXT_ERA_STATUSES, false)?;
	let Some(era) = next.first() else {
		return Ok(None);
	};
	if !has_status(era, &NEXT_ERA_STATUSES) || anchor.is_some_and(|id| era.id <= id) {
		log!(error, "❌ Era listing ignored the status filter or cursor; the node predates them");
		return Err(http::Error::Unknown);
	}
	Ok((era.status == proto::era::EraStatus::EraProcessed as i32).then_some(era.id))
}

fn has_status(era: &proto::era::Era, statuses: &[proto::era::EraStatus]) -> bool {
	statuses.iter().any(|status| era.status == *status as i32)
}

/// The era a cluster should inspect next, read from its G-Collector. See
/// `next_era_to_inspect`. `discovery_timeout` bounds only the grouping-collectors request
/// that resolves the G-Collector; the era listing keeps `RESPONSE_TIMEOUT`.
pub fn fetch_era_to_inspect_for_cluster<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	discovery_timeout: Duration,
) -> Result<Option<EhdEra>, ApiError> {
	let (g_collector_key, params) =
		get_g_collector_node::<AccountId, BlockNumber, CM, NM>(cluster_id, discovery_timeout)
		.map_err(|e| {
			log!(error, "❌ Failed to fetch G-Collector node for cluster {:?}: {:?}", cluster_id, e);
			ApiError::FailedToFetchGCollectors { cluster_id: *cluster_id }
		})?;
	let host = str::from_utf8(&params.host).map_err(|e| {
		log!(error, "❌ Failed to parse era-list node host for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchProcessedEras { cluster_id: *cluster_id }
	})?;
	let base_url = format!("http://{}:{}", host, params.http_port);
	let client = DdcClient::new(
		g_collector_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);
	next_era_to_inspect(&client).map_err(|e| {
		log!(error, "❌ Failed to read the era to inspect for cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchProcessedEras { cluster_id: *cluster_id }
	})
}

/// Fetch inspected EHD eras from a node via /activity/inspected-eras.
#[allow(dead_code)]
pub fn fetch_inspected_eras(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for inspected eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client = DdcClient::new(
		node_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);
	Ok(client.inspected_eras(cursor, limit)?.response)
}

/// Fetch a single page of `/activity/tcas`. `cursor` is the opaque token
/// returned from the previous page (`None` for the first page). `limit`
/// caps the number of records; the server also enforces its own max.
pub fn fetch_tcas_page(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetTcasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for TCAs: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client = DdcClient::new(
		node_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);
	let api_response = client.tcas(cursor, limit)?;
	Ok(api_response.response)
}

/// Walks `/activity/tcas` page by page until `next_cursor` is absent.
/// Concatenates all records into a single Vec. Intended for callers that
/// genuinely need a full enumeration; prefer fetch_tcas_page where the
/// caller can persist a cursor across calls.
pub fn fetch_tcas_all(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	page_limit: Option<u32>,
) -> Result<Vec<proto::era::Tca>, http::Error> {
	let mut out: Vec<proto::era::Tca> = Vec::new();
	let mut cursor: Option<Vec<u8>> = None;
	loop {
		let page = fetch_tcas_page(node_key, node_params, cursor.as_deref(), page_limit)?;
		out.extend(page.records.into_iter());
		match page.next_cursor {
			Some(c) if !c.is_empty() => cursor = Some(c),
			_ => return Ok(out),
		}
	}
}

/// Same as fetch_tcas_page for `/activity/eras`.
pub fn fetch_eras_page(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
) -> Result<proto::activity::GetErasResponse, http::Error> {
	let host = str::from_utf8(&node_params.host).map_err(|e| {
		log!(error, "❌ Failed to parse node host for eras: {:?}", e);
		http::Error::Unknown
	})?;
	let base_url = format!("http://{}:{}", host, node_params.http_port);
	let client = DdcClient::new(
		node_key.clone(),
		&base_url,
		Duration::from_millis(RESPONSE_TIMEOUT),
		MAX_RETRIES_COUNT,
	);
	let api_response = client.eras(cursor, limit)?;
	Ok(api_response.response)
}

/// Walks `/activity/eras` page by page until `next_cursor` is absent.
pub fn fetch_eras_all(
	node_key: &NodePubKey,
	node_params: &StorageNodeParams,
	page_limit: Option<u32>,
) -> Result<Vec<proto::era::Era>, http::Error> {
	let mut out: Vec<proto::era::Era> = Vec::new();
	let mut cursor: Option<Vec<u8>> = None;
	loop {
		let page = fetch_eras_page(node_key, node_params, cursor.as_deref(), page_limit)?;
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
/// asked again in the same tick.
fn with_shared_memory<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
	R,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	operation: &str,
	mut call: impl FnMut(&DdcClient) -> Result<R, http::Error>,
) -> Result<R, ApiError> {
	let nodes = crate::shared_memory::discovered_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(
		cluster_id, signer,
	)?;
	if let Ok(result) = try_shared_memory_replicas(cluster_id, operation, &nodes, &mut call) {
		return Ok(result);
	}

	log!(warn, "No cached shared-memory replica of cluster {:?} answered; discovering again", cluster_id);
	let nodes =
		crate::shared_memory::rediscover_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id, signer)?;
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
					"❌ Failed to parse shared-memory node host for node {:?} in cluster {:?}: {:?}",
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
		let client = DdcClient::new(
			node.key.clone(),
			&base_url,
			Duration::from_millis(RESPONSE_TIMEOUT),
			MAX_RETRIES_COUNT,
		);

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
	signer: &ReadSigner,
	request: &proto::inspection::LeaseRequest,
) -> Result<proto::inspection::LeaseResult, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, signer, "post ITM lease", |client| {
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
	signer: &ReadSigner,
	request: &proto::inspection::PostAssignmentTableRequest,
) -> Result<proto::inspection::PostAssignmentTableResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		signer,
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
	signer: &ReadSigner,
	era: EhdEra,
) -> Result<proto::inspection::GetAssignmentTableResponse, ApiError> {
	let response = with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		signer,
		"get assignments table",
		|client| client.get_assignments_table(era, signer),
	)?;
	if response.status == proto::inspection::GetAssignmentTableStatus::Found as i32 {
		let table = response.table.as_ref();
		require_era_and_cluster(
			cluster_id,
			era,
			table.map(|t| t.cluster_id.as_slice()).unwrap_or_default(),
			table.map(|t| t.era).unwrap_or_default(),
		)?;
	}
	Ok(response)
}

pub fn post_era_nudge<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	request: &proto::inspection::PostEraNudgeRequest,
) -> Result<proto::inspection::PostEraNudgeResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, signer, "post era nudge", |client| {
		client.post_era_nudge(request)
	})
}

pub fn post_seed_contribution<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	request: &proto::inspection::PostSeedContributionRequest,
) -> Result<proto::inspection::PostSeedContributionResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		signer,
		"post seed contribution",
		|client| client.post_seed_contribution(request),
	)
}

pub fn submit_inspection_result<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	request: &proto::inspection::PostInspectionResultRequest,
) -> Result<proto::inspection::PostInspectionResultResponse, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		signer,
		"submit inspection result",
		|client| client.submit_inspection_result(request),
	)
}

/// Writes inspection results to the inspectors' shared memory, then reads them
/// back through a different replica to confirm they were committed
/// (ADR-006 §6).
///
/// The shared memory's reads are linearizable, so a path missing this
/// inspector's key when read back elsewhere was not committed: it is written
/// again through the reader and the first replica is dropped from the cached
/// list. A replica that turns out not to hold the shared memory proves the
/// list false and drops it. A replica that cannot answer is no evidence either
/// way and the next one reads back.
pub fn submit_inspection_result_read_back<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	request: &proto::inspection::PostInspectionResultRequest,
) -> Result<proto::inspection::PostInspectionResultResponse, ApiError> {
	let nodes = crate::shared_memory::discovered_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(
		cluster_id, signer,
	)?;
	let mut submit = |client: &DdcClient| client.submit_inspection_result(request);

	let mut submitted = None;
	for (index, node) in nodes.iter().enumerate() {
		if let Ok(response) =
			try_shared_memory_replicas(cluster_id, "submit inspection result", core::slice::from_ref(node), &mut submit)
		{
			submitted = Some((index, response));
			break;
		}
	}
	let Some((submitter_index, response)) = submitted else {
		return submit_inspection_result::<AccountId, BlockNumber, CM, NM>(cluster_id, signer, request);
	};
	let submitter = &nodes[submitter_index];

	let rejected: Vec<&Vec<u8>> = response.rejected_paths.iter().map(|p| &p.path_hash).collect();
	let expected: Vec<Vec<u8>> = request
		.paths_results
		.iter()
		.map(|result| result.path_hash.clone())
		.filter(|path_hash| !rejected.contains(&path_hash))
		.collect();

	for reader in nodes.iter().filter(|node| node.key != submitter.key) {
		let Ok(host) = str::from_utf8(&reader.params.host) else {
			continue;
		};
		let base_url = format!("http://{}:{}", host, reader.params.http_port);
		let client = DdcClient::new(
			reader.key.clone(),
			&base_url,
			Duration::from_millis(RESPONSE_TIMEOUT),
			MAX_RETRIES_COUNT,
		);

		match client.read_back_inspection_state(request.era_id, signer) {
			Ok(state) => {
				let missing =
					crate::shared_memory::uncommitted_paths(&state, &request.inspector_key, &expected);
				if missing.is_empty() {
					return Ok(response);
				}
				log!(
					error,
					"❌ Shared-memory replica {:?} of cluster {:?} accepted {} inspection results for era {:?} that do not read back through {:?}; writing them again there. At fault: {:?}; reader of record: {:?}",
					submitter.key,
					cluster_id,
					missing.len(),
					request.era_id,
					reader.key,
					submitter.key,
					reader.key
				);
				crate::shared_memory::forget_cached_shared_memory_node(cluster_id, &submitter.key);
				return try_shared_memory_replicas(
					cluster_id,
					"resubmit inspection result",
					core::slice::from_ref(reader),
					&mut submit,
				);
			},
			Err(ReadBackError::NotSharedMemory) => {
				log!(
					error,
					"❌ Node {:?} was named as a shared-memory replica of cluster {:?} but does not hold it; the cached list is false and is dropped",
					reader.key,
					cluster_id
				);
				crate::shared_memory::forget_cached_shared_memory_nodes(cluster_id);
			},
			Err(ReadBackError::SignedByAnotherNode) => {
				log!(
					error,
					"❌ The read-back of era {:?} through shared-memory replica {:?} of cluster {:?} is signed by another node (logged with the response); the cached list is false and is dropped",
					request.era_id,
					reader.key,
					cluster_id
				);
				crate::shared_memory::forget_cached_shared_memory_nodes(cluster_id);
			},
			Err(ReadBackError::Unavailable) => {
				log!(
					warn,
					"Shared-memory replica {:?} of cluster {:?} could not read back era {:?}; trying the next one",
					reader.key,
					cluster_id,
					request.era_id
				);
			},
		}
	}

	log!(
		warn,
		"Inspection results for era {:?} of cluster {:?} were accepted by {:?} but no other replica read them back",
		request.era_id,
		cluster_id,
		submitter.key
	);
	Ok(response)
}

pub fn get_inspection_state<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	era: EhdEra,
) -> Result<proto::inspection::InspectionState, ApiError> {
	let state = with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(
		cluster_id,
		signer,
		"get inspection state",
		|client| client.get_inspection_state(era, signer),
	)?;
	require_era_and_cluster(cluster_id, era, &state.cluster_id, state.era_id)?;
	Ok(state)
}

pub fn get_inspection_receipt<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	era: EhdEra,
) -> Result<(proto::inspection::InspectionReceipt, Vec<u8>), ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, signer, "get inspection receipt", |client| {
		client.get_inspection_receipt(era, signer)
	})
	.map_err(|e| match e {
		ApiError::HttpClientError { .. } => {
			ApiError::FailedToFetchInspSummary { cluster_id: *cluster_id, era }
		},
		other => other,
	})
	.and_then(|(receipt, bytes)| {
		require_era_and_cluster(cluster_id, era, &receipt.cluster_id, receipt.era_id)?;
		Ok((receipt, bytes))
	})
}

pub fn get_quorum_info<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
	signer: &ReadSigner,
	era: EhdEra,
) -> Result<proto::inspection::InspSyncQuorumInfo, ApiError> {
	with_shared_memory::<AccountId, BlockNumber, CM, NM, _>(cluster_id, signer, "get quorum info", |client| {
		client.get_quorum_info(era, signer)
	})
}

#[cfg(test)]
mod tests {
	use ddc_primitives::{
		traits::ClusterQuery, ClusterNodeKind, ClusterNodeState, ClusterNodeStatus,
		ClusterNodesStats, ClusterStatus, StorageNodePubKey,
	};
	use polkadot_sdk::sp_core::{
		ed25519,
		offchain::{
			testing::{PendingRequest, TestOffchainExt},
			Externalities, HttpError, HttpRequestId, HttpRequestStatus, OffchainDbExt,
			OffchainWorkerExt, Timestamp,
		},
		Pair,
	};
	use polkadot_sdk::sp_core::crypto::KeyTypeId;
	use polkadot_sdk::sp_io::TestExternalities;
	use polkadot_sdk::sp_keystore::{testing::MemoryKeystore, KeystoreExt};
	use polkadot_sdk::sp_runtime::DispatchError;
	use prost::Message;
	use std::sync::Arc;

	use super::*;
	use crate::proto::{
		activity::GroupingCollectorsResponse,
		activity_tree::{Ehd, Phd, SealedEhd, SealedPhd},
		inspection::{
			InspSyncQuorumInfo, InspSyncQuorumMember, InspectionPathResult, InspectionPathStatus,
			AssignmentTable, GetAssignmentTableResponse, GetAssignmentTableStatus, InspectionReceipt,
			InspectionState, PostInspectionResultRequest,
			PostInspectionResultResponse,
		},
		signature::{signature::Algorithm, Signature, SignedResponse},
	};

	type AccountId = u64;
	type BlockNumber = u64;

	/// The node at HOST_A signs with this seed's key, and is registered under it.
	const SEED_A: [u8; 32] = [0x22; 32];
	/// The node at HOST_B signs with this seed's key, and is registered under it.
	const SEED_B: [u8; 32] = [0x11; 32];
	const HOST_A: &str = "node-a";
	const HOST_B: &str = "node-b";
	const TEST_HTTP_PORT: u16 = 8080;
	const TEST_ERA: EhdEra = 7;
	const INSPECTOR: &[u8] = b"inspector-key";
	const READ_KEY_TYPE: KeyTypeId = KeyTypeId(*b"insp");
	const PATH_HASH: [u8; 2] = [0x01, 0x02];
	/// Field 99, varint 1: a field this build's InspectionReceipt does not know.
	const UNKNOWN_RECEIPT_FIELD: [u8; 3] = [0x98, 0x06, 0x01];
	/// Field 99, varint 1: a field this build's Ehd does not know.
	const UNKNOWN_DOCUMENT_FIELD: [u8; 3] = [0x98, 0x06, 0x01];

	fn key_a() -> [u8; 32] {
		ed25519::Pair::from_seed(&SEED_A).public().0
	}

	fn key_b() -> [u8; 32] {
		ed25519::Pair::from_seed(&SEED_B).public().0
	}

	fn this_cluster_state() -> InspectionState {
		InspectionState {
			cluster_id: ClusterId::zero().as_bytes().to_vec(),
			era_id: TEST_ERA,
			..Default::default()
		}
	}

	fn node_params(host: &str) -> StorageNodeParams {
		StorageNodeParams {
			mode: StorageNodeMode::Storage,
			host: host.as_bytes().to_vec(),
			http_port: TEST_HTTP_PORT,
			..Default::default()
		}
	}

	#[test]
	fn a_shared_memory_answer_signed_by_another_node_is_refused_and_the_next_replica_answers() {
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(get(HOST_A, "/itm/v1/state/7", signed_by(SEED_B, &this_cluster_state())));
		requests.push(get(HOST_B, "/itm/v1/state/7", signed_by(SEED_B, &this_cluster_state())));
		run_with(requests, || {
			let state = get_inspection_state::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				&signer(),
				TEST_ERA,
			);
			assert_eq!(state, Ok(this_cluster_state()));
		});
	}

	#[test]
	fn an_activity_answer_signed_by_another_node_is_refused_as_a_failed_fetch() {
		let grouping =
			GroupingCollectorsResponse { keys: vec![format!("0x{}", hex::encode(key_b()))] };
		let requests =
			vec![get(HOST_A, "/activity/v1/grouping-collectors", signed_by(SEED_B, &grouping))];
		run_with(requests, || {
			assert_eq!(
				get_grouping_collectors_keys(
					&ClusterId::zero(),
					&node_key(key_a()),
					&node_params(HOST_A),
					Duration::from_millis(RESPONSE_TIMEOUT)
				),
				Err(ApiError::HttpClientError {
					cluster_id: ClusterId::zero(),
					host: HOST_A.as_bytes().to_vec()
				})
			);
		});
	}

	#[test]
	fn a_sealed_phd_whose_envelope_another_node_signed_is_refused() {
		let requests = vec![get(
			HOST_B,
			"/activity/v1/phds/7",
			signed_payload_by(SEED_A, SealedPhd::default().encode_to_vec()),
		)];
		run_with(requests, || {
			let fetched = get_sealed_phd::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				TEST_ERA,
				node_key(key_b()),
			);
			assert!(fetched.is_err(), "{:?}", fetched.map(|r| r.response));
		});
	}

	#[test]
	fn a_forwarded_quorum_answer_signed_by_a_member_it_names_is_accepted() {
		let members = InspSyncQuorumInfo {
			quorum_members: vec![member(key_a()), member(key_b())],
			..Default::default()
		};
		let mut requests = Vec::new();
		requests.push(get(HOST_A, "/itm/v1/quorum/0", signed_by(SEED_B, &members)));
		requests.push(get(HOST_A, "/itm/v1/quorum/7", signed_by(SEED_B, &members)));
		run_with(requests, || {
			let quorum = get_quorum_info::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				&signer(),
				TEST_ERA,
			);
			assert_eq!(quorum, Ok(members.clone()));
		});
	}

	#[test]
	fn a_quorum_answer_signed_by_a_node_it_does_not_name_is_refused() {
		let members =
			InspSyncQuorumInfo { quorum_members: vec![member(key_b())], ..Default::default() };
		let requests = vec![get(HOST_A, "/itm/v1/quorum/7", signed_by(SEED_A, &members))];
		run_with(requests, || {
			let client = DdcClient::new(
				node_key(key_a()),
				"http://node-a:8080",
				Duration::from_millis(RESPONSE_TIMEOUT),
				MAX_RETRIES_COUNT,
			);
			assert!(client.get_quorum_info(TEST_ERA, &signer()).is_err());
		});
	}

	#[test]
	fn a_read_back_signed_by_the_submitter_is_refused_and_drops_the_cached_list() {
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(post(
			HOST_A,
			"/itm/v1/path",
			request().encode_to_vec(),
			signed_by(SEED_A, &accepted()),
		));
		requests.push(get(
			HOST_B,
			"/itm/v1/state/7",
			signed_by(SEED_A, &state_listing(vec![INSPECTOR.to_vec()])),
		));
		expect_discovery(&mut requests);
		run_with(requests, || {
			submit_inspection_result_read_back::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				&signer(),
				&request(),
			)
			.unwrap();
			crate::shared_memory::discovered_shared_memory_nodes::<
				AccountId,
				BlockNumber,
				MockCluster,
				MockNodes,
			>(&ClusterId::zero(), &signer())
			.unwrap();
		});
	}

	#[test]
	fn the_read_back_tells_a_signer_mismatch_from_an_unreadable_answer() {
		let requests =
			vec![get(HOST_B, "/itm/v1/state/7", signed_by(SEED_A, &state_listing(vec![])))];
		run_with(requests, || {
			let client = DdcClient::new(
				node_key(key_b()),
				"http://node-b:8080",
				Duration::from_millis(RESPONSE_TIMEOUT),
				MAX_RETRIES_COUNT,
			);
			assert_eq!(
				client.read_back_inspection_state(TEST_ERA, &signer()),
				Err(crate::client::ReadBackError::SignedByAnotherNode)
			);
		});
	}

	#[test]
	fn the_fixture_nodes_are_in_key_order() {
		assert!(key_a() < key_b(), "discovery and the replica order ask HOST_A first");
	}

	fn node_key(bytes: [u8; 32]) -> NodePubKey {
		NodePubKey::StoragePubKey(StorageNodePubKey::new(bytes))
	}

	struct MockCluster;

	impl ClusterQuery<AccountId> for MockCluster {
		fn cluster_exists(_: &ClusterId) -> bool {
			unimplemented!()
		}
		fn get_cluster_status(_: &ClusterId) -> Result<ClusterStatus, DispatchError> {
			unimplemented!()
		}
		fn get_manager_and_reserve_id(
			_: &ClusterId,
		) -> Result<(AccountId, AccountId), DispatchError> {
			unimplemented!()
		}
	}

	impl ClusterManager<AccountId, BlockNumber> for MockCluster {
		fn get_manager_account_id(_: &ClusterId) -> Result<AccountId, DispatchError> {
			unimplemented!()
		}
		fn contains_node(_: &ClusterId, _: &NodePubKey, _: Option<ClusterNodeStatus>) -> bool {
			unimplemented!()
		}
		fn get_nodes(_: &ClusterId) -> Result<Vec<NodePubKey>, DispatchError> {
			Ok(vec![node_key(key_a()), node_key(key_b())])
		}
		fn add_node(
			_: &ClusterId,
			_: &NodePubKey,
			_: &ClusterNodeKind,
		) -> Result<(), DispatchError> {
			unimplemented!()
		}
		fn remove_node(_: &ClusterId, _: &NodePubKey) -> Result<(), DispatchError> {
			unimplemented!()
		}
		fn get_node_state(
			_: &ClusterId,
			_: &NodePubKey,
		) -> Result<ClusterNodeState<BlockNumber>, DispatchError> {
			Ok(ClusterNodeState {
				kind: ClusterNodeKind::External,
				status: ClusterNodeStatus::ValidationSucceeded,
				added_at: 0,
			})
		}
		fn get_nodes_stats(_: &ClusterId) -> Result<ClusterNodesStats, DispatchError> {
			unimplemented!()
		}
		fn get_clusters(_: ClusterStatus) -> Result<Vec<ClusterId>, DispatchError> {
			unimplemented!()
		}
	}

	struct MockNodes;

	impl NodeManager<AccountId> for MockNodes {
		fn get_cluster_id(_: &NodePubKey) -> Result<Option<ClusterId>, DispatchError> {
			unimplemented!()
		}
		fn exists(_: &NodePubKey) -> bool {
			unimplemented!()
		}
		fn get_node_provider_id(_: &NodePubKey) -> Result<AccountId, DispatchError> {
			unimplemented!()
		}
		fn get_node_params(key: &NodePubKey) -> Result<NodeParams, DispatchError> {
			let host = if *key == node_key(key_a()) { HOST_A } else { HOST_B };
			Ok(NodeParams::StorageParams(StorageNodeParams {
				mode: StorageNodeMode::Storage,
				host: host.as_bytes().to_vec(),
				http_port: TEST_HTTP_PORT,
				..Default::default()
			}))
		}
	}

	fn signed_by<M: Message>(seed: [u8; 32], message: &M) -> Vec<u8> {
		signed_payload_by(seed, message.encode_to_vec())
	}

	fn signed_payload_by(seed: [u8; 32], payload: Vec<u8>) -> Vec<u8> {
		let pair = ed25519::Pair::from_seed(&seed);
		let value = pair.sign(&payload).0.to_vec();
		SignedResponse {
			payload,
			signature: Some(Signature {
				algorithm: Algorithm::Ed25519 as i32,
				value,
				signer: pair.public().0.to_vec(),
			}),
		}
		.encode_to_vec()
	}

	fn get(host: &str, path: &str, response: Vec<u8>) -> PendingRequest {
		PendingRequest {
			method: "GET".into(),
			uri: format!("http://{}:{}{}", host, TEST_HTTP_PORT, path),
			headers: vec![("Accept".into(), "application/protobuf".into())],
			response: Some(response),
			sent: true,
			..Default::default()
		}
	}

	fn post(host: &str, path: &str, body: Vec<u8>, response: Vec<u8>) -> PendingRequest {
		PendingRequest {
			method: "POST".into(),
			uri: format!("http://{}:{}{}", host, TEST_HTTP_PORT, path),
			headers: vec![
				("content-type".into(), "application/protobuf".into()),
				("Accept".into(), "application/protobuf".into()),
			],
			body,
			response: Some(response),
			sent: true,
			..Default::default()
		}
	}

	fn member(key: [u8; 32]) -> InspSyncQuorumMember {
		InspSyncQuorumMember {
			node_key: format!("0x{}", hex::encode(key)).into_bytes(),
			..Default::default()
		}
	}

	fn request() -> PostInspectionResultRequest {
		PostInspectionResultRequest {
			era_id: TEST_ERA,
			inspector_key: INSPECTOR.to_vec(),
			paths_results: vec![InspectionPathResult {
				path_hash: PATH_HASH.to_vec(),
				..Default::default()
			}],
			..Default::default()
		}
	}

	fn state_listing(inspectors: Vec<Vec<u8>>) -> InspectionState {
		let mut state = InspectionState { era_id: TEST_ERA, ..Default::default() };
		state.paths.insert(
			hex::encode(PATH_HASH),
			InspectionPathStatus { inspectors, ..Default::default() },
		);
		state
	}

	fn accepted() -> PostInspectionResultResponse {
		PostInspectionResultResponse { accepted_count: 1, ..Default::default() }
	}

	// Discovery asks the first candidate (A, lowest key) and both are named.
	fn expect_discovery(requests: &mut Vec<PendingRequest>) {
		let members = InspSyncQuorumInfo {
			quorum_members: vec![member(key_a()), member(key_b())],
			..Default::default()
		};
		requests.push(get(HOST_A, "/itm/v1/quorum/0", signed_by(SEED_A, &members)));
	}

	// The keystore holds no key for it, so its reads go unsigned, as a node in
	// counting mode serves them.
	fn signer() -> ReadSigner {
		ReadSigner { cluster_id: ClusterId::zero(), key_type: READ_KEY_TYPE, key: [0x77; 32], block: 0 }
	}

	fn run_with(requests: Vec<PendingRequest>, test: impl FnOnce()) {
		let (offchain, state) = TestOffchainExt::new();
		for request in requests {
			state.write().expect_request(request);
		}
		let mut ext = TestExternalities::default();
		ext.register_extension(OffchainDbExt::new(offchain.clone()));
		ext.register_extension(OffchainWorkerExt::new(offchain));
		ext.register_extension(KeystoreExt(Arc::new(MemoryKeystore::new())));
		ext.execute_with(test);
	}

	#[test]
	fn a_receipt_comes_back_with_the_bytes_the_node_sent_including_fields_this_build_does_not_know(
	) {
		let receipt = InspectionReceipt {
			cluster_id: ClusterId::zero().as_bytes().to_vec(),
			era_id: TEST_ERA,
			..Default::default()
		};
		let mut sent = receipt.encode_to_vec();
		sent.extend_from_slice(&UNKNOWN_RECEIPT_FIELD);
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(get(HOST_A, "/itm/v1/receipt/7", signed_payload_by(SEED_A, sent.clone())));

		run_with(requests, || {
			let (decoded, bytes) =
				get_inspection_receipt::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					&signer(),
					TEST_ERA,
				)
				.unwrap();
			assert_eq!(decoded, receipt);
			assert_eq!(bytes, sent);
			assert_ne!(decoded.encode_to_vec(), sent);
		});
	}

	fn fetch_receipt_naming(cluster: Vec<u8>, era: EhdEra) -> Result<(), ApiError> {
		let receipt = InspectionReceipt { cluster_id: cluster, era_id: era, ..Default::default() };
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(get(HOST_A, "/itm/v1/receipt/7", signed_by(SEED_A, &receipt)));
		let mut result = None;
		run_with(requests, || {
			result = Some(
				get_inspection_receipt::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					&signer(),
					TEST_ERA,
				)
				.map(|_| ()),
			);
		});
		result.unwrap()
	}

	#[test]
	fn a_receipt_naming_another_cluster_or_era_is_refused() {
		let asked = ClusterId::zero().as_bytes().to_vec();
		assert_eq!(fetch_receipt_naming(asked.clone(), TEST_ERA), Ok(()));
		let refused = Err(ApiError::AnotherEraOrCluster {
			cluster_id: ClusterId::zero(),
			era: TEST_ERA,
		});
		assert_eq!(fetch_receipt_naming(vec![1; 20], TEST_ERA), refused);
		assert_eq!(fetch_receipt_naming(asked, TEST_ERA + 1), refused);
	}

	#[test]
	fn a_state_naming_another_cluster_is_refused() {
		let state = InspectionState { cluster_id: vec![1; 20], era_id: TEST_ERA, ..Default::default() };
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(get(HOST_A, "/itm/v1/state/7", signed_by(SEED_A, &state)));
		run_with(requests, || {
			assert_eq!(
				get_inspection_state::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					&signer(),
					TEST_ERA,
				),
				Err(ApiError::AnotherEraOrCluster {
					cluster_id: ClusterId::zero(),
					era: TEST_ERA,
				})
			);
		});
	}

	#[test]
	fn a_found_table_naming_another_era_is_refused_and_a_missing_one_is_not_checked() {
		let found = GetAssignmentTableResponse {
			status: GetAssignmentTableStatus::Found as i32,
			era_id: TEST_ERA,
			table: Some(AssignmentTable {
				cluster_id: ClusterId::zero().as_bytes().to_vec(),
				era: TEST_ERA + 1,
				..Default::default()
			}),
			..Default::default()
		};
		let missing = GetAssignmentTableResponse {
			status: GetAssignmentTableStatus::NotFound as i32,
			era_id: TEST_ERA,
			..Default::default()
		};
		for (response, refused) in [(found, true), (missing, false)] {
			let mut requests = Vec::new();
			expect_discovery(&mut requests);
			requests.push(get(HOST_A, "/itm/v1/table/7", signed_by(SEED_A, &response)));
			run_with(requests, || {
				let result = get_assignments_table::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					&signer(),
					TEST_ERA,
				);
				assert_eq!(result.is_err(), refused, "{:?}", result);
			});
		}
	}

	#[test]
	fn a_sealed_ehd_comes_from_the_g_collector_as_the_envelope_bytes_it_signed_including_fields_this_build_does_not_know(
	) {
		let document = Ehd { era_id: TEST_ERA, ..Default::default() };
		let mut sealed_document = document.encode_to_vec();
		sealed_document.extend_from_slice(&UNKNOWN_DOCUMENT_FIELD);
		let sealed = SealedEhd {
			document: sealed_document.clone(),
			builder_signature: Some(Signature {
				algorithm: Algorithm::Ed25519 as i32,
				signer: key_b().to_vec(),
				value: vec![0x5a; 64],
			}),
		};
		let grouping = GroupingCollectorsResponse {
			keys: vec![format!("0x{}", hex::encode(key_b()))],
		};
		let mut envelope = sealed.encode_to_vec();
		envelope.extend_from_slice(&UNKNOWN_DOCUMENT_FIELD);
		let requests = vec![
			get(HOST_A, "/activity/v1/grouping-collectors", signed_by(SEED_A, &grouping)),
			get(HOST_B, "/activity/v1/ehds/7", signed_payload_by(SEED_B, envelope.clone())),
		];

		run_with(requests, || {
			let (asked, fetched) =
				get_sealed_ehd::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					TEST_ERA,
				)
				.unwrap();
			assert_eq!(asked, node_key(key_b()));
			assert_eq!(fetched.response, envelope);
			let decoded = SealedEhd::decode(fetched.response.as_slice()).unwrap();
			assert_eq!(decoded, sealed);
			assert_ne!(decoded.encode_to_vec(), fetched.response);
			assert_eq!(decoded.document, sealed_document);
		});
	}

	#[test]
	fn a_sealed_phd_comes_from_the_collector_asked_as_the_envelope_bytes_it_signed_including_fields_this_build_does_not_know(
	) {
		let document = Phd { era_id: TEST_ERA, node_key: key_b().to_vec(), ..Default::default() };
		let mut sealed_document = document.encode_to_vec();
		sealed_document.extend_from_slice(&UNKNOWN_DOCUMENT_FIELD);
		let sealed = SealedPhd {
			document: sealed_document.clone(),
			builder_signature: Some(Signature {
				algorithm: Algorithm::Ed25519 as i32,
				signer: key_b().to_vec(),
				value: vec![0x5a; 64],
			}),
		};
		let mut envelope = sealed.encode_to_vec();
		envelope.extend_from_slice(&UNKNOWN_DOCUMENT_FIELD);
		let requests =
			vec![get(HOST_B, "/activity/v1/phds/7", signed_payload_by(SEED_B, envelope.clone()))];

		run_with(requests, || {
			let fetched = get_sealed_phd::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				TEST_ERA,
				node_key(key_b()),
			)
			.unwrap();
			assert_eq!(fetched.response, envelope);
			let decoded = SealedPhd::decode(fetched.response.as_slice()).unwrap();
			assert_eq!(decoded, sealed);
			assert_ne!(decoded.encode_to_vec(), fetched.response);
			assert_eq!(decoded.document, sealed_document);
		});
	}

	#[test]
	fn a_submission_another_replica_reads_back_is_not_resubmitted() {
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(post(
			HOST_A,
			"/itm/v1/path",
			request().encode_to_vec(),
			signed_by(SEED_A, &accepted()),
		));
		requests.push(get(
			HOST_B,
			"/itm/v1/state/7",
			signed_by(SEED_B, &state_listing(vec![INSPECTOR.to_vec()])),
		));

		run_with(requests, || {
			let response = submit_inspection_result_read_back::<
				AccountId,
				BlockNumber,
				MockCluster,
				MockNodes,
			>(&ClusterId::zero(), &signer(), &request())
			.unwrap();
			assert_eq!(response.accepted_count, 1);
		});
	}

	#[test]
	fn a_submission_missing_on_read_back_is_resubmitted_to_the_reader_and_the_first_replica_dropped(
	) {
		let mut requests = Vec::new();
		expect_discovery(&mut requests);
		requests.push(post(
			HOST_A,
			"/itm/v1/path",
			request().encode_to_vec(),
			signed_by(SEED_A, &accepted()),
		));
		requests.push(get(HOST_B, "/itm/v1/state/7", signed_by(SEED_B, &state_listing(vec![]))));
		requests.push(post(
			HOST_B,
			"/itm/v1/path",
			request().encode_to_vec(),
			signed_by(SEED_B, &accepted()),
		));

		run_with(requests, || {
			submit_inspection_result_read_back::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				&signer(),
				&request(),
			)
			.unwrap();

			let cached = crate::shared_memory::discovered_shared_memory_nodes::<
				AccountId,
				BlockNumber,
				MockCluster,
				MockNodes,
			>(&ClusterId::zero(), &signer())
			.unwrap();
			assert_eq!(
				cached.iter().map(|n| n.key.clone()).collect::<Vec<_>>(),
				vec![node_key(key_b())]
			);
		});
	}

	fn era(id: EhdEra, status: proto::era::EraStatus) -> proto::era::Era {
		proto::era::Era { id, status: status as i32, ..Default::default() }
	}

	fn eras(records: Vec<proto::era::Era>) -> Vec<u8> {
		signed_by(SEED_A, &proto::activity::GetErasResponse { records, ..Default::default() })
	}

	const ANCHOR_QUERY: &str =
		"/activity/v1/eras?limit=2&status=ERA_INSPECTED&status=ERA_PAID&order=desc";

	fn next_query(anchor: EhdEra) -> String {
		format!(
			"/activity/v1/eras?cursor={}&limit=1&status=ERA_PROCESSED&status=ERA_IN_PROGRESS",
			hex::encode(anchor.to_be_bytes())
		)
	}

	const HOST_A_URL: &str = "http://node-a:8080";

	fn host_a_key() -> NodePubKey {
		node_key(key_a())
	}

	fn client_for_host_a() -> DdcClient<'static> {
		DdcClient::new(
			host_a_key(),
			HOST_A_URL,
			Duration::from_millis(RESPONSE_TIMEOUT),
			MAX_RETRIES_COUNT,
		)
	}

	#[test]
	fn the_next_era_is_the_processed_one_right_above_the_newest_inspected_or_paid_era() {
		use proto::era::EraStatus::*;
		let requests = vec![
			get(HOST_A, ANCHOR_QUERY, eras(vec![era(6, EraPaid), era(4, EraInspected)])),
			get(HOST_A, &next_query(6), eras(vec![era(8, EraProcessed)])),
		];
		run_with(requests, || {
			assert_eq!(next_era_to_inspect(&client_for_host_a()), Ok(Some(8)));
		});
	}

	#[test]
	fn an_era_still_in_progress_right_above_the_anchor_is_waited_for() {
		use proto::era::EraStatus::*;
		let requests = vec![
			get(HOST_A, ANCHOR_QUERY, eras(vec![era(6, EraInspected)])),
			get(HOST_A, &next_query(6), eras(vec![era(7, EraInProgress)])),
		];
		run_with(requests, || {
			assert_eq!(next_era_to_inspect(&client_for_host_a()), Ok(None));
		});
	}

	#[test]
	fn without_an_inspected_era_the_oldest_processed_era_is_next() {
		use proto::era::EraStatus::*;
		let requests = vec![
			get(HOST_A, ANCHOR_QUERY, eras(vec![])),
			get(
				HOST_A,
				"/activity/v1/eras?limit=1&status=ERA_PROCESSED&status=ERA_IN_PROGRESS",
				eras(vec![era(3, EraProcessed)]),
			),
		];
		run_with(requests, || {
			assert_eq!(next_era_to_inspect(&client_for_host_a()), Ok(Some(3)));
		});
	}

	#[test]
	fn a_node_that_ignores_the_era_filter_is_an_error_not_an_era() {
		use proto::era::EraStatus::*;
		let requests = vec![get(
			HOST_A,
			ANCHOR_QUERY,
			eras(vec![era(1, EraInspected), era(2, EraInspected)]),
		)];
		run_with(requests, || {
			assert!(next_era_to_inspect(&client_for_host_a()).is_err());
		});
	}

	struct DeadlineRecorder {
		inner: TestOffchainExt,
		uris: std::collections::BTreeMap<u16, String>,
		awaited: Arc<std::sync::Mutex<Vec<(String, u64)>>>,
	}

	impl Externalities for DeadlineRecorder {
		fn is_validator(&self) -> bool {
			self.inner.is_validator()
		}
		fn network_state(
			&self,
		) -> Result<polkadot_sdk::sp_core::offchain::OpaqueNetworkState, ()> {
			self.inner.network_state()
		}
		fn timestamp(&mut self) -> Timestamp {
			self.inner.timestamp()
		}
		fn sleep_until(&mut self, deadline: Timestamp) {
			self.inner.sleep_until(deadline)
		}
		fn random_seed(&mut self) -> [u8; 32] {
			self.inner.random_seed()
		}
		fn http_request_start(
			&mut self,
			method: &str,
			uri: &str,
			meta: &[u8],
		) -> Result<HttpRequestId, ()> {
			let id = self.inner.http_request_start(method, uri, meta)?;
			self.uris.insert(id.0, uri.to_string());
			Ok(id)
		}
		fn http_request_add_header(
			&mut self,
			request_id: HttpRequestId,
			name: &str,
			value: &str,
		) -> Result<(), ()> {
			self.inner.http_request_add_header(request_id, name, value)
		}
		fn http_request_write_body(
			&mut self,
			request_id: HttpRequestId,
			chunk: &[u8],
			deadline: Option<Timestamp>,
		) -> Result<(), HttpError> {
			self.inner.http_request_write_body(request_id, chunk, deadline)
		}
		fn http_response_wait(
			&mut self,
			ids: &[HttpRequestId],
			deadline: Option<Timestamp>,
		) -> Vec<HttpRequestStatus> {
			for id in ids {
				let deadline = deadline.map(|d| d.unix_millis()).unwrap_or(u64::MAX);
				self.awaited.lock().unwrap().push((self.uris[&id.0].clone(), deadline));
			}
			self.inner.http_response_wait(ids, deadline)
		}
		fn http_response_headers(&mut self, request_id: HttpRequestId) -> Vec<(Vec<u8>, Vec<u8>)> {
			self.inner.http_response_headers(request_id)
		}
		fn http_response_read_body(
			&mut self,
			request_id: HttpRequestId,
			buffer: &mut [u8],
			deadline: Option<Timestamp>,
		) -> Result<usize, HttpError> {
			self.inner.http_response_read_body(request_id, buffer, deadline)
		}
		fn set_authorized_nodes(
			&mut self,
			nodes: Vec<polkadot_sdk::sp_core::OpaquePeerId>,
			authorized_only: bool,
		) {
			self.inner.set_authorized_nodes(nodes, authorized_only)
		}
	}

	// The test clock stands at zero, so a request's deadline is the timeout it was given.
	fn deadlines_of(requests: Vec<PendingRequest>, test: impl FnOnce()) -> Vec<(String, u64)> {
		let (offchain, state) = TestOffchainExt::new();
		for request in requests {
			state.write().expect_request(request);
		}
		let awaited = Arc::new(std::sync::Mutex::new(Vec::new()));
		let recorder = DeadlineRecorder {
			inner: offchain.clone(),
			uris: Default::default(),
			awaited: awaited.clone(),
		};
		let mut ext = TestExternalities::default();
		ext.register_extension(OffchainDbExt::new(offchain));
		ext.register_extension(OffchainWorkerExt::new(recorder));
		ext.register_extension(KeystoreExt(Arc::new(MemoryKeystore::new())));
		ext.execute_with(test);
		let awaited = awaited.lock().unwrap().clone();
		awaited
	}

	const SHORT_DISCOVERY_MILLIS: u64 = 5_000;
	const GROUPING_COLLECTORS_PATH: &str = "/activity/v1/grouping-collectors";

	fn url(host: &str, path: &str) -> String {
		format!("http://{}:{}{}", host, TEST_HTTP_PORT, path)
	}

	fn g_collector_is_node_b() -> PendingRequest {
		let grouping =
			GroupingCollectorsResponse { keys: vec![format!("0x{}", hex::encode(key_b()))] };
		get(HOST_A, GROUPING_COLLECTORS_PATH, signed_by(SEED_A, &grouping))
	}

	fn inspected_eras_from_node_b(path: &str) -> PendingRequest {
		let page = proto::activity::GetErasResponse {
			records: vec![era(TEST_ERA, proto::era::EraStatus::EraInspected)],
			..Default::default()
		};
		get(HOST_B, path, signed_by(SEED_B, &page))
	}

	#[test]
	fn a_discovery_timeout_bounds_only_the_grouping_collectors_request_of_an_inspected_eras_fetch() {
		let requests = vec![
			g_collector_is_node_b(),
			inspected_eras_from_node_b("/activity/v1/inspected-eras"),
		];
		let awaited = deadlines_of(requests, || {
			fetch_inspected_eras_for_cluster::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				None,
				None,
				Duration::from_millis(SHORT_DISCOVERY_MILLIS),
			)
			.unwrap();
		});
		assert_eq!(
			awaited,
			vec![
				(url(HOST_A, GROUPING_COLLECTORS_PATH), SHORT_DISCOVERY_MILLIS),
				(url(HOST_B, "/activity/v1/inspected-eras"), RESPONSE_TIMEOUT),
			]
		);
	}

	#[test]
	fn a_single_inspected_era_resolves_its_g_collector_within_the_response_timeout() {
		let path = format!(
			"/activity/v1/inspected-eras?cursor={}",
			hex::encode((TEST_ERA - 1).to_be_bytes())
		);
		let requests = vec![g_collector_is_node_b(), inspected_eras_from_node_b(&path)];
		let awaited = deadlines_of(requests, || {
			fetch_inspected_era::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				TEST_ERA,
			)
			.unwrap();
		});
		assert_eq!(
			awaited,
			vec![
				(url(HOST_A, GROUPING_COLLECTORS_PATH), RESPONSE_TIMEOUT),
				(url(HOST_B, &path), RESPONSE_TIMEOUT),
			]
		);
	}

	#[test]
	fn a_sealed_ehd_resolves_its_g_collector_within_the_response_timeout() {
		let requests = vec![
			g_collector_is_node_b(),
			get(HOST_B, "/activity/v1/ehds/7", signed_payload_by(SEED_B, vec![0x5a])),
		];
		let awaited = deadlines_of(requests, || {
			get_sealed_ehd::<AccountId, BlockNumber, MockCluster, MockNodes>(
				&ClusterId::zero(),
				TEST_ERA,
			)
			.unwrap();
		});
		assert_eq!(
			awaited,
			vec![
				(url(HOST_A, GROUPING_COLLECTORS_PATH), RESPONSE_TIMEOUT),
				(url(HOST_B, "/activity/v1/ehds/7"), RESPONSE_TIMEOUT),
			]
		);
	}

	#[test]
	fn a_discovery_timeout_bounds_only_the_grouping_collectors_request_of_the_era_to_inspect() {
		use proto::era::EraStatus::*;
		let page = |records| {
			signed_by(SEED_B, &proto::activity::GetErasResponse { records, ..Default::default() })
		};
		let requests = vec![
			g_collector_is_node_b(),
			get(HOST_B, ANCHOR_QUERY, page(vec![era(6, EraInspected)])),
			get(HOST_B, &next_query(6), page(vec![era(TEST_ERA, EraProcessed)])),
		];
		let awaited = deadlines_of(requests, || {
			assert_eq!(
				fetch_era_to_inspect_for_cluster::<AccountId, BlockNumber, MockCluster, MockNodes>(
					&ClusterId::zero(),
					Duration::from_millis(SHORT_DISCOVERY_MILLIS),
				),
				Ok(Some(TEST_ERA))
			);
		});
		assert_eq!(
			awaited,
			vec![
				(url(HOST_A, GROUPING_COLLECTORS_PATH), SHORT_DISCOVERY_MILLIS),
				(url(HOST_B, ANCHOR_QUERY), RESPONSE_TIMEOUT),
				(url(HOST_B, &next_query(6)), RESPONSE_TIMEOUT),
			]
		);
	}
}
