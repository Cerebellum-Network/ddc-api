//! Discovery of the inspectors' shared memory (ADR-006).
//!
//! The sync store is the inspectors' shared memory; which nodes hold it is
//! learned, not configured. An inspector asks a registry node of the cluster
//! who the store's members are, keeps only the members the registry confirms,
//! caches that list and asks again once the refresh mark expires. Members are
//! named as such only here, where membership is the subject. G-Collectors and
//! shared-memory nodes are different subsets of a cluster, so nothing here
//! reads one for the other.

use codec::{Decode, Encode};
use ddc_primitives::{
	traits::{ClusterManager, NodeManager},
	ClusterId, ClusterNodeStatus, EhdEra, NodeParams, NodePubKey, StorageNodeMode,
	StorageNodeParams,
};
use polkadot_sdk::sp_runtime::offchain::{
	storage::StorageValueRef,
	storage_lock::{StorageLock, Time},
	Duration,
};
use polkadot_sdk::sp_std::prelude::*;
use scale_info::prelude::{format, string::String};

use crate::{
	api::ApiError,
	client::{DdcClient, QuorumAnswerKind, QuorumProbe},
	log, proto,
};

/// A usable answer names at least this many registry-confirmed members.
pub const MEMBER_FLOOR: usize = 2;
/// Candidates asked per discovery; the next tick asks again.
pub const MAX_DISCOVERY_ATTEMPTS: usize = 3;
/// Reader timeout for one membership question.
pub const DISCOVERY_TIMEOUT_MS: u64 = 15_000;
/// Headroom the reader timeout must leave above a node's declared deadline.
pub const DEADLINE_MARGIN_MS: u64 = 2_000;
/// Minimum interval between refreshes of a successful answer.
pub const REFRESH_INTERVAL_MS: u64 = 600_000;

/// Membership does not depend on the era; the route takes one.
const MEMBERSHIP_ERA: EhdEra = 0;
const DISCOVERY_RETRIES: u32 = 1;
const CACHE_KEY_PREFIX: &[u8] = b"ddc-api::shared-memory-nodes::";
const REFRESH_KEY_PREFIX: &[u8] = b"ddc-api::shared-memory-refresh::";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SharedMemoryNode {
	pub dry_run: bool,
	pub key: NodePubKey,
	pub params: StorageNodeParams,
}

/// The nodes holding a cluster's shared memory, in key order.
///
/// A sync node configured in the cluster's dry-run parameters overrides
/// discovery and is not checked against the registry: a dry-run sync node
/// sits outside the inspected cluster by design.
pub fn shared_memory_nodes<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
) -> Result<Vec<SharedMemoryNode>, ApiError> {
	match dry_run_shared_memory_node::<AccountId, BlockNumber, CM>(cluster_id)? {
		Some(node) => Ok(vec![node]),
		None => discovered_shared_memory_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id),
	}
}

/// The discovered sync members of a cluster: the cached list while the
/// refresh mark stands, a fresh discovery once it has expired.
pub fn discovered_shared_memory_nodes<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
) -> Result<Vec<SharedMemoryNode>, ApiError> {
	let refresh_key = refresh_key(cluster_id);
	let mut lock = StorageLock::<Time>::with_deadline(
		&refresh_key,
		Duration::from_millis(REFRESH_INTERVAL_MS),
	);
	let nodes = match lock.try_lock() {
		Ok(guard) => {
			let nodes = discover_and_cache::<AccountId, BlockNumber, CM, NM>(cluster_id);
			// Only a successful answer leaves the mark; a failure asks again next tick.
			if nodes.is_ok() {
				guard.forget();
			}
			nodes
		}
		Err(_) => match cached_shared_memory_nodes(cluster_id) {
			Some(nodes) => Ok(nodes),
			None => discover_and_cache::<AccountId, BlockNumber, CM, NM>(cluster_id),
		},
	};
	nodes
}

/// Discovers again regardless of the refresh mark, for when no cached member
/// answered.
pub fn rediscover_shared_memory_nodes<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
) -> Result<Vec<SharedMemoryNode>, ApiError> {
	discover_and_cache::<AccountId, BlockNumber, CM, NM>(cluster_id)
}

/// The sync node named in the cluster's dry-run parameters, if any.
pub fn dry_run_shared_memory_node<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
>(
	cluster_id: &ClusterId,
) -> Result<Option<SharedMemoryNode>, ApiError> {
	let params = CM::get_inspection_dry_run_params(cluster_id).map_err(|e| {
		log!(
			error,
			"❌ Failed to fetch inspection dry run params for cluster {:?}: {:?}",
			cluster_id,
			e
		);
		ApiError::FailedToFetchInspectionDryRunParams { cluster_id: *cluster_id }
	})?;
	Ok(params.map(|p| SharedMemoryNode {
		dry_run: p.enabled,
		key: p.sync_node_key,
		params: p.sync_node_params,
	}))
}

fn discover_and_cache<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
) -> Result<Vec<SharedMemoryNode>, ApiError> {
	let registry = validated_storage_nodes::<AccountId, BlockNumber, CM, NM>(cluster_id)?;
	let nodes = discover(cluster_id, &registry, probe_node)?;
	StorageValueRef::persistent(&cache_key(cluster_id)).set(&nodes);
	Ok(nodes)
}

/// Asks the first candidates in key order and returns the first usable
/// answer. `probe` asks one node.
pub fn discover<P: FnMut(&StorageNodeParams) -> QuorumProbe>(
	cluster_id: &ClusterId,
	registry: &[(NodePubKey, StorageNodeParams)],
	mut probe: P,
) -> Result<Vec<SharedMemoryNode>, ApiError> {
	let mut seen = Vec::new();
	let candidates = registry
		.iter()
		.filter(|(_, params)| params.mode != StorageNodeMode::Compute)
		.take(MAX_DISCOVERY_ATTEMPTS);
	for (key, params) in candidates {
		match probe(params) {
			QuorumProbe::Answer { info, declared_deadline_ms } => {
				check_deadline_coupling(key, declared_deadline_ms);
				let members = accept_members(&info, registry);
				if members.len() >= MEMBER_FLOOR {
					log!(
						debug,
						"Shared memory of cluster {:?} discovered from node {:?}",
						cluster_id,
						key
					);
					return Ok(members);
				}
				seen.push(QuorumAnswerKind::Rejected);
			}
			QuorumProbe::Refused(kind) => seen.push(kind),
		}
	}

	log!(
		error,
		"❌ No usable shared-memory answer for cluster {:?}; answers seen: {:?}",
		cluster_id,
		seen
	);
	Err(ApiError::FailedToFetchSharedMemoryNodes { cluster_id: *cluster_id })
}

/// Keeps the members whose decoded key is a validated storage node of the
/// cluster, with the registry's endpoint, in key order. An unconfirmed member
/// is dropped rather than failing the whole answer.
pub fn accept_members(
	info: &proto::inspection::InspSyncQuorumInfo,
	registry: &[(NodePubKey, StorageNodeParams)],
) -> Vec<SharedMemoryNode> {
	let mut members: Vec<SharedMemoryNode> =
		info.quorum_members
			.iter()
			.filter_map(|member| decode_member_key(&member.node_key))
			.filter_map(|key| {
				registry.iter().find(|(registered, _)| *registered == key).map(|(_, params)| {
					SharedMemoryNode { dry_run: false, key, params: params.clone() }
				})
			})
			.collect();
	members.sort_by(|a, b| a.key.cmp(&b.key));
	members.dedup_by(|a, b| a.key == b.key);
	members
}

/// A member's name is the text form of its chain key ("0x" + hex) carried in a
/// bytes field. Decoding those bytes as a raw key fails on every real member,
/// so the text is decoded first.
fn decode_member_key(name: &[u8]) -> Option<NodePubKey> {
	let text = core::str::from_utf8(name).ok()?;
	NodePubKey::try_from(String::from(text)).ok()
}

fn check_deadline_coupling(node: &NodePubKey, declared_deadline_ms: Option<u64>) {
	if let Some(declared) = declared_deadline_ms {
		if DISCOVERY_TIMEOUT_MS < declared.saturating_add(DEADLINE_MARGIN_MS) {
			log!(
				error,
				"❌ Sync membership timeout {} ms does not exceed node {:?}'s declared deadline {} ms by {} ms; the reader will time out before the node answers",
				DISCOVERY_TIMEOUT_MS,
				node,
				declared,
				DEADLINE_MARGIN_MS
			);
		}
	}
}

/// Validated storage nodes of the cluster, in key order.
pub fn validated_storage_nodes<
	AccountId,
	BlockNumber,
	CM: ClusterManager<AccountId, BlockNumber>,
	NM: NodeManager<AccountId>,
>(
	cluster_id: &ClusterId,
) -> Result<Vec<(NodePubKey, StorageNodeParams)>, ApiError> {
	let keys = CM::get_nodes(cluster_id).map_err(|e| {
		log!(error, "❌ Failed to fetch nodes of cluster {:?}: {:?}", cluster_id, e);
		ApiError::FailedToFetchSharedMemoryNodes { cluster_id: *cluster_id }
	})?;
	let mut nodes: Vec<(NodePubKey, StorageNodeParams)> = keys
		.into_iter()
		.filter(|key| {
			CM::get_node_state(cluster_id, key)
				.map(|state| state.status == ClusterNodeStatus::ValidationSucceeded)
				.unwrap_or(false)
		})
		.filter_map(|key| match NM::get_node_params(&key) {
			Ok(NodeParams::StorageParams(params)) => Some((key, params)),
			_ => None,
		})
		.collect();
	nodes.sort_by(|a, b| a.0.cmp(&b.0));
	Ok(nodes)
}

fn probe_node(params: &StorageNodeParams) -> QuorumProbe {
	let Ok(host) = core::str::from_utf8(&params.host) else {
		return QuorumProbe::Refused(QuorumAnswerKind::Transport);
	};
	// Plaintext over the registry host and published port, as every reader builds it.
	let base_url = format!("http://{}:{}", host, params.http_port);
	DdcClient::new(&base_url, Duration::from_millis(DISCOVERY_TIMEOUT_MS), DISCOVERY_RETRIES)
		.probe_quorum_info(MEMBERSHIP_ERA)
}

/// Drops one node from the cached shared-memory list, so later calls stop going to it.
pub fn forget_cached_shared_memory_node(cluster_id: &ClusterId, key: &NodePubKey) {
	if let Some(mut nodes) = cached_shared_memory_nodes(cluster_id) {
		nodes.retain(|node| node.key != *key);
		StorageValueRef::persistent(&cache_key(cluster_id)).set(&nodes);
	}
}

/// Drops the cached list, so the next call discovers again.
pub fn forget_cached_shared_memory_nodes(cluster_id: &ClusterId) {
	StorageValueRef::persistent(&cache_key(cluster_id)).clear();
}

/// The submitted paths whose status in `state` does not list `inspector_key`
/// among its inspectors, i.e. the submissions that were not committed.
pub fn uncommitted_paths(
	state: &proto::inspection::InspectionState,
	inspector_key: &[u8],
	submitted: &[Vec<u8>],
) -> Vec<Vec<u8>> {
	submitted
		.iter()
		.filter(|path_hash| {
			!state.paths.iter().any(|(path_key, status)| {
				let hex_key = path_key.strip_prefix("0x").unwrap_or(path_key);
				hex::decode(hex_key).map(|bytes| bytes == **path_hash).unwrap_or(false)
					&& status.inspectors.iter().any(|inspector| inspector == inspector_key)
			})
		})
		.cloned()
		.collect()
}

fn cached_shared_memory_nodes(cluster_id: &ClusterId) -> Option<Vec<SharedMemoryNode>> {
	StorageValueRef::persistent(&cache_key(cluster_id))
		.get::<Vec<SharedMemoryNode>>()
		.ok()
		.flatten()
}

fn cache_key(cluster_id: &ClusterId) -> Vec<u8> {
	[CACHE_KEY_PREFIX, cluster_id.as_bytes()].concat()
}

fn refresh_key(cluster_id: &ClusterId) -> Vec<u8> {
	[REFRESH_KEY_PREFIX, cluster_id.as_bytes()].concat()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::client::classify_quorum_refusal;
	use ddc_primitives::StorageNodePubKey;
	use proto::inspection::{InspSyncQuorumInfo, InspSyncQuorumMember};

	const KEY_A: [u8; 32] = [0x11; 32];
	const KEY_B: [u8; 32] = [0x22; 32];
	const KEY_C: [u8; 32] = [0x33; 32];
	const KEY_D: [u8; 32] = [0x44; 32];
	const TEST_HTTP_PORT: u16 = 8080;

	fn key(bytes: [u8; 32]) -> NodePubKey {
		NodePubKey::StoragePubKey(StorageNodePubKey::new(bytes))
	}

	fn params(host: &str, mode: StorageNodeMode) -> StorageNodeParams {
		StorageNodeParams {
			mode,
			host: host.as_bytes().to_vec(),
			http_port: TEST_HTTP_PORT,
			..Default::default()
		}
	}

	fn registry() -> Vec<(NodePubKey, StorageNodeParams)> {
		vec![
			(key(KEY_A), params("compute-a", StorageNodeMode::Compute)),
			(key(KEY_B), params("storage-b", StorageNodeMode::Storage)),
			(key(KEY_C), params("storage-c", StorageNodeMode::Storage)),
		]
	}

	// The member name is what ddc-node writes: "0x" + hex of the node key.
	fn member(bytes: [u8; 32], endpoint: &str) -> InspSyncQuorumMember {
		InspSyncQuorumMember {
			node_key: format!("0x{}", hex::encode(bytes)).into_bytes(),
			http_endpoint: endpoint.into(),
			etcd_client_url: endpoint.into(),
			is_leader: false,
			is_healthy: true,
		}
	}

	fn info(members: Vec<InspSyncQuorumMember>) -> InspSyncQuorumInfo {
		InspSyncQuorumInfo { quorum_members: members, ..Default::default() }
	}

	#[test]
	fn a_member_name_decodes_to_the_registry_key_of_that_node() {
		let accepted =
			accept_members(&info(vec![member(KEY_C, "x"), member(KEY_B, "x")]), &registry());
		assert_eq!(
			accepted.iter().map(|n| n.key.clone()).collect::<Vec<_>>(),
			vec![key(KEY_B), key(KEY_C)]
		);
	}

	#[test]
	fn a_member_name_carrying_raw_key_bytes_is_not_accepted() {
		let mut raw = member(KEY_B, "x");
		raw.node_key = KEY_B.to_vec();
		assert!(accept_members(&info(vec![raw]), &registry()).is_empty());
	}

	#[test]
	fn an_unconfirmed_member_is_dropped_and_the_rest_are_kept() {
		let accepted = accept_members(
			&info(vec![member(KEY_B, "x"), member(KEY_D, "x"), member(KEY_C, "x")]),
			&registry(),
		);
		assert_eq!(accepted.len(), 2);
		assert!(accepted.iter().all(|n| n.key != key(KEY_D)));
	}

	#[test]
	fn a_member_is_contacted_at_its_registry_endpoint_not_the_one_it_names() {
		let accepted =
			accept_members(&info(vec![member(KEY_B, "http://elsewhere:2379")]), &registry());
		assert_eq!(accepted[0].params.host, b"storage-b".to_vec());
	}

	#[test]
	fn discovery_skips_compute_nodes_and_stops_at_the_first_usable_answer() {
		let mut asked = Vec::new();
		let nodes = discover(&ClusterId::zero(), &registry(), |p| {
			asked.push(p.host.clone());
			QuorumProbe::Answer {
				info: info(vec![member(KEY_B, "x"), member(KEY_C, "x")]),
				declared_deadline_ms: None,
			}
		})
		.unwrap();
		assert_eq!(asked, vec![b"storage-b".to_vec()]);
		assert_eq!(nodes.len(), 2);
	}

	#[test]
	fn an_answer_below_the_member_floor_is_not_usable() {
		let result = discover(&ClusterId::zero(), &registry(), |_| QuorumProbe::Answer {
			info: info(vec![member(KEY_B, "x"), member(KEY_D, "x")]),
			declared_deadline_ms: None,
		});
		assert_eq!(
			result,
			Err(ApiError::FailedToFetchSharedMemoryNodes { cluster_id: ClusterId::zero() })
		);
	}

	#[test]
	fn discovery_asks_at_most_three_candidates() {
		let wide: Vec<_> = (1u8..=5)
			.map(|i| (key([i; 32]), params("storage", StorageNodeMode::Storage)))
			.collect();
		let mut asked = 0;
		let result = discover(&ClusterId::zero(), &wide, |_| {
			asked += 1;
			QuorumProbe::Refused(QuorumAnswerKind::Transport)
		});
		assert!(result.is_err());
		assert_eq!(asked, MAX_DISCOVERY_ATTEMPTS);
	}

	const INSPECTOR: &[u8] = b"inspector-key";
	const PATH_ONE: [u8; 2] = [0x01, 0x02];
	const PATH_TWO: [u8; 2] = [0x03, 0x04];

	fn state_with(path_key: &str, inspectors: Vec<Vec<u8>>) -> proto::inspection::InspectionState {
		let mut state = proto::inspection::InspectionState::default();
		state.paths.insert(
			path_key.into(),
			proto::inspection::InspectionPathStatus { inspectors, ..Default::default() },
		);
		state
	}

	#[test]
	fn a_path_listing_the_inspector_counts_as_committed() {
		let state = state_with("0x0102", vec![INSPECTOR.to_vec()]);
		assert!(uncommitted_paths(&state, INSPECTOR, &[PATH_ONE.to_vec()]).is_empty());
	}

	#[test]
	fn a_path_without_the_inspector_or_absent_from_the_state_is_uncommitted() {
		let state = state_with("0102", vec![b"someone-else".to_vec()]);
		assert_eq!(
			uncommitted_paths(&state, INSPECTOR, &[PATH_ONE.to_vec(), PATH_TWO.to_vec()]),
			vec![PATH_ONE.to_vec(), PATH_TWO.to_vec()]
		);
	}

	#[test]
	fn a_refusal_from_a_node_without_the_shared_memory_is_recognised_with_or_without_its_reason() {
		use crate::client::is_not_shared_memory_refusal;
		assert!(is_not_shared_memory_refusal(
			503,
			br#"{"message":"Inspection sync is disabled on this node.","reason":"not-a-member"}"#
		));
		assert!(is_not_shared_memory_refusal(
			503,
			br#"{"message":"Inspection sync is disabled on this node."}"#
		));
		assert!(!is_not_shared_memory_refusal(503, br#"{"message":"m","reason":"store-unreachable"}"#));
		assert!(!is_not_shared_memory_refusal(500, b""));
	}

	#[test]
	fn a_refusal_is_classified_by_its_reason() {
		assert_eq!(
			classify_quorum_refusal(503, br#"{"message":"m","reason":"no-client"}"#),
			QuorumAnswerKind::NoClient
		);
		assert_eq!(
			classify_quorum_refusal(503, br#"{"message":"m","reason":"store-unreachable"}"#),
			QuorumAnswerKind::StoreUnreachable
		);
		assert_eq!(
			classify_quorum_refusal(
				503,
				br#"{"message":"Inspection sync is disabled on this node."}"#
			),
			QuorumAnswerKind::Predates
		);
		assert_eq!(classify_quorum_refusal(404, b""), QuorumAnswerKind::NoRoute);
	}
}
