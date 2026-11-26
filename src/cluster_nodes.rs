//! A cluster's node registry, read once for a pass.
//!
//! An offchain worker reads chain state at the block that triggered it, and a
//! node keeps that state only for a limited number of finalized blocks. A pass
//! that outlives it cannot read the chain any more: the read panics. All the
//! chain state this crate reads is the cluster's node registry, so a pass reads
//! the registry once, at its start, and every lookup inside the pass is
//! answered from that read. Every read in one execution sees the same block,
//! so the answers are the ones a later read would have given.

use ddc_primitives::{
	traits::{ClusterManager, NodeManager},
	ClusterId, ClusterNodeStatus, NodeParams, NodePubKey, StorageNodeMode, StorageNodeParams,
};
use polkadot_sdk::sp_std::prelude::*;

use crate::{api::ApiError, log};

/// A registered node of the cluster with storage params, and its status in
/// the cluster, if the chain gave one.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterNode {
	pub key: NodePubKey,
	pub params: StorageNodeParams,
	pub status: Option<ClusterNodeStatus>,
}

/// The nodes of one cluster, in the order the chain lists them.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterNodes {
	cluster_id: ClusterId,
	nodes: Vec<ClusterNode>,
}

impl ClusterNodes {
	/// Reads the cluster's nodes, their storage params and their status from
	/// the chain.
	pub fn read<
		AccountId,
		BlockNumber,
		CM: ClusterManager<AccountId, BlockNumber>,
		NM: NodeManager<AccountId>,
	>(
		cluster_id: &ClusterId,
	) -> Result<Self, ApiError> {
		let keys = CM::get_nodes(cluster_id).map_err(|e| {
			log!(error, "❌ Failed to fetch nodes of cluster {:?}: {:?}", cluster_id, e);
			ApiError::FailedToFetchCollectors { cluster_id: *cluster_id }
		})?;
		let nodes = keys
			.into_iter()
			.filter_map(|key| match NM::get_node_params(&key) {
				Ok(NodeParams::StorageParams(params)) => {
					let status = CM::get_node_state(cluster_id, &key).ok().map(|state| state.status);
					Some(ClusterNode { key, params, status })
				},
				_ => None,
			})
			.collect();
		Ok(Self { cluster_id: *cluster_id, nodes })
	}

	pub fn cluster_id(&self) -> &ClusterId {
		&self.cluster_id
	}

	/// The nodes that can serve as collectors: every mode but compute.
	pub fn collectors(&self) -> Vec<(NodePubKey, StorageNodeParams)> {
		self.nodes
			.iter()
			.filter(|node| node.params.mode != StorageNodeMode::Compute)
			.map(|node| (node.key.clone(), node.params.clone()))
			.collect()
	}

	/// The node registered under `key`, in any mode.
	pub fn node(&self, key: &NodePubKey) -> Option<(NodePubKey, StorageNodeParams)> {
		self.nodes
			.iter()
			.find(|node| node.key == *key)
			.map(|node| (node.key.clone(), node.params.clone()))
	}

	/// The nodes whose validation succeeded, in key order.
	pub fn validated(&self) -> Vec<(NodePubKey, StorageNodeParams)> {
		let mut nodes: Vec<(NodePubKey, StorageNodeParams)> = self
			.nodes
			.iter()
			.filter(|node| node.status == Some(ClusterNodeStatus::ValidationSucceeded))
			.map(|node| (node.key.clone(), node.params.clone()))
			.collect();
		nodes.sort_by(|a, b| a.0.cmp(&b.0));
		nodes
	}
}

environmental::environmental!(pass_nodes: ClusterNodes);

/// Runs `f` with every registry lookup for `nodes`' cluster answered from
/// `nodes` instead of the chain.
pub fn with_cluster_nodes<R>(nodes: &mut ClusterNodes, f: impl FnOnce() -> R) -> R {
	pass_nodes::using(nodes, f)
}

/// `lookup` applied to the nodes of `cluster_id` the enclosing
/// `with_cluster_nodes` holds, if it holds that cluster's.
pub(crate) fn from_pass<R>(
	cluster_id: &ClusterId,
	lookup: impl FnOnce(&ClusterNodes) -> R,
) -> Option<R> {
	pass_nodes::with(|nodes| (nodes.cluster_id == *cluster_id).then(|| lookup(nodes))).flatten()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::api::{get_collector_node, get_collectors_nodes};
	use crate::shared_memory::validated_storage_nodes;
	use ddc_primitives::{
		traits::ClusterQuery, ClusterNodeKind, ClusterNodeState, ClusterNodesStats, ClusterStatus,
		StorageNodePubKey,
	};
	use polkadot_sdk::sp_runtime::DispatchError;
	use std::cell::Cell;

	type AccountId = u64;
	type BlockNumber = u64;

	const COMPUTE: u8 = 3;
	const VALIDATED: u8 = 1;
	const FAILED: u8 = 2;
	const NO_STATE: u8 = 4;
	const UNREGISTERED: u8 = 9;

	thread_local! {
		static CHAIN_READS: Cell<u32> = const { Cell::new(0) };
	}

	fn chain_reads() -> u32 {
		CHAIN_READS.with(Cell::get)
	}

	fn read_chain() {
		CHAIN_READS.with(|reads| reads.set(reads.get() + 1));
	}

	fn key(byte: u8) -> NodePubKey {
		NodePubKey::StoragePubKey(StorageNodePubKey::new([byte; 32]))
	}

	fn cluster(byte: u8) -> ClusterId {
		ClusterId::from([byte; 20])
	}

	struct Chain;

	impl ClusterQuery<AccountId> for Chain {
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

	impl ClusterManager<AccountId, BlockNumber> for Chain {
		fn get_manager_account_id(_: &ClusterId) -> Result<AccountId, DispatchError> {
			unimplemented!()
		}
		fn contains_node(_: &ClusterId, _: &NodePubKey, _: Option<ClusterNodeStatus>) -> bool {
			unimplemented!()
		}
		fn get_nodes(_: &ClusterId) -> Result<Vec<NodePubKey>, DispatchError> {
			read_chain();
			Ok(vec![key(COMPUTE), key(VALIDATED), key(NO_STATE), key(FAILED)])
		}
		fn add_node(_: &ClusterId, _: &NodePubKey, _: &ClusterNodeKind) -> Result<(), DispatchError> {
			unimplemented!()
		}
		fn remove_node(_: &ClusterId, _: &NodePubKey) -> Result<(), DispatchError> {
			unimplemented!()
		}
		fn get_node_state(
			_: &ClusterId,
			node: &NodePubKey,
		) -> Result<ClusterNodeState<BlockNumber>, DispatchError> {
			read_chain();
			let status = if *node == key(FAILED) {
				ClusterNodeStatus::ValidationFailed
			} else if *node == key(NO_STATE) {
				return Err(DispatchError::Other("no state"));
			} else {
				ClusterNodeStatus::ValidationSucceeded
			};
			Ok(ClusterNodeState { kind: ClusterNodeKind::External, status, added_at: 0 })
		}
		fn get_nodes_stats(_: &ClusterId) -> Result<ClusterNodesStats, DispatchError> {
			unimplemented!()
		}
		fn get_clusters(_: ClusterStatus) -> Result<Vec<ClusterId>, DispatchError> {
			unimplemented!()
		}
	}

	impl NodeManager<AccountId> for Chain {
		fn get_cluster_id(_: &NodePubKey) -> Result<Option<ClusterId>, DispatchError> {
			unimplemented!()
		}
		fn exists(_: &NodePubKey) -> bool {
			unimplemented!()
		}
		fn get_node_provider_id(_: &NodePubKey) -> Result<AccountId, DispatchError> {
			unimplemented!()
		}
		fn get_node_params(node: &NodePubKey) -> Result<NodeParams, DispatchError> {
			read_chain();
			let mode =
				if *node == key(COMPUTE) { StorageNodeMode::Compute } else { StorageNodeMode::Storage };
			Ok(NodeParams::StorageParams(StorageNodeParams {
				mode,
				host: node_key_host(node),
				http_port: 8080,
				..Default::default()
			}))
		}
	}

	fn node_key_host(node: &NodePubKey) -> Vec<u8> {
		let NodePubKey::StoragePubKey(raw) = node;
		let bytes: &[u8] = raw.as_ref();
		bytes[..1].to_vec()
	}

	fn snapshot(cluster_id: &ClusterId) -> ClusterNodes {
		ClusterNodes::read::<AccountId, BlockNumber, Chain, Chain>(cluster_id).unwrap()
	}

	struct Lookups {
		collectors: Vec<(NodePubKey, StorageNodeParams)>,
		compute_node: Result<(NodePubKey, StorageNodeParams), ApiError>,
		unregistered_node: Result<(NodePubKey, StorageNodeParams), ApiError>,
		validated: Vec<(NodePubKey, StorageNodeParams)>,
	}

	fn lookups(cluster_id: &ClusterId) -> Lookups {
		Lookups {
			collectors: get_collectors_nodes::<AccountId, BlockNumber, Chain, Chain>(cluster_id)
				.unwrap(),
			compute_node: get_collector_node::<AccountId, BlockNumber, Chain, Chain>(
				cluster_id,
				key(COMPUTE),
			),
			unregistered_node: get_collector_node::<AccountId, BlockNumber, Chain, Chain>(
				cluster_id,
				key(UNREGISTERED),
			),
			validated: validated_storage_nodes::<AccountId, BlockNumber, Chain, Chain>(cluster_id)
				.unwrap(),
		}
	}

	#[test]
	fn a_pass_answers_every_registry_lookup_without_reading_the_chain() {
		let cluster_id = cluster(1);
		let mut nodes = snapshot(&cluster_id);
		let before = chain_reads();

		with_cluster_nodes(&mut nodes, || lookups(&cluster_id));

		assert_eq!(chain_reads(), before, "no lookup inside the pass read the chain");
	}

	#[test]
	fn a_pass_answers_registry_lookups_as_the_chain_does() {
		let cluster_id = cluster(1);
		let from_chain = lookups(&cluster_id);
		let mut nodes = snapshot(&cluster_id);

		let from_pass = with_cluster_nodes(&mut nodes, || lookups(&cluster_id));

		assert_eq!(from_pass.collectors, from_chain.collectors);
		assert_eq!(from_pass.compute_node, from_chain.compute_node);
		assert_eq!(from_pass.unregistered_node, from_chain.unregistered_node);
		assert_eq!(from_pass.validated, from_chain.validated);
		assert_eq!(
			from_pass.collectors.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
			vec![key(VALIDATED), key(NO_STATE), key(FAILED)],
		);
		assert_eq!(
			from_pass.validated.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
			vec![key(VALIDATED), key(COMPUTE)],
		);
	}

	#[test]
	fn registry_lookups_outside_a_pass_read_the_chain() {
		let cluster_id = cluster(1);
		let before = chain_reads();

		lookups(&cluster_id);

		assert!(chain_reads() > before);
	}

	#[test]
	fn a_pass_over_another_cluster_leaves_this_cluster_s_lookups_to_the_chain() {
		let mut other = snapshot(&cluster(2));
		let before = chain_reads();

		with_cluster_nodes(&mut other, || lookups(&cluster(1)));

		assert!(chain_reads() > before);
	}
}
