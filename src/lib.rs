#![cfg_attr(not(feature = "std"), no_std)]

pub const LOG_TARGET: &str = "ddc-api";

pub mod api;
pub mod client;
pub mod shared_memory;
pub mod verification;

pub mod proto {
	pub mod signature {
		include!(concat!(env!("OUT_DIR"), "/signature.rs"));
	}

	pub mod auth {
		include!(concat!(env!("OUT_DIR"), "/auth.rs"));
	}

	pub mod activity {
		include!(concat!(env!("OUT_DIR"), "/activity.rs"));

		// Backward compatibility: AuthToken, Payload, Operation moved to proto::auth
		pub use super::auth::{AuthToken, Operation, Payload};

		impl ActivityTreeTraversedNode {
			pub fn get_activity(&self) -> Option<super::activity_tree::ActivityNode> {
				self.activity.clone()
			}
		}
	}

	pub mod era {
		include!(concat!(env!("OUT_DIR"), "/era.rs"));
	}

	pub mod inspection {
		include!(concat!(env!("OUT_DIR"), "/inspection.rs"));

		#[cfg(test)]
		mod tests {
			use super::*;
			use prost::Message;
			use std::collections::BTreeMap;

			// =================================================================
			// T091: Protobuf serialization round-trip tests
			// =================================================================

			#[test]
			fn lease_request_round_trip() {
				let req =
					LeaseRequest {
					era_id: 42,
					inspector_key: "0xabc123".into(),
					ttl_seconds: 300,
					inspector_signature: vec![],
				};

				let bytes = req.encode_to_vec();
				assert!(!bytes.is_empty());

				let decoded = LeaseRequest::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era_id, 42);
				assert_eq!(decoded.inspector_key, b"0xabc123");
				assert_eq!(decoded.ttl_seconds, 300);
			}

			#[test]
			fn lease_result_round_trip() {
				let res = LeaseResult {
					status: LeaseStatus::Acquired as i32,
					era_id: 42,
					inspector_key: "0xabc123".into(),
					lease_id: "lease-001".into(),
					expires_at: 1700000000,
					current_holder: vec![],
					error_message: String::new(),
					collective_seed: 0,
				};

				let bytes = res.encode_to_vec();
				let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, LeaseStatus::Acquired as i32);
				assert_eq!(decoded.era_id, 42);
				assert_eq!(decoded.inspector_key, b"0xabc123");
				assert_eq!(decoded.lease_id, "lease-001");
				assert_eq!(decoded.expires_at, 1700000000);
			}

			#[test]
			fn assignment_table_round_trip() {
				use inspection_path::PathData;

				let mut paths = BTreeMap::new();
				paths.insert(
					"path-001".into(),
					PathAssignment {
						path: Some(InspectionPath {
							path_type: InspectionPathType::NodeAr as i32,
							collectors: vec!["0xc0c1".into(), "0xc2c3".into()],
							path_data: Some(PathData::NodeAr(NodeArPath {
								node_key: "0x0a0b".into(),
								leaves_pos: vec![1, 2, 3],
								tca_id: 5,
								record_id_range_start: vec![],
								record_id_range_end: vec![],
								value: None,
							})),
						}),
						assignments: Some(InspectorAssignments {
							main_inspectors: vec!["insp1".into(), "insp2".into()],
							backup_inspectors: vec!["insp3".into()],
						}),
					},
				);

				let table = AssignmentTable {
					cluster_id: "0xaabb".into(),
					era: 42,
					irf: 3,
					paths,
					collective_seed: 12345,
					builder: "0xabc123".into(),
					submitted_at: 1700000000,
					builder_signature: vec![],
					era_give_up_distance: 24,
				};

				let bytes = table.encode_to_vec();
				let decoded = AssignmentTable::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era, 42);
				assert_eq!(decoded.irf, 3);
				assert_eq!(decoded.era_give_up_distance, 24);
				assert_eq!(decoded.paths.len(), 1);
				let path = decoded.paths["path-001"].path.as_ref().unwrap();
				assert_eq!(path.path_type, InspectionPathType::NodeAr as i32);
				assert_eq!(path.collectors.len(), 2);
				match &path.path_data {
					Some(PathData::NodeAr(node_ar)) => {
						assert_eq!(node_ar.node_key, b"0x0a0b");
						assert_eq!(node_ar.leaves_pos, vec![1, 2, 3]);
						assert_eq!(node_ar.tca_id, 5);
					},
					_ => panic!("Expected NodeAr path_data"),
				}
				let assignments = decoded.paths["path-001"].assignments.as_ref().unwrap();
				assert_eq!(assignments.main_inspectors.len(), 2);
			}

			#[test]
			fn post_assignment_table_request_round_trip() {
				let req = PostAssignmentTableRequest {
					era_id: 42,
					inspector_key: "0xabc123".into(),
					table: Some(AssignmentTable {
						cluster_id: "0xaa".into(),
						era: 42,
						irf: 3,
						paths: BTreeMap::new(),
						collective_seed: 0,
						builder: "0xabc123".into(),
						submitted_at: 0,
						builder_signature: vec![],
						era_give_up_distance: 0,
					}),
				};

				let bytes = req.encode_to_vec();
				let decoded = PostAssignmentTableRequest::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era_id, 42);
				assert!(decoded.table.is_some());
				assert_eq!(decoded.table.unwrap().irf, 3);
			}

			#[test]
			fn post_assignment_table_response_round_trip() {
				let res = PostAssignmentTableResponse {
					status: PostAssignmentTableStatus::Accepted as i32,
					era_id: 42,
					submitted_at: 1700000000,
					error_code: String::new(),
					error_message: String::new(),
				};

				let bytes = res.encode_to_vec();
				let decoded = PostAssignmentTableResponse::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, PostAssignmentTableStatus::Accepted as i32);
				assert_eq!(decoded.submitted_at, 1700000000);
			}

			#[test]
			fn get_assignment_table_response_round_trip() {
				let res = GetAssignmentTableResponse {
					status: GetAssignmentTableStatus::Building as i32,
					era_id: 42,
					table: None,
					lease_holder: "0xdef456".into(),
					lease_expires_at: 1700001000,
				};

				let bytes = res.encode_to_vec();
				let decoded = GetAssignmentTableResponse::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, GetAssignmentTableStatus::Building as i32);
				assert!(decoded.table.is_none());
				assert_eq!(decoded.lease_holder, b"0xdef456");
			}

			#[test]
			fn post_inspection_result_request_round_trip() {
				let req = PostInspectionResultRequest {
					era_id: 42,
					inspector_key: "0xabc123".into(),
					inspector_signature: vec![],
					paths_results: vec![
						InspectionPathResult {
							path_hash: "0x01".into(),
							result_hash: "0xaabbcc".into(),
							exception: None,
							source_nodes: vec![],
						},
						InspectionPathResult {
							path_hash: "0x02".into(),
							result_hash: "0xddee".into(),
							exception: Some(InspPathException {
								kind: Some(insp_path_exception::Kind::NodeArsUnavailable(
									NodeARsUnavailable {
										node_key: "0xnode1".into(),
										tca_id: 1,
										leaves_ids: vec![],
										unverified_usage: None,
									},
								)),
							}),
							source_nodes: vec![],
						},
					],
				};

				let bytes = req.encode_to_vec();
				let decoded = PostInspectionResultRequest::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.paths_results.len(), 2);
				assert_eq!(decoded.paths_results[0].path_hash, b"0x01");
				assert!(decoded.paths_results[1].exception.is_some());
				match &decoded.paths_results[1].exception.as_ref().unwrap().kind {
					Some(insp_path_exception::Kind::NodeArsUnavailable(inner)) => {
						assert_eq!(inner.node_key, b"0xnode1");
						assert_eq!(inner.tca_id, 1);
					},
					_ => panic!("Expected NodeArsUnavailable exception"),
				}
			}

			#[test]
			fn post_inspection_result_response_round_trip() {
				let res = PostInspectionResultResponse {
					status: PostInspectionResultStatus::Partial as i32,
					accepted_count: 3,
					rejected_count: 1,
					quorum_reached_paths: vec!["path-001".into()],
					rejected_paths: vec![RejectedInspectionPath {
						path_hash: "0x02".into(),
						reason: RejectionReason::Duplicate as i32,
					}],
				};

				let bytes = res.encode_to_vec();
				let decoded = PostInspectionResultResponse::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, PostInspectionResultStatus::Partial as i32);
				assert_eq!(decoded.accepted_count, 3);
				assert_eq!(decoded.rejected_count, 1);
				assert_eq!(decoded.rejected_paths[0].reason, RejectionReason::Duplicate as i32);
			}

			#[test]
			fn inspection_state_round_trip() {
				let mut paths = BTreeMap::new();
				let mut submissions = BTreeMap::new();
				submissions.insert("0xaabb".into(), 2);
				submissions.insert("0xccdd".into(), 1);

				paths.insert(
					"path-001".into(),
					InspectionPathStatus {
						status: InspectionPathStatusEnum::InspectionPathStatusIrfReached as i32,
						result_hash: "0xaabb".into(),
						exception: None,
						submissions,
						inspectors: vec!["insp1".into(), "insp2".into(), "insp3".into()],
					},
				);

				let state = InspectionState {
					cluster_id: "0xaabb".into(),
					era_id: 42,
					total_paths: 10,
					verified_paths: 5,
					unverified_paths: 2,
					pending_paths: 3,
					quorum_unreached_paths: 0,
					irf: 3,
					paths,
					submissions: vec![],
				};

				let bytes = state.encode_to_vec();
				let decoded = InspectionState::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era_id, 42);
				assert_eq!(decoded.total_paths, 10);
				assert_eq!(decoded.verified_paths, 5);
				assert_eq!(decoded.irf, 3);
				assert_eq!(decoded.paths.len(), 1);
				let path_status = &decoded.paths["path-001"];
				assert_eq!(path_status.submissions.len(), 2);
				assert_eq!(path_status.inspectors.len(), 3);
			}

			#[test]
			fn inspection_receipt_round_trip() {
				let receipt = InspectionReceipt {
					era_id: 42,
					cluster_id: "0xaabb".into(),
					verified_paths: vec!["0x01".into(), "0x02".into()],
					unverified_paths: vec![UnverifiedPath {
						path_hash: "0x03".into(),
						exception: Some(InspPathException {
							kind: Some(insp_path_exception::Kind::BucketArsUnavailable(
								BucketARsUnavailable {
									bucket_id: 42,
									node_key: "0xnode1".into(),
									tca_id: 1,
									leaves_ids: vec![],
									unverified_usage: None,
								},
							)),
						}),
					}],
					quorum_unreached_paths: vec![UnverifiedPath { path_hash: "0x04".into(), exception: None }],
					assignments_hash: vec![],
					state_hash: vec![],
					generated_at: 1700000000,
					complete: true,
					assignments_cid: vec![0x01, 0x02, 0x1e, 0x20],
					state_cid: vec![0x01, 0x02, 0x1e, 0x20],
				};

				let bytes = receipt.encode_to_vec();
				let decoded = InspectionReceipt::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era_id, 42);
				assert_eq!(decoded.verified_paths.len(), 2);
				assert_eq!(decoded.unverified_paths.len(), 1);
				assert!(decoded.unverified_paths[0].exception.is_some());
				assert_eq!(decoded.quorum_unreached_paths.len(), 1);
				assert!(decoded.complete);
			}

			#[test]
			fn quorum_info_round_trip() {
				let info = InspSyncQuorumInfo {
					era_id: 42,
					quorum_members: vec![
						InspSyncQuorumMember {
							node_key: "node1".into(),
							http_endpoint: "http://node1:8080".into(),
							etcd_client_url: "http://node1:2379".into(),
							is_leader: true,
							is_healthy: true,
						},
						InspSyncQuorumMember {
							node_key: "node2".into(),
							http_endpoint: "http://node2:8080".into(),
							etcd_client_url: "http://node2:2379".into(),
							is_leader: false,
							is_healthy: true,
						},
					],
					quorum_size: 2,
					healthy_members: 2,
					election_seed: vec![0x01, 0x02, 0x03],
					formation_time: 1700000000,
					single_endpoint: String::new(),
				};

				let bytes = info.encode_to_vec();
				let decoded = InspSyncQuorumInfo::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.quorum_members.len(), 2);
				assert_eq!(decoded.quorum_size, 2);
				assert!(decoded.quorum_members[0].is_leader);
				assert!(!decoded.quorum_members[1].is_leader);
			}

			#[test]
			fn default_values_are_zero() {
				let req = LeaseRequest::default();
				assert_eq!(req.era_id, 0);
				assert!(req.inspector_key.is_empty());
				assert_eq!(req.ttl_seconds, 0);

				let state = InspectionState::default();
				assert_eq!(state.total_paths, 0);
				assert_eq!(state.paths.len(), 0);
			}

			#[test]
			fn enum_values_preserved() {
				assert_eq!(LeaseStatus::Unspecified as i32, 0);
				assert_eq!(LeaseStatus::Acquired as i32, 1);
				assert_eq!(LeaseStatus::HeldByOther as i32, 2);
				assert_eq!(LeaseStatus::Error as i32, 3);

				assert_eq!(InspectionPathStatusEnum::InspectionPathStatusUnspecified as i32, 0);
				assert_eq!(InspectionPathStatusEnum::InspectionPathStatusPending as i32, 1);
				assert_eq!(InspectionPathStatusEnum::InspectionPathStatusIrfReached as i32, 2);
				assert_eq!(InspectionPathStatusEnum::InspectionPathStatusIrfUnreached as i32, 3);

				assert_eq!(GetAssignmentTableStatus::Found as i32, 1);
				assert_eq!(GetAssignmentTableStatus::NotFound as i32, 2);
				assert_eq!(GetAssignmentTableStatus::Building as i32, 3);

				assert_eq!(PostAssignmentTableStatus::Accepted as i32, 1);
				assert_eq!(PostAssignmentTableStatus::Rejected as i32, 2);

				assert_eq!(PostInspectionResultStatus::Accepted as i32, 1);
				assert_eq!(PostInspectionResultStatus::Partial as i32, 2);
				assert_eq!(PostInspectionResultStatus::Rejected as i32, 3);
			}

			// =================================================================
			// T092: Lease acquisition protobuf tests
			// =================================================================

			#[test]
			fn lease_request_serialize_and_deserialize() {
				let req = LeaseRequest {
					era_id: 100,
					inspector_key: "0x1234567890abcdef".into(),
					ttl_seconds: 60,
					inspector_signature: vec![],
				};

				// Serialize to bytes (as inspector client would send)
				let bytes = req.encode_to_vec();
				assert!(!bytes.is_empty());

				// Deserialize (as ddc-node would receive)
				let decoded = LeaseRequest::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.era_id, req.era_id);
				assert_eq!(decoded.inspector_key, req.inspector_key);
				assert_eq!(decoded.ttl_seconds, req.ttl_seconds);
			}

			#[test]
			fn lease_result_acquired_deserialize() {
				// Simulate ddc-node returning ACQUIRED lease
				let result = LeaseResult {
					status: LeaseStatus::Acquired as i32,
					era_id: 100,
					inspector_key: "0x1234567890abcdef".into(),
					lease_id: "lease-abc-123".into(),
					expires_at: 1700000060,
					current_holder: vec![],
					error_message: String::new(),
					collective_seed: 0,
				};

				let bytes = result.encode_to_vec();

				// Deserialize (as inspector client would receive)
				let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, LeaseStatus::Acquired as i32);
				assert_eq!(decoded.era_id, 100);
				assert_eq!(decoded.lease_id, "lease-abc-123");
				assert_eq!(decoded.expires_at, 1700000060);
				assert!(decoded.current_holder.is_empty());
				assert!(decoded.error_message.is_empty());
			}

			#[test]
			fn lease_result_held_by_other_deserialize() {
				// Simulate ddc-node returning HELD_BY_OTHER lease
				let result = LeaseResult {
					status: LeaseStatus::HeldByOther as i32,
					era_id: 100,
					inspector_key: "0x1234567890abcdef".into(),
					lease_id: String::new(),
					expires_at: 1700000120,
					current_holder: "0xother_inspector_key".into(),
					error_message: String::new(),
					collective_seed: 0,
				};

				let bytes = result.encode_to_vec();
				let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, LeaseStatus::HeldByOther as i32);
				assert_eq!(decoded.current_holder, b"0xother_inspector_key");
				assert!(decoded.lease_id.is_empty());
			}

			#[test]
			fn lease_result_error_deserialize() {
				// Simulate ddc-node returning ERROR lease
				let result = LeaseResult {
					status: LeaseStatus::Error as i32,
					era_id: 100,
					inspector_key: "0x1234567890abcdef".into(),
					lease_id: String::new(),
					expires_at: 0,
					current_holder: vec![],
					error_message: "etcd cluster unavailable".into(),
					collective_seed: 0,
				};

				let bytes = result.encode_to_vec();
				let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
				assert_eq!(decoded.status, LeaseStatus::Error as i32);
				assert_eq!(decoded.error_message, "etcd cluster unavailable");
				assert!(decoded.lease_id.is_empty());
				assert_eq!(decoded.expires_at, 0);
			}
		}
	}

	pub use self::inspection::insp_path_exception;
	pub use self::inspection::InspPathException;
	pub use self::inspection::InspectionReceipt;
	pub use self::inspection::UnverifiedPath;

	impl InspectionReceipt {
		pub fn to_proto_bytes(&self) -> polkadot_sdk::sp_std::vec::Vec<u8> {
			use prost::Message;
			self.encode_to_vec()
		}

		pub fn from_proto_bytes(bytes: &[u8]) -> Option<Self> {
			use prost::Message;
			Self::decode(bytes).ok()
		}
	}

	impl InspPathException {
		/// Merges `other` into `self`, wrapping both in `MultipleExceptions` if needed.
		/// If `self` is already a `MultipleExceptions`, appends `other` to its list.
		pub fn merge(self, other: Self) -> Self {
			match self.kind {
				Some(insp_path_exception::Kind::MultipleExceptions(mut m)) => {
					m.exceptions.push(other);
					Self { kind: Some(insp_path_exception::Kind::MultipleExceptions(m)) }
				},
				_ => Self {
					kind: Some(insp_path_exception::Kind::MultipleExceptions(
						inspection::MultipleExceptions {
							exceptions: polkadot_sdk::sp_std::vec![self, other],
						},
					)),
				},
			}
		}
	}

	impl From<&activity_tree::ActivityNode> for inspection::PathValue {
		fn from(a: &activity_tree::ActivityNode) -> Self {
			inspection::PathValue {
				put_count: a.put_count,
				get_count: a.get_count,
				stored: a.stored,
				transferred: a.transferred,
				cpu_units: a.cpu_units,
				gpu_units: a.gpu_units,
				ram_units: a.ram_units,
				compute_count: a.compute_count,
			}
		}
	}

	impl inspection::InspectionPath {
		/// Blake2b-256 hash of protobuf-serialized bytes, returned as raw 32-byte array.
		pub fn path_hash(&self) -> [u8; 32] {
			use blake2::digest::{consts::U32, Digest};
			use prost::Message;
			blake2::Blake2b::<U32>::digest(self.encode_to_vec()).into()
		}

		/// Blake2b-256 hash of protobuf-serialized bytes, returned as 0x-hex string.
		pub fn path_hash_hex(&self) -> scale_info::prelude::string::String {
			scale_info::prelude::format!("0x{}", hex::encode(self.path_hash()))
		}
	}

	/// Separates a result hash from any other BLAKE2b-256 digest, as ddc-dac's
	/// `inspection.ResultHashTag`.
	pub const RESULT_HASH_TAG: &[u8] = b"ddc-insp/result/v1";

	/// Separates an inspector's submission signature from anything else its key
	/// signs, as ddc-dac's `inspection.SubmissionSigningTag`.
	pub const SUBMISSION_SIGNING_TAG: &[u8] = b"ddc-insp/submission/v1";

	fn push_len_bytes(out: &mut polkadot_sdk::sp_std::vec::Vec<u8>, bytes: &[u8]) {
		out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
		out.extend_from_slice(bytes);
	}

	impl inspection::InspectionPathResult {
		/// Creates a new `InspectionPathResult` with `result_hash` computed as
		/// ddc-dac's `inspection.ResultHash`: BLAKE2b-256 of the tag, the path
		/// hash, the exception bytes, then each source node's key and response
		/// signature, every field length-prefixed with a 4-byte little-endian
		/// length. Without the framing, bytes moved from the exception into a
		/// source key land on the same hash.
		pub fn new(
			path_hash: polkadot_sdk::sp_std::vec::Vec<u8>,
			exception: Option<inspection::InspPathException>,
			source_nodes: polkadot_sdk::sp_std::vec::Vec<inspection::NodeProvenance>,
		) -> Self {
			use blake2::digest::{consts::U32, Digest};
			use prost::Message;
			let exception_bytes = exception.as_ref().map(|exc| exc.encode_to_vec()).unwrap_or_default();
			let mut data = RESULT_HASH_TAG.to_vec();
			push_len_bytes(&mut data, &path_hash);
			push_len_bytes(&mut data, &exception_bytes);
			data.extend_from_slice(&(source_nodes.len() as u32).to_le_bytes());
			for node in &source_nodes {
				push_len_bytes(&mut data, &node.node_key);
				push_len_bytes(&mut data, &node.response_signature);
			}
			let hash: [u8; 32] = blake2::Blake2b::<U32>::digest(&data).into();
			Self { path_hash, result_hash: hash.to_vec(), exception, source_nodes }
		}
	}

	/// The bytes an inspector signs for one submission, as ddc-dac's
	/// `inspection.SubmissionSigningMessage` builds them: the tag, the cluster,
	/// the era and the inspector key, then one entry per result,
	/// path_hash ‖ BLAKE2b-256(exception bytes) ‖ result_hash, in ascending
	/// byte order. Variable-length fields carry a 4-byte little-endian length.
	/// `exceptions[i]` is result `i`'s exception bytes, empty for none.
	pub fn submission_signing_message(
		cluster_id: &[u8],
		era_id: u32,
		inspector_key: &[u8],
		path_hashes: &[polkadot_sdk::sp_std::vec::Vec<u8>],
		result_hashes: &[polkadot_sdk::sp_std::vec::Vec<u8>],
		exceptions: &[polkadot_sdk::sp_std::vec::Vec<u8>],
	) -> Option<polkadot_sdk::sp_std::vec::Vec<u8>> {
		use blake2::digest::{consts::U32, Digest};
		if result_hashes.len() != path_hashes.len() || exceptions.len() != path_hashes.len() {
			return None;
		}
		let mut entries: polkadot_sdk::sp_std::vec::Vec<polkadot_sdk::sp_std::vec::Vec<u8>> = path_hashes
			.iter()
			.zip(result_hashes)
			.zip(exceptions)
			.map(|((path_hash, result_hash), exception)| {
				let digest: [u8; 32] = blake2::Blake2b::<U32>::digest(exception).into();
				let mut entry = polkadot_sdk::sp_std::vec::Vec::new();
				push_len_bytes(&mut entry, path_hash);
				entry.extend_from_slice(&digest);
				push_len_bytes(&mut entry, result_hash);
				entry
			})
			.collect();
		entries.sort();
		let mut message = SUBMISSION_SIGNING_TAG.to_vec();
		push_len_bytes(&mut message, cluster_id);
		message.extend_from_slice(&era_id.to_le_bytes());
		push_len_bytes(&mut message, inspector_key);
		message.extend_from_slice(&(entries.len() as u32).to_le_bytes());
		for entry in entries {
			message.extend_from_slice(&entry);
		}
		Some(message)
	}

	pub mod activity_wasm {
		include!(concat!(env!("OUT_DIR"), "/activity_wasm.rs"));
	}

	pub mod activity_tree {
		include!(concat!(env!("OUT_DIR"), "/activity_tree.rs"));

		use ddc_primitives::NodePubKey;

		impl EhdTreeTraversedNode {
			/// Returns parsed PHD collector keys, filtering out any that fail to parse.
			pub fn get_phd_collectors(&self) -> impl Iterator<Item = NodePubKey> + '_ {
				self.phd_collectors.iter().filter_map(|s| NodePubKey::try_from(s.clone()).ok())
			}

			/// Returns cluster usage aggregated from all providers.
			pub fn get_cluster_usage(&self) -> ActivityNode {
				self.providers.iter().fold(ActivityNode::default(), |mut acc, provider| {
					if let Some(usage) = &provider.provided_usage {
						acc.stored = acc.stored.saturating_add(usage.stored);
						acc.transferred = acc.transferred.saturating_add(usage.transferred);
						acc.put_count = acc.put_count.saturating_add(usage.put_count);
						acc.get_count = acc.get_count.saturating_add(usage.get_count);
						acc.cpu_units = acc.cpu_units.saturating_add(usage.cpu_units);
						acc.gpu_units = acc.gpu_units.saturating_add(usage.gpu_units);
						acc.ram_units = acc.ram_units.saturating_add(usage.ram_units);
						acc.compute_count = acc.compute_count.saturating_add(usage.compute_count);
					}
					acc
				})
			}
		}

		impl PhdNodeAggregateGroup {
			pub fn get_node_key(&self) -> Option<NodePubKey> {
				if self.node_key.len() == 32 {
					let arr: [u8; 32] = self.node_key.as_slice().try_into().ok()?;
					Some(NodePubKey::StoragePubKey(polkadot_sdk::sp_runtime::AccountId32::from(
						arr,
					)))
				} else {
					None
				}
			}
		}

		impl BucketSubAggregate {
			pub fn get_node_key(&self) -> Option<NodePubKey> {
				if self.node_key.len() == 32 {
					let arr: [u8; 32] = self.node_key.as_slice().try_into().ok()?;
					Some(NodePubKey::StoragePubKey(polkadot_sdk::sp_runtime::AccountId32::from(
						arr,
					)))
				} else {
					None
				}
			}
		}

		impl ActivityNode {
			/// Encodes ActivityNode to protobuf bytes
			pub fn to_proto_bytes(&self) -> polkadot_sdk::sp_std::vec::Vec<u8> {
				use prost::Message;
				self.encode_to_vec()
			}

			/// Decodes ActivityNode from protobuf bytes
			pub fn from_proto_bytes(bytes: &[u8]) -> Option<Self> {
				use prost::Message;
				Self::decode(bytes).ok()
			}
		}
	}
}

#[cfg(test)]
mod result_hash_vectors {
	use prost::Message;

	use crate::proto::inspection::{
		insp_path_exception::Kind, provenance_evidence, BucketARsSigUnverified,
		BucketARsUnavailable, BucketAggregateMalformed, BucketIrfUnreached,
		BucketTcaTreeNeedsDeepInspection, InspPathException, InspectionPathResult,
		MultipleExceptions, NodeARsSigUnverified, NodeARsUnavailable, NodeAggregateMalformed,
		NodeIrfUnreached, NodeProvenance, NodeTcaTreeNeedsDeepInspection, PathValue,
		PostInspectionResultRequest, ProvenanceEvidence, TcaInspectionStage, UnverifiedUsage,
	};

	const FIXTURE: &str = include_str!("test_data/result_hash_vectors.json");
	const FIXTURE_PATH: &str = "src/test_data/result_hash_vectors.json";
	const REGENERATE_ENV: &str = "REGENERATE_RESULT_HASH_VECTORS";

	fn usage() -> UnverifiedUsage {
		UnverifiedUsage {
			usage: Some(PathValue {
				put_count: 3,
				get_count: 5,
				stored: -4096,
				transferred: 1 << 40,
				cpu_units: 7,
				gpu_units: 0,
				ram_units: u64::MAX,
				compute_count: 2,
			}),
			evidence: Some(ProvenanceEvidence {
				kind: Some(provenance_evidence::Kind::Signed(NodeProvenance {
					node_key: vec![0xaa; 32],
					response_signature: vec![0xbb; 64],
				})),
			}),
		}
	}

	fn unavailable_usage() -> UnverifiedUsage {
		UnverifiedUsage {
			usage: Some(PathValue::default()),
			evidence: Some(ProvenanceEvidence {
				kind: Some(provenance_evidence::Kind::Unavailable(NodeProvenance {
					node_key: vec![0xcc; 32],
					response_signature: vec![],
				})),
			}),
		}
	}

	fn exception(kind: Kind) -> Option<InspPathException> {
		Some(InspPathException { kind: Some(kind) })
	}

	fn sources(count: u8) -> Vec<NodeProvenance> {
		(0..count)
			.map(|i| NodeProvenance { node_key: vec![i; 32], response_signature: vec![i ^ 0xff; 64] })
			.collect()
	}

	fn cases() -> Vec<(&'static str, Option<InspPathException>, Vec<NodeProvenance>)> {
		let node_key = vec![0x11; 32];
		vec![
			("no exception, no sources", None, vec![]),
			("no exception, three sources", None, sources(3)),
			("empty exception", Some(InspPathException::default()), sources(1)),
			(
				"node irf unreached",
				exception(Kind::NodeIrfUnreached(NodeIrfUnreached {
					node_key: node_key.clone(),
					tca_id: 29807910,
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"bucket irf unreached with empty usage",
				exception(Kind::BucketIrfUnreached(BucketIrfUnreached {
					bucket_id: u64::MAX,
					tca_id: 0,
					unverified_usage: Some(UnverifiedUsage::default()),
				})),
				vec![],
			),
			(
				"node ars sig unverified",
				exception(Kind::NodeArsSigUnverified(NodeARsSigUnverified {
					node_key: node_key.clone(),
					tca_id: 1,
					bad_records_ids: vec![vec![1, 2, 3], vec![], vec![0xff; 16]],
					unverified_usage: Some(usage()),
				})),
				sources(2),
			),
			(
				"bucket ars sig unverified",
				exception(Kind::BucketArsSigUnverified(BucketARsSigUnverified {
					bucket_id: 42,
					node_key: node_key.clone(),
					tca_id: 2,
					bad_records_ids: vec![vec![9; 8]],
					unverified_usage: Some(unavailable_usage()),
				})),
				sources(1),
			),
			(
				"node ars unavailable",
				exception(Kind::NodeArsUnavailable(NodeARsUnavailable {
					node_key: node_key.clone(),
					tca_id: 3,
					leaves_ids: vec![0, 1, 300, u64::MAX],
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"bucket ars unavailable",
				exception(Kind::BucketArsUnavailable(BucketARsUnavailable {
					bucket_id: 7,
					node_key: node_key.clone(),
					tca_id: 4,
					leaves_ids: vec![5],
					unverified_usage: None,
				})),
				sources(1),
			),
			(
				"node aggregate malformed",
				exception(Kind::NodeAggregateMalformed(NodeAggregateMalformed {
					node_key: node_key.clone(),
					tca_id: 5,
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"bucket aggregate malformed",
				exception(Kind::BucketAggregateMalformed(BucketAggregateMalformed {
					bucket_id: 8,
					tca_id: 6,
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"node tca tree needs deep inspection",
				exception(Kind::NodeTcaTreeNeedsDeepInspection(NodeTcaTreeNeedsDeepInspection {
					node_key: node_key.clone(),
					tca_id: 7,
					stage: TcaInspectionStage::RebuildMismatch as i32,
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"bucket tca tree needs deep inspection",
				exception(Kind::BucketTcaTreeNeedsDeepInspection(BucketTcaTreeNeedsDeepInspection {
					bucket_id: 9,
					node_key: node_key.clone(),
					tca_id: 8,
					stage: TcaInspectionStage::NoMatchingPair as i32,
					unverified_usage: Some(usage()),
				})),
				sources(1),
			),
			(
				"multiple exceptions, nested",
				exception(Kind::MultipleExceptions(MultipleExceptions {
					exceptions: vec![
						InspPathException {
							kind: Some(Kind::NodeIrfUnreached(NodeIrfUnreached {
								node_key: node_key.clone(),
								tca_id: 10,
								unverified_usage: Some(usage()),
							})),
						},
						InspPathException {
							kind: Some(Kind::MultipleExceptions(MultipleExceptions {
								exceptions: vec![InspPathException {
									kind: Some(Kind::BucketAggregateMalformed(
										BucketAggregateMalformed {
											bucket_id: 11,
											tca_id: 12,
											unverified_usage: None,
										},
									)),
								}],
							})),
						},
					],
				})),
				sources(3),
			),
		]
	}

	fn render() -> String {
		let vectors: Vec<serde_json::Value> = cases()
			.into_iter()
			.enumerate()
			.map(|(i, (name, exception, source_nodes))| {
				let path_hash = vec![i as u8 + 1; 32];
				let result = InspectionPathResult::new(path_hash, exception, source_nodes);
				let request = PostInspectionResultRequest {
					era_id: 1,
					inspector_key: vec![0x22; 32],
					inspector_signature: vec![0x33; 64],
					paths_results: vec![result.clone()],
				};
				serde_json::json!({
					"name": name,
					"request": hex::encode(request.encode_to_vec()),
					"result_hash": hex::encode(&result.result_hash),
				})
			})
			.collect();
		serde_json::to_string_pretty(&vectors).unwrap() + "\n"
	}

	#[test]
	fn a_result_hash_matches_ddc_dacs_pinned_encoding() {
		let exception = InspPathException {
			kind: Some(Kind::NodeAggregateMalformed(NodeAggregateMalformed {
				node_key: vec![],
				tca_id: 1,
				unverified_usage: None,
			})),
		};
		assert_eq!(exception.encode_to_vec(), vec![0x42, 0x02, 0x10, 0x01]);
		let sources = vec![
			NodeProvenance { node_key: vec![0x33; 32], response_signature: vec![0x44; 64] },
			NodeProvenance { node_key: vec![0x55; 32], response_signature: vec![] },
		];
		let framed = InspectionPathResult::new(vec![0x11; 32], Some(exception), sources);
		assert_eq!(
			hex::encode(&framed.result_hash),
			"8689d061cbf4ed8650e9d96cc9b6f32c39fcbbba5a4dcffd0af30c1dc37fa669"
		);
		let bare = InspectionPathResult::new(vec![0x11; 32], None, vec![]);
		assert_eq!(
			hex::encode(&bare.result_hash),
			"10cf76eff7571c249ebd971cafff37d9e47efb011bbae834a2668c5566338745"
		);
	}

	#[test]
	fn an_exception_moved_into_a_source_key_changes_the_result_hash() {
		let exception = InspPathException {
			kind: Some(Kind::NodeIrfUnreached(NodeIrfUnreached {
				node_key: vec![0x22; 32],
				tca_id: 1,
				unverified_usage: Some(usage()),
			})),
		};
		let source = NodeProvenance { node_key: vec![0x33; 32], response_signature: vec![0x44; 64] };
		let mut shifted = exception.encode_to_vec();
		shifted.extend_from_slice(&source.node_key);
		shifted.extend_from_slice(&source.response_signature);

		let honest = InspectionPathResult::new(vec![0x11; 32], Some(exception), vec![source]);
		let forged = InspectionPathResult::new(
			vec![0x11; 32],
			None,
			vec![NodeProvenance { node_key: shifted, response_signature: vec![] }],
		);
		assert_ne!(honest.result_hash, forged.result_hash);
	}

	#[test]
	fn a_submission_signing_message_matches_ddc_dacs_pinned_encoding() {
		let message = crate::proto::submission_signing_message(
			b"cluster-1",
			1495203,
			&[0x0c; 32],
			&[vec![0x02; 32], vec![0x01; 32]],
			&[vec![0xbb; 32], vec![0xaa; 32]],
			&[vec![0x0a, 0x02, 0x08, 0x01], vec![]],
		)
		.unwrap();
		assert_eq!(hex::encode(message), "6464632d696e73702f7375626d697373696f6e2f763109000000636c75737465722d31a3d01600200000000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c020000002000000001010101010101010101010101010101010101010101010101010101010101010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a820000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2000000002020202020202020202020202020202020202020202020202020202020202026862d269447d0413e07bbb23be38dea34b151ff6a9898fa6dd34657e6f909a3820000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
	}

	#[test]
	fn a_submission_signing_message_needs_one_exception_and_result_per_path() {
		assert!(crate::proto::submission_signing_message(b"c", 1, b"k", &[vec![1]], &[vec![2]], &[]).is_none());
	}

	#[test]
	fn result_hash_vectors_match_the_committed_fixture() {
		let rendered = render();
		if std::env::var(REGENERATE_ENV).is_ok() {
			std::fs::write(FIXTURE_PATH, &rendered).unwrap();
			return;
		}
		assert_eq!(rendered, FIXTURE, "regenerate with {}=1 cargo test", REGENERATE_ENV);
	}
}
