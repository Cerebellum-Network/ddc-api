#![cfg_attr(not(feature = "std"), no_std)]

pub const LOG_TARGET: &str = "ddc-api";

pub mod api;
pub mod client;
pub mod verification;

pub mod json;
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
        pub use super::auth::{AuthToken, Payload, Operation};

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
                let req = LeaseRequest {
                    era_id: 42,
                    inspector_key: "0xabc123".into(),
                    ttl_seconds: 300,
                };

                let bytes = req.encode_to_vec();
                assert!(!bytes.is_empty());

                let decoded = LeaseRequest::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.era_id, 42);
                assert_eq!(decoded.inspector_key, "0xabc123");
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
                    current_holder: String::new(),
                    error_message: String::new(),
                };

                let bytes = res.encode_to_vec();
                let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.status, LeaseStatus::Acquired as i32);
                assert_eq!(decoded.era_id, 42);
                assert_eq!(decoded.inspector_key, "0xabc123");
                assert_eq!(decoded.lease_id, "lease-001");
                assert_eq!(decoded.expires_at, 1700000000);
            }

            #[test]
            fn assignment_table_round_trip() {
                use inspection_path::PathData;

                let mut paths = BTreeMap::new();
                paths.insert(
                    "path-001".into(),
                    InspectionPath {
                        path_type: InspectionPathType::NodeAr as i32,
                        collectors: vec!["0xc0c1".into(), "0xc2c3".into()],
                        path_data: Some(PathData::NodeAr(NodeArPath {
                            node_key: "0x0a0b".into(),
                            leaves_ids: vec![1, 2, 3],
                            tca_id: 5,
                        })),
                    },
                );

                let mut assignments = BTreeMap::new();
                assignments.insert(
                    "path-001".into(),
                    InspectorAssignments {
                        main_inspectors: vec!["insp1".into(), "insp2".into()],
                        backup_inspectors: vec!["insp3".into()],
                    },
                );

                let table = AssignmentTable {
                    cluster_id: "0xaabb".into(),
                    era: 42,
                    irf: 3,
                    paths,
                    assignments,
                    collective_seed: 12345,
                    builder: "0xabc123".into(),
                    submitted_at: 1700000000,
                    archived_cid: vec![],
                    archived_at: 0,
                    archival_status: ArchivalStatus::Pending as i32,
                };

                let bytes = table.encode_to_vec();
                let decoded = AssignmentTable::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.era, 42);
                assert_eq!(decoded.irf, 3);
                assert_eq!(decoded.paths.len(), 1);
                assert_eq!(decoded.assignments.len(), 1);
                assert_eq!(
                    decoded.paths["path-001"].path_type,
                    InspectionPathType::NodeAr as i32
                );
                assert_eq!(decoded.paths["path-001"].collectors.len(), 2);
                match &decoded.paths["path-001"].path_data {
                    Some(PathData::NodeAr(node_ar)) => {
                        assert_eq!(node_ar.node_key, "0x0a0b");
                        assert_eq!(node_ar.leaves_ids, vec![1, 2, 3]);
                        assert_eq!(node_ar.tca_id, 5);
                    }
                    _ => panic!("Expected NodeAr path_data"),
                }
                assert_eq!(decoded.assignments["path-001"].main_inspectors.len(), 2);
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
                        assignments: BTreeMap::new(),
                        collective_seed: 0,
                        builder: "0xabc123".into(),
                        submitted_at: 0,
                        archived_cid: vec![],
                        archived_at: 0,
                        archival_status: 0,
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
                assert_eq!(decoded.lease_holder, "0xdef456");
            }

            #[test]
            fn post_inspection_result_request_round_trip() {
                let req = PostInspectionResultRequest {
                    era_id: 42,
                    inspector_key: "0xabc123".into(),
                    inspector_signature: String::new(),
                    paths_results: vec![
                        InspectionPathResult {
                            path_hash: "0x01".into(),
                            result_hash: "0xaabbcc".into(),
                            exception: None,
                            source_collectors: vec![],
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
                            source_collectors: vec![],
                        },
                    ],
                };

                let bytes = req.encode_to_vec();
                let decoded = PostInspectionResultRequest::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.paths_results.len(), 2);
                assert_eq!(decoded.paths_results[0].path_hash, "0x01");
                assert!(decoded.paths_results[1].exception.is_some());
                match &decoded.paths_results[1].exception.as_ref().unwrap().kind {
                    Some(insp_path_exception::Kind::NodeArsUnavailable(inner)) => {
                        assert_eq!(inner.node_key, "0xnode1");
                        assert_eq!(inner.tca_id, 1);
                    }
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
                        remaining_inspectors: vec!["insp4".into()],
                    },
                );

                let state = InspectionState {
                    era_id: 42,
                    total_paths: 10,
                    verified_paths: 5,
                    unverified_paths: 2,
                    pending_paths: 3,
                    irf: 3,
                    paths,
                    updated_at: 1700000000,
                    archived_cid: vec![],
                    archived_at: 0,
                    archival_status: 0,
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
                    quorum_unreached_paths: vec!["0x04".into()],
                    assignments_hash: String::new(),
                    state_hash: String::new(),
                    generated_at: 1700000000,
                    complete: true,
                    archived_cid: vec![],
                    archived_at: 0,
                    archival_status: 0,
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
                assert_eq!(req.inspector_key, "");
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
                    current_holder: String::new(),
                    error_message: String::new(),
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
                };

                let bytes = result.encode_to_vec();
                let decoded = LeaseResult::decode(bytes.as_slice()).unwrap();
                assert_eq!(decoded.status, LeaseStatus::HeldByOther as i32);
                assert_eq!(decoded.current_holder, "0xother_inspector_key");
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
                    current_holder: String::new(),
                    error_message: "etcd cluster unavailable".into(),
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

    pub use self::inspection::InspectionReceipt;
    pub use self::inspection::InspPathException;
    pub use self::inspection::insp_path_exception;
    pub use self::inspection::UnverifiedPath;


    impl InspectionReceipt {
        pub fn to_proto_bytes(&self) -> sp_std::vec::Vec<u8> {
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
                }
                _ => Self {
                    kind: Some(insp_path_exception::Kind::MultipleExceptions(
                        inspection::MultipleExceptions {
                            exceptions: sp_std::vec![self, other],
                        },
                    )),
                },
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

    impl inspection::InspectionPathResult {
        /// Creates a new `InspectionPathResult` with `result_hash` computed as
        /// Blake2b-256(path_hash_bytes || exception_bytes || source_collectors).
        pub fn new(
            path_hash: scale_info::prelude::string::String,
            exception: Option<inspection::InspPathException>,
            source_collectors: sp_std::vec::Vec<inspection::Provenance>,
        ) -> Self {
            use blake2::digest::{consts::U32, Digest};
            use prost::Message;
            let path_hash_bytes = hex::decode(path_hash.trim_start_matches("0x"))
                .unwrap_or_default();
            let mut data = sp_std::vec::Vec::new();
            data.extend_from_slice(&path_hash_bytes);
            if let Some(ref exc) = exception {
                data.extend_from_slice(&exc.encode_to_vec());
            }
            for cr in &source_collectors {
                data.extend_from_slice(cr.collector_key.as_bytes());
                data.extend_from_slice(&cr.response_signature);
            }
            let hash: [u8; 32] = blake2::Blake2b::<U32>::digest(&data).into();
            Self {
                path_hash,
                result_hash: scale_info::prelude::format!("0x{}", hex::encode(hash)),
                exception,
                source_collectors,
            }
        }
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
                self.providers.iter().fold(
                    ActivityNode::default(),
                    |mut acc, provider| {
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
                    },
                )
            }
        }

        impl PhdTreeTraversedNode {
            // TODO(T094): the collector_id field was removed from PhdTreeTraversedNode;
            // the serving Collector's identity is now read from the SignedResponse
            // envelope, not from the message body. Until the call sites in
            // insp_task_manager.rs are migrated to consume the envelope's signer,
            // this stub keeps the public API shape and returns None so existing
            // `let Some(...) else { ... }` branches take the short-circuit path.
            pub fn get_collector_key(&self) -> Option<NodePubKey> {
                None
            }
        }

        impl PhdNodeAggregateGroup {
            pub fn get_node_key(&self) -> Option<NodePubKey> {
                if self.node_key.len() == 32 {
                    let arr: [u8; 32] = self.node_key.as_slice().try_into().ok()?;
                    Some(NodePubKey::StoragePubKey(sp_runtime::AccountId32::from(arr)))
                } else {
                    None
                }
            }
        }

        impl BucketSubAggregate {
            pub fn get_node_key(&self) -> Option<NodePubKey> {
                if self.node_key.len() == 32 {
                    let arr: [u8; 32] = self.node_key.as_slice().try_into().ok()?;
                    Some(NodePubKey::StoragePubKey(sp_runtime::AccountId32::from(arr)))
                } else {
                    None
                }
            }
        }

        impl ActivityNode {

            /// Encodes ActivityNode to protobuf bytes
            pub fn to_proto_bytes(&self) -> sp_std::vec::Vec<u8> {
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
