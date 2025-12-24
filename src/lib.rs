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

    pub mod activity {
        include!(concat!(env!("OUT_DIR"), "/activity.rs"));
    }

    pub mod inspection {
        include!(concat!(env!("OUT_DIR"), "/inspection.rs"));
    }

    pub mod activity_tree {
        include!(concat!(env!("OUT_DIR"), "/activity_tree.rs"));

        use ddc_primitives::{NodePubKey, PHDId};

        impl EhdTreeTraversedNode {
            /// Returns parsed PHD IDs, filtering out any that fail to parse.
            pub fn get_phds(&self) -> impl Iterator<Item = PHDId> + '_ {
                self.phd_ids.iter().filter_map(|s| PHDId::try_from(s.clone()).ok())
            }

            /// Returns cluster usage aggregated from all providers.
            pub fn get_cluster_usage(&self) -> ActivityNode {
                self.providers.iter().fold(
                    ActivityNode::default(),
                    |mut acc, provider| {
                        if let Some(usage) = &provider.provided_usage {
                            acc.stored += usage.stored;
                            acc.transferred += usage.transferred;
                            acc.put_count += usage.put_count;
                            acc.get_count += usage.get_count;
                            acc.cpu_units += usage.cpu_units;
                            acc.gpu_units += usage.gpu_units;
                            acc.ram_units += usage.ram_units;
                            acc.compute_count += usage.compute_count;
                        }
                        acc
                    },
                )
            }
        }

        impl PhdTreeTraversedNode {
            pub fn get_collector_key(&self) -> Option<NodePubKey> {
                if self.collector_id.len() == 32 {
                    let arr: [u8; 32] = self.collector_id.as_slice().try_into().ok()?;
                    Some(NodePubKey::StoragePubKey(sp_runtime::AccountId32::from(arr)))
                } else {
                    None
                }
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
    }
}
