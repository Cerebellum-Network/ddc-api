#![allow(dead_code)]
#![allow(clippy::from_over_into)]

use api::{ApiResponse, SignedBy};
use ddc_primitives::{BucketId, ClusterId, EHDId, EhdEra, NodePubKey, PHDId, TcaEra};
use prost::Message;
use scale_info::prelude::{format, string::String, vec::Vec};
use sp_io::offchain::timestamp;
use sp_runtime::offchain::{http, Duration};
use sp_std::vec;

use super::*;
use crate::{json, log, verification::Verify};

pub struct DdcClient<'a> {
    pub base_url: &'a str,
    timeout: Duration,
    retries: u32,
    verify_sig: bool,
    dry_run: bool,
}

macro_rules! fetch_and_parse_json {
    (
        // Self reference (the aggregator client)
        $self:expr,
        // URL string variable (mutable)
        $url:expr,
        // The type of the JSON response if not signed
        $unsigned_ty:ty,
        // The type of the JSON response if signed
        $signed_ty:ty
    ) => {{
        if $self.verify_sig {
            if $url.contains('?') {
                $url = format!("{}&sign=true", $url);
            } else {
                $url = format!("{}?sign=true", $url);
            }
        }

        let response = $self.get(&$url, Accept::Any)?;
        let body = response.body().collect::<Vec<u8>>();

        if $self.verify_sig {
            let json_signed_response: json::SignedJsonResponse<$signed_ty> =
                serde_json::from_slice(&body).map_err(|e| {
                    log!(error, "❌ Failed to parse signed .json: {:?}", e);
                    http::Error::Unknown
                })?;

            if !json_signed_response.verify() {
                log!(
                    error,
                    "❌ Bad .json signature, req: {:?}, resp: {:?}",
                    $url,
                    json_signed_response
                );
                return Err(http::Error::Unknown);
            }

            let json_response = json_signed_response.payload;
            let signed_by = SignedBy {
                signer: json_signed_response.signer,
                signature: json_signed_response.signature,
            };

            Ok((json_response, Some(signed_by)))
        } else {
            let json_response: $unsigned_ty = serde_json::from_slice(&body).map_err(|e| {
                log!(error, "❌ Failed to parse unsigned .json: {:?}", e);
                http::Error::Unknown
            })?;

            Ok((json_response, None))
        }
    }};
}

macro_rules! fetch_and_parse_proto {
    (
        // Self reference (the aggregator client)
        $self:expr,
        // URL string variable (mutable)
        $url:expr,
        // The type of the JSON response if not signed
        $unsigned_ty:ty,
        // The type of the JSON response if signed
        $signed_ty:ty
    ) => {{
        if $self.verify_sig {
            if $url.contains('?') {
                $url = format!("{}&sign=true", $url);
            } else {
                $url = format!("{}?sign=true", $url);
            }
        }

        let response = $self.get(&$url, Accept::Protobuf)?;
        let body = response.body().collect::<Vec<u8>>();

        if $self.verify_sig {
            let proto_signed_response = proto::signature::SignedResponse::decode(body.as_slice())
                .map_err(|_| http::Error::Unknown)?;

            if !proto_signed_response.verify() {
                log!(
                    error,
                    "❌ Bad .proto signature, req: {:?}, resp: {:?}",
                    $url,
                    proto_signed_response
                );
                return Err(http::Error::Unknown);
            }

            let proto_response: $signed_ty =
                <$signed_ty>::decode(proto_signed_response.payload.as_slice())
                    .map_err(|_| http::Error::Unknown)
                    .map_err(|e| {
                        log::error!("❌ Failed to parse signed .proto: {:?}", e);
                        http::Error::Unknown
                    })?;
            let signed_by = proto_signed_response
                .signature
                .map(|v| SignedBy {
                    signer: v.signer,
                    signature: v.value,
                })
                .ok_or(http::Error::Unknown)?;

            Ok((proto_response, Some(signed_by)))
        } else {
            let proto_response: $unsigned_ty = <$unsigned_ty>::decode(body.as_slice())
                .map_err(|_| http::Error::Unknown)
                .map_err(|e| {
                    log!(error, "❌ Failed to parse unsigned .proto: {:?}", e);
                    http::Error::Unknown
                })?;

            Ok((proto_response, None))
        }
    }};
}

impl<'a> DdcClient<'a> {
    pub fn new(base_url: &'a str, timeout: Duration, retries: u32, verify_sig: bool) -> Self {
        Self {
            base_url,
            timeout,
            retries,
            verify_sig,
            dry_run: false,
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    fn insp_mem_url(&self, path: &str) -> String {
        let url = format!("{}{}", self.base_url, path);
        if self.dry_run {
            if url.contains('?') {
                format!("{}&dryRun=true", url)
            } else {
                format!("{}?dryRun=true", url)
            }
        } else {
            url
        }
    }

    pub fn buckets_aggregates(
        &self,
        era_id: TcaEra,
        prev_token: Option<BucketId>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<proto::activity_tree::BucketAggregatesResponse>, http::Error> {
        let mut url = format!("{}/activity/buckets?tcaId={}", self.base_url, era_id);
        if let Some(prev_token) = prev_token {
            url = format!("{}&prevToken={}", url, prev_token);
        }
        if let Some(limit) = limit {
            url = format!("{}&limit={}", url, limit);
        }

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::BucketAggregatesResponse,
            proto::activity_tree::BucketAggregatesResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn bucket_aggregate(
        &self,
        era_id: TcaEra,
        bucket_id: BucketId,
    ) -> Result<ApiResponse<proto::activity_tree::BucketAggregatesResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/buckets/{}?tcaId={}",
            self.base_url, bucket_id, era_id
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::BucketAggregatesResponse,
            proto::activity_tree::BucketAggregatesResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn node_aggregate(
        &self,
        era_id: TcaEra,
        node_key: NodePubKey,
    ) -> Result<ApiResponse<proto::activity_tree::NodeAggregatesResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/nodes/{}?tcaId={}",
            self.base_url,
            <NodePubKey as Into<String>>::into(node_key),
            era_id
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::NodeAggregatesResponse,
            proto::activity_tree::NodeAggregatesResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn challenge_bucket_sub_aggregate(
        &self,
        era_id: TcaEra,
        bucket_id: BucketId,
        node_id: &str,
        merkle_tree_node_id: Vec<u64>,
    ) -> Result<ApiResponse<proto::activity::ChallengeResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/buckets/{}/challenge?tcaId={}&nodeId={}&merkleTreeNodeId={}",
            self.base_url,
            bucket_id,
            era_id,
            node_id,
            Self::merkle_tree_node_id_param(merkle_tree_node_id.as_slice()),
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity::ChallengeResponse,
            proto::activity::ChallengeResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn challenge_node_aggregate(
        &self,
        era_id: TcaEra,
        node_id: &str,
        merkle_tree_node_id: Vec<u64>,
    ) -> Result<ApiResponse<proto::activity::ChallengeResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/nodes/{}/challenge?tcaId={}&merkleTreeNodeId={}",
            self.base_url,
            node_id,
            era_id,
            Self::merkle_tree_node_id_param(merkle_tree_node_id.as_slice()),
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity::ChallengeResponse,
            proto::activity::ChallengeResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn tcas(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::AggregationEraResponse>>, http::Error> {
        let mut url = format!("{}/activity/tcas", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) = fetch_and_parse_json!(
            self,
            url,
            Vec<json::AggregationEraResponse>,
            Vec<json::AggregationEraResponse>
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn eras(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::EHDEra>>, http::Error> {
        let mut url = format!("{}/activity/eras", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) =
            fetch_and_parse_json!(self, url, Vec<json::EHDEra>, Vec<json::EHDEra>)?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn inspected_eras(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::EHDEra>>, http::Error> {
        let mut url = format!("{}/activity/inspected-eras", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) =
            fetch_and_parse_json!(self, url, Vec<json::EHDEra>, Vec<json::EHDEra>)?;

        Ok(ApiResponse { response, signed_by })
    }

    pub fn processed_eras(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::EHDEra>>, http::Error> {
        let mut url = format!("{}/activity/processed-eras", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) =
            fetch_and_parse_json!(self, url, Vec<json::EHDEra>, Vec<json::EHDEra>)?;

        Ok(ApiResponse { response, signed_by })
    }

    pub fn dry_run_inspected_eras(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::EHDEra>>, http::Error> {
        let mut url = format!("{}/itm/dry-run/inspected-eras", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) =
            fetch_and_parse_json!(self, url, Vec<json::EHDEra>, Vec<json::EHDEra>)?;

        Ok(ApiResponse { response, signed_by })
    }

    pub fn dry_run_processed_eras(
        &self,
        prev: Option<EhdEra>,
        limit: Option<u32>,
    ) -> Result<ApiResponse<Vec<json::EHDEra>>, http::Error> {
        let mut url = format!("{}/itm/dry-run/processed-eras", self.base_url);
        if let Some(prev) = prev {
            url = format!("{}?prevToken={}", url, prev);
        }
        if let Some(limit) = limit {
            if url.contains('?') {
                url = format!("{}&limit={}", url, limit);
            } else {
                url = format!("{}?limit={}", url, limit);
            }
        }

        let (response, signed_by) =
            fetch_and_parse_json!(self, url, Vec<json::EHDEra>, Vec<json::EHDEra>)?;

        Ok(ApiResponse { response, signed_by })
    }

    pub fn traverse_era_historical_document(
        &self,
        cluster_id: ClusterId,
        era: EhdEra,
        g_collector: NodePubKey,
        tree_node_id: u32,
        tree_levels_count: u32,
    ) -> Result<ApiResponse<proto::activity_tree::EhdTreeTraversalResponse>, http::Error> {
        let ehd_id = EHDId(cluster_id, g_collector, era);
        let mut url = format!(
            "{}/activity/ehds/{}/traverse?merkleTreeNodeId={}&levels={}",
            self.base_url,
            <EHDId as Into<String>>::into(ehd_id),
            tree_node_id,
            tree_levels_count
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::EhdTreeTraversalResponse,
            proto::activity_tree::EhdTreeTraversalResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn traverse_partial_historical_document(
        &self,
        era: EhdEra,
        collector: NodePubKey,
        tree_node_id: u32,
        tree_levels_count: u32,
    ) -> Result<ApiResponse<proto::activity_tree::PhdTreeTraversalResponse>, http::Error> {
        let phd_id = PHDId(collector, era);
        let mut url = format!(
            "{}/activity/phds/{}/traverse?merkleTreeNodeId={}&levels={}",
            self.base_url,
            <PHDId as Into<String>>::into(phd_id),
            tree_node_id,
            tree_levels_count
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::PhdTreeTraversalResponse,
            proto::activity_tree::PhdTreeTraversalResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn traverse_node_aggregate(
        &self,
        tca_id: TcaEra,
        node_key: NodePubKey,
        merkle_tree_node_id: u64,
        levels: u16,
    ) -> Result<ApiResponse<proto::activity_tree::ActivityTreeTraversalResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/nodes/{}/traverse?tcaId={}&merkleTreeNodeId={}&levels={}",
            self.base_url,
            <NodePubKey as Into<String>>::into(node_key),
            tca_id,
            merkle_tree_node_id,
            levels,
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::ActivityTreeTraversalResponse,
            proto::activity_tree::ActivityTreeTraversalResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    pub fn traverse_bucket_sub_aggregate(
        &self,
        tca_id: TcaEra,
        bucket_id: BucketId,
        node_key: NodePubKey,
        merkle_tree_node_id: u64,
        levels: u16,
    ) -> Result<ApiResponse<proto::activity_tree::ActivityTreeTraversalResponse>, http::Error> {
        let mut url = format!(
            "{}/activity/buckets/{}/traverse?tcaId={}&nodeId={}&merkleTreeNodeId={}&levels={}",
            self.base_url,
            bucket_id,
            tca_id,
            <NodePubKey as Into<String>>::into(node_key),
            merkle_tree_node_id,
            levels,
        );

        let (response, signed_by) = fetch_and_parse_proto!(
            self,
            url,
            proto::activity_tree::ActivityTreeTraversalResponse,
            proto::activity_tree::ActivityTreeTraversalResponse
        )?;

        let api_response = ApiResponse {
            response,
            signed_by,
        };

        Ok(api_response)
    }

    fn merkle_tree_node_id_param(merkle_tree_node_id: &[u64]) -> String {
        merkle_tree_node_id
            .iter()
            .map(|x| format!("{}", x.clone()))
            .collect::<Vec<_>>()
            .join(",")
    }


    // ========================================================================
    // Inspection Client Methods (inspection protobuf types)
    // ========================================================================
    // These methods use the new etcd-based sync quorum API with full protobuf
    // serialization for both request and response bodies.

    /// POST /itm/lease - Acquire exclusive lease for building assignment table (protobuf)
    pub fn post_itm_lease(
        &self,
        request: &proto::inspection::LeaseRequest,
    ) -> Result<proto::inspection::LeaseResult, http::Error> {
        let url = self.insp_mem_url("/itm/lease");
        let body = request.encode_to_vec();

        let response = self.post_proto(&url, body)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::LeaseResult::decode(body.as_slice()).map_err(|e| {
            log!(error, "❌ Failed to decode LeaseResult protobuf: {:?}", e);
            http::Error::Unknown
        })
    }

    /// POST /itm/submit - Submit completed assignment table (protobuf)
    pub fn submit_assignments_table(
        &self,
        request: &proto::inspection::PostAssignmentTableRequest,
    ) -> Result<proto::inspection::PostAssignmentTableResponse, http::Error> {
        let url = self.insp_mem_url("/itm/submit");
        let body = request.encode_to_vec();

        let response = self.post_proto(&url, body)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::PostAssignmentTableResponse::decode(body.as_slice()).map_err(
            |e| {
                log!(
                    error,
                    "❌ Failed to decode PostAssignmentTableResponse protobuf: {:?}",
                    e
                );
                http::Error::Unknown
            },
        )
    }

    /// GET /itm/table - Retrieve assignment table (protobuf)
    pub fn get_assignments_table(
        &self,
        era: EhdEra,
    ) -> Result<proto::inspection::GetAssignmentTableResponse, http::Error> {
        let url = self.insp_mem_url(&format!("/itm/table?eraId={}", era));

        let response = self.get(&url, Accept::Protobuf)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::GetAssignmentTableResponse::decode(body.as_slice()).map_err(
            |e| {
                log!(
                    error,
                    "❌ Failed to decode GetAssignmentTableResponse protobuf: {:?}",
                    e
                );
                http::Error::Unknown
            },
        )
    }

    /// POST /itm/path - Submit inspection path results (protobuf)
    pub fn submit_inspection_result(
        &self,
        request: &proto::inspection::PostInspectionResultRequest,
    ) -> Result<proto::inspection::PostInspectionResultResponse, http::Error> {
        let url = self.insp_mem_url("/itm/path");
        let body = request.encode_to_vec();

        let response = self.post_proto(&url, body)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::PostInspectionResultResponse::decode(body.as_slice()).map_err(
            |e| {
                log!(
                    error,
                    "❌ Failed to decode PostInspectionResultResponse protobuf: {:?}",
                    e
                );
                http::Error::Unknown
            },
        )
    }

    /// GET /itm/state - Retrieve inspection state (protobuf)
    pub fn get_inspection_state(
        &self,
        era: EhdEra,
    ) -> Result<proto::inspection::InspectionState, http::Error> {
        let url = self.insp_mem_url(&format!("/itm/state?eraId={}", era));

        let response = self.get(&url, Accept::Protobuf)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::InspectionState::decode(body.as_slice()).map_err(|e| {
            log!(
                error,
                "❌ Failed to decode InspectionState protobuf: {:?}",
                e
            );
            http::Error::Unknown
        })
    }

    /// GET /itm/receipt - Retrieve inspection receipt (protobuf)
    pub fn get_inspection_receipt(
        &self,
        era: EhdEra,
    ) -> Result<proto::inspection::InspectionReceipt, http::Error> {
        let url = self.insp_mem_url(&format!("/itm/receipt?eraId={}", era));

        let response = self.get(&url, Accept::Protobuf)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::InspectionReceipt::decode(body.as_slice()).map_err(|e| {
            log!(
                error,
                "❌ Failed to decode InspectionReceipt protobuf: {:?}",
                e
            );
            http::Error::Unknown
        })
    }

    /// GET /itm/quorum - Retrieve quorum information (protobuf)
    pub fn get_quorum_info(
        &self,
        era: EhdEra,
    ) -> Result<proto::inspection::InspSyncQuorumInfo, http::Error> {
        let url = format!("{}/itm/quorum?eraId={}", self.base_url, era);

        let response = self.get(&url, Accept::Protobuf)?;
        let body = response.body().collect::<Vec<u8>>();

        proto::inspection::InspSyncQuorumInfo::decode(body.as_slice()).map_err(|e| {
            log!(
                error,
                "❌ Failed to decode InspSyncQuorumInfo protobuf: {:?}",
                e
            );
            http::Error::Unknown
        })
    }

    pub fn get_grouping_collectors(&self) -> Result<json::GCollectorsResponse, http::Error> {
        let mut url = format!("{}/activity/grouping-collectors", self.base_url);
        let (response, _) = fetch_and_parse_json!(
            self,
            url,
            json::GCollectorsResponse,
            json::GCollectorsResponse
        )?;

        Ok(response)
    }

    fn get(&self, url: &str, accept: Accept) -> Result<http::Response, http::Error> {
        let mut maybe_response = None;

        let deadline = timestamp().add(self.timeout);
        let mut error = None;

        for i in 0..self.retries {
            log!(
                trace,
                "Sending HTTP GET request to {:?}, attempt: {:?}",
                url,
                i + 1
            );
            let mut request = http::Request::get(url).deadline(deadline);
            request = match accept {
                Accept::Any => request,
                Accept::Protobuf => request.add_header("Accept", "application/protobuf"),
            };

            let pending = match request.send() {
                Ok(p) => p,
                Err(_) => {
                    error = Some(http::Error::IoError);
                    continue;
                }
            };

            match pending.try_wait(deadline) {
                Ok(Ok(r)) => {
                    maybe_response = Some(r);
                    error = None;
                    break;
                }
                Ok(Err(_)) | Err(_) => {
                    error = Some(http::Error::DeadlineReached);
                    continue;
                }
            }
        }

        if let Some(e) = error {
            log!(
                error,
                "❌ HTTP GET client error for url {:?}, error {:?}",
                url,
                e
            );
            return Err(e);
        }

        let response = match maybe_response {
            Some(r) => r,
            None => {
                log!(
                    error,
                    "❌ HTTP GET client error for url {:?}, no response",
                    url
                );
                return Err(http::Error::Unknown);
            }
        };

        if response.code >= 500 {
            log!(
                error,
                "❌ HTTP GET client error for url {:?}, status code is {:?}",
                url,
                response.code
            );
            return Err(http::Error::Unknown);
        }

        log!(trace, "HTTP GET request to {:?} completed", url,);

        Ok(response)
    }

    /// Send a POST request with protobuf-encoded body (Content-Type: application/protobuf)
    /// and expect a protobuf response (Accept: application/protobuf).
    /// Used by inspection client methods for the new etcd-based sync quorum API.
    fn post_proto(
        &self,
        url: &str,
        request_body: Vec<u8>,
    ) -> Result<http::Response, http::Error> {
        let mut maybe_response = None;

        let deadline = timestamp().add(self.timeout);
        let mut error = None;

        for i in 0..self.retries {
            log!(
                trace,
                "Sending HTTP POST (protobuf) request to {:?}, attempt: {:?}",
                url,
                i + 1
            );
            let request = http::Request::post(url, vec![request_body.clone()])
                .add_header("content-type", "application/protobuf")
                .add_header("Accept", "application/protobuf");

            let pending = request
                .deadline(deadline)
                .body(vec![request_body.clone()])
                .send()
                .map_err(|_| http::Error::IoError)?;

            match pending.try_wait(deadline) {
                Ok(Ok(r)) => {
                    maybe_response = Some(r);
                    error = None;
                    break;
                }
                Ok(Err(_)) | Err(_) => {
                    error = Some(http::Error::DeadlineReached);
                    continue;
                }
            }
        }

        if let Some(e) = error {
            log!(
                error,
                "❌ HTTP POST (protobuf) client error for url {:?}, error {:?}",
                url,
                e
            );
            return Err(e);
        }

        let response = match maybe_response {
            Some(r) => r,
            None => {
                log!(
                    error,
                    "❌ HTTP POST (protobuf) client error for url {:?}, no response",
                    url
                );
                return Err(http::Error::Unknown);
            }
        };

        if response.code >= 500 {
            log!(
                error,
                "❌ HTTP POST (protobuf) client error for url {:?}, status code is {:?}",
                url,
                response.code
            );
            return Err(http::Error::Unknown);
        }

        log!(
            trace,
            "HTTP POST (protobuf) request to {:?} completed",
            url,
        );

        Ok(response)
    }

    fn post(
        &self,
        url: &str,
        request_body: Vec<u8>,
        accept: Accept,
    ) -> Result<http::Response, http::Error> {
        let mut maybe_response = None;

        let deadline = timestamp().add(self.timeout);
        let mut error = None;

        for i in 0..self.retries {
            log!(
                trace,
                "Sending HTTP POST request to {:?}, attempt: {:?}",
                url,
                i + 1
            );
            let mut request = http::Request::post(url, vec![request_body.clone()])
                .add_header("content-type", "application/json");

            request = match accept {
                Accept::Any => request,
                Accept::Protobuf => request.add_header("Accept", "application/protobuf"),
            };

            let pending = request
                .deadline(deadline)
                .body(vec![request_body.clone()])
                .send()
                .map_err(|_| http::Error::IoError)?;

            match pending.try_wait(deadline) {
                Ok(Ok(r)) => {
                    maybe_response = Some(r);
                    error = None;
                    break;
                }
                Ok(Err(_)) | Err(_) => {
                    error = Some(http::Error::DeadlineReached);
                    continue;
                }
            }
        }

        if let Some(e) = error {
            log!(
                error,
                "❌ HTTP POST client error for url {:?}, error {:?}",
                url,
                e
            );
            return Err(e);
        }

        let response = match maybe_response {
            Some(r) => r,
            None => {
                log!(
                    error,
                    "❌ HTTP POST client error for url {:?}, no response",
                    url
                );
                return Err(http::Error::Unknown);
            }
        };

        if response.code >= 500 {
            log!(
                error,
                "❌ HTTP POST client error for url {:?}, status code is {:?}",
                url,
                response.code
            );
            return Err(http::Error::Unknown);
        }

        log!(trace, "HTTP POST request to {:?} completed", url,);

        Ok(response)
    }
}

enum Accept {
    Any,
    Protobuf,
}
