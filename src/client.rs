#![allow(dead_code)]
#![allow(clippy::from_over_into)]

use api::{ApiResponse, SignedBy};
use ddc_primitives::{BucketId, EhdEra, NodePubKey, TcaEra};
use polkadot_sdk::sp_io::offchain::timestamp;
use polkadot_sdk::sp_runtime::offchain::{http, Duration};
use polkadot_sdk::sp_std::vec;
use prost::Message;
use scale_info::prelude::{format, string::String, vec::Vec};

use super::*;
use crate::{log, verification::Verify};

pub struct DdcClient<'a> {
	pub base_url: &'a str,
	timeout: Duration,
	retries: u32,
	dry_run: bool,
}

/// fetch_and_parse_proto fetches a proto-envelope response, verifies the
/// signature, and returns the inner decoded message together with the signer
/// information. Signing is unconditional — every server-side endpoint
/// produces a SignedResponse envelope; a missing or invalid signature is a
/// protocol error, not a configurable client behaviour.
macro_rules! fetch_and_parse_proto {
	($self:expr, $url:expr, $response_ty:ty) => {{
		let response = $self.get(&$url, Accept::Protobuf)?;
		let body = response.body().collect::<Vec<u8>>();

		let proto_signed_response = proto::signature::SignedResponse::decode(body.as_slice())
			.map_err(|e| {
				log!(error, "❌ Failed to decode SignedResponse protobuf: {:?}", e);
				http::Error::Unknown
			})?;

		if !proto_signed_response.verify() {
			log!(
				error,
				"❌ Bad .proto signature, req: {:?}, resp: {:?}",
				$url,
				proto_signed_response
			);
			return Err(http::Error::Unknown);
		}

		let proto_response: $response_ty =
			<$response_ty>::decode(proto_signed_response.payload.as_slice()).map_err(|e| {
				log!(error, "❌ Failed to parse signed .proto payload: {:?}", e);
				http::Error::Unknown
			})?;
		let signed_by = proto_signed_response
			.signature
			.map(|v| SignedBy { signer: v.signer, signature: v.value })
			.ok_or_else(|| {
				log!(error, "❌ Missing signature in signed proto response");
				http::Error::Unknown
			})?;

		Ok((proto_response, Some(signed_by)))
	}};
}

/// Decode a signed-envelope response body, verify the signature, and
/// return the inner proto. Used by every /v1/itm/* call (both POST and GET)
/// that receives a SignedResponse-wrapped body.
fn decode_signed_proto<R: Message + Default>(url: &str, body: &[u8]) -> Result<R, http::Error> {
	let signed = proto::signature::SignedResponse::decode(body).map_err(|e| {
		log!(error, "❌ Failed to decode SignedResponse from {:?}: {:?}", url, e);
		http::Error::Unknown
	})?;
	if !signed.verify() {
		log!(error, "❌ Bad signature on response from {:?}", url);
		return Err(http::Error::Unknown);
	}
	R::decode(signed.payload.as_slice()).map_err(|e| {
		log!(error, "❌ Failed to decode signed payload from {:?}: {:?}", url, e);
		http::Error::Unknown
	})
}

impl<'a> DdcClient<'a> {
	pub fn new(base_url: &'a str, timeout: Duration, retries: u32) -> Self {
		Self { base_url, timeout, retries, dry_run: false }
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
		let mut url = format!("{}/activity/v1/buckets?tcaId={}", self.base_url, era_id);
		if let Some(prev_token) = prev_token {
			url = format!("{}&prevToken={}", url, prev_token);
		}
		if let Some(limit) = limit {
			url = format!("{}&limit={}", url, limit);
		}

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity_tree::BucketAggregatesResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn bucket_aggregate(
		&self,
		era_id: TcaEra,
		bucket_id: BucketId,
	) -> Result<ApiResponse<proto::activity_tree::BucketAggregatesResponse>, http::Error> {
		let mut url =
			format!("{}/activity/v1/buckets/{}?tcaId={}", self.base_url, bucket_id, era_id);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity_tree::BucketAggregatesResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn node_aggregate(
		&self,
		era_id: TcaEra,
		node_key: NodePubKey,
	) -> Result<ApiResponse<proto::activity_tree::NodeAggregatesResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/nodes/{}?tcaId={}",
			self.base_url,
			<NodePubKey as Into<String>>::into(node_key),
			era_id
		);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity_tree::NodeAggregatesResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn tcas(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetTcasResponse>, http::Error> {
		let mut url = build_list_url(&self.base_url, "/activity/v1/tcas", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetTcasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn eras(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url = build_list_url(&self.base_url, "/activity/v1/eras", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetErasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn inspected_eras(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url = build_list_url(&self.base_url, "/activity/v1/inspected-eras", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetErasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn processed_eras(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url = build_list_url(&self.base_url, "/activity/v1/processed-eras", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetErasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn get_tca(&self, tca_id: TcaEra) -> Result<ApiResponse<proto::era::Tca>, http::Error> {
		let mut url = format!("{}/activity/v1/tcas/{}", self.base_url, tca_id);
		let (response, signed_by) = fetch_and_parse_proto!(self, url, proto::era::Tca)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn dry_run_inspected_eras(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url =
			build_list_url(&self.base_url, "/itm/v1/dry-run/inspected-eras", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetErasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn dry_run_processed_eras(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url =
			build_list_url(&self.base_url, "/itm/v1/dry-run/processed-eras", cursor, limit);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetErasResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	pub fn fetch_records_range(
		&self,
		tca_id: TcaEra,
		bucket_id: Option<BucketId>,
		record_id_gte: &[u8],
		record_id_lte: &[u8],
		cursor: Option<&[u8]>,
		limit: Option<u32>,
		indexes: Option<&[u64]>,
	) -> Result<ApiResponse<proto::activity::GetRecordsResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/records?tcaId={}&recordIdGte={}&recordIdLte={}",
			self.base_url,
			tca_id,
			hex::encode(record_id_gte),
			hex::encode(record_id_lte),
		);
		if let Some(b) = bucket_id {
			url = format!("{}&bucketId={}", url, b);
		}
		if let Some(idx) = indexes {
			let joined = idx.iter().map(|i| format!("{}", i)).collect::<Vec<_>>().join(",");
			url = format!("{}&indexes={}", url, joined);
		} else {
			if let Some(c) = cursor {
				url = format!("{}&cursor={}", url, hex::encode(c));
			}
			if let Some(l) = limit {
				url = format!("{}&limit={}", url, l);
			}
		}

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GetRecordsResponse)?;

		Ok(ApiResponse { response, signed_by })
	}

	pub fn traverse_era_historical_document(
		&self,
		era: EhdEra,
		tree_node_id: u32,
		tree_levels_count: u32,
	) -> Result<ApiResponse<proto::activity_tree::EhdTreeTraversalResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/ehds/traverse/{}?merkleTreeNodeId={}&levels={}",
			self.base_url, era, tree_node_id, tree_levels_count
		);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity_tree::EhdTreeTraversalResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn traverse_partial_historical_document(
		&self,
		era: EhdEra,
		tree_node_id: u32,
		tree_levels_count: u32,
	) -> Result<ApiResponse<proto::activity_tree::PhdTreeTraversalResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/phds/traverse/{}?merkleTreeNodeId={}&levels={}",
			self.base_url, era, tree_node_id, tree_levels_count
		);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity_tree::PhdTreeTraversalResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn traverse_node_aggregate(
		&self,
		tca_id: TcaEra,
		node_key: NodePubKey,
		merkle_tree_node_id: u64,
		levels: u16,
	) -> Result<ApiResponse<proto::activity::ActivityTreeTraversalResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/nodes/{}/traverse/{}?merkleTreeNodeId={}&levels={}",
			self.base_url,
			<NodePubKey as Into<String>>::into(node_key),
			tca_id,
			merkle_tree_node_id,
			levels,
		);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::ActivityTreeTraversalResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
	}

	pub fn traverse_bucket_sub_aggregate(
		&self,
		tca_id: TcaEra,
		bucket_id: BucketId,
		node_key: NodePubKey,
		merkle_tree_node_id: u64,
		levels: u16,
	) -> Result<ApiResponse<proto::activity::ActivityTreeTraversalResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/buckets/{}/traverse/{}?nodeId={}&merkleTreeNodeId={}&levels={}",
			self.base_url,
			bucket_id,
			tca_id,
			<NodePubKey as Into<String>>::into(node_key),
			merkle_tree_node_id,
			levels,
		);

		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::ActivityTreeTraversalResponse)?;

		let api_response = ApiResponse { response, signed_by };

		Ok(api_response)
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
		let url = self.insp_mem_url("/itm/v1/lease");
		let body = request.encode_to_vec();

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::LeaseResult>(&url, &body)
	}

	/// POST /itm/submit - Submit completed assignment table (protobuf)
	pub fn submit_assignments_table(
		&self,
		request: &proto::inspection::PostAssignmentTableRequest,
	) -> Result<proto::inspection::PostAssignmentTableResponse, http::Error> {
		let url = self.insp_mem_url("/itm/v1/submit");
		let body = request.encode_to_vec();

		log!(
			trace,
			"submit_assignments_table: encoded body = {} bytes, paths = {}",
			body.len(),
			request.table.as_ref().map(|t| t.paths.len()).unwrap_or(0),
		);

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::PostAssignmentTableResponse>(&url, &body)
	}

	/// GET /itm/table - Retrieve assignment table (protobuf)
	pub fn get_assignments_table(
		&self,
		era: EhdEra,
	) -> Result<proto::inspection::GetAssignmentTableResponse, http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/table/{}", era));

		let response = self.get(&url, Accept::Protobuf)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::GetAssignmentTableResponse>(&url, &body)
	}

	/// POST /itm/path - Submit inspection path results (protobuf)
	pub fn submit_inspection_result(
		&self,
		request: &proto::inspection::PostInspectionResultRequest,
	) -> Result<proto::inspection::PostInspectionResultResponse, http::Error> {
		let url = self.insp_mem_url("/itm/v1/path");
		let body = request.encode_to_vec();

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::PostInspectionResultResponse>(&url, &body)
	}

	/// GET /itm/state - Retrieve inspection state (protobuf)
	pub fn get_inspection_state(
		&self,
		era: EhdEra,
	) -> Result<proto::inspection::InspectionState, http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/state/{}", era));

		let response = self.get(&url, Accept::Protobuf)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::InspectionState>(&url, &body)
	}

	/// GET /itm/receipt - Retrieve inspection receipt (protobuf)
	pub fn get_inspection_receipt(
		&self,
		era: EhdEra,
	) -> Result<proto::inspection::InspectionReceipt, http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/receipt/{}", era));

		let response = self.get(&url, Accept::Protobuf)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::InspectionReceipt>(&url, &body)
	}

	/// GET /itm/quorum - Retrieve quorum information (protobuf)
	pub fn get_quorum_info(
		&self,
		era: EhdEra,
	) -> Result<proto::inspection::InspSyncQuorumInfo, http::Error> {
		let url = format!("{}/itm/v1/quorum/{}", self.base_url, era);

		let response = self.get(&url, Accept::Protobuf)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::InspSyncQuorumInfo>(&url, &body)
	}

	pub fn get_grouping_collectors(
		&self,
	) -> Result<ApiResponse<proto::activity::GroupingCollectorsResponse>, http::Error> {
		let mut url = format!("{}/activity/v1/grouping-collectors", self.base_url);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GroupingCollectorsResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	fn get(&self, url: &str, accept: Accept) -> Result<http::Response, http::Error> {
		let mut maybe_response = None;

		let deadline = timestamp().add(self.timeout);
		let mut error = None;

		for i in 0..self.retries {
			log!(trace, "Sending HTTP GET request to {:?}, attempt: {:?}", url, i + 1);
			let mut request = http::Request::get(url).deadline(deadline);
			request = match accept {
				Accept::Any => request,
				Accept::Protobuf => request.add_header("Accept", "application/protobuf"),
			};

			let pending = match request.send() {
				Ok(p) => p,
				Err(e) => {
					log!(error, "❌ HTTP GET send failed for url {:?}: {:?}", url, e);
					error = Some(http::Error::IoError);
					continue;
				},
			};

			match pending.try_wait(deadline) {
				Ok(Ok(r)) => {
					maybe_response = Some(r);
					error = None;
					break;
				},
				Ok(Err(e)) => {
					log!(error, "❌ HTTP GET response error for url {:?}: {:?}", url, e);
					error = Some(http::Error::DeadlineReached);
					continue;
				},
				Err(_) => {
					error = Some(http::Error::DeadlineReached);
					continue;
				},
			}
		}

		if let Some(e) = error {
			log!(error, "❌ HTTP GET client error for url {:?}, error {:?}", url, e);
			return Err(e);
		}

		let response = match maybe_response {
			Some(r) => r,
			None => {
				log!(error, "❌ HTTP GET client error for url {:?}, no response", url);
				return Err(http::Error::Unknown);
			},
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
	fn post_proto(&self, url: &str, request_body: Vec<u8>) -> Result<http::Response, http::Error> {
		let mut maybe_response = None;

		let deadline = timestamp().add(self.timeout);
		let mut error = None;
		let body_size = request_body.len();

		for i in 0..self.retries {
			log!(
				trace,
				"Sending HTTP POST (protobuf) request to {:?}, attempt: {:?}, body_size: {} bytes",
				url,
				i + 1,
				body_size
			);
			let pending = http::Request::post(url, vec![request_body.clone()])
				.add_header("content-type", "application/protobuf")
				.add_header("Accept", "application/protobuf")
				.deadline(deadline)
				.send()
				.map_err(|e| {
					log!(error, "❌ HTTP POST (protobuf) send failed for url {:?}: {:?}", url, e);
					http::Error::IoError
				})?;

			match pending.try_wait(deadline) {
				Ok(Ok(r)) => {
					maybe_response = Some(r);
					error = None;
					break;
				},
				Ok(Err(e)) => {
					log!(
						error,
						"❌ HTTP POST (protobuf) response error for url {:?}: {:?}",
						url,
						e
					);
					error = Some(http::Error::DeadlineReached);
					continue;
				},
				Err(_) => {
					error = Some(http::Error::DeadlineReached);
					continue;
				},
			}
		}

		if let Some(e) = error {
			log!(error, "❌ HTTP POST (protobuf) client error for url {:?}, error {:?}", url, e);
			return Err(e);
		}

		let response = match maybe_response {
			Some(r) => r,
			None => {
				log!(error, "❌ HTTP POST (protobuf) client error for url {:?}, no response", url);
				return Err(http::Error::Unknown);
			},
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

		log!(trace, "HTTP POST (protobuf) request to {:?} completed", url,);

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
			log!(trace, "Sending HTTP POST request to {:?}, attempt: {:?}", url, i + 1);
			let mut request = http::Request::post(url, vec![request_body.clone()])
				.add_header("content-type", "application/json");

			request = match accept {
				Accept::Any => request,
				Accept::Protobuf => request.add_header("Accept", "application/protobuf"),
			};

			let pending =
				request.deadline(deadline).body(vec![request_body.clone()]).send().map_err(
					|e| {
						log!(error, "❌ HTTP POST send failed for url {:?}: {:?}", url, e);
						http::Error::IoError
					},
				)?;

			match pending.try_wait(deadline) {
				Ok(Ok(r)) => {
					maybe_response = Some(r);
					error = None;
					break;
				},
				Ok(Err(e)) => {
					log!(error, "❌ HTTP POST response error for url {:?}: {:?}", url, e);
					error = Some(http::Error::DeadlineReached);
					continue;
				},
				Err(_) => {
					error = Some(http::Error::DeadlineReached);
					continue;
				},
			}
		}

		if let Some(e) = error {
			log!(error, "❌ HTTP POST client error for url {:?}, error {:?}", url, e);
			return Err(e);
		}

		let response = match maybe_response {
			Some(r) => r,
			None => {
				log!(error, "❌ HTTP POST client error for url {:?}, no response", url);
				return Err(http::Error::Unknown);
			},
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

fn build_list_url(base: &str, path: &str, cursor: Option<&[u8]>, limit: Option<u32>) -> String {
	let mut url = format!("{}{}", base, path);
	let mut first = true;
	if let Some(c) = cursor {
		url = format!("{}{}cursor={}", url, if first { "?" } else { "&" }, hex::encode(c));
		first = false;
	}
	if let Some(l) = limit {
		url = format!("{}{}limit={}", url, if first { "?" } else { "&" }, l);
	}
	url
}
