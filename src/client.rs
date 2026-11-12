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
use crate::{
	log,
	read_auth::{ReadRoute, ReadSigner},
	verification::Verify,
};

/// Header in which a node declares the deadline it bounds the shared-memory
/// membership route (`/itm/v1/quorum`) to.
pub const SHARED_MEMORY_DEADLINE_HEADER: &str = "X-Insp-Quorum-Deadline-Ms";

const REFUSAL_NO_CLIENT: &str = "no-client";
const REFUSAL_STORE_UNREACHABLE: &str = "store-unreachable";
/// Wire reason a node that is not a member gives when no member it knows answered.
const REFUSAL_MEMBERS_UNREACHABLE: &str = "members-unreachable";
/// Wire reason a node gives when it does not hold the shared memory.
const REFUSAL_NOT_A_MEMBER: &str = "not-a-member";
/// The non-member refusal of a binary older than its `not-a-member` reason.
const NOT_A_MEMBER_MESSAGE: &str = "Inspection sync is disabled on this node.";
const HTTP_OK: u16 = 200;
const HTTP_NOT_FOUND: u16 = 404;
const HTTP_SERVICE_UNAVAILABLE: u16 = 503;

/// What a node said, or failed to say, when asked who the sync members are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedMemoryAnswerKind {
	/// A list that did not survive the registry intersection or the member floor.
	Rejected,
	/// The node holds no sync client.
	NoClient,
	/// The node holds a client and the store did not answer in time.
	StoreUnreachable,
	/// The node has no such route.
	NoRoute,
	/// The node is not a member and no member it knows answered.
	MembersUnreachable,
	/// A refusal without the route's own reason: a binary older than discovery.
	Predates,
	/// The node did not answer, or answered with something unreadable.
	Transport,
}

pub enum SharedMemoryProbe {
	Answer {
		info: proto::inspection::InspSyncQuorumInfo,
		declared_deadline_ms: Option<u64>,
		signer: Vec<u8>,
	},
	Refused(SharedMemoryAnswerKind),
}

#[derive(serde::Deserialize)]
struct SharedMemoryRefusalBody {
	message: Option<String>,
	reason: Option<String>,
}

/// Why reading the inspectors' shared memory back through a node failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadBackError {
	/// The node does not hold the shared memory, though it was named as holding it.
	NotSharedMemory,
	/// The answer is signed by a node other than the one asked.
	SignedByAnotherNode,
	/// Anything else: no answer, an error, an unreadable body.
	Unavailable,
}

/// Whether a response is a node's refusal as one not holding the shared memory.
pub fn is_not_shared_memory_refusal(code: u16, body: &[u8]) -> bool {
	if code != HTTP_SERVICE_UNAVAILABLE {
		return false;
	}
	match serde_json::from_slice::<SharedMemoryRefusalBody>(body) {
		Ok(refusal) => {
			refusal.reason.as_deref() == Some(REFUSAL_NOT_A_MEMBER)
				|| refusal.message.as_deref() == Some(NOT_A_MEMBER_MESSAGE)
		},
		Err(_) => false,
	}
}

/// Classifies a non-success answer from the shared-memory membership route by
/// its status and refusal reason.
pub fn classify_shared_memory_refusal(code: u16, body: &[u8]) -> SharedMemoryAnswerKind {
	match code {
		HTTP_NOT_FOUND => SharedMemoryAnswerKind::NoRoute,
		HTTP_SERVICE_UNAVAILABLE => {
			match serde_json::from_slice::<SharedMemoryRefusalBody>(body).ok().and_then(|b| b.reason) {
				Some(r) if r == REFUSAL_NO_CLIENT => SharedMemoryAnswerKind::NoClient,
				Some(r) if r == REFUSAL_STORE_UNREACHABLE => SharedMemoryAnswerKind::StoreUnreachable,
				Some(r) if r == REFUSAL_MEMBERS_UNREACHABLE => SharedMemoryAnswerKind::MembersUnreachable,
				_ => SharedMemoryAnswerKind::Predates,
			}
		},
		_ => SharedMemoryAnswerKind::Predates,
	}
}

pub struct DdcClient<'a> {
	/// The node this client asks: every signed response must be signed by it.
	node: NodePubKey,
	pub base_url: &'a str,
	timeout: Duration,
	retries: u32,
}

/// fetch_and_parse_proto fetches a proto-envelope response, verifies the
/// signature, and returns the inner decoded message together with the signer
/// information. Signing is unconditional — every server-side endpoint
/// produces a SignedResponse envelope; a missing or invalid signature is a
/// protocol error, not a configurable client behaviour.
macro_rules! fetch_and_parse_proto {
	($self:expr, $url:expr, $response_ty:ty) => {{
		let response = $self.get(&$url, Accept::Protobuf, &[])?;
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
		signed_by_expected(&$url, &$self.node, proto_signed_response.signature.as_ref())
			.map_err(|_| http::Error::Unknown)?;

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

/// Why a signed response was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeRejection {
	/// Not a readable, validly signed envelope.
	Unreadable,
	/// Validly signed, by a node other than the one asked.
	SignedByAnotherNode,
}

/// A signed response's verified payload, decoded, with the payload's bytes as
/// signed and its signer.
struct OpenedEnvelope<R> {
	message: R,
	payload: Vec<u8>,
	signer: Vec<u8>,
}

/// Checks that a response was signed by the node that was asked.
fn signed_by_expected(
	url: &str,
	expected: &NodePubKey,
	signature: Option<&proto::signature::Signature>,
) -> Result<(), EnvelopeRejection> {
	let signature = signature.ok_or(EnvelopeRejection::Unreadable)?;
	let NodePubKey::StoragePubKey(expected_key) = expected;
	if signature.signer.as_slice() != AsRef::<[u8]>::as_ref(expected_key) {
		log!(
			error,
			"❌ Response from {:?} is signed by 0x{} where 0x{} was asked",
			url,
			hex::encode(&signature.signer),
			hex::encode(AsRef::<[u8]>::as_ref(expected_key))
		);
		return Err(EnvelopeRejection::SignedByAnotherNode);
	}
	Ok(())
}

/// Decodes a signed-envelope response body and verifies its signature,
/// whoever signed it.
fn open_signed_envelope<R: Message + Default>(
	url: &str,
	body: &[u8],
) -> Result<OpenedEnvelope<R>, EnvelopeRejection> {
	let signed = proto::signature::SignedResponse::decode(body).map_err(|e| {
		log!(error, "❌ Failed to decode SignedResponse from {:?}: {:?}", url, e);
		EnvelopeRejection::Unreadable
	})?;
	if !signed.verify() {
		log!(error, "❌ Bad signature on response from {:?}", url);
		return Err(EnvelopeRejection::Unreadable);
	}
	let signer = signed.signature.as_ref().map(|s| s.signer.clone()).ok_or_else(|| {
		log!(error, "❌ Missing signature in signed response from {:?}", url);
		EnvelopeRejection::Unreadable
	})?;
	let message = R::decode(signed.payload.as_slice()).map_err(|e| {
		log!(error, "❌ Failed to decode signed payload from {:?}: {:?}", url, e);
		EnvelopeRejection::Unreadable
	})?;
	Ok(OpenedEnvelope { message, payload: signed.payload, signer })
}

/// Like `open_signed_envelope`, and refuses a response not signed by expected.
fn open_envelope_signed_by<R: Message + Default>(
	url: &str,
	body: &[u8],
	expected: &NodePubKey,
) -> Result<OpenedEnvelope<R>, EnvelopeRejection> {
	let opened = open_signed_envelope::<R>(url, body)?;
	let signature =
		proto::signature::Signature { signer: opened.signer.clone(), ..Default::default() };
	signed_by_expected(url, expected, Some(&signature))?;
	Ok(opened)
}

/// Decode a signed-envelope response body, verify the signature and that the
/// node asked signed it, and return the inner proto. Used by every /v1/itm/*
/// call (both POST and GET) that receives a SignedResponse-wrapped body.
fn decode_signed_proto<R: Message + Default>(
	url: &str,
	body: &[u8],
	expected: &NodePubKey,
) -> Result<R, http::Error> {
	decode_signed_proto_with_payload(url, body, expected).map(|(message, _)| message)
}

/// Like `decode_signed_proto`, and also returns the payload exactly as the node
/// signed it.
fn decode_signed_proto_with_payload<R: Message + Default>(
	url: &str,
	body: &[u8],
	expected: &NodePubKey,
) -> Result<(R, Vec<u8>), http::Error> {
	open_envelope_signed_by::<R>(url, body, expected)
		.map(|opened| (opened.message, opened.payload))
		.map_err(|_| http::Error::Unknown)
}

/// Like `decode_signed_proto` with no check of who signed, returning the
/// signer. Only the membership route may answer with another node's
/// signature, because a node that is not a member relays a member's answer.
fn decode_signed_proto_unbound<R: Message + Default>(
	url: &str,
	body: &[u8],
) -> Result<(R, Vec<u8>), http::Error> {
	open_signed_envelope::<R>(url, body)
		.map(|opened| (opened.message, opened.signer))
		.map_err(|_| http::Error::Unknown)
}

/// Adds headers to a request, in order.
fn with_headers<'a>(
	mut request: http::Request<'a>,
	headers: &'a [(&'static str, String)],
) -> http::Request<'a> {
	for (name, value) in headers {
		request = request.add_header(name, value);
	}
	request
}

impl<'a> DdcClient<'a> {
	/// A client for node, at base_url: every signed response must be node's.
	pub fn new(node: NodePubKey, base_url: &'a str, timeout: Duration, retries: u32) -> Self {
		Self { node, base_url, timeout, retries }
	}

	fn insp_mem_url(&self, path: &str) -> String {
		format!("{}{}", self.base_url, path)
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

	/// Lists eras through `/activity/v1/eras`, keeping only `statuses` and
	/// newest first when `newest_first` is set.
	pub fn eras_with_status(
		&self,
		cursor: Option<&[u8]>,
		limit: Option<u32>,
		statuses: &[proto::era::EraStatus],
		newest_first: bool,
	) -> Result<ApiResponse<proto::activity::GetErasResponse>, http::Error> {
		let mut url =
			build_era_filter_url(&self.base_url, ERAS_PATH, cursor, limit, statuses, newest_first);
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

	pub fn fetch_records_range(
		&self,
		tca_id: TcaEra,
		node_pubkey: &[u8],
		bucket_id: Option<BucketId>,
		record_id_gte: &[u8],
		record_id_lte: &[u8],
		cursor: Option<&[u8]>,
		limit: Option<u32>,
		indexes: Option<&[u64]>,
	) -> Result<ApiResponse<proto::activity::GetRecordsResponse>, http::Error> {
		let mut url = format!(
			"{}/activity/v1/records?tcaId={}&nodePubKey={}&recordIdGte={}&recordIdLte={}",
			self.base_url,
			tca_id,
			hex::encode(node_pubkey),
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

	/// GET the era's sealed EHD: the envelope bytes exactly as the node signed
	/// them. Its address is the raw-piece CID of those bytes, so hand them on
	/// as they are: a decode and re-encode changes them, since prost drops
	/// fields it does not know.
	pub fn get_sealed_ehd(&self, era: EhdEra) -> Result<ApiResponse<Vec<u8>>, http::Error> {
		let url = format!("{}/activity/v1/ehds/{}", self.base_url, era);
		self.get_signed_payload(&url)
	}

	/// GET this collector's sealed PHD of the era: the envelope bytes exactly
	/// as the node signed them, for the same reason as `get_sealed_ehd`.
	pub fn get_sealed_phd(&self, era: EhdEra) -> Result<ApiResponse<Vec<u8>>, http::Error> {
		let url = format!("{}/activity/v1/phds/{}", self.base_url, era);
		self.get_signed_payload(&url)
	}

	/// GETs a signed response and returns its payload undecoded, with its signer.
	fn get_signed_payload(&self, url: &str) -> Result<ApiResponse<Vec<u8>>, http::Error> {
		let response = self.get(url, Accept::Protobuf, &[])?;
		let body = response.body().collect::<Vec<u8>>();
		let signed = proto::signature::SignedResponse::decode(body.as_slice()).map_err(|e| {
			log!(error, "❌ Failed to decode SignedResponse from {:?}: {:?}", url, e);
			http::Error::Unknown
		})?;
		if !signed.verify() {
			log!(error, "❌ Bad signature on response from {:?}", url);
			return Err(http::Error::Unknown);
		}
		signed_by_expected(url, &self.node, signed.signature.as_ref())
			.map_err(|_| http::Error::Unknown)?;
		let signed_by = signed
			.signature
			.map(|v| SignedBy { signer: v.signer, signature: v.value })
			.ok_or_else(|| {
				log!(error, "❌ Missing signature in signed proto response");
				http::Error::Unknown
			})?;
		Ok(ApiResponse { response: signed.payload, signed_by: Some(signed_by) })
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

		decode_signed_proto::<proto::inspection::LeaseResult>(&url, &body, &self.node)
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

		decode_signed_proto::<proto::inspection::PostAssignmentTableResponse>(
			&url, &body, &self.node,
		)
	}

	/// GET /itm/table - Retrieve assignment table (protobuf)
	pub fn get_assignments_table(
		&self,
		era: EhdEra,
		signer: &ReadSigner,
	) -> Result<proto::inspection::GetAssignmentTableResponse, http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/table/{}", era));

		let response = self.get(&url, Accept::Protobuf, &signer.headers(ReadRoute::Table, era))?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::GetAssignmentTableResponse>(
			&url, &body, &self.node,
		)
	}

	/// POST /itm/path - Submit inspection path results (protobuf)
	pub fn post_era_nudge(
		&self,
		request: &proto::inspection::PostEraNudgeRequest,
	) -> Result<proto::inspection::PostEraNudgeResponse, http::Error> {
		let url = self.insp_mem_url("/itm/v1/nudge");
		let body = request.encode_to_vec();

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::PostEraNudgeResponse>(&url, &body, &self.node)
	}

	pub fn post_seed_contribution(
		&self,
		request: &proto::inspection::PostSeedContributionRequest,
	) -> Result<proto::inspection::PostSeedContributionResponse, http::Error> {
		let url = self.insp_mem_url("/itm/v1/collective-seed");
		let body = request.encode_to_vec();

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::PostSeedContributionResponse>(
			&url, &body, &self.node,
		)
	}

	pub fn submit_inspection_result(
		&self,
		request: &proto::inspection::PostInspectionResultRequest,
	) -> Result<proto::inspection::PostInspectionResultResponse, http::Error> {
		let url = self.insp_mem_url("/itm/v1/path");
		let body = request.encode_to_vec();

		let response = self.post_proto(&url, body)?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::PostInspectionResultResponse>(
			&url, &body, &self.node,
		)
	}

	/// GET /itm/state - Retrieve inspection state (protobuf)
	pub fn get_inspection_state(
		&self,
		era: EhdEra,
		signer: &ReadSigner,
	) -> Result<proto::inspection::InspectionState, http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/state/{}", era));

		let response = self.get(&url, Accept::Protobuf, &signer.headers(ReadRoute::State, era))?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto::<proto::inspection::InspectionState>(&url, &body, &self.node)
	}

	/// Reads an era's inspection state back from the inspectors' shared memory
	/// through this node, once, telling a node that does not hold the shared
	/// memory apart from one that could not answer.
	pub fn read_back_inspection_state(
		&self,
		era: EhdEra,
		signer: &ReadSigner,
	) -> Result<proto::inspection::InspectionState, ReadBackError> {
		let url = format!("{}/itm/v1/state/{}", self.base_url, era);
		let deadline = timestamp().add(self.timeout);
		let headers = signer.headers(ReadRoute::State, era);
		let request = with_headers(
			http::Request::get(&url).deadline(deadline).add_header("Accept", "application/protobuf"),
			&headers,
		);
		let response = match request.send().map(|pending| pending.try_wait(deadline)) {
			Ok(Ok(Ok(response))) => response,
			_ => return Err(ReadBackError::Unavailable),
		};

		let code = response.code;
		let body = response.body().collect::<Vec<u8>>();
		if code != HTTP_OK {
			return Err(if is_not_shared_memory_refusal(code, &body) {
				ReadBackError::NotSharedMemory
			} else {
				ReadBackError::Unavailable
			});
		}
		open_envelope_signed_by::<proto::inspection::InspectionState>(&url, &body, &self.node)
			.map(|opened| opened.message)
			.map_err(|rejection| match rejection {
				EnvelopeRejection::SignedByAnotherNode => ReadBackError::SignedByAnotherNode,
				EnvelopeRejection::Unreadable => ReadBackError::Unavailable,
			})
	}

	/// GET /itm/receipt - Retrieve inspection receipt (protobuf), with the
	/// receipt's bytes as the node sent them. Hash those bytes, not a re-encode
	/// of the receipt: prost drops fields it does not know, so a re-encode can
	/// differ from what the node stored.
	pub fn get_inspection_receipt(
		&self,
		era: EhdEra,
		signer: &ReadSigner,
	) -> Result<(proto::inspection::InspectionReceipt, Vec<u8>), http::Error> {
		let url = self.insp_mem_url(&format!("/itm/v1/receipt/{}", era));

		let response = self.get(&url, Accept::Protobuf, &signer.headers(ReadRoute::Receipt, era))?;
		let body = response.body().collect::<Vec<u8>>();

		decode_signed_proto_with_payload::<proto::inspection::InspectionReceipt>(
			&url, &body, &self.node,
		)
	}

	/// GET /itm/quorum - Retrieve quorum information (protobuf)
	pub fn get_quorum_info(
		&self,
		era: EhdEra,
		signer: &ReadSigner,
	) -> Result<proto::inspection::InspSyncQuorumInfo, http::Error> {
		let url = format!("{}/itm/v1/quorum/{}", self.base_url, era);

		let response = self.get(&url, Accept::Protobuf, &signer.headers(ReadRoute::Quorum, era))?;
		let body = response.body().collect::<Vec<u8>>();

		let (info, signer) =
			decode_signed_proto_unbound::<proto::inspection::InspSyncQuorumInfo>(&url, &body)?;
		let signed_by_member = info.quorum_members.iter().any(|member| {
			crate::shared_memory::decode_member_key(&member.node_key)
				.is_some_and(|key| crate::shared_memory::node_key_bytes(&key) == signer.as_slice())
		});
		if !signed_by_member {
			log!(
				error,
				"❌ Quorum answer from {:?} is signed by 0x{}, which it does not name as a member",
				url,
				hex::encode(&signer)
			);
			return Err(http::Error::Unknown);
		}
		Ok(info)
	}

	/// Asks once, with no retry, who the sync members are. Retrying is the
	/// caller's next tick, not this request's.
	pub fn probe_shared_memory(&self, era: EhdEra, signer: &ReadSigner) -> SharedMemoryProbe {
		let url = format!("{}/itm/v1/quorum/{}", self.base_url, era);
		let deadline = timestamp().add(self.timeout);
		let headers = signer.headers(ReadRoute::Quorum, era);
		let request = with_headers(
			http::Request::get(&url).deadline(deadline).add_header("Accept", "application/protobuf"),
			&headers,
		);
		let mut response = match request.send().map(|pending| pending.try_wait(deadline)) {
			Ok(Ok(Ok(response))) => response,
			_ => {
				log!(debug, "Sync membership probe to {:?} got no answer", url);
				return SharedMemoryProbe::Refused(SharedMemoryAnswerKind::Transport);
			},
		};

		let code = response.code;
		let declared_deadline_ms =
			response.headers().find(SHARED_MEMORY_DEADLINE_HEADER).and_then(|v| v.parse::<u64>().ok());
		let body = response.body().collect::<Vec<u8>>();
		if code != HTTP_OK {
			return SharedMemoryProbe::Refused(classify_shared_memory_refusal(code, &body));
		}
		match decode_signed_proto_unbound::<proto::inspection::InspSyncQuorumInfo>(&url, &body) {
			Ok((info, signer)) => SharedMemoryProbe::Answer { info, declared_deadline_ms, signer },
			Err(_) => SharedMemoryProbe::Refused(SharedMemoryAnswerKind::Transport),
		}
	}

	pub fn get_grouping_collectors(
		&self,
	) -> Result<ApiResponse<proto::activity::GroupingCollectorsResponse>, http::Error> {
		let mut url = format!("{}/activity/v1/grouping-collectors", self.base_url);
		let (response, signed_by) =
			fetch_and_parse_proto!(self, url, proto::activity::GroupingCollectorsResponse)?;
		Ok(ApiResponse { response, signed_by })
	}

	fn get(
		&self,
		url: &str,
		accept: Accept,
		headers: &[(&'static str, String)],
	) -> Result<http::Response, http::Error> {
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
			request = with_headers(request, headers);

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

const ERAS_PATH: &str = "/activity/v1/eras";
/// `order` value of an era listing that puts the newest era first.
const ERA_ORDER_NEWEST_FIRST: &str = "desc";

fn build_era_filter_url(
	base: &str,
	path: &str,
	cursor: Option<&[u8]>,
	limit: Option<u32>,
	statuses: &[proto::era::EraStatus],
	newest_first: bool,
) -> String {
	let mut url = build_list_url(base, path, cursor, limit);
	let mut params: Vec<String> =
		statuses.iter().map(|status| format!("status={}", status.as_str_name())).collect();
	if newest_first {
		params.push(format!("order={}", ERA_ORDER_NEWEST_FIRST));
	}
	for param in params {
		let separator = if url.contains('?') { "&" } else { "?" };
		url = format!("{}{}{}", url, separator, param);
	}
	url
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
