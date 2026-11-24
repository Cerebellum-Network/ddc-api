//! Concurrent GETs for the offchain worker.
//!
//! A caller plans the GETs it is about to make, issues them together with
//! `prefetch_round`, and then runs its usual fetch code inside
//! `serve_prefetched`. While that scope is active, `DdcClient` takes the
//! prefetched body for a URL instead of sending the request. A body is served
//! only for the exact URL it was fetched for, and it goes through the same
//! decode and signature checks as a body fetched on demand. A URL that was not
//! prefetched, or whose prefetch failed, is fetched on demand as before.

use ddc_primitives::NodePubKey;
use polkadot_sdk::sp_io::offchain::timestamp;
use polkadot_sdk::sp_runtime::offchain::{http, Duration};
use polkadot_sdk::sp_std::collections::{btree_map::BTreeMap, btree_set::BTreeSet};
use polkadot_sdk::sp_std::prelude::*;
use scale_info::prelude::string::String;

use crate::log;

/// Most requests one round keeps in flight at once; a round with more is sent
/// in consecutive batches of this size.
pub const MAX_IN_FLIGHT: usize = 32;

/// A GET to prefetch: the exact URL the fetch code will request, and the node
/// that serves it, for attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchRequest {
	pub url: String,
	pub node_key: NodePubKey,
}

/// Why a prefetched request was not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefetchFailure {
	Send,
	DeadlineReached,
	Io,
	Invalid,
	Status(u16),
	BodyRead,
}

/// Counts for one cache's life.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrefetchStats {
	/// Requests sent by `prefetch_round`.
	pub requested: u32,
	/// Requests whose body was kept.
	pub fetched: u32,
	/// Requests that failed and were not kept.
	pub failed: u32,
	/// GETs inside `serve_prefetched` answered from the cache.
	pub served: u32,
	/// GETs inside `serve_prefetched` sent on demand.
	pub missed: u32,
}

/// Prefetched response bodies, keyed by the exact URL requested.
#[derive(Default)]
pub struct PrefetchCache {
	bodies: BTreeMap<String, Vec<u8>>,
	stats: PrefetchStats,
}

impl PrefetchCache {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn stats(&self) -> PrefetchStats {
		self.stats
	}

	pub fn contains(&self, url: &str) -> bool {
		self.bodies.contains_key(url)
	}

	/// The prefetched body for url, unverified: for planning the next round
	/// only, never as a result.
	pub fn body(&self, url: &str) -> Option<&[u8]> {
		self.bodies.get(url).map(|body| body.as_slice())
	}
}

environmental::environmental!(active_cache: PrefetchCache);

/// Runs f with cache answering the GETs `DdcClient` makes for its URLs.
pub fn serve_prefetched<R>(cache: &mut PrefetchCache, f: impl FnOnce() -> R) -> R {
	active_cache::using(cache, f)
}

/// The prefetched body for url, if a `serve_prefetched` scope holds one. Each
/// body is served once.
pub(crate) fn take_prefetched(url: &str) -> Option<Vec<u8>> {
	active_cache::with(|cache| {
		let body = cache.bodies.remove(url);
		if body.is_some() {
			cache.stats.served += 1;
		} else {
			cache.stats.missed += 1;
		}
		body
	})
	.flatten()
}

/// Sends every request not already cached, at most `MAX_IN_FLIGHT` at a time,
/// waits for them together, and keeps each body that arrived whole with a
/// status below 500. Returns each sent request with its outcome; a failure is
/// logged with its own URL and node.
pub fn prefetch_round(
	cache: &mut PrefetchCache,
	requests: Vec<PrefetchRequest>,
	timeout: Duration,
) -> Vec<(PrefetchRequest, Result<(), PrefetchFailure>)> {
	let mut seen = BTreeSet::new();
	let to_send: Vec<PrefetchRequest> = requests
		.into_iter()
		.filter(|request| !cache.contains(&request.url) && seen.insert(request.url.clone()))
		.collect();

	let mut outcomes = Vec::with_capacity(to_send.len());
	for batch in to_send.chunks(MAX_IN_FLIGHT) {
		let deadline = timestamp().add(timeout);
		let mut sent: Vec<(PrefetchRequest, http::PendingRequest)> = Vec::with_capacity(batch.len());
		for request in batch {
			cache.stats.requested += 1;
			let pending = http::Request::get(&request.url)
				.add_header("Accept", "application/protobuf")
				.deadline(deadline)
				.send();
			match pending {
				Ok(pending) => sent.push((request.clone(), pending)),
				Err(_) => outcomes.push(record_failure(cache, request.clone(), PrefetchFailure::Send)),
			}
		}

		let (sent_requests, pendings): (Vec<_>, Vec<_>) = sent.into_iter().unzip();
		let results = http::PendingRequest::try_wait_all(pendings, deadline);
		for (request, result) in sent_requests.into_iter().zip(results) {
			let outcome = match result {
				Err(_) => Err(PrefetchFailure::DeadlineReached),
				Ok(Err(http::Error::IoError)) => Err(PrefetchFailure::Io),
				Ok(Err(http::Error::DeadlineReached)) => Err(PrefetchFailure::DeadlineReached),
				Ok(Err(http::Error::Unknown)) => Err(PrefetchFailure::Invalid),
				Ok(Ok(response)) if response.code >= 500 => {
					Err(PrefetchFailure::Status(response.code))
				},
				Ok(Ok(response)) => {
					let mut body = response.body();
					body.deadline(deadline);
					let bytes: Vec<u8> = body.by_ref().collect();
					if body.error().is_some() {
						Err(PrefetchFailure::BodyRead)
					} else {
						Ok(bytes)
					}
				},
			};
			match outcome {
				Ok(bytes) => {
					cache.stats.fetched += 1;
					cache.bodies.insert(request.url.clone(), bytes);
					outcomes.push((request, Ok(())));
				},
				Err(failure) => outcomes.push(record_failure(cache, request, failure)),
			}
		}
	}
	outcomes
}

fn record_failure(
	cache: &mut PrefetchCache,
	request: PrefetchRequest,
	failure: PrefetchFailure,
) -> (PrefetchRequest, Result<(), PrefetchFailure>) {
	cache.stats.failed += 1;
	log!(
		warn,
		"Prefetch of {:?} from node {:?} failed: {:?}; it will be fetched on demand",
		request.url,
		request.node_key,
		failure
	);
	(request, Err(failure))
}
