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
/// Most bytes of prefetched bodies a cache holds at once: 64 MiB. A body that
/// would pass it is not kept, and its path fetches it when it runs.
pub const PREFETCH_CACHE_BUDGET: usize = 64 << 20;

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
	/// Keeping the body would pass the cache's budget.
	OverBudget,
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
	/// Bodies that arrived but were not kept, for the cache's budget.
	pub over_budget: u32,
}

/// Prefetched response bodies, keyed by the exact URL requested, holding at
/// most `budget` bytes at once.
pub struct PrefetchCache {
	bodies: BTreeMap<String, Vec<u8>>,
	stats: PrefetchStats,
	held: usize,
	budget: usize,
}

impl Default for PrefetchCache {
	fn default() -> Self {
		Self::with_budget(PREFETCH_CACHE_BUDGET)
	}
}

impl PrefetchCache {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn with_budget(budget: usize) -> Self {
		PrefetchCache { bodies: BTreeMap::new(), stats: PrefetchStats::default(), held: 0, budget }
	}

	/// Keeps `body` for `url` if it fits the budget; a body that does not is
	/// refused, and what is already kept stays.
	fn keep(&mut self, url: String, body: Vec<u8>) -> bool {
		let held = self.held.saturating_add(body.len());
		if held > self.budget {
			self.stats.over_budget += 1;
			return false;
		}
		self.held = held;
		if let Some(replaced) = self.bodies.insert(url, body) {
			self.held = self.held.saturating_sub(replaced.len());
		}
		true
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
		if let Some(body) = &body {
			cache.held = cache.held.saturating_sub(body.len());
		}
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
					let bytes = crate::client::read_body_capped(
						body.by_ref(),
						crate::client::PATH_BODY_LIMIT,
						usize::MAX,
						|_| {},
					);
					match bytes {
						Ok(bytes) if body.error().is_none() => Ok(bytes),
						_ => Err(PrefetchFailure::BodyRead),
					}
				},
			};
			let outcome = outcome.map(|bytes| cache.keep(request.url.clone(), bytes));
			match outcome {
				Ok(true) => {
					cache.stats.fetched += 1;
					outcomes.push((request, Ok(())));
				},
				Ok(false) => {
					log!(
						warn,
						"Prefetch of {:?} from node {:?} is over the cache budget; it will be fetched on demand",
						request.url,
						request.node_key
					);
					outcomes.push((request, Err(PrefetchFailure::OverBudget)));
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::client::{read_path_body, PATH_BODY_LIMIT};
	use polkadot_sdk::sp_core::offchain::{
		testing::{PendingRequest, TestOffchainExt},
		OffchainDbExt, OffchainWorkerExt,
	};
	use polkadot_sdk::sp_io::TestExternalities;
	use polkadot_sdk::sp_runtime::AccountId32;

	const ROUND: usize = 32;
	const ALLOCATION_CAP: usize = 33_554_432;

	fn url(i: usize) -> String {
		format!("http://node-{}:8080/activity/v1/records/{}", i % 4, i)
	}

	/// An honest round: 32 bodies between 1 KB and 85 KB, the largest path
	/// fetch the testnet sample saw.
	fn round() -> Vec<(String, Vec<u8>)> {
		(0..ROUND).map(|i| (url(i), vec![i as u8; 1_000 + (i * 2_711) % 84_000])).collect()
	}

	fn expected(url: &str, body: &[u8]) -> PendingRequest {
		PendingRequest {
			method: "GET".into(),
			uri: url.into(),
			headers: vec![("Accept".into(), "application/protobuf".into())],
			response: Some(body.to_vec()),
			sent: true,
			..Default::default()
		}
	}

	fn with_responses<R>(responses: &[(String, Vec<u8>)], f: impl FnOnce() -> R) -> R {
		let (offchain, state) = TestOffchainExt::new();
		let mut ext = TestExternalities::default();
		ext.register_extension(OffchainWorkerExt::new(offchain.clone()));
		ext.register_extension(OffchainDbExt::new(offchain));
		{
			let mut state = state.write();
			for (url, body) in responses {
				state.expect_request(expected(url, body));
			}
		}
		ext.execute_with(f)
	}

	fn planned(url: &str) -> PrefetchRequest {
		PrefetchRequest { url: url.into(), node_key: NodePubKey::StoragePubKey(AccountId32::from([1; 32])) }
	}

	/// What a cache of `budget` keeps from the round, and what each of the
	/// round's paths then takes from it.
	fn run_round(budget: usize) -> (Vec<String>, PrefetchStats, Vec<Option<Vec<u8>>>) {
		let round = round();
		with_responses(&round, || {
			let mut cache = PrefetchCache::with_budget(budget);
			prefetch_round(&mut cache, round.iter().map(|(u, _)| planned(u)).collect(), Duration::from_millis(5_000));
			let cached: Vec<String> = round.iter().map(|(u, _)| u.clone()).filter(|u| cache.contains(u)).collect();
			let taken = serve_prefetched(&mut cache, || round.iter().map(|(u, _)| take_prefetched(u)).collect());
			(cached, cache.stats(), taken)
		})
	}

	#[test]
	fn the_budget_changes_nothing_in_an_honest_round() {
		let unbounded = run_round(usize::MAX);
		let budgeted = run_round(PREFETCH_CACHE_BUDGET);
		assert_eq!(unbounded.0.len(), ROUND);
		assert_eq!(budgeted, unbounded);
	}

	#[test]
	fn a_round_one_byte_over_the_budget_leaves_only_its_last_body_to_be_fetched_directly() {
		let round = round();
		let total: usize = round.iter().map(|(_, body)| body.len()).sum();
		let (cached, stats, taken) = run_round(total - 1);
		let (last, last_body) = round.last().unwrap();
		let expected: Vec<String> = round[..ROUND - 1].iter().map(|(u, _)| u.clone()).collect();
		assert_eq!(cached, expected);
		assert_eq!(stats.over_budget, 1);
		assert_eq!(taken.last(), Some(&None));
		let direct = with_responses(&[(last.clone(), last_body.clone())], || {
			let response = http::Request::get(last).add_header("Accept", "application/protobuf").send().unwrap().wait().unwrap();
			read_path_body(response.body()).unwrap()
		});
		assert_eq!(&direct, last_body);
	}

	#[test]
	fn a_body_one_byte_over_the_path_limit_fails_as_a_failed_read() {
		let read = read_path_body(core::iter::repeat(7u8).take(PATH_BODY_LIMIT + 1));
		assert_eq!(read, Err(http::Error::Unknown));
		let body = read_path_body(core::iter::repeat(7u8).take(PATH_BODY_LIMIT)).unwrap();
		assert_eq!(body.len(), PATH_BODY_LIMIT);
		assert!(body.capacity() <= ALLOCATION_CAP);
	}
}
