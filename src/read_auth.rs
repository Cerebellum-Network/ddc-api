//! An inspector's signature on its reads of the coordination routes.

use ddc_primitives::{ClusterId, EhdEra};
use polkadot_sdk::sp_core::{crypto::KeyTypeId, sr25519};
use scale_info::prelude::{string::String, string::ToString, vec::Vec};

use crate::log;

/// Domain tag for canonical read-request bytes. Same 12 bytes as the Go side
/// (ddc-node internal/storage/inspection/read_canonical.go); changing it
/// invalidates every read signature.
const READ_DOMAIN_TAG: &[u8] = b"DDC_READ_V1\x00";

/// Headers a signed read carries: the inspector key and signature as hex, and
/// the block it signed at as a decimal.
pub const READ_KEY_HEADER: &str = "X-Insp-Read-Key";
pub const READ_BLOCK_HEADER: &str = "X-Insp-Read-Block";
pub const READ_SIGNATURE_HEADER: &str = "X-Insp-Read-Signature";

/// The coordination route a signed read names, so a signature for one route is
/// not valid on another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReadRoute {
	Table = 1,
	State = 2,
	Receipt = 3,
	Quorum = 4,
}

/// Returns the canonical bytes an inspector signs to read a coordination route.
/// Layout MUST match CanonicalReadRequest in ddc-node:
///   "DDC_READ_V1\x00" (12)
///   | cluster_id (32, zero-padded)
///   | route (1)
///   | era_id u32 LE (4)
///   | inspector_key (32, zero-padded)
///   | block_number u32 LE (4)
pub fn canonical_read_bytes(
	cluster_id: &ClusterId,
	route: ReadRoute,
	era_id: EhdEra,
	inspector_key: &[u8],
	block_number: u32,
) -> Vec<u8> {
	let mut out = Vec::with_capacity(READ_DOMAIN_TAG.len() + 32 + 1 + 4 + 32 + 4);
	out.extend_from_slice(READ_DOMAIN_TAG);

	let mut cluster = [0u8; 32];
	let cluster_src = cluster_id.as_bytes();
	let n = core::cmp::min(cluster_src.len(), 32);
	cluster[..n].copy_from_slice(&cluster_src[..n]);
	out.extend_from_slice(&cluster);

	out.push(route as u8);
	out.extend_from_slice(&era_id.to_le_bytes());

	let mut key = [0u8; 32];
	let n = core::cmp::min(inspector_key.len(), 32);
	key[..n].copy_from_slice(&inspector_key[..n]);
	out.extend_from_slice(&key);

	out.extend_from_slice(&block_number.to_le_bytes());

	out
}

/// The inspector key in the local keystore that signs reads, and the block
/// they are signed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSigner {
	pub cluster_id: ClusterId,
	pub key_type: KeyTypeId,
	pub key: [u8; 32],
	pub block: u32,
}

impl ReadSigner {
	/// The headers that sign a read of route for era. Empty when the keystore
	/// cannot sign; the read is then sent unsigned.
	pub fn headers(&self, route: ReadRoute, era: EhdEra) -> Vec<(&'static str, String)> {
		let payload = canonical_read_bytes(&self.cluster_id, route, era, &self.key, self.block);
		let public = sr25519::Public::from_raw(self.key);
		match polkadot_sdk::sp_io::crypto::sr25519_sign(self.key_type, &public, &payload) {
			Some(signature) => Vec::from([
				(READ_KEY_HEADER, hex::encode(self.key)),
				(READ_BLOCK_HEADER, self.block.to_string()),
				(READ_SIGNATURE_HEADER, hex::encode(signature.0)),
			]),
			None => {
				log!(error, "❌ Failed to sign a read of {:?} for era {:?}; reading unsigned", route, era);
				Vec::new()
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{
		panic::{catch_unwind, AssertUnwindSafe},
		sync::Arc,
	};

	use polkadot_sdk::{
		sp_core::offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt},
		sp_io::TestExternalities,
		sp_keystore::{testing::MemoryKeystore, Keystore, KeystoreExt},
		sp_runtime::offchain::Duration,
	};

	use super::*;
	use crate::client::DdcClient;

	const READ_KEY_TYPE: KeyTypeId = KeyTypeId(*b"insp");
	const TEST_ERA: EhdEra = 7;
	const TEST_BLOCK: u32 = 42;
	const BASE_URL: &str = "http://192.0.2.1:8080";

	fn keystore_with_key() -> (MemoryKeystore, [u8; 32]) {
		let keystore = MemoryKeystore::new();
		let public = keystore.sr25519_generate_new(READ_KEY_TYPE, None).unwrap();
		(keystore, public.0)
	}

	fn signer(key: [u8; 32]) -> ReadSigner {
		ReadSigner { cluster_id: ClusterId::repeat_byte(0x0c), key_type: READ_KEY_TYPE, key, block: TEST_BLOCK }
	}

	fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
		headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
	}

	fn assert_signed_for(headers: &[(String, String)], signer: &ReadSigner, route: ReadRoute, era: EhdEra) {
		assert_eq!(header(headers, READ_KEY_HEADER), Some(hex::encode(signer.key).as_str()));
		assert_eq!(header(headers, READ_BLOCK_HEADER), Some(TEST_BLOCK.to_string().as_str()));
		let signature: [u8; 64] =
			hex::decode(header(headers, READ_SIGNATURE_HEADER).unwrap()).unwrap().try_into().unwrap();
		let payload = canonical_read_bytes(&signer.cluster_id, route, era, &signer.key, signer.block);
		assert!(polkadot_sdk::sp_io::crypto::sr25519_verify(
			&sr25519::Signature::from_raw(signature),
			&payload,
			&sr25519::Public::from_raw(signer.key),
		));
	}

	#[test]
	fn the_canonical_read_bytes_bind_cluster_route_era_key_and_block() {
		let cluster = ClusterId::repeat_byte(0xab);
		let key = [0xcd; 32];

		let bytes = canonical_read_bytes(&cluster, ReadRoute::Receipt, 0x01020304, &key, 0x0a0b0c0d);

		let mut expected = b"DDC_READ_V1\x00".to_vec();
		expected.extend_from_slice(cluster.as_bytes());
		expected.extend_from_slice(&[0u8; 12]);
		expected.push(3);
		expected.extend_from_slice(&[0x04, 0x03, 0x02, 0x01]);
		expected.extend_from_slice(&key);
		expected.extend_from_slice(&[0x0d, 0x0c, 0x0b, 0x0a]);
		assert_eq!(bytes, expected);
	}

	#[test]
	fn a_read_is_signed_by_the_keystore_key_over_its_route_and_era() {
		let (keystore, key) = keystore_with_key();
		let mut ext = TestExternalities::default();
		ext.register_extension(KeystoreExt(Arc::new(keystore)));
		ext.execute_with(|| {
			let signer = signer(key);

			let headers: Vec<(String, String)> = signer
				.headers(ReadRoute::State, TEST_ERA)
				.into_iter()
				.map(|(n, v)| (n.into(), v))
				.collect();

			assert_signed_for(&headers, &signer, ReadRoute::State, TEST_ERA);
		});
	}

	#[test]
	fn a_read_the_keystore_cannot_sign_goes_unsigned() {
		let mut ext = TestExternalities::default();
		ext.register_extension(KeystoreExt(Arc::new(MemoryKeystore::new())));
		ext.execute_with(|| {
			assert!(signer([0x77; 32]).headers(ReadRoute::Quorum, TEST_ERA).is_empty());
		});
	}

	#[test]
	fn every_coordination_read_the_client_sends_is_signed_for_its_own_route() {
		let (keystore, key) = keystore_with_key();
		let (offchain, state) = TestOffchainExt::new();
		let mut ext = TestExternalities::default();
		ext.register_extension(KeystoreExt(Arc::new(keystore)));
		ext.register_extension(OffchainDbExt::new(offchain.clone()));
		ext.register_extension(OffchainWorkerExt::new(offchain));
		ext.execute_with(|| {
			let signer = signer(key);
			let client = DdcClient::new(BASE_URL, Duration::from_millis(1_000), 1);
			let reads: [(&str, ReadRoute, Box<dyn Fn()>); 6] = [
				("/itm/v1/table/7", ReadRoute::Table, Box::new(|| drop(client.get_assignments_table(TEST_ERA, &signer)))),
				("/itm/v1/state/7", ReadRoute::State, Box::new(|| drop(client.get_inspection_state(TEST_ERA, &signer)))),
				("/itm/v1/receipt/7", ReadRoute::Receipt, Box::new(|| drop(client.get_inspection_receipt(TEST_ERA, &signer)))),
				("/itm/v1/quorum/7", ReadRoute::Quorum, Box::new(|| drop(client.get_quorum_info(TEST_ERA, &signer)))),
				("/itm/v1/state/7", ReadRoute::State, Box::new(|| drop(client.read_back_inspection_state(TEST_ERA, &signer)))),
				("/itm/v1/quorum/7", ReadRoute::Quorum, Box::new(|| drop(client.probe_shared_memory(TEST_ERA, &signer)))),
			];
			for (path, route, read) in reads {
				state.write().requests.clear();
				let _ = catch_unwind(AssertUnwindSafe(|| read()));

				let state = state.read();
				let sent = state.requests.values().collect::<Vec<_>>();
				assert_eq!(sent.len(), 1, "{path}");
				assert_eq!(sent[0].uri, format!("{BASE_URL}{path}"));
				assert_signed_for(&sent[0].headers, &signer, route, TEST_ERA);
			}
		});
	}
}
