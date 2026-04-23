#![allow(clippy::from_over_into)]

// The signed JSON envelope kept here is the legacy typed-payload form. The
// activity-API client no longer uses it — all signed responses are proto
// envelopes now. Kept only because `verification::Verify` is generic over it.
use codec::{Decode, Encode};
use scale_info::prelude::string::String;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use sp_std::prelude::*;

/// Json response wrapped with a signature.
#[serde_as]
#[derive(
    Debug, Serialize, Deserialize, Clone, Hash, Ord, PartialOrd, PartialEq, Eq, Encode, Decode,
)]
pub struct SignedJsonResponse<T> {
    pub payload: T,
    #[serde_as(as = "Base64")]
    pub signer: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub signature: Vec<u8>,
}
