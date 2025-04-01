#![cfg_attr(not(feature = "std"), no_std)]

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
}
