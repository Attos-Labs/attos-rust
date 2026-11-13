//! Attos Rust SDK: memory-mapped v1 blob reader with lock-free hot-swap,
//! background sync (CONTRACTS.md §4) and telemetry (CONTRACTS.md §5).
mod delta;
pub mod error;
pub mod map;
mod overflow;
pub mod redirect;
mod sha256;
pub mod signature;
mod stats;
pub mod sync;
pub mod synchronizer;
pub mod telemetry;
mod v2;

pub use error::AttosError;
pub use map::{AttosMap, OpenConfig};
pub use signature::{
    parse_public_key, public_key_for, sha256_digest, sign_artifact, SIGNATURE_HEADER,
};
pub use stats::LatencySnapshot;
pub use sync::AttosClient;
pub use synchronizer::{AttosSynchronizer, SyncConfig, SyncOutcome};

/// SDK version reported in `User-Agent` and telemetry.
pub const VERSION: &str = "1.4.0";
