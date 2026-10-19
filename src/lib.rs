//! Attos Rust SDK: memory-mapped v1 blob reader with lock-free hot-swap,
//! background sync (CONTRACTS.md §4) and telemetry (CONTRACTS.md §5).
pub mod error;
pub mod map;
mod stats;
pub mod sync;
pub mod synchronizer;
pub mod telemetry;

pub use error::AttosError;
pub use map::{AttosMap, OpenConfig};
pub use stats::LatencySnapshot;
pub use sync::AttosClient;
pub use synchronizer::{AttosSynchronizer, SyncConfig, SyncOutcome};

/// SDK version reported in `User-Agent` and telemetry.
pub const VERSION: &str = "1.2.0";
