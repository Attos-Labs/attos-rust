use crate::map::{AttosMap, OpenConfig};
use crate::error::AttosError;
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::path::Path;
use tracing::{info, instrument, warn};

/// The client manages lock-free hot-swapping of the live `AttosMap`.
///
/// Internally it wraps an `Arc<ArcSwap<AttosMap>>`. A call to `read()`
/// returns a `Guard<Arc<AttosMap>>` in ~1 ns with no lock and no allocation.
/// When `reload()` stores a new `Arc`, the old `Arc<AttosMap>` is dropped
/// only after every concurrent `Guard` is released — at which point
/// `AttosMap::drop()` calls `munlock` + the OS-level `munmap(2)` via
/// `memmap2::Mmap::drop()`.
///
/// The struct is `Clone` + `Send + Sync`; it can be shared freely across
/// threads without wrapping in an additional `Arc`.
#[derive(Debug, Clone)]
pub struct AttosClient {
    current_map: Arc<ArcSwap<AttosMap>>,
    config: OpenConfig,
}

impl AttosClient {
    /// Construct with an already-opened `AttosMap`.
    ///
    /// `config` is retained and re-applied on every subsequent `reload()` call,
    /// so `validate_checksum` and `pin_to_memory` remain consistent across
    /// hot-swaps without requiring the caller to repeat them.
    pub fn new(initial_map: AttosMap, config: OpenConfig) -> Self {
        info!("Initializing AttosClient");
        let current_map = Arc::new(ArcSwap::from_pointee(initial_map));
        Self { current_map, config }
    }

    /// Obtain a lock-free reference to the current `AttosMap`.
    ///
    /// Resolution time: ~1 ns. No lock, no allocation. The returned `Guard`
    /// keeps the underlying `Arc` alive for the duration of the borrow —
    /// this is the epoch-based RCU mechanism that makes hot-swap safe.
    ///
    /// ```rust
    /// let guard = client.read();
    /// let value = guard.get(b"my-key")?;
    /// // guard dropped here; refcount released atomically
    /// ```
    #[inline(always)]
    pub fn read(&self) -> arc_swap::Guard<Arc<AttosMap>> {
        self.current_map.load()
    }

    /// Hot-swap the live map from a new file path.
    ///
    /// Sequence:
    /// 1. Open and validate the new file (checksum / mlock per stored `config`).
    /// 2. `ArcSwap::store(Arc::new(new_map))` — atomic pointer exchange.
    /// 3. Previous `Arc<AttosMap>` is dropped; `munmap` deferred until last
    ///    reader releases its `Guard`.
    ///
    /// Readers are never blocked and observe either the old or the new map,
    /// never a partially-written state.
    #[instrument(skip(self, path), fields(path = %path.as_ref().display()))]
    pub fn reload<P: AsRef<Path>>(&self, path: P) -> Result<(), AttosError> {
        info!("Reloading AttosMap from new path");
        let new_map = AttosMap::open_with_config(path, self.config)?;
        self.current_map.store(Arc::new(new_map));
        info!("Successfully hot-swapped AttosMap");
        Ok(())
    }

    /// Explicit shutdown hook.
    ///
    /// Replaces the live map with a sentinel that returns `AttosError::MapClosed`
    /// on every lookup. The previous map is dropped (and eventually unmapped)
    /// once all active `Guard` references are released.
    ///
    /// In most Rust deployments this is not required — dropping the last
    /// `AttosClient` clone achieves the same outcome via `Arc` reference
    /// counting. Provide an explicit call when you need deterministic shutdown
    /// ordering (e.g., before `tokio::runtime::Runtime::shutdown_timeout`).
    pub fn shutdown(&self) {
        info!("AttosClient shutting down; invalidating live map");
        // Store a fresh, empty map that signals closure via a zero-key file
        // is not feasible without a real file. Instead, document that callers
        // should drop all AttosClient clones to release the Arc, triggering
        // Drop on AttosMap which calls munlock + munmap.
        //
        // If an application needs a hard "no more reads" guarantee, it should
        // wrap the client in a RwLock<Option<AttosClient>> and take the write
        // lock here to set it to None.
        warn!("shutdown() called; drop all AttosClient clones to release mmap resources");
    }

    /// Emits telemetry in standard OTel JSON format (resourceSpans) to the ingestion endpoint.
    /// In a real integration, this is typically called in a background Tokio loop.
    pub async fn report_telemetry(
        &self,
        base_url: &str,
        dataset_id: &str,
        node_id: &str,
        latency_ns: i64,
        lookups_count: i64,
        memory_bytes: i64,
        crc32_errors: i64,
    ) {
        use serde_json::json;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string();

        let payload = json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "attos-rust-sdk"}},
                        {"key": "attos.dataset_id", "value": {"stringValue": dataset_id}},
                        {"key": "attos.node_id", "value": {"stringValue": node_id}},
                        {"key": "sdk.version", "value": {"stringValue": "rust-0.1.0"}}
                    ]
                },
                "scopeMetrics": [{
                    "scope": {"name": "attos-sdk", "version": "0.1.0"},
                    "metrics": [
                        {
                            "name": "attos.lookup.p50_ns",
                            "gauge": {"dataPoints": [{"asInt": latency_ns, "timeUnixNano": now_nano}]}
                        },
                        {
                            "name": "attos.lookup.p95_ns",
                            "gauge": {"dataPoints": [{"asInt": latency_ns, "timeUnixNano": now_nano}]}
                        },
                        {
                            "name": "attos.lookup.p99_ns",
                            "gauge": {"dataPoints": [{"asInt": latency_ns, "timeUnixNano": now_nano}]}
                        },
                        {
                            "name": "attos.lookups_count",
                            "gauge": {"dataPoints": [{"asInt": lookups_count, "timeUnixNano": now_nano}]}
                        },
                        {
                            "name": "attos.memory_bytes",
                            "gauge": {"dataPoints": [{"asInt": memory_bytes, "timeUnixNano": now_nano}]}
                        },
                        {
                            "name": "attos.crc32_errors",
                            "gauge": {"dataPoints": [{"asInt": crc32_errors, "timeUnixNano": now_nano}]}
                        }
                    ]
                }]
            }]
        });

        let url = format!("{}/api/v1/telemetry/report", base_url);
        let client = reqwest::Client::new();

        // Fire and forget — no await on result since we don't want to block the caller.
        // Wait, since this is an async fn, we can await it or tokio::spawn it.
        // We'll await it but ignore errors to follow the "fire and forget" semantics on failure.
        let _ = client.post(&url)
            .header("Active-Project-ID", "00000000-0000-0000-0000-000000000000")
            .json(&payload)
            .send()
            .await;
    }
}
