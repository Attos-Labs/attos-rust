use crate::error::AttosError;
use crate::map::{AttosMap, OpenConfig};
use crate::stats::{LatencyHistogram, LatencySnapshot};
use arc_swap::ArcSwap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tracing::{info, instrument, warn};

/// At most this many replaced maps may still be alive (held by readers) when a
/// new swap starts; otherwise the swap waits (CONTRACTS.md §4.5).
pub const MAX_RETIRED: usize = 2;

/// The client manages lock-free hot-swapping of the live `AttosMap`.
///
/// # Reclamation scheme
///
/// The live map is an `Arc<AttosMap>` inside an [`arc_swap::ArcSwap`]. `read()`
/// returns an `arc_swap::Guard`, which pins the map without a lock: arc-swap
/// uses a small per-thread set of *debt slots* (a hazard-pointer-like scheme);
/// when `store`/`swap` replaces the pointer it pays every outstanding debt by
/// converting it into a real reference count. The old map is therefore dropped
/// — and `AttosMap::drop` munlocks and `munmap`s it — exactly when the last
/// `Guard`/`Arc` referring to it is released (reference counting). This was
/// chosen over an epoch scheme because it is sound without any `unsafe` in this
/// crate, wait-free for readers, and gives deterministic, prompt unmapping.
///
/// Zero-copy values (`&[u8]`, `&str`) borrow the `Guard`, so the borrow checker
/// enforces their validity window: they cannot outlive the guard and hence
/// never point at unmapped memory. Use `get_copy` to keep a value longer.
///
/// Bounded retirement: the client keeps `Weak` handles to replaced maps. A swap
/// waits while `MAX_RETIRED` of them are still alive, so retired maps cannot
/// accumulate without bound. (A caller that holds a `Guard`/`Arc` forever
/// therefore blocks further swaps rather than growing memory.) File descriptors
/// are closed right after `mmap`, so retirement never leaks fds.
///
/// The struct is `Clone` + `Send + Sync`; it can be shared freely across
/// threads without wrapping in an additional `Arc`.
#[derive(Clone)]
pub struct AttosClient {
    current_map: Arc<ArcSwap<AttosMap>>,
    config: OpenConfig,
    shared: Arc<Shared>,
}

struct Shared {
    retired: Mutex<Vec<Weak<AttosMap>>>,
    swaps: AtomicU64,
    retired_lookups: AtomicU64,
    latency: LatencyHistogram,
}

impl std::fmt::Debug for AttosClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttosClient")
            .field("current_map", &*self.current_map.load())
            .field("config", &self.config)
            .field("swaps", &self.shared.swaps.load(Ordering::Relaxed))
            .finish()
    }
}

impl AttosClient {
    /// Construct with an already-opened `AttosMap`.
    ///
    /// `config` is retained and re-applied on every subsequent `reload()` call,
    /// so `validate_checksum` and `pin_to_memory` remain consistent across
    /// hot-swaps without requiring the caller to repeat them.
    pub fn new(initial_map: AttosMap, config: OpenConfig) -> Self {
        info!("Initializing AttosClient");
        Self {
            current_map: Arc::new(ArcSwap::from_pointee(initial_map)),
            config,
            shared: Arc::new(Shared {
                retired: Mutex::new(Vec::new()),
                swaps: AtomicU64::new(0),
                retired_lookups: AtomicU64::new(0),
                latency: LatencyHistogram::default(),
            }),
        }
    }

    /// Obtain a lock-free reference to the current `AttosMap`.
    ///
    /// No lock, no allocation. The returned `Guard` keeps the underlying map
    /// alive (and mapped) for the duration of the borrow.
    ///
    /// ```no_run
    /// # use attos_client::{AttosClient, AttosMap, OpenConfig, AttosError};
    /// # fn main() -> Result<(), AttosError> {
    /// let client = AttosClient::new(AttosMap::open("data.attos")?, OpenConfig::default());
    /// let guard = client.read();
    /// let value = guard.get(b"my-key")?;
    /// println!("{:?}", value);
    /// // guard dropped here; the old map (if swapped meanwhile) can now be unmapped
    /// # Ok(())
    /// # }
    /// ```
    #[inline(always)]
    pub fn read(&self) -> arc_swap::Guard<Arc<AttosMap>> {
        self.current_map.load()
    }

    /// Copying lookup against the current map: appends the value to `dst`.
    /// The result stays valid across swaps and shutdown.
    #[inline]
    pub fn get_copy(&self, key: &[u8], dst: &mut Vec<u8>) -> Result<(), AttosError> {
        self.current_map.load().get_copy(key, dst)
    }

    /// Hot-swap the live map from a new file path.
    ///
    /// Sequence:
    /// 1. Open and validate the new file (checksum / mlock per stored `config`).
    /// 2. Wait while `MAX_RETIRED` replaced maps are still referenced.
    /// 3. `ArcSwap::swap` — a single atomic pointer exchange.
    /// 4. The previous map is unmapped when its last reader releases it.
    ///
    /// Readers are never blocked and observe either the old or the new map,
    /// never a partially-written state. On error the current map is kept.
    #[instrument(skip(self, path), fields(path = %path.as_ref().display()))]
    pub fn reload<P: AsRef<Path>>(&self, path: P) -> Result<(), AttosError> {
        info!("Reloading AttosMap from new path");
        let new_map = AttosMap::open_with_config(path, self.config)?;
        self.swap_map(new_map)?;
        info!("Successfully hot-swapped AttosMap");
        Ok(())
    }

    /// Publish an already-validated map (used by the synchronizer).
    pub fn swap_map(&self, new_map: AttosMap) -> Result<(), AttosError> {
        if self.current_map.load().is_closed() {
            return Err(AttosError::MapClosed);
        }
        let new_map = Arc::new(new_map);
        let mut retired = self.shared.retired.lock().unwrap();
        let mut waited = Duration::ZERO;
        loop {
            retired.retain(|w| w.strong_count() > 0);
            if retired.len() < MAX_RETIRED {
                break;
            }
            drop(retired);
            std::thread::sleep(Duration::from_millis(1));
            waited += Duration::from_millis(1);
            if waited.as_millis() % 5000 == 0 {
                warn!("hot-swap waiting: {} retired maps still referenced by readers", MAX_RETIRED);
            }
            retired = self.shared.retired.lock().unwrap();
        }
        let old = self.current_map.swap(new_map);
        self.shared
            .retired_lookups
            .fetch_add(old.lookups(), Ordering::Relaxed);
        self.shared.latency.absorb(&old.latency);
        self.shared.swaps.fetch_add(1, Ordering::Relaxed);
        retired.push(Arc::downgrade(&old));
        drop(retired);
        drop(old); // unmapped now unless a reader still holds it
        Ok(())
    }

    /// Number of replaced maps that are still referenced by readers.
    pub fn pending_retired(&self) -> usize {
        let mut retired = self.shared.retired.lock().unwrap();
        retired.retain(|w| w.strong_count() > 0);
        retired.len()
    }

    /// Number of completed hot swaps.
    pub fn swaps(&self) -> u64 {
        self.shared.swaps.load(Ordering::Relaxed)
    }

    /// Total lookups served (current + retired maps).
    pub fn lookups(&self) -> u64 {
        self.shared.retired_lookups.load(Ordering::Relaxed) + self.current_map.load().lookups()
    }

    /// Sampled lookup-latency percentiles since the previous call (resets).
    pub fn drain_latency(&self) -> LatencySnapshot {
        self.shared.latency.absorb(&self.current_map.load().latency);
        self.shared.latency.drain()
    }

    /// Size in bytes of the currently mapped blob.
    pub fn memory_bytes(&self) -> usize {
        self.current_map.load().size()
    }

    /// Explicit shutdown hook.
    ///
    /// Replaces the live map with a sentinel whose lookups return
    /// `AttosError::MapClosed`, then waits (up to 5 s) until every previously
    /// published map has been released by its readers and unmapped. Further
    /// `reload`/`swap_map` calls fail with `MapClosed`. Safe to call repeatedly.
    pub fn shutdown(&self) {
        info!("AttosClient shutting down; invalidating live map");
        let old = self.current_map.swap(Arc::new(AttosMap::closed_sentinel()));
        if old.is_closed() {
            return;
        }
        self.shared
            .retired_lookups
            .fetch_add(old.lookups(), Ordering::Relaxed);
        let mut retired = self.shared.retired.lock().unwrap();
        retired.push(Arc::downgrade(&old));
        drop(retired);
        drop(old);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.pending_retired() > 0 {
            if Instant::now() > deadline {
                warn!(
                    "shutdown: {} maps still referenced by readers; they will be unmapped when released",
                    self.pending_retired()
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Legacy one-shot telemetry call.
    ///
    /// Sends no API key, so it cannot authenticate against the contract
    /// endpoint; use [`crate::AttosSynchronizer`] (which runs the CONTRACTS §5
    /// emitter with `X-API-Key`) instead. Kept for API compatibility.
    #[deprecated(note = "use AttosSynchronizer, which reports telemetry with X-API-Key per CONTRACTS §5")]
    #[allow(clippy::too_many_arguments)]
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
        let snap = LatencySnapshot {
            samples: 1,
            p50: latency_ns.max(0) as u64,
            p95: latency_ns.max(0) as u64,
            p99: latency_ns.max(0) as u64,
            max: latency_ns.max(0) as u64,
        };
        let body = crate::telemetry::report_body(
            dataset_id,
            node_id,
            &snap,
            lookups_count.max(0) as u64,
            memory_bytes.max(0) as u64,
            crc32_errors.max(0) as u64,
            0,
        );
        let url = format!("{}/api/v1/telemetry/report", base_url.trim_end_matches('/'));
        let _ = reqwest::Client::new()
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await;
    }
}
