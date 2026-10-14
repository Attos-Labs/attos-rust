//! Background sync (CONTRACTS.md §4) and telemetry emitter (§5).
//!
//! All network I/O runs on one dedicated background thread that owns a
//! current-thread Tokio runtime, so the synchronizer works the same from sync
//! and async applications (no runtime is required from the caller, and no
//! `block_on` happens on a caller's runtime). Public calls communicate with
//! that thread over channels.
use crate::error::AttosError;
use crate::map::{AttosMap, OpenConfig};
use crate::sync::AttosClient;
use crate::telemetry::{
    now_ms, report_body, Report, TelemetryState, TelemetryStats, DEFAULT_TELEMETRY_INTERVAL,
    TELEMETRY_429_PAUSE, TELEMETRY_QUEUE,
};
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as stdmpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Default poll interval — identical in the Go, Rust and Java SDKs.
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);
/// Pause after 402/429 without `Retry-After`.
pub const QUOTA_PAUSE: Duration = Duration::from_secs(300);
/// Cap for `Retry-After`.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);
const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(300);

/// Synchronizer configuration.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub base_url: String,
    pub api_key: String,
    pub dataset_id: String,
    /// Directory holding `<dataset_id>.attos`, its ETag and in-progress downloads.
    pub cache_dir: PathBuf,
    /// `X-Attos-Node-ID` (1–128 chars). Default: a UUIDv4 generated at start.
    pub node_id: Option<String>,
    /// Background poll interval; `Duration::ZERO` disables polling.
    pub poll_interval: Duration,
    pub open: OpenConfig,
    /// Telemetry report interval; `Duration::ZERO` disables the emitter.
    pub telemetry_interval: Duration,
    pub telemetry_base_url: Option<String>,
    pub telemetry_api_key: Option<String>,
    pub http_timeout: Duration,
    /// Telemetry retry delays (default 1 s, 2 s, 4 s). Exposed for tests.
    pub telemetry_retry_delays: Vec<Duration>,
    /// Base unit of the transient back-off (default 1 s). Exposed for tests.
    pub backoff_base: Duration,
}

impl SyncConfig {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>, dataset_id: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            dataset_id: dataset_id.into(),
            cache_dir: PathBuf::from("./.attos/cache"),
            node_id: None,
            poll_interval: DEFAULT_SYNC_INTERVAL,
            open: OpenConfig::default(),
            telemetry_interval: DEFAULT_TELEMETRY_INTERVAL,
            telemetry_base_url: None,
            telemetry_api_key: None,
            http_timeout: Duration::from_secs(600),
            telemetry_retry_delays: vec![Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)],
            backoff_base: Duration::from_secs(1),
        }
    }
}

/// Result of one successful sync attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    Updated,
    NotModified,
}

enum Cmd {
    Sync(stdmpsc::Sender<Result<SyncOutcome, AttosError>>),
    FlushTelemetry,
    Shutdown,
}

struct Inner {
    cfg: SyncConfig,
    node_id: String,
    etag: Mutex<Option<String>>,
    dataset_name: Mutex<Option<String>>,
    telemetry_enabled: AtomicBool,
    crc_errors: AtomicU64,
    tel: TelemetryState,
}

/// Background synchronizer: download → fsync → validate → rename → mmap →
/// atomic publish, with ETag/304, 402/429 pause and exponential back-off.
pub struct AttosSynchronizer {
    client: AttosClient,
    inner: Arc<Inner>,
    cmd: mpsc::UnboundedSender<Cmd>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// A random UUIDv4 without extra dependencies (std RandomState is seeded from
/// the OS RNG).
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    for (i, chunk) in b.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Exponential back-off 1 s·2^k with ±20 % jitter, capped at min(interval, 5 min).
pub fn transient_backoff(k: u32, interval: Duration, base: Duration) -> Duration {
    let mut cap = MAX_TRANSIENT_BACKOFF;
    if !interval.is_zero() && interval < cap {
        cap = interval;
    }
    let d = base.saturating_mul(1u32 << k.min(20)).min(cap);
    let r = (RandomState::new().build_hasher().finish() % 10_000) as f64 / 10_000.0;
    d.mul_f64(0.8 + 0.4 * r)
}

/// Policy: delay before the next poll after an attempt's outcome.
pub fn next_delay(
    res: &Result<SyncOutcome, AttosError>,
    failures: &mut u32,
    interval: Duration,
    base: Duration,
    logged: &mut HashSet<u16>,
) -> Duration {
    match res {
        Ok(_) => {
            *failures = 0;
            interval
        }
        Err(AttosError::HttpStatus { code, retry_after }) if *code == 402 || *code == 429 => {
            let d = retry_after.map(|d| d.min(MAX_RETRY_AFTER)).unwrap_or(QUOTA_PAUSE);
            warn!("quota/node limit ({}); sync paused for {:?}, serving local data", code, d);
            d
        }
        Err(AttosError::HttpStatus { code, .. }) if (400..500).contains(code) => {
            if logged.insert(*code) {
                warn!("sync rejected with HTTP {}; keeping current data", code);
            }
            *failures = 0;
            interval
        }
        Err(e) => {
            let d = transient_backoff(*failures, interval, base);
            *failures += 1;
            warn!("sync failed ({}); keeping current data, retrying in {:?}", e, d);
            d
        }
    }
}

fn parse_retry_after(v: Option<&reqwest::header::HeaderValue>) -> Option<Duration> {
    v.and_then(|h| h.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

impl AttosSynchronizer {
    /// Load a cached blob (if valid), run the initial sync and start the
    /// background thread. Fails only if no data at all could be loaded.
    pub fn start(cfg: SyncConfig) -> Result<Self, AttosError> {
        let node_id = cfg.node_id.clone().unwrap_or_else(uuid_v4);
        if node_id.is_empty() || node_id.len() > 128 {
            return Err(AttosError::Config(format!("node id must be 1-128 chars, got {}", node_id.len())));
        }
        if cfg.dataset_id.is_empty() {
            return Err(AttosError::Config("dataset_id is required".into()));
        }
        fs::create_dir_all(&cfg.cache_dir)?;
        let inner = Arc::new(Inner {
            cfg,
            node_id,
            etag: Mutex::new(None),
            dataset_name: Mutex::new(None),
            telemetry_enabled: AtomicBool::new(true),
            crc_errors: AtomicU64::new(0),
            tel: TelemetryState::default(),
        });
        remove_stale_temps(&inner);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = stdmpsc::channel::<Result<AttosClient, AttosError>>();
        let inner2 = inner.clone();
        let handle = std::thread::Builder::new()
            .name("attos-sync".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(AttosError::IoError(e)));
                        return;
                    }
                };
                rt.block_on(run(inner2, cmd_rx, ready_tx));
            })?;
        match ready_rx.recv() {
            Ok(Ok(client)) => Ok(Self { client, inner, cmd: cmd_tx, thread: Mutex::new(Some(handle)) }),
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = handle.join();
                Err(AttosError::Transport("sync thread exited".into()))
            }
        }
    }

    /// The hot-swappable client (lock-free reads via `read()`).
    pub fn client(&self) -> &AttosClient {
        &self.client
    }

    /// Shorthand for `client().read()`.
    #[inline(always)]
    pub fn read(&self) -> arc_swap::Guard<Arc<AttosMap>> {
        self.client.read()
    }

    /// Run one sync attempt now (blocks the calling thread until it finishes).
    pub fn sync_now(&self) -> Result<SyncOutcome, AttosError> {
        let (tx, rx) = stdmpsc::channel();
        self.cmd.send(Cmd::Sync(tx)).map_err(|_| AttosError::MapClosed)?;
        rx.recv().map_err(|_| AttosError::MapClosed)?
    }

    /// Build and enqueue a telemetry report now.
    pub fn flush_telemetry(&self) {
        let _ = self.cmd.send(Cmd::FlushTelemetry);
    }

    pub fn telemetry_stats(&self) -> TelemetryStats {
        self.inner.tel.stats()
    }
    pub fn node_id(&self) -> &str {
        &self.inner.node_id
    }
    pub fn etag(&self) -> Option<String> {
        self.inner.etag.lock().unwrap().clone()
    }
    pub fn dataset_name(&self) -> Option<String> {
        self.inner.dataset_name.lock().unwrap().clone()
    }
    pub fn telemetry_enabled(&self) -> bool {
        self.inner.telemetry_enabled.load(Ordering::Relaxed)
    }
    pub fn crc_errors(&self) -> u64 {
        self.inner.crc_errors.load(Ordering::Relaxed)
    }

    /// Stop the background thread and unmap all data (waits for readers up to 5 s).
    pub fn shutdown(&self) {
        let _ = self.cmd.send(Cmd::Shutdown);
        if let Some(h) = self.thread.lock().unwrap().take() {
            let _ = h.join();
        }
        self.client.shutdown();
    }
}

impl Drop for AttosSynchronizer {
    fn drop(&mut self) {
        let _ = self.cmd.send(Cmd::Shutdown);
        if let Some(h) = self.thread.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

fn live_path(i: &Inner) -> PathBuf {
    i.cfg.cache_dir.join(format!("{}.attos", i.cfg.dataset_id))
}
fn etag_path(i: &Inner) -> PathBuf {
    i.cfg.cache_dir.join(format!("{}.etag", i.cfg.dataset_id))
}
fn temp_prefix(i: &Inner) -> String {
    format!(".{}.attos.download-", i.cfg.dataset_id)
}

fn remove_stale_temps(i: &Inner) {
    if let Ok(rd) = fs::read_dir(&i.cfg.cache_dir) {
        let p = temp_prefix(i);
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&p) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

struct TempGuard(Option<PathBuf>);
impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

async fn run(
    inner: Arc<Inner>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    ready: stdmpsc::Sender<Result<AttosClient, AttosError>>,
) {
    let http = match reqwest::Client::builder().timeout(inner.cfg.http_timeout).build() {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(AttosError::Transport(e.to_string())));
            return;
        }
    };
    // 1. Cached blob.
    let mut client: Option<AttosClient> = None;
    let live = live_path(&inner);
    if live.exists() {
        match AttosMap::open_inner(&live, inner.cfg.open, true) {
            Ok(m) => {
                client = Some(AttosClient::new(m, inner.cfg.open));
                *inner.etag.lock().unwrap() = fs::read_to_string(etag_path(&inner)).ok();
            }
            Err(e) => warn!("cached blob not usable: {}", e),
        }
    }
    // 2. Initial sync (up to 3 attempts for transient errors).
    let mut first: Result<SyncOutcome, AttosError> = Err(AttosError::MapClosed);
    for attempt in 0..3u32 {
        first = sync_once(&inner, &http, &mut client).await;
        match &first {
            Ok(_) | Err(AttosError::HttpStatus { .. }) => break,
            Err(_) => tokio::time::sleep(Duration::from_millis(100 << attempt)).await,
        }
    }
    let client = match (client, &first) {
        (Some(c), r) => {
            if let Err(e) = r {
                warn!("initial sync failed, serving cached blob: {}", e);
            }
            c
        }
        (None, _) => {
            let e = first.err().unwrap_or(AttosError::MapClosed);
            let _ = ready.send(Err(e));
            return;
        }
    };
    let _ = ready.send(Ok(client.clone()));
    let mut client_opt = Some(client.clone());

    // 3. Telemetry tasks.
    let (tel_tx, tel_rx) = mpsc::channel::<Report>(TELEMETRY_QUEUE);
    let tel_on = !inner.cfg.telemetry_interval.is_zero();
    if tel_on {
        *inner.tel.window.lock().unwrap() = (client.lookups(), inner.crc_errors.load(Ordering::Relaxed));
        tokio::spawn(sender(inner.clone(), http.clone(), tel_rx));
    }
    let mut tel_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + inner.cfg.telemetry_interval.max(Duration::from_millis(1)),
        inner.cfg.telemetry_interval.max(Duration::from_millis(1)),
    );

    // 4. Poll loop.
    let interval = inner.cfg.poll_interval;
    let mut failures = 0u32;
    let mut logged = HashSet::new();
    let mut delay = next_delay(&first, &mut failures, interval, inner.cfg.backoff_base, &mut logged);
    let far = Duration::from_secs(86400 * 365);
    loop {
        let sleep = tokio::time::sleep(if interval.is_zero() { far } else { delay });
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                _ = tel_tick.tick(), if tel_on => enqueue(&inner, &client, &tel_tx),
                cmd = cmd_rx.recv() => match cmd {
                    Some(Cmd::Sync(reply)) => {
                        let r = sync_once(&inner, &http, &mut client_opt).await;
                        let _ = reply.send(r);
                    }
                    Some(Cmd::FlushTelemetry) => if tel_on { enqueue(&inner, &client, &tel_tx) },
                    Some(Cmd::Shutdown) | None => return,
                },
            }
        }
        let r = sync_once(&inner, &http, &mut client_opt).await;
        delay = next_delay(&r, &mut failures, interval, inner.cfg.backoff_base, &mut logged);
    }
}

/// One conditional GET; on 200 install the blob per the §4 swap invariant.
async fn sync_once(
    inner: &Inner,
    http: &reqwest::Client,
    client: &mut Option<AttosClient>,
) -> Result<SyncOutcome, AttosError> {
    let url = format!("{}/api/v1/datasets/sync/{}", inner.cfg.base_url, inner.cfg.dataset_id);
    let mut req = http
        .get(&url)
        .header("X-API-Key", &inner.cfg.api_key)
        .header("X-Attos-Node-ID", &inner.node_id)
        .header("User-Agent", format!("attos-rust/{}", crate::VERSION));
    let etag = inner.etag.lock().unwrap().clone();
    if let (Some(e), Some(_)) = (&etag, client.as_ref()) {
        req = req.header("If-None-Match", e);
    }
    let mut resp = req.send().await.map_err(|e| AttosError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    if status == 304 {
        return Ok(SyncOutcome::NotModified);
    }
    if status != 200 {
        let retry_after = if status == 402 || status == 429 {
            parse_retry_after(resp.headers().get("retry-after"))
        } else {
            None
        };
        return Err(AttosError::HttpStatus { code: status, retry_after });
    }
    let new_etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(String::from);
    let cfg_hdr = resp.headers().get("x-attos-config").and_then(|v| v.to_str().ok()).map(String::from);
    let name = resp.headers().get("x-dataset-name").and_then(|v| v.to_str().ok()).map(String::from);
    let content_length = resp.content_length();

    // Download to a temp file in the same directory as the live blob.
    let tmp = inner
        .cfg
        .cache_dir
        .join(format!("{}{:016x}", temp_prefix(inner), RandomState::new().build_hasher().finish()));
    let mut guard = TempGuard(Some(tmp.clone()));
    let mut f = fs::File::create(&tmp)?;
    let mut written: u64 = 0;
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                f.write_all(&c)?;
                written += c.len() as u64;
            }
            Ok(None) => break,
            Err(e) => return Err(AttosError::Transport(format!("download interrupted: {}", e))),
        }
    }
    if let Some(cl) = content_length {
        if cl != written {
            return Err(AttosError::Transport(format!("truncated download: {} of {} bytes", written, cl)));
        }
    }
    f.sync_all()?;
    drop(f);
    // Validate the complete file (magic, version, flag, sizes, CRC) before it
    // can become visible.
    let map = match AttosMap::open_inner(&tmp, inner.cfg.open, true) {
        Ok(m) => m,
        Err(e) => {
            if matches!(e, AttosError::ChecksumMismatch { .. }) {
                inner.crc_errors.fetch_add(1, Ordering::Relaxed);
            }
            return Err(e);
        }
    };
    fs::rename(&tmp, live_path(inner))?;
    guard.0 = None;
    if let Ok(d) = fs::File::open(&inner.cfg.cache_dir) {
        let _ = d.sync_all();
    }
    match client {
        Some(c) => c.swap_map(map)?,
        None => *client = Some(AttosClient::new(map, inner.cfg.open)),
    }
    info!("hot-swapped dataset {} ({} bytes)", inner.cfg.dataset_id, written);
    let ep = etag_path(inner);
    match &new_etag {
        Some(e) => {
            let t = ep.with_extension("etag.tmp");
            if fs::write(&t, e).is_ok() {
                let _ = fs::rename(&t, &ep);
            }
        }
        None => {
            let _ = fs::remove_file(&ep);
        }
    }
    *inner.etag.lock().unwrap() = new_etag;
    if let Some(h) = cfg_hdr {
        match serde_json::from_str::<serde_json::Value>(&h) {
            Ok(v) => {
                if let Some(b) = v.get("telemetry_enabled").and_then(|b| b.as_bool()) {
                    inner.telemetry_enabled.store(b, Ordering::Relaxed);
                }
            }
            Err(e) => warn!("ignoring malformed X-Attos-Config: {}", e),
        }
    }
    if name.is_some() {
        *inner.dataset_name.lock().unwrap() = name;
    }
    Ok(SyncOutcome::Updated)
}

/// Snapshot the window and enqueue (drop-newest on a full queue).
fn enqueue(inner: &Inner, client: &AttosClient, tx: &mpsc::Sender<Report>) {
    let lookups = client.lookups();
    let crc = inner.crc_errors.load(Ordering::Relaxed);
    let (d_lookups, d_crc) = {
        let mut w = inner.tel.window.lock().unwrap();
        let d = (lookups.saturating_sub(w.0), crc.saturating_sub(w.1));
        *w = (lookups, crc);
        d
    };
    let lat = client.drain_latency();
    if !inner.telemetry_enabled.load(Ordering::Relaxed) {
        return;
    }
    let dropped = inner.tel.dropped.swap(0, Ordering::Relaxed);
    let body = report_body(
        &inner.cfg.dataset_id,
        &inner.node_id,
        &lat,
        d_lookups,
        client.memory_bytes() as u64,
        d_crc,
        dropped,
    );
    if tx.try_send(Report { body, dropped_carried: dropped }).is_err() {
        inner.tel.dropped.fetch_add(1 + dropped, Ordering::Relaxed);
    }
}

async fn sender(inner: Arc<Inner>, http: reqwest::Client, mut rx: mpsc::Receiver<Report>) {
    let base = inner.cfg.telemetry_base_url.clone().unwrap_or_else(|| inner.cfg.base_url.clone());
    let url = format!("{}/api/v1/telemetry/report", base.trim_end_matches('/'));
    let key = inner.cfg.telemetry_api_key.clone().unwrap_or_else(|| inner.cfg.api_key.clone());
    while let Some(r) = rx.recv().await {
        let until = inner.tel.pause_until_ms.load(Ordering::Relaxed);
        let now = now_ms();
        if until > now {
            tokio::time::sleep(Duration::from_millis(until - now)).await;
        }
        if !deliver(&inner, &http, &url, &key, &r.body).await {
            inner.tel.dropped.fetch_add(1 + r.dropped_carried, Ordering::Relaxed);
        }
    }
}

async fn deliver(inner: &Inner, http: &reqwest::Client, url: &str, key: &str, body: &str) -> bool {
    let delays = &inner.cfg.telemetry_retry_delays;
    let mut attempt = 0usize;
    loop {
        inner.tel.attempts.fetch_add(1, Ordering::Relaxed);
        let res = http
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-API-Key", key)
            .header("User-Agent", format!("attos-rust/{}", crate::VERSION))
            .timeout(Duration::from_secs(30))
            .body(body.to_string())
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {
                inner.tel.sent.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            Ok(r) if r.status().as_u16() == 429 => {
                let d = parse_retry_after(r.headers().get("retry-after")).unwrap_or(TELEMETRY_429_PAUSE);
                inner
                    .tel
                    .pause_until_ms
                    .store(now_ms() + d.as_millis() as u64, Ordering::Relaxed);
                return false;
            }
            Ok(r) if r.status().is_client_error() => {
                warn!("telemetry rejected: HTTP {} (dropped)", r.status());
                return false;
            }
            other => {
                if attempt >= delays.len() {
                    warn!("telemetry send failed after {} attempts (dropped): {:?}", attempt + 1, other.map(|r| r.status()));
                    return false;
                }
                tokio::time::sleep(delays[attempt]).await;
                attempt += 1;
            }
        }
    }
}
