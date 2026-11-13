//! Background sync (CONTRACTS.md §4) and telemetry emitter (§5).
//!
//! All network I/O runs on one dedicated background thread that owns a
//! current-thread Tokio runtime, so the synchronizer works the same from sync
//! and async applications (no runtime is required from the caller, and no
//! `block_on` happens on a caller's runtime). Public calls communicate with
//! that thread over channels.
use crate::error::AttosError;
use crate::map::{AttosMap, OpenConfig};
use crate::redirect::{same_origin_host, RedirectPolicy};
use crate::sync::AttosClient;
use crate::telemetry::{
    now_ms, report_body, Report, TelemetryState, TelemetryStats, DEFAULT_TELEMETRY_INTERVAL,
    TELEMETRY_429_PAUSE, TELEMETRY_QUEUE,
};
use reqwest::Url;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as stdmpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
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
    /// `X-Attos-Node-ID` (1–128 chars). Default: the `ATTOS_NODE_ID`
    /// environment variable, else the hostname, else a random UUIDv4. Active
    /// nodes are counted by distinct ID, so processes or containers sharing a
    /// hostname count as one node unless they set their own ID.
    pub node_id: Option<String>,
    /// Ask for the gzip copy of the blob (`Accept-Encoding: gzip`; default
    /// true). Transport-only: the stored and mapped blob is always the v1 file.
    pub compression: bool,
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
    /// Ask for patches (`X-Attos-Capabilities: overflow`, `X-Attos-Accept-Delta: 2`; default true). A patch that
    /// fails to apply is retried as a full blob either way.
    pub delta: bool,
    /// Ask for signed redirects (`X-Attos-Capabilities: redirect`; default true).
    pub redirect: bool,
    /// Extra hosts a signed-download redirect may point at, on top of Google Cloud Storage
    /// (`storage.googleapis.com`, `*.storage.googleapis.com`): exact hosts or `*.domain`. The
    /// `ATTOS_REDIRECT_HOSTS` environment variable (comma separated) is added to them. Targets must be https
    /// on port 443 without userinfo.
    pub redirect_hosts: Vec<String>,
    /// How long redirects stay off after a signed download failed (default 1 h).
    pub redirect_cooldown: Duration,
    /// Tests against local servers only: lifts the redirect host policy (http, IP literals, any host).
    pub test_redirect_any_target: bool,
    /// Trusted Ed25519 public keys by key id (see [`crate::signature`]). When non-empty, signed artifacts are
    /// enforced: only files whose `X-Attos-Signature` verifies against one of these keys are installed or served
    /// from the cache (fail closed). Decode keys with [`crate::parse_public_key`].
    pub signature_keys: HashMap<String, [u8; 32]>,
}

impl SyncConfig {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        dataset_id: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            dataset_id: dataset_id.into(),
            cache_dir: PathBuf::from("./.attos/cache"),
            node_id: None,
            compression: true,
            poll_interval: DEFAULT_SYNC_INTERVAL,
            open: OpenConfig::default(),
            telemetry_interval: DEFAULT_TELEMETRY_INTERVAL,
            telemetry_base_url: None,
            telemetry_api_key: None,
            http_timeout: Duration::from_secs(600),
            telemetry_retry_delays: vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
            ],
            backoff_base: Duration::from_secs(1),
            delta: true,
            redirect: true,
            redirect_hosts: Vec::new(),
            redirect_cooldown: Duration::from_secs(3600),
            test_redirect_any_target: false,
            signature_keys: HashMap::new(),
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
    policy: RedirectPolicy,
    redirect_off: Mutex<Option<Instant>>,
    delta_applied: AtomicU64,
    delta_fallbacks: AtomicU64,
    redirected: AtomicU64,
    redirect_fallbacks: AtomicU64,
    sig_errors: AtomicU64,
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
/// The default node ID: `ATTOS_NODE_ID`, else the hostname, else a random
/// UUIDv4, cut to 128 characters. A process restarted on the same host keeps
/// its ID, so a restart is one active node, not two.
pub fn default_node_id() -> String {
    node_id_from(std::env::var("ATTOS_NODE_ID").ok(), hostname())
}

fn node_id_from(env: Option<String>, host: Option<String>) -> String {
    let pick = |v: Option<String>| v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let id = pick(env).or_else(|| pick(host)).unwrap_or_else(uuid_v4);
    id.chars().take(128).collect()
}

#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates
    // on success when the name fits.
    if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    for (i, chunk) in b.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Exponential back-off 1 s·2^k with ±20 % jitter, capped at min(interval, 5 min).
pub fn transient_backoff(k: u32, interval: Duration, base: Duration) -> Duration {
    transient_backoff_with(k, interval, base, random())
}

/// [`transient_backoff`] with the jitter draw `r` in `[0, 1)` supplied by the caller.
pub fn transient_backoff_with(k: u32, interval: Duration, base: Duration, r: f64) -> Duration {
    let mut cap = MAX_TRANSIENT_BACKOFF;
    if !interval.is_zero() && interval < cap {
        cap = interval;
    }
    let d = base.saturating_mul(1u32 << k.min(20)).min(cap);
    d.mul_f64(0.8 + 0.4 * r)
}

/// A draw in `[0, 1)` from the OS-seeded std hasher.
fn random() -> f64 {
    (RandomState::new().build_hasher().finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// The wait between polls: the base interval plus a random share of up to half of it ("30 s + up to 15 s"),
/// so a fleet that reconnects together does not poll in lockstep. An interval of 0 (polling off) stays 0.
/// `r` is a draw in `[0, 1)`.
pub fn jitter_interval(interval: Duration, r: f64) -> Duration {
    if interval.is_zero() {
        return interval;
    }
    interval + (interval / 2).mul_f64(r)
}

/// Policy: delay before the next poll after an attempt's outcome (jittered with a fresh random draw).
pub fn next_delay(
    res: &Result<SyncOutcome, AttosError>,
    failures: &mut u32,
    interval: Duration,
    base: Duration,
    logged: &mut HashSet<u16>,
) -> Duration {
    next_delay_with(res, failures, interval, base, logged, random(), random())
}

/// [`next_delay`] with the random draws (`r1` for the poll/pause jitter, `r2` for the transient back-off, both in
/// `[0, 1)`) supplied by the caller. Success and 4xx wait `interval + up to 50 %`; a 402/429 pause is stretched by
/// up to 20 % ("resume at spread-out moments, never earlier than asked"); transient errors back off 1 s·2^k ±20 %.
pub fn next_delay_with(
    res: &Result<SyncOutcome, AttosError>,
    failures: &mut u32,
    interval: Duration,
    base: Duration,
    logged: &mut HashSet<u16>,
    r1: f64,
    r2: f64,
) -> Duration {
    match res {
        Ok(_) => {
            *failures = 0;
            jitter_interval(interval, r1)
        }
        Err(AttosError::HttpStatus { code, retry_after }) if *code == 402 || *code == 429 => {
            let d = retry_after
                .map(|d| d.min(MAX_RETRY_AFTER))
                .unwrap_or(QUOTA_PAUSE);
            let d = d + d.mul_f64(0.2 * r1);
            warn!(
                "quota/node limit ({}); sync paused for {:?}, serving local data",
                code, d
            );
            d
        }
        Err(AttosError::HttpStatus { code, .. }) if (400..500).contains(code) => {
            if logged.insert(*code) {
                warn!("sync rejected with HTTP {}; keeping current data", code);
            }
            *failures = 0;
            jitter_interval(interval, r1)
        }
        Err(e) => {
            let d = transient_backoff_with(*failures, interval, base, r2);
            *failures += 1;
            warn!(
                "sync failed ({}); keeping current data, retrying in {:?}",
                e, d
            );
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
        let node_id = cfg.node_id.clone().unwrap_or_else(default_node_id);
        if node_id.is_empty() || node_id.len() > 128 {
            return Err(AttosError::Config(format!(
                "node id must be 1-128 chars, got {}",
                node_id.len()
            )));
        }
        if cfg.dataset_id.is_empty() {
            return Err(AttosError::Config("dataset_id is required".into()));
        }
        fs::create_dir_all(&cfg.cache_dir)?;
        let policy = RedirectPolicy::new(
            &cfg.redirect_hosts,
            std::env::var(crate::redirect::REDIRECT_HOSTS_ENV)
                .ok()
                .as_deref(),
            cfg.test_redirect_any_target,
        );
        let inner = Arc::new(Inner {
            cfg,
            node_id,
            etag: Mutex::new(None),
            dataset_name: Mutex::new(None),
            telemetry_enabled: AtomicBool::new(true),
            crc_errors: AtomicU64::new(0),
            tel: TelemetryState::default(),
            policy,
            redirect_off: Mutex::new(None),
            delta_applied: AtomicU64::new(0),
            delta_fallbacks: AtomicU64::new(0),
            redirected: AtomicU64::new(0),
            redirect_fallbacks: AtomicU64::new(0),
            sig_errors: AtomicU64::new(0),
        });
        remove_stale_temps(&inner);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = stdmpsc::channel::<Result<AttosClient, AttosError>>();
        let inner2 = inner.clone();
        let handle = std::thread::Builder::new()
            .name("attos-sync".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(AttosError::IoError(e)));
                        return;
                    }
                };
                rt.block_on(run(inner2, cmd_rx, ready_tx));
            })?;
        match ready_rx.recv() {
            Ok(Ok(client)) => Ok(Self {
                client,
                inner,
                cmd: cmd_tx,
                thread: Mutex::new(Some(handle)),
            }),
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
        self.cmd
            .send(Cmd::Sync(tx))
            .map_err(|_| AttosError::MapClosed)?;
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
    /// Downloaded or cached files rejected by signature verification.
    pub fn signature_errors(&self) -> u64 {
        self.inner.sig_errors.load(Ordering::Relaxed)
    }
    /// `(applied, fallbacks)`: syncs completed from a patch, and patches that failed and fell back to a full blob.
    pub fn delta_stats(&self) -> (u64, u64) {
        (
            self.inner.delta_applied.load(Ordering::Relaxed),
            self.inner.delta_fallbacks.load(Ordering::Relaxed),
        )
    }
    /// `(redirected, fallbacks)`: syncs completed from a signed URL, and signed downloads that failed and were
    /// repeated through the sync endpoint.
    pub fn redirect_stats(&self) -> (u64, u64) {
        (
            self.inner.redirected.load(Ordering::Relaxed),
            self.inner.redirect_fallbacks.load(Ordering::Relaxed),
        )
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
    let http = match reqwest::Client::builder()
        .timeout(inner.cfg.http_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
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
        // With signing enforced the cached file is re-verified against the signature saved with it.
        let cached = match verify_cached(&inner, &live) {
            Ok(()) => AttosMap::open_inner(&live, inner.cfg.open, true),
            Err(e) => {
                inner.sig_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        };
        match cached {
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
        *inner.tel.window.lock().unwrap() =
            (client.lookups(), inner.crc_errors.load(Ordering::Relaxed));
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
    let mut delay = next_delay(
        &first,
        &mut failures,
        interval,
        inner.cfg.backoff_base,
        &mut logged,
    );
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
        delay = next_delay(
            &r,
            &mut failures,
            interval,
            inner.cfg.backoff_base,
            &mut logged,
        );
    }
}

/// Where a download is written: the temp file, or a gzip decoder in front of it.
#[allow(clippy::large_enum_variant)] // one short-lived value per download
enum Sink {
    Raw(fs::File),
    Gzip(flate2::write::GzDecoder<fs::File>),
}

impl Sink {
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Sink::Raw(f) => f.write_all(b),
            Sink::Gzip(d) => d.write_all(b),
        }
    }

    /// The temp file, once a gzip stream has ended with a valid trailer.
    fn finish(self) -> Result<fs::File, AttosError> {
        match self {
            Sink::Raw(f) => Ok(f),
            Sink::Gzip(d) => d.finish().map_err(|e| {
                AttosError::Transport(format!("truncated or corrupt gzip download: {}", e))
            }),
        }
    }
}

/// A failed sync attempt, classified so `sync_once` can pick the fallback.
enum Fail {
    /// The signed-URL download failed (refused host, expired, HTTP error, truncated/corrupt body, bad patch).
    Redirect(AttosError),
    /// A patch could not be applied; the full blob is the safe path.
    Delta(AttosError),
    Other(AttosError),
}

impl From<AttosError> for Fail {
    fn from(e: AttosError) -> Self {
        Fail::Other(e)
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail::Other(AttosError::IoError(e))
    }
}

/// The response whose bytes are installed: the 200 itself, or the object behind a signed 302 (headers of the
/// 302, body of the download).
struct Effective {
    headers: reqwest::header::HeaderMap,
    body: reqwest::Response,
    /// Body length the sender declared (Content-Length, or X-Attos-Content-Length for a redirect).
    declared: Option<u64>,
    redirected: bool,
}

const MAX_ORDINARY_REDIRECTS: usize = 10;
const SIGNED_LENGTH_HEADER: &str = "x-attos-content-length";
const SIGNED_ENCODING_HEADER: &str = "x-attos-content-encoding";

fn hv(r: &reqwest::header::HeaderMap, k: &str) -> Option<String> {
    r.get(k).and_then(|v| v.to_str().ok()).map(String::from)
}

/// One sync, with the fallbacks of the Go SDK: a failed signed download is repeated through the endpoint
/// (`X-Attos-No-Redirect: 1`) and switches redirects off for `redirect_cooldown`; a failed patch is repeated
/// without delta capabilities, i.e. as a full blob.
async fn sync_once(
    inner: &Inner,
    http: &reqwest::Client,
    client: &mut Option<AttosClient>,
) -> Result<SyncOutcome, AttosError> {
    let mut allow_delta = inner.cfg.delta;
    let mut allow_redirect = inner.cfg.redirect && redirect_allowed_now(inner);
    loop {
        match sync_attempt(inner, http, client, allow_delta, allow_redirect).await {
            Ok(o) => return Ok(o),
            Err(Fail::Redirect(e)) if allow_redirect => {
                inner.redirect_fallbacks.fetch_add(1, Ordering::Relaxed);
                // Stop asking for a while: a node that cannot reach the download host would otherwise be handed
                // a URL, fail, and stream the same bytes through the endpoint on every sync, billed twice each time.
                *inner.redirect_off.lock().unwrap() =
                    Some(Instant::now() + inner.cfg.redirect_cooldown);
                warn!("signed download failed ({}); fetching through the sync endpoint, no redirects for {:?}", e, inner.cfg.redirect_cooldown);
                allow_redirect = false;
            }
            Err(Fail::Delta(e)) if allow_delta => {
                inner.delta_fallbacks.fetch_add(1, Ordering::Relaxed);
                warn!("delta update failed ({}); downloading the full blob", e);
                allow_delta = false;
            }
            Err(Fail::Redirect(e)) | Err(Fail::Delta(e)) | Err(Fail::Other(e)) => return Err(e),
        }
    }
}

#[allow(clippy::unnecessary_map_or)] // is_none_or needs a newer MSRV
fn redirect_allowed_now(inner: &Inner) -> bool {
    inner
        .redirect_off
        .lock()
        .unwrap()
        .map_or(true, |t| Instant::now() >= t)
}

/// Builds the sync GET. `creds` = false drops the API key and node id (a redirect to another host).
fn sync_request(
    inner: &Inner,
    http: &reqwest::Client,
    url: &str,
    creds: bool,
    have_blob: bool,
    allow_delta: bool,
    allow_redirect: bool,
) -> reqwest::RequestBuilder {
    let mut req = http
        .get(url)
        .header("User-Agent", format!("attos-rust/{}", crate::VERSION))
        .header(
            "Accept-Encoding",
            if inner.cfg.compression {
                "gzip"
            } else {
                "identity"
            },
        );
    if creds {
        req = req
            .header("X-API-Key", &inner.cfg.api_key)
            .header("X-Attos-Node-ID", &inner.node_id);
    }
    if have_blob {
        if let Some(e) = inner.etag.lock().unwrap().clone() {
            req = req.header("If-None-Match", e);
        }
    }
    // Capabilities are sent on every request, a first sync included, so a fresh node can be given the
    // overflow-capable file that later tail patches build on.
    let mut caps: Vec<&str> = Vec::new();
    if allow_delta {
        req = req.header("X-Attos-Accept-Delta", "2");
        caps.push("overflow");
    }
    if allow_redirect {
        caps.push("redirect");
    } else if inner.cfg.redirect {
        req = req.header("X-Attos-No-Redirect", "1"); // fallback after a failed signed download: stream it
    }
    if !caps.is_empty() {
        req = req.header("X-Attos-Capabilities", caps.join(","));
    }
    req
}

/// Sends the sync request, following ordinary redirects by hand: never from https to http, never to a host
/// outside the policy, and the API key and node id travel only to the original host. A redirect that the sync
/// endpoint marks as a signed download (`X-Attos-Content-Length`) is returned as is.
async fn send_sync(
    inner: &Inner,
    http: &reqwest::Client,
    have_blob: bool,
    allow_delta: bool,
    allow_redirect: bool,
) -> Result<reqwest::Response, AttosError> {
    let first = Url::parse(&format!(
        "{}/api/v1/datasets/sync/{}",
        inner.cfg.base_url, inner.cfg.dataset_id
    ))
    .map_err(|e| AttosError::Config(format!("invalid base_url: {}", e)))?;
    let mut cur = first.clone();
    for _ in 0..=MAX_ORDINARY_REDIRECTS {
        let creds = same_origin_host(&cur, &first);
        let resp = sync_request(
            inner,
            http,
            cur.as_str(),
            creds,
            have_blob,
            allow_delta,
            allow_redirect,
        )
        .send()
        .await
        .map_err(|e| AttosError::Transport(e.to_string()))?;
        let st = resp.status();
        if !st.is_redirection() || resp.headers().contains_key(SIGNED_LENGTH_HEADER) {
            return Ok(resp);
        }
        let Some(loc) = hv(resp.headers(), "location") else {
            return Ok(resp);
        };
        let next = cur
            .join(&loc)
            .map_err(|e| AttosError::Transport(format!("bad redirect location: {}", e)))?;
        inner
            .policy
            .allows_ordinary(&next, &first)
            .map_err(AttosError::Transport)?;
        cur = next;
    }
    Err(AttosError::Transport("stopped after 10 redirects".into()))
}

/// Downloads the object behind a signed redirect. The request is built from scratch: no X-API-Key,
/// Authorization or node id, and the download itself is never redirected again.
async fn fetch_redirect(
    inner: &Inner,
    http: &reqwest::Client,
    r302: reqwest::Response,
) -> Result<Effective, AttosError> {
    let t = |m: String| AttosError::Transport(m);
    let loc = hv(r302.headers(), "location").unwrap_or_default();
    let u = Url::parse(&loc).map_err(|e| t(format!("unusable redirect target: {}", e)))?;
    inner.policy.check(&u).map_err(t)?;
    let declared: u64 = hv(r302.headers(), SIGNED_LENGTH_HEADER)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| t("invalid X-Attos-Content-Length".into()))?;
    let resp = http
        .get(u)
        .header("User-Agent", format!("attos-rust/{}", crate::VERSION))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .map_err(|e| t(format!("signed download: {}", e)))?;
    if resp.status().as_u16() != 200 {
        return Err(t(format!(
            "signed download: HTTP {}",
            resp.status().as_u16()
        )));
    }
    if let Some(cl) = resp.content_length() {
        if cl != declared {
            return Err(t(format!(
                "signed download: {} bytes, expected {}",
                cl, declared
            )));
        }
    }
    let mut headers = r302.headers().clone();
    headers.remove("location");
    headers.remove("content-encoding");
    if let Some(enc) = headers.get(SIGNED_ENCODING_HEADER).cloned() {
        headers.insert("content-encoding", enc);
    }
    Ok(Effective {
        headers,
        body: resp,
        declared: Some(declared),
        redirected: true,
    })
}

/// One conditional GET; on 200 install the blob (or rebuild it from a patch) per the §4 swap invariant.
async fn sync_attempt(
    inner: &Inner,
    http: &reqwest::Client,
    client: &mut Option<AttosClient>,
    allow_delta: bool,
    allow_redirect: bool,
) -> Result<SyncOutcome, Fail> {
    let resp = send_sync(inner, http, client.is_some(), allow_delta, allow_redirect).await?;
    // A signed redirect: the bytes come from a short-lived URL, fetched WITHOUT any credential header;
    // everything else about the response is read from this 302.
    let mut eff =
        if resp.status().as_u16() == 302 && resp.headers().contains_key(SIGNED_LENGTH_HEADER) {
            fetch_redirect(inner, http, resp)
                .await
                .map_err(Fail::Redirect)?
        } else {
            Effective {
                headers: resp.headers().clone(),
                declared: resp.content_length(),
                body: resp,
                redirected: false,
            }
        };
    let redirected = eff.redirected;
    // A failure while handling redirected bytes is a redirect failure.
    let fail = move |e: AttosError| {
        if redirected {
            Fail::Redirect(e)
        } else {
            Fail::Other(e)
        }
    };
    let status = eff.body.status().as_u16();
    if !redirected {
        if status == 304 {
            return Ok(SyncOutcome::NotModified);
        }
        if status != 200 {
            let retry_after = if status == 402 || status == 429 {
                parse_retry_after(eff.headers.get("retry-after"))
            } else {
                None
            };
            return Err(AttosError::HttpStatus {
                code: status,
                retry_after,
            }
            .into());
        }
    }
    let new_etag = hv(&eff.headers, "etag");
    let cfg_hdr = hv(&eff.headers, "x-attos-config");
    let name = hv(&eff.headers, "x-dataset-name");
    let is_patch = hv(&eff.headers, "x-attos-delta").as_deref() == Some("1");
    let gzip = match hv(&eff.headers, "content-encoding").as_deref() {
        None | Some("identity") => false,
        Some("gzip") => true,
        Some(other) => {
            return Err(fail(AttosError::Transport(format!(
                "unsupported Content-Encoding {:?}",
                other
            ))))
        }
    };
    if is_patch && gzip {
        return Err(Fail::Delta(AttosError::Transport(
            "unsupported Content-Encoding on a patch".into(),
        )));
    }

    // Download to a temp file in the same directory as the live blob.
    let rnd = || RandomState::new().build_hasher().finish();
    let tmp = inner
        .cfg
        .cache_dir
        .join(format!("{}{:016x}", temp_prefix(inner), rnd()));
    let mut guard = TempGuard(Some(tmp.clone()));
    let mut patch_guard = TempGuard(None);
    // Compressed sync (CONTRACTS §4): a gzip body is decompressed while it is written. Content-Length counts
    // wire bytes; an incomplete or corrupted gzip stream fails its trailer check, and the decompressed blob
    // still gets the full validation (CRC32) below. A patch goes to its own temp file first.
    let dl_path = if is_patch {
        let p = inner
            .cfg
            .cache_dir
            .join(format!("{}patch-{:016x}", temp_prefix(inner), rnd()));
        patch_guard.0 = Some(p.clone());
        p
    } else {
        tmp.clone()
    };
    let file = fs::File::create(&dl_path)?;
    let mut out = if gzip {
        Sink::Gzip(flate2::write::GzDecoder::new(file))
    } else {
        Sink::Raw(file)
    };
    let mut written: u64 = 0;
    loop {
        match eff.body.chunk().await {
            Ok(Some(c)) => {
                written += c.len() as u64;
                // Never take more than one byte past the declared size of a signed download.
                if let (true, Some(d)) = (redirected, eff.declared) {
                    if written > d {
                        return Err(fail(AttosError::Transport(format!(
                            "signed download larger than the declared {} bytes",
                            d
                        ))));
                    }
                }
                out.write_all(&c)
                    .map_err(|e| fail(AttosError::Transport(format!("corrupt download: {}", e))))?;
            }
            Ok(None) => break,
            Err(e) => {
                return Err(fail(AttosError::Transport(format!(
                    "download interrupted: {}",
                    e
                ))))
            }
        }
    }
    if let Some(cl) = eff.declared {
        if cl != written {
            return Err(fail(AttosError::Transport(format!(
                "truncated download: {} of {} bytes",
                written, cl
            ))));
        }
    }
    let f = out.finish().map_err(fail)?;
    f.sync_all()?;
    drop(f);

    if is_patch {
        let rebuilt = rebuild_from_patch(inner, &eff.headers, &dl_path, &tmp);
        if let Err(e) = rebuilt {
            return Err(if redirected {
                Fail::Redirect(e)
            } else {
                Fail::Delta(e)
            });
        }
        drop(patch_guard);
    }

    // Signed artifacts: the signature covers the SHA-256 of the complete plain file, however it arrived.
    if !inner.cfg.signature_keys.is_empty() {
        let sig = hv(&eff.headers, "x-attos-signature");
        if let Err(e) = file_digest(&tmp).and_then(|d| {
            crate::signature::verify(
                &inner.cfg.signature_keys,
                &inner.cfg.dataset_id,
                sig.as_deref(),
                &d,
            )
        }) {
            inner.sig_errors.fetch_add(1, Ordering::Relaxed);
            return Err(if is_patch { Fail::Delta(e) } else { fail(e) });
        }
    }
    // Validate the complete file (magic, version, flag, sizes, CRC) before it can become visible.
    let map = match AttosMap::open_inner(&tmp, inner.cfg.open, true) {
        Ok(m) => m,
        Err(e) => {
            if matches!(e, AttosError::ChecksumMismatch { .. }) {
                inner.crc_errors.fetch_add(1, Ordering::Relaxed);
            }
            return Err(if is_patch { Fail::Delta(e) } else { fail(e) });
        }
    };
    fs::rename(&tmp, live_path(inner))?;
    guard.0 = None;
    if !inner.cfg.signature_keys.is_empty() {
        write_sig(
            inner,
            hv(&eff.headers, "x-attos-signature")
                .as_deref()
                .unwrap_or(""),
        );
    }
    if let Ok(d) = fs::File::open(&inner.cfg.cache_dir) {
        let _ = d.sync_all();
    }
    match client {
        Some(c) => c.swap_map(map)?,
        None => *client = Some(AttosClient::new(map, inner.cfg.open)),
    }
    info!(
        "hot-swapped dataset {} ({} bytes{})",
        inner.cfg.dataset_id,
        written,
        if is_patch { ", patch" } else { "" }
    );
    if is_patch {
        inner.delta_applied.fetch_add(1, Ordering::Relaxed);
    }
    if redirected {
        inner.redirected.fetch_add(1, Ordering::Relaxed);
    }
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

fn sig_path(i: &Inner) -> PathBuf {
    let mut p = live_path(i).into_os_string();
    p.push(".sig");
    PathBuf::from(p)
}

fn write_sig(i: &Inner, header: &str) {
    use std::io::Write as _;
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    if let Err(e) = o
        .open(sig_path(i))
        .and_then(|mut f| f.write_all(header.as_bytes()))
    {
        warn!("could not persist signature: {}", e);
    }
}

/// SHA-256 of a whole file.
fn file_digest(p: &std::path::Path) -> Result<[u8; 32], AttosError> {
    use std::io::Read;
    let mut f = fs::File::open(p)?;
    let mut h = crate::sha256::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finish());
        }
        h.update(&buf[..n]);
    }
}

/// Re-checks the cached live file against the signature saved with it (no-op without enforced signing).
fn verify_cached(i: &Inner, live: &std::path::Path) -> Result<(), AttosError> {
    if i.cfg.signature_keys.is_empty() {
        return Ok(());
    }
    let hdr = fs::read_to_string(sig_path(i)).map_err(|_| AttosError::SignatureMissing)?;
    crate::signature::verify(
        &i.cfg.signature_keys,
        &i.cfg.dataset_id,
        Some(hdr.trim()),
        &file_digest(live)?,
    )
}

/// Rebuilds the new blob into `dst` from the live file and the downloaded patch (`patch_path`). The patch's
/// base tag must be the tag this node holds, and its target SHA-256 must match the server's header.
fn rebuild_from_patch(
    inner: &Inner,
    headers: &reqwest::header::HeaderMap,
    patch_path: &std::path::Path,
    dst: &std::path::Path,
) -> Result<(), AttosError> {
    let mut have = inner.etag.lock().unwrap().clone().unwrap_or_default();
    if let Some(raw) = have.strip_suffix("-gzip\"") {
        // the raw tag of the same version
        have = format!("{}\"", raw);
    }
    let base_tag = hv(headers, "x-attos-delta-base-etag").unwrap_or_default();
    if base_tag != have {
        return Err(AttosError::Transport(format!(
            "patch is for base {}, this node has {}",
            base_tag, have
        )));
    }
    let live = fs::File::open(live_path(inner))?;
    // SAFETY: the live file is replaced only by an atomic rename of a fresh file, never written in place.
    let base = unsafe { memmap2::Mmap::map(&live) }?;
    let patch = fs::File::open(patch_path)?;
    let mut w = std::io::BufWriter::with_capacity(1 << 16, fs::File::create(dst)?);
    let sha = crate::delta::apply_delta(&mut w, &base, patch)?;
    w.flush()?;
    w.into_inner()
        .map_err(|e| AttosError::IoError(e.into_error()))?
        .sync_all()?;
    if let Some(want) = hv(headers, "x-attos-delta-target-sha256") {
        if !want.is_empty() && crate::sha256::hex(&sha) != want.to_ascii_lowercase() {
            return Err(crate::delta::corrupt(
                "target SHA-256 differs from the server's header",
            ));
        }
    }
    Ok(())
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
    if tx
        .try_send(Report {
            body,
            dropped_carried: dropped,
        })
        .is_err()
    {
        inner.tel.dropped.fetch_add(1 + dropped, Ordering::Relaxed);
    }
}

async fn sender(inner: Arc<Inner>, http: reqwest::Client, mut rx: mpsc::Receiver<Report>) {
    let base = inner
        .cfg
        .telemetry_base_url
        .clone()
        .unwrap_or_else(|| inner.cfg.base_url.clone());
    let url = format!("{}/api/v1/telemetry/report", base.trim_end_matches('/'));
    let key = inner
        .cfg
        .telemetry_api_key
        .clone()
        .unwrap_or_else(|| inner.cfg.api_key.clone());
    while let Some(r) = rx.recv().await {
        let until = inner.tel.pause_until_ms.load(Ordering::Relaxed);
        let now = now_ms();
        if until > now {
            tokio::time::sleep(Duration::from_millis(until - now)).await;
        }
        if !deliver(&inner, &http, &url, &key, &r.body).await {
            inner
                .tel
                .dropped
                .fetch_add(1 + r.dropped_carried, Ordering::Relaxed);
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
                let d = parse_retry_after(r.headers().get("retry-after"))
                    .unwrap_or(TELEMETRY_429_PAUSE);
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
                    warn!(
                        "telemetry send failed after {} attempts (dropped): {:?}",
                        attempt + 1,
                        other.map(|r| r.status())
                    );
                    return false;
                }
                tokio::time::sleep(delays[attempt]).await;
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod node_id_tests {
    use super::node_id_from;

    #[test]
    fn precedence_and_limits() {
        assert_eq!(
            node_id_from(Some(" pod-1 ".into()), Some("host".into())),
            "pod-1"
        );
        assert_eq!(
            node_id_from(None, Some("web-7.internal".into())),
            "web-7.internal"
        );
        assert_eq!(node_id_from(Some("  ".into()), Some("host".into())), "host");
        assert_eq!(node_id_from(None, None).len(), 36);
        assert_eq!(node_id_from(Some("x".repeat(300)), None).len(), 128);
    }
}
