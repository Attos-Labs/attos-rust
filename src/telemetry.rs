//! Telemetry emitter (CONTRACTS.md §5).
//!
//! A collector task builds one report per interval from counters the lookup
//! path maintains anyway (striped lookup counters, 1/256-sampled latency
//! histogram); nothing is built or sent on the hot path. Reports go through a
//! bounded queue of 64; when full the newest report is dropped and
//! `attos.telemetry_dropped` is incremented. The sender POSTs with `X-API-Key`
//! (no `Active-Project-ID`): 5xx/network → up to 3 retries after 1 s, 2 s,
//! 4 s, then drop; 4xx except 429 → drop; 429 → drop and pause for
//! `Retry-After` or 60 s. Reports are only built while the last sync's
//! `X-Attos-Config.telemetry_enabled` is true (default true until first sync).
use crate::stats::LatencySnapshot;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_TELEMETRY_INTERVAL: Duration = Duration::from_secs(60);
pub const TELEMETRY_QUEUE: usize = 64;
pub const TELEMETRY_429_PAUSE: Duration = Duration::from_secs(60);

/// Build the §5 JSON body.
pub fn report_body(
    dataset_id: &str,
    node_id: &str,
    lat: &LatencySnapshot,
    lookups: u64,
    memory_bytes: u64,
    crc32_errors: u64,
    dropped: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();
    let clamp = |v: u64| v.min(i64::MAX as u64) as i64;
    let metric = |name: &str, v: u64| {
        json!({"name": name, "gauge": {"dataPoints": [{"asInt": clamp(v), "timeUnixNano": now}]}})
    };
    json!({"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "attos.dataset_id", "value": {"stringValue": dataset_id}},
            {"key": "attos.node_id", "value": {"stringValue": node_id}},
            {"key": "sdk.version", "value": {"stringValue": format!("rust-{}", crate::VERSION)}}
        ]},
        "scopeMetrics": [{
            "scope": {"name": "attos-sdk", "version": crate::VERSION},
            "metrics": [
                metric("attos.lookup.p50_ns", lat.p50),
                metric("attos.lookup.p95_ns", lat.p95),
                metric("attos.lookup.p99_ns", lat.p99),
                metric("attos.lookups_count", lookups),
                metric("attos.memory_bytes", memory_bytes),
                metric("attos.crc32_errors", crc32_errors),
                metric("attos.telemetry_dropped", dropped)
            ]
        }]
    }]})
    .to_string()
}

/// Counters shared between the collector, the sender and the public API.
#[derive(Default)]
pub struct TelemetryState {
    pub dropped: AtomicU64,
    pub sent: AtomicU64,
    pub attempts: AtomicU64,
    pub pause_until_ms: AtomicU64,
    pub(crate) window: Mutex<(u64, u64)>, // (last lookups, last crc errors)
}

/// Snapshot of emitter counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelemetryStats {
    pub sent: u64,
    pub attempts: u64,
    pub dropped_pending: u64,
}

impl TelemetryState {
    pub fn stats(&self) -> TelemetryStats {
        TelemetryStats {
            sent: self.sent.load(Ordering::Relaxed),
            attempts: self.attempts.load(Ordering::Relaxed),
            dropped_pending: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// One queued report and the dropped count it carries.
pub(crate) struct Report {
    pub body: String,
    pub dropped_carried: u64,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
