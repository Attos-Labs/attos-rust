//! Sync protocol (CONTRACTS §4) and telemetry (§5) against a local fake
//! server, including fault injection: truncated body, connection killed
//! mid-download, corrupted CRC, unknown version, 402/429/500/404.
mod common;
use attos_client::synchronizer::{next_delay, transient_backoff, MAX_RETRY_AFTER, QUOTA_PAUSE};
use attos_client::{AttosError, AttosSynchronizer, SyncConfig, SyncOutcome};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
enum Resp {
    Normal,
    Status(u16, Vec<(String, String)>),
    Truncated(Vec<u8>),
    Kill(Vec<u8>),
    Raw(Vec<u8>),
    /// A body sent with Content-Encoding (e.g. gzip) and ETag.
    Encoded(Vec<u8>, &'static str, &'static str),
}

#[derive(Default)]
struct State {
    blob: Vec<u8>,
    etag: String,
    config: String,
    script: VecDeque<Resp>,
    sync_reqs: Vec<HashMap<String, String>>,
    served: usize,
    telem: Vec<(HashMap<String, String>, String)>,
    telem_script: VecDeque<(u16, Vec<(String, String)>)>,
}

struct Fake {
    url: String,
    st: Arc<Mutex<State>>,
}

fn write_resp(s: &mut TcpStream, code: u16, hdrs: &[(String, String)], body: &[u8], declared: Option<usize>) {
    let mut h = format!("HTTP/1.1 {} X\r\nConnection: close\r\nContent-Length: {}\r\n", code, declared.unwrap_or(body.len()));
    for (k, v) in hdrs {
        h.push_str(&format!("{}: {}\r\n", k, v));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn handle(mut s: TcpStream, st: Arc<Mutex<State>>) {
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    if r.read_line(&mut line).unwrap_or(0) == 0 { return; }
    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
    let mut hdr = HashMap::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap_or(0) == 0 { break; }
        let l = l.trim_end();
        if l.is_empty() { break; }
        if let Some((k, v)) = l.split_once(':') {
            hdr.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if path == "/api/v1/telemetry/report" {
        let n: usize = hdr.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = vec![0; n];
        r.read_exact(&mut body).unwrap();
        let (code, h) = {
            let mut g = st.lock().unwrap();
            g.telem.push((hdr, String::from_utf8(body).unwrap()));
            g.telem_script.pop_front().unwrap_or((204, vec![]))
        };
        write_resp(&mut s, code, &h, b"", None);
        return;
    }
    let (resp, blob, etag, cfg) = {
        let mut g = st.lock().unwrap();
        g.sync_reqs.push(hdr.clone());
        (g.script.pop_front().unwrap_or(Resp::Normal), g.blob.clone(), g.etag.clone(), g.config.clone())
    };
    match resp {
        Resp::Normal => {
            if !etag.is_empty() && hdr.get("if-none-match") == Some(&etag) {
                write_resp(&mut s, 304, &[], b"", None);
                return;
            }
            let h = vec![("ETag".into(), etag), ("X-Attos-Config".into(), cfg), ("X-Dataset-Name".into(), "fake".into())];
            write_resp(&mut s, 200, &h, &blob, None);
            st.lock().unwrap().served += 1;
        }
        Resp::Status(c, h) => write_resp(&mut s, c, &h, b"err", None),
        Resp::Truncated(b) => write_resp(&mut s, 200, &[("ETag".into(), "t".into())], &b[..b.len() / 2], Some(b.len())),
        Resp::Kill(b) => {
            write_resp(&mut s, 200, &[], &b[..b.len() / 3], Some(b.len()));
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        Resp::Raw(b) => write_resp(&mut s, 200, &[("ETag".into(), "raw".into())], &b, None),
        Resp::Encoded(b, enc, etag) => write_resp(
            &mut s,
            200,
            &[("ETag".into(), etag.into()), ("Content-Encoding".into(), enc.into()), ("Vary".into(), "Accept-Encoding".into())],
            &b,
            None,
        ),
    }
}

fn fake(blob: Vec<u8>, etag: &str) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let st = Arc::new(Mutex::new(State { blob, etag: etag.into(), config: r#"{"telemetry_enabled":true}"#.into(), ..Default::default() }));
    let st2 = st.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let st = st2.clone();
            std::thread::spawn(move || handle(s, st));
        }
    });
    Fake { url, st }
}

fn blob(tag: &str, n: usize) -> Vec<u8> {
    let rows: Vec<_> = (0..n).map(|i| (format!("key_{}", i).into_bytes(), format!("{}_{}", tag, i).into_bytes())).collect();
    common::build(&rows)
}

fn cfg(f: &Fake, dir: &std::path::Path) -> SyncConfig {
    let mut c = SyncConfig::new(&f.url, "test-key", "ds-1");
    c.cache_dir = dir.to_path_buf();
    c.poll_interval = Duration::ZERO;
    c.telemetry_interval = Duration::ZERO;
    c.node_id = Some("node-r".into());
    c
}

fn value(s: &AttosSynchronizer, k: &str) -> String {
    let mut d = Vec::new();
    s.client().get_copy(k.as_bytes(), &mut d).unwrap();
    String::from_utf8(d).unwrap()
}

fn temps(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("download")).count()
}

#[test]
fn headers_etag_304_and_swap() {
    let f = fake(blob("A", 100), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&f, dir.path())).unwrap();
    assert_eq!(value(&s, "key_7"), "A_7");
    {
        let g = f.st.lock().unwrap();
        let h = &g.sync_reqs[0];
        assert_eq!(h.get("x-api-key").map(String::as_str), Some("test-key"));
        assert_eq!(h.get("x-attos-node-id").map(String::as_str), Some("node-r"));
        assert_eq!(h.get("user-agent").cloned(), Some(format!("attos-rust/{}", attos_client::VERSION)));
        assert!(h.get("if-none-match").is_none());
    }
    assert_eq!(s.dataset_name().as_deref(), Some("fake"));
    assert_eq!(s.sync_now().unwrap(), SyncOutcome::NotModified);
    {
        let g = f.st.lock().unwrap();
        assert_eq!(g.sync_reqs[1].get("if-none-match").map(String::as_str), Some("\"a\""));
        assert_eq!(g.served, 1);
    }
    let swaps = s.client().swaps();
    {
        let mut g = f.st.lock().unwrap();
        g.blob = blob("B", 100);
        g.etag = "\"b\"".into();
    }
    assert_eq!(s.sync_now().unwrap(), SyncOutcome::Updated);
    assert_eq!(value(&s, "key_7"), "B_7");
    assert_eq!(s.client().swaps(), swaps + 1);
    assert_eq!(std::fs::read_to_string(dir.path().join("ds-1.etag")).unwrap(), "\"b\"");
    assert_eq!(temps(dir.path()), 0);
    s.shutdown();
}

#[test]
fn fault_injection_keeps_serving_and_recovers() {
    let good = blob("A", 200);
    let f = fake(good.clone(), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&f, dir.path())).unwrap();
    assert_eq!(value(&s, "key_42"), "A_42");
    let next = blob("B", 200);
    let mut bad_crc = next.clone();
    let n = bad_crc.len();
    bad_crc[n - 6] ^= 0xFF;
    let mut bad_ver = next.clone();
    bad_ver[7] = 3;
    let cases: Vec<(&str, Resp, fn(&AttosError) -> bool)> = vec![
        ("truncated", Resp::Truncated(next.clone()), |e| matches!(e, AttosError::Transport(_))),
        ("killed", Resp::Kill(next.clone()), |e| matches!(e, AttosError::Transport(_))),
        ("bad-crc", Resp::Raw(bad_crc), |e| matches!(e, AttosError::ChecksumMismatch { .. })),
        ("bad-version", Resp::Raw(bad_ver), |e| matches!(e, AttosError::InvalidVersion(3))),
        ("garbage", Resp::Raw(b"<html>oops</html>".to_vec()), |e| matches!(e, AttosError::InvalidMagic)),
        ("402", Resp::Status(402, vec![]), |e| e.is_quota()),
        ("429", Resp::Status(429, vec![("Retry-After".into(), "7".into())]),
            |e| matches!(e, AttosError::HttpStatus { code: 429, retry_after: Some(d) } if *d == Duration::from_secs(7))),
        ("500", Resp::Status(500, vec![]), |e| matches!(e, AttosError::HttpStatus { code: 500, .. })),
        ("404", Resp::Status(404, vec![]), |e| matches!(e, AttosError::HttpStatus { code: 404, .. })),
    ];
    for (name, r, check) in cases {
        f.st.lock().unwrap().script.push_back(r);
        let e = s.sync_now().unwrap_err();
        assert!(check(&e), "{}: unexpected {}", name, e);
        assert_eq!(value(&s, "key_42"), "A_42", "{}", name);
        assert_eq!(temps(dir.path()), 0, "{}: temp left", name);
        println!("{} -> {} (still serving A)", name, e);
    }
    assert_eq!(s.crc_errors(), 1);
    assert_eq!(std::fs::read(dir.path().join("ds-1.attos")).unwrap(), good);
    {
        let mut g = f.st.lock().unwrap();
        g.blob = next;
        g.etag = "\"b\"".into();
    }
    s.sync_now().unwrap();
    assert_eq!(value(&s, "key_42"), "B_42");
    s.shutdown();
}

#[test]
fn backoff_policy() {
    let i = Duration::from_secs(30);
    let b = Duration::from_secs(1);
    let mut f = 0;
    let mut logged = HashSet::new();
    let q = |c, ra| Err(AttosError::HttpStatus { code: c, retry_after: ra });
    assert_eq!(next_delay(&q(402, None), &mut f, i, b, &mut logged), QUOTA_PAUSE);
    assert_eq!(next_delay(&q(429, Some(Duration::from_secs(90))), &mut f, i, b, &mut logged), Duration::from_secs(90));
    assert_eq!(next_delay(&q(429, Some(Duration::from_secs(99999))), &mut f, i, b, &mut logged), MAX_RETRY_AFTER);
    for c in [400, 401, 403, 404, 409] {
        assert_eq!(next_delay(&q(c, None), &mut f, i, b, &mut logged), i);
    }
    for k in 0..8u32 {
        let d = next_delay(&q(503, None), &mut f, i, b, &mut logged);
        let base = (b * (1 << k)).min(i);
        assert!(d >= base.mul_f64(0.8) && d <= base.mul_f64(1.2), "k={} d={:?}", k, d);
    }
    assert_eq!(next_delay(&Ok(SyncOutcome::Updated), &mut f, i, b, &mut logged), i);
    assert_eq!(f, 0);
    assert!(transient_backoff(30, Duration::from_secs(3600), b) <= Duration::from_secs(360));
}

#[test]
fn poll_loop_recovers() {
    let f = fake(blob("A", 64), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&f, dir.path());
    c.poll_interval = Duration::from_millis(50);
    c.backoff_base = Duration::from_millis(5);
    let s = AttosSynchronizer::start(c).unwrap();
    let next = blob("B", 64);
    {
        let mut g = f.st.lock().unwrap();
        g.script.extend([Resp::Status(500, vec![]), Resp::Status(503, vec![]), Resp::Truncated(next.clone())]);
        g.blob = next;
        g.etag = "\"b\"".into();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let v = value(&s, "key_1");
        if v == "B_1" { break; }
        assert_eq!(v, "A_1");
        assert!(Instant::now() < deadline, "poll loop did not recover");
        std::thread::sleep(Duration::from_millis(5));
    }
    s.shutdown();
}

#[test]
fn serves_cache_when_server_down() {
    let f = fake(blob("A", 30), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&f, dir.path())).unwrap();
    s.shutdown();
    drop(s);
    let mut c = cfg(&f, dir.path());
    c.base_url = "http://127.0.0.1:1".into();
    let s2 = AttosSynchronizer::start(c.clone()).expect("cached blob should be served");
    assert_eq!(value(&s2, "key_5"), "A_5");
    assert_eq!(s2.etag().as_deref(), Some("\"a\""));
    s2.shutdown();
    let other = tempfile::tempdir().unwrap();
    c.cache_dir = other.path().to_path_buf();
    assert!(AttosSynchronizer::start(c).is_err());
}

fn wait<F: Fn() -> bool>(f: F) {
    let d = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < d, "condition not met");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn telemetry_contract_and_retry_policy() {
    let f = fake(blob("A", 100), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&f, dir.path());
    c.telemetry_interval = Duration::from_secs(3600);
    c.api_key = "tkey".into();
    c.telemetry_retry_delays = vec![Duration::from_millis(1); 3];
    let s = AttosSynchronizer::start(c).unwrap();
    for i in 0..5000 {
        let _ = s.read().get(format!("key_{}", i % 100).as_bytes());
    }
    s.flush_telemetry();
    wait(|| f.st.lock().unwrap().telem.len() == 1);
    let (h, body) = f.st.lock().unwrap().telem[0].clone();
    assert_eq!(h.get("x-api-key").map(String::as_str), Some("tkey"));
    assert!(h.get("active-project-id").is_none());
    assert_eq!(h.get("content-type").map(String::as_str), Some("application/json"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let rs = &v["resourceSpans"][0];
    let attrs: HashMap<String, String> = rs["resource"]["attributes"].as_array().unwrap().iter()
        .map(|a| (a["key"].as_str().unwrap().to_string(), a["value"]["stringValue"].as_str().unwrap().to_string())).collect();
    assert_eq!(attrs["attos.dataset_id"], "ds-1");
    assert_eq!(attrs["attos.node_id"], "node-r");
    assert_eq!(attrs["sdk.version"], format!("rust-{}", attos_client::VERSION));
    let m: HashMap<String, i64> = rs["scopeMetrics"][0]["metrics"].as_array().unwrap().iter()
        .map(|m| (m["name"].as_str().unwrap().to_string(), m["gauge"]["dataPoints"][0]["asInt"].as_i64().unwrap())).collect();
    assert_eq!(m["attos.lookups_count"], 5000);
    assert_eq!(m["attos.memory_bytes"], s.client().memory_bytes() as i64);
    assert!(m["attos.lookup.p50_ns"] > 0 && m["attos.lookup.p99_ns"] >= m["attos.lookup.p50_ns"]);
    for k in ["attos.lookup.p95_ns", "attos.crc32_errors", "attos.telemetry_dropped"] {
        assert!(m[k] >= 0);
    }
    println!("telemetry body: {}", body);
    // 5xx → 1 + 3 retries then drop.
    f.st.lock().unwrap().telem_script.extend(vec![(500, vec![]); 4]);
    s.flush_telemetry();
    wait(|| s.telemetry_stats().dropped_pending == 1);
    assert_eq!(f.st.lock().unwrap().telem.len(), 5);
    // 4xx → no retry.
    f.st.lock().unwrap().telem_script.push_back((400, vec![]));
    s.flush_telemetry();
    wait(|| s.telemetry_stats().dropped_pending == 2);
    assert_eq!(f.st.lock().unwrap().telem.len(), 6);
    // dropped count travels with the next successful report.
    s.flush_telemetry();
    wait(|| s.telemetry_stats().sent == 2);
    let last = f.st.lock().unwrap().telem.last().unwrap().1.clone();
    let lv: serde_json::Value = serde_json::from_str(&last).unwrap();
    let dropped = lv["resourceSpans"][0]["scopeMetrics"][0]["metrics"].as_array().unwrap().iter()
        .find(|m| m["name"] == "attos.telemetry_dropped").unwrap()["gauge"]["dataPoints"][0]["asInt"].as_i64().unwrap();
    assert_eq!(dropped, 2, "{}", last);
    // 429 → drop + pause.
    f.st.lock().unwrap().telem_script.push_back((429, vec![("Retry-After".into(), "3600".into())]));
    s.flush_telemetry();
    wait(|| s.telemetry_stats().dropped_pending == 1);
    s.shutdown();
}

#[test]
fn telemetry_disabled_by_server() {
    let f = fake(blob("A", 10), "\"a\"");
    f.st.lock().unwrap().config = r#"{"telemetry_enabled":false}"#.into();
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&f, dir.path());
    c.telemetry_interval = Duration::from_secs(3600);
    let s = AttosSynchronizer::start(c).unwrap();
    assert!(!s.telemetry_enabled());
    s.flush_telemetry();
    std::thread::sleep(Duration::from_millis(100));
    assert!(f.st.lock().unwrap().telem.is_empty());
    s.shutdown();
}

fn gz(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

#[test]
fn gzip_sync_decompresses_and_validates() {
    let a = blob("A", 200);
    let f = fake(a.clone(), "\"a\"");
    f.st.lock().unwrap().script.push_back(Resp::Encoded(gz(&a), "gzip", "\"a-gzip\""));
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&f, dir.path())).unwrap();
    assert_eq!(value(&s, "key_9"), "A_9");
    assert_eq!(f.st.lock().unwrap().sync_reqs[0].get("accept-encoding").map(String::as_str), Some("gzip"));
    // The cached file is the raw v1 blob, not the gzip bytes.
    assert_eq!(std::fs::read(dir.path().join("ds-1.attos")).unwrap(), a);
    assert_eq!(std::fs::read_to_string(dir.path().join("ds-1.etag")).unwrap(), "\"a-gzip\"");

    let b = blob("B", 200);
    let wire = gz(&b);
    let mut bad_crc = b.clone();
    let n = bad_crc.len();
    bad_crc[n - 6] ^= 0xFF;
    let mut corrupt = wire.clone();
    let m = corrupt.len();
    corrupt[m / 2] ^= 0xFF;
    let cases: Vec<(&str, Resp, fn(&AttosError) -> bool)> = vec![
        // The HTTP body is complete (Content-Length matches) but the gzip
        // stream stops halfway: only the gzip trailer check catches it.
        ("cut gzip", Resp::Encoded(wire[..wire.len() / 2].to_vec(), "gzip", "\"t\""), |e| matches!(e, AttosError::Transport(_))),
        ("corrupt gzip", Resp::Encoded(corrupt, "gzip", "\"c\""), |e| matches!(e, AttosError::Transport(_))),
        ("bad blob crc", Resp::Encoded(gz(&bad_crc), "gzip", "\"x\""), |e| matches!(e, AttosError::ChecksumMismatch { .. })),
        ("unknown coding", Resp::Encoded(b.clone(), "br", "\"y\""), |e| matches!(e, AttosError::Transport(_))),
    ];
    for (name, r, check) in cases {
        f.st.lock().unwrap().script.push_back(r);
        let e = s.sync_now().unwrap_err();
        assert!(check(&e), "{}: unexpected {}", name, e);
        assert_eq!(value(&s, "key_9"), "A_9", "{}", name);
        assert_eq!(temps(dir.path()), 0, "{}: temp left", name);
    }
    f.st.lock().unwrap().script.push_back(Resp::Encoded(wire, "gzip", "\"b-gzip\""));
    assert_eq!(s.sync_now().unwrap(), SyncOutcome::Updated);
    assert_eq!(value(&s, "key_9"), "B_9");
    s.shutdown();
}

#[test]
fn compression_off_asks_for_identity() {
    let f = fake(blob("A", 10), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&f, dir.path());
    c.compression = false;
    let s = AttosSynchronizer::start(c).unwrap();
    assert_eq!(value(&s, "key_1"), "A_1");
    assert_eq!(f.st.lock().unwrap().sync_reqs[0].get("accept-encoding").map(String::as_str), Some("identity"));
    s.shutdown();
}

#[test]
fn default_node_id_is_env_or_hostname() {
    let f = fake(blob("A", 10), "\"a\"");
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&f, dir.path());
    c.node_id = None;
    let s = AttosSynchronizer::start(c).unwrap();
    let id = s.node_id().to_string();
    let want = std::env::var("ATTOS_NODE_ID").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| {
        let out = std::process::Command::new("hostname").output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    });
    assert_eq!(id, want);
    assert_eq!(f.st.lock().unwrap().sync_reqs[0].get("x-attos-node-id"), Some(&id));
    s.shutdown();
}
