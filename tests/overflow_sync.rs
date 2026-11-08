//! Overflow capability, signed redirects and tail patches against local fake servers: the capability header,
//! credential-free signed downloads, the redirect host allowlist, the redirect cool-down, ordinary redirects
//! across hosts, ATDL v2 tail patches and the full-blob fallback.
use attos_client::{AttosError, AttosSynchronizer, SyncConfig, SyncOutcome};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Req = HashMap<String, String>;
type Reply = (u16, Vec<(String, String)>, Vec<u8>);
type Handler = Box<dyn FnMut(&str, &Req) -> Reply + Send>;

struct Srv {
    addr: String,
    reqs: Arc<Mutex<Vec<(String, Req)>>>,
}

fn serve(mut h: Handler) -> Srv {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("127.0.0.1:{}", l.local_addr().unwrap().port());
    let reqs: Arc<Mutex<Vec<(String, Req)>>> = Default::default();
    let log = reqs.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut hdr = Req::new();
            loop {
                let mut l = String::new();
                if r.read_line(&mut l).unwrap_or(0) == 0 || l.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = l.split_once(':') {
                    hdr.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            let (code, hs, body) = h(&path, &hdr);
            log.lock().unwrap().push((path, hdr));
            let mut out = TcpStream::try_clone(&s).unwrap();
            let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\nContent-Length: {}\r\n", code, body.len());
            for (k, v) in hs {
                head.push_str(&format!("{}: {}\r\n", k, v));
            }
            head.push_str("\r\n");
            let _ = out.write_all(head.as_bytes());
            let _ = out.write_all(&body);
            let _ = out.flush();
            let _ = r.read(&mut [0u8; 1]);
        }
    });
    Srv { addr, reqs }
}

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/golden/overflow/{}", env!("CARGO_MANIFEST_DIR"), name)).unwrap()
}

fn cfg(url: &str, dir: &std::path::Path) -> SyncConfig {
    let mut c = SyncConfig::new(url, "test-key", "ds-1");
    c.cache_dir = dir.to_path_buf();
    c.poll_interval = Duration::ZERO;
    c.telemetry_interval = Duration::ZERO;
    c.node_id = Some("node-o".into());
    c
}

fn h(k: &str, v: &str) -> (String, String) {
    (k.into(), v.into())
}

fn val(s: &AttosSynchronizer, k: &str) -> Result<String, AttosError> {
    let mut d = Vec::new();
    s.client().get_copy(k.as_bytes(), &mut d).map(|_| String::from_utf8(d).unwrap())
}

const SYNC: &str = "/api/v1/datasets/sync/ds-1";

fn is_sync(p: &str) -> bool {
    p.starts_with(SYNC)
}

#[test]
fn requests_advertise_overflow_and_redirect() {
    let base = fx("v1_base.attos");
    let api = serve(Box::new(move |_, _| (200, vec![h("ETag", "\"v1\"")], base.clone())));
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&format!("http://{}", api.addr), dir.path())).unwrap();
    let r = api.reqs.lock().unwrap();
    let q = &r[0].1;
    assert_eq!(q.get("x-attos-capabilities").map(String::as_str), Some("overflow,redirect"));
    assert_eq!(q.get("x-attos-accept-delta").map(String::as_str), Some("2"));
    assert!(q.get("x-attos-no-redirect").is_none());
    drop(r);
    // disabled features are not advertised
    let dir2 = tempfile::tempdir().unwrap();
    let mut c = cfg(&format!("http://{}", api.addr), dir2.path());
    c.delta = false;
    c.redirect = false;
    let _s2 = AttosSynchronizer::start(c).unwrap();
    let r = api.reqs.lock().unwrap();
    let q = &r.last().unwrap().1;
    assert!(q.get("x-attos-capabilities").is_none() && q.get("x-attos-accept-delta").is_none() && q.get("x-attos-no-redirect").is_none());
    drop(s);
}

#[test]
fn signed_redirect_is_fetched_without_credentials() {
    let blob = fx("v2_expected.attos");
    let n = blob.len();
    let store = serve(Box::new(move |_, _| (200, vec![], blob.clone())));
    let loc = format!("http://{}/bkt/obj?X-Goog-Signature=abc", store.addr);
    let api = serve(Box::new(move |_, _| {
        (302, vec![h("Location", &loc), h("X-Attos-Content-Length", &n.to_string()), h("ETag", "\"v2\""), h("X-Dataset-Name", "fake")], vec![])
    }));
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&format!("http://{}", api.addr), dir.path());
    c.test_redirect_any_target = true;
    let s = AttosSynchronizer::start(c).unwrap();
    assert_eq!(val(&s, "ins_3").unwrap(), "inserted_3");
    assert_eq!(s.etag().as_deref(), Some("\"v2\""));
    assert_eq!(s.dataset_name().as_deref(), Some("fake"));
    assert_eq!(s.redirect_stats(), (1, 0));
    // The API server saw the credentials, the storage host saw none of them.
    assert_eq!(api.reqs.lock().unwrap()[0].1.get("x-api-key").map(String::as_str), Some("test-key"));
    let r = store.reqs.lock().unwrap();
    assert_eq!(r.len(), 1);
    for k in ["x-api-key", "authorization", "x-attos-node-id", "cookie", "if-none-match", "x-attos-capabilities"] {
        assert!(!r[0].1.contains_key(k), "storage request carried {}", k);
    }
}

#[test]
fn redirect_to_a_host_outside_the_allowlist_is_refused_and_backs_off() {
    let blob = fx("v2_expected.attos");
    let n = blob.len();
    let evil = serve(Box::new(|_, _| (200, vec![], b"x".to_vec())));
    let (b2, evil_addr) = (blob.clone(), evil.addr.clone());
    let api = serve(Box::new(move |_, q| {
        if q.get("x-attos-no-redirect").map(String::as_str) == Some("1") || !q.get("x-attos-capabilities").map_or(false, |c| c.contains("redirect")) {
            return (200, vec![h("ETag", "\"v2\"")], b2.clone());
        }
        let loc = format!("http://{}/bkt/obj", evil_addr);
        (302, vec![h("Location", &loc), h("X-Attos-Content-Length", &n.to_string()), h("ETag", "\"v2\"")], vec![])
    }));
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&format!("http://{}", api.addr), dir.path());
    c.redirect_cooldown = Duration::from_millis(600);
    let s = AttosSynchronizer::start(c).unwrap();
    // The first sync: redirect refused (http, loopback) → repeated through the endpoint with No-Redirect.
    assert_eq!(val(&s, "key_1").unwrap(), "val_1");
    assert_eq!(s.redirect_stats(), (0, 1));
    assert_eq!(evil.reqs.lock().unwrap().len(), 0, "the refused host was contacted");
    {
        let r = api.reqs.lock().unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].1.get("x-attos-capabilities").unwrap().contains("redirect"));
        assert_eq!(r[1].1.get("x-attos-no-redirect").map(String::as_str), Some("1"));
        assert!(!r[1].1.get("x-attos-capabilities").unwrap().contains("redirect"));
    }
    // Back-off: while the cool-down runs, new syncs do not ask for a redirect at all.
    s.sync_now().unwrap();
    {
        let r = api.reqs.lock().unwrap();
        assert_eq!(r.len(), 3);
        assert!(!r[2].1.get("x-attos-capabilities").unwrap().contains("redirect"));
        assert_eq!(r[2].1.get("x-attos-no-redirect").map(String::as_str), Some("1"));
    }
    // After the cool-down the SDK asks again (and is refused again).
    std::thread::sleep(Duration::from_millis(700));
    s.sync_now().unwrap();
    let r = api.reqs.lock().unwrap();
    assert!(r[3].1.get("x-attos-capabilities").unwrap().contains("redirect"));
    assert_eq!(s.redirect_stats().1, 2);
}

#[test]
fn failed_signed_downloads_fall_back() {
    for case in ["404", "short", "long"] {
        let blob = fx("v2_expected.attos");
        let n = blob.len();
        let b = blob.clone();
        let store = serve(Box::new(move |_, _| match case {
            "404" => (404, vec![], vec![]),
            "short" => (200, vec![], b[..b.len() - 10].to_vec()),
            _ => (200, vec![], [b.clone(), vec![0u8; 5]].concat()),
        }));
        let (loc, b2) = (format!("http://{}/o", store.addr), blob.clone());
        let api = serve(Box::new(move |_, q| {
            if q.contains_key("x-attos-no-redirect") {
                return (200, vec![h("ETag", "\"v2\"")], b2.clone());
            }
            (302, vec![h("Location", &loc), h("X-Attos-Content-Length", &n.to_string()), h("ETag", "\"v2\"")], vec![])
        }));
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(&format!("http://{}", api.addr), dir.path());
        c.test_redirect_any_target = true;
        let s = AttosSynchronizer::start(c).unwrap();
        assert_eq!(val(&s, "ins_1").unwrap(), "inserted_1", "{}", case);
        assert_eq!(s.redirect_stats(), (0, 1), "{}", case);
        let temps = std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("download")).count();
        assert_eq!(temps, 0, "{}: temp files left", case);
    }
}

#[test]
fn ordinary_redirect_drops_credentials_on_another_host() {
    let blob = fx("v1_base.attos");
    let other = serve(Box::new(move |_, _| (200, vec![h("ETag", "\"v1\"")], blob.clone())));
    let loc = format!("http://{}/moved", other.addr);
    let api = serve(Box::new(move |_, _| (302, vec![h("Location", &loc)], vec![])));
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&format!("http://{}", api.addr), dir.path());
    c.test_redirect_any_target = true; // http loopback hosts; the credential rule is independent of it
    let s = AttosSynchronizer::start(c).unwrap();
    assert_eq!(val(&s, "key_5").unwrap(), "val_5");
    assert!(api.reqs.lock().unwrap()[0].1.contains_key("x-api-key"));
    let r = other.reqs.lock().unwrap();
    assert_eq!(r.len(), 1);
    assert!(!r[0].1.contains_key("x-api-key") && !r[0].1.contains_key("x-attos-node-id") && !r[0].1.contains_key("authorization"));
}

#[test]
fn ordinary_redirect_to_a_disallowed_host_is_refused() {
    let other = serve(Box::new(|_, _| (200, vec![], b"x".to_vec())));
    let loc = format!("http://{}/moved", other.addr);
    let api = serve(Box::new(move |_, _| (302, vec![h("Location", &loc)], vec![])));
    let dir = tempfile::tempdir().unwrap();
    // http://127.0.0.1:<other port> is a different host:port and not on the allowlist (no test escape hatch).
    let err = AttosSynchronizer::start(cfg(&format!("http://{}", api.addr), dir.path())).err().expect("must fail");
    assert!(matches!(err, AttosError::Transport(_)), "{:?}", err);
    assert_eq!(other.reqs.lock().unwrap().len(), 0);
}

/// Serves v1_base first; then answers a conditional request with the tail patch (or a damaged one).
fn patch_server(patch: Vec<u8>) -> (Srv, Arc<Mutex<u32>>) {
    let (base, expected) = (fx("v1_base.attos"), fx("v2_expected.attos"));
    let full_after_fail = Arc::new(Mutex::new(0u32));
    let fa = full_after_fail.clone();
    let srv = serve(Box::new(move |_, q| {
        if q.get("if-none-match").map(String::as_str) != Some("\"v1\"") {
            // first sync, or the repeat after a failed patch: the matching full file
            if q.contains_key("if-none-match") {
                *fa.lock().unwrap() += 1;
                return (200, vec![h("ETag", "\"v2\"")], expected.clone());
            }
            return (200, vec![h("ETag", "\"v1\"")], base.clone());
        }
        if q.get("x-attos-capabilities").map_or(false, |c| c.contains("overflow")) {
            return (
                200,
                vec![
                    h("X-Attos-Delta", "1"),
                    h("X-Attos-Delta-Base-ETag", "\"v1\""),
                    h("X-Attos-Delta-Target-SHA256", "3f1d70c6fe07303e162d50266ceb2c6d292df1c54227016114520bef216164ab"),
                    h("ETag", "\"v2\""),
                ],
                patch.clone(),
            );
        }
        (200, vec![h("ETag", "\"v2\"")], expected.clone())
    }));
    (srv, full_after_fail)
}

#[test]
fn tail_patch_is_applied_and_hot_swapped() {
    let (api, _) = patch_server(fx("v1_to_v2_tail.patch"));
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&format!("http://{}", api.addr), dir.path())).unwrap();
    assert!(val(&s, "ins_0").is_err());
    assert_eq!(val(&s, "key_10").unwrap(), "val_10");
    assert_eq!(s.sync_now().unwrap(), SyncOutcome::Updated);
    assert_eq!(val(&s, "ins_0").unwrap(), "inserted_0");
    assert_eq!(val(&s, "key_10").unwrap(), "overwritten_10");
    assert!(matches!(val(&s, "key_100"), Err(AttosError::KeyNotFound)));
    assert_eq!(s.client().read().len(), 1048);
    assert_eq!(s.delta_stats(), (1, 0));
    assert_eq!(s.etag().as_deref(), Some("\"v2\""));
    // the file on disk is the byte-identical rebuilt target
    assert_eq!(std::fs::read(dir.path().join("ds-1.attos")).unwrap(), fx("v2_expected.attos"));
    // and nothing is left behind
    assert!(std::fs::read_dir(dir.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().contains("download")));
}

#[test]
fn damaged_patch_falls_back_to_the_full_file() {
    let mut bad = fx("v1_to_v2_tail.patch");
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    let (api, full) = patch_server(bad);
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&format!("http://{}", api.addr), dir.path())).unwrap();
    assert_eq!(s.sync_now().unwrap(), SyncOutcome::Updated);
    assert_eq!(val(&s, "ins_0").unwrap(), "inserted_0");
    assert_eq!(s.delta_stats(), (0, 1));
    assert_eq!(std::fs::read(dir.path().join("ds-1.attos")).unwrap(), fx("v2_expected.attos"));
    drop(full);
    let r = api.reqs.lock().unwrap();
    // the repeat asked without the delta capability
    let last = &r.last().unwrap().1;
    assert!(last.get("x-attos-accept-delta").is_none());
    assert!(!last.get("x-attos-capabilities").map_or(false, |c| c.contains("overflow")));
    assert!(is_sync(&r[0].0));
}

fn signed_header(seed: u8, bytes: &[u8]) -> String {
    attos_client::sign_artifact(&[seed; 32], "k1", "ds-1", &attos_client::sha256_digest(bytes))
}

fn signed_cfg(url: &str, dir: &std::path::Path) -> SyncConfig {
    let mut c = cfg(url, dir);
    c.signature_keys.insert("k1".into(), attos_client::public_key_for(&[7; 32]));
    c
}

/// With signing enforced, the signature covers the rebuilt file: a patch is accepted when the target verifies.
#[test]
fn signed_tail_patch_is_verified_on_the_rebuilt_file() {
    let (base, expected, patch) = (fx("v1_base.attos"), fx("v2_expected.attos"), fx("v1_to_v2_tail.patch"));
    for good in [true, false] {
        let (b, e, p) = (base.clone(), expected.clone(), patch.clone());
        let (sig_base, sig_exp) = (signed_header(7, &base), signed_header(if good { 7 } else { 9 }, &expected));
        let api = serve(Box::new(move |_, q| {
            let inm = q.get("if-none-match").map(String::as_str);
            if inm != Some("\"v1\"") {
                return if inm.is_some() {
                    (200, vec![h("ETag", "\"v2\""), h("X-Attos-Signature", &sig_exp)], e.clone())
                } else {
                    (200, vec![h("ETag", "\"v1\""), h("X-Attos-Signature", &sig_base)], b.clone())
                };
            }
            if q.get("x-attos-capabilities").map_or(false, |c| c.contains("overflow")) {
                return (200, vec![h("X-Attos-Delta", "1"), h("X-Attos-Delta-Base-ETag", "\"v1\""), h("ETag", "\"v2\""), h("X-Attos-Signature", &sig_exp)], p.clone());
            }
            (200, vec![h("ETag", "\"v2\""), h("X-Attos-Signature", &sig_exp)], e.clone())
        }));
        let dir = tempfile::tempdir().unwrap();
        let s = AttosSynchronizer::start(signed_cfg(&format!("http://{}", api.addr), dir.path())).unwrap();
        if good {
            assert_eq!(s.sync_now().unwrap(), SyncOutcome::Updated);
            assert_eq!(val(&s, "ins_0").unwrap(), "inserted_0");
            assert_eq!(s.delta_stats(), (1, 0));
            assert_eq!(s.signature_errors(), 0);
        } else {
            // patch rebuilds fine but its signature is wrong → patch fails, full blob fails too, v1 keeps serving
            assert!(matches!(s.sync_now(), Err(AttosError::SignatureInvalid(_))));
            assert_eq!(val(&s, "key_10").unwrap(), "val_10");
            assert!(val(&s, "ins_0").is_err());
            assert_eq!(s.signature_errors(), 2);
        }
    }
}

/// The signature header of a signed redirect comes from the 302 and covers the downloaded bytes.
#[test]
fn signed_redirect_download_is_verified() {
    let blob = fx("v2_expected.attos");
    for good in [true, false] {
        let b = blob.clone();
        let store = serve(Box::new(move |_, _| (200, vec![], b.clone())));
        let (loc, n) = (format!("http://{}/o", store.addr), blob.len());
        let sig = signed_header(7, &blob);
        let b2 = blob.clone();
        let api = serve(Box::new(move |_, q| {
            if q.contains_key("x-attos-no-redirect") {
                return (200, vec![h("ETag", "\"v2\""), h("X-Attos-Signature", &sig)], b2.clone());
            }
            let s = if good { sig.clone() } else { sig.replace("sig=", "sig=AAAA") };
            (302, vec![h("Location", &loc), h("X-Attos-Content-Length", &n.to_string()), h("ETag", "\"v2\""), h("X-Attos-Signature", &s)], vec![])
        }));
        let dir = tempfile::tempdir().unwrap();
        let mut c = signed_cfg(&format!("http://{}", api.addr), dir.path());
        c.test_redirect_any_target = true;
        let s = AttosSynchronizer::start(c).unwrap();
        assert_eq!(val(&s, "ins_2").unwrap(), "inserted_2");
        // good: taken from the signed URL; bad signature on the 302 → redirect failure → one fallback through the endpoint
        assert_eq!(s.redirect_stats(), if good { (1, 0) } else { (0, 1) });
    }
}
