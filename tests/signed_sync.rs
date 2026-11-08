//! Signed artifacts (mirrors the Go SDK's TestSignedArtifacts) plus a cross-language vector produced by the
//! Go SDK's SignArtifact: Ed25519 over "attos-artifact-v1\0" + datasetID + "\0" + SHA-256(file).
use attos_client::{parse_public_key, public_key_for, sha256_digest, sign_artifact, AttosError, AttosSynchronizer, SyncConfig};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/golden/overflow/{}", env!("CARGO_MANIFEST_DIR"), name)).unwrap()
}

fn vector() -> HashMap<String, String> {
    let t = std::fs::read_to_string(format!("{}/tests/golden/signed/go_vector.txt", env!("CARGO_MANIFEST_DIR"))).unwrap();
    t.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

const SEED_A: [u8; 32] = [7; 32];
const SEED_B: [u8; 32] = [9; 32];

type Sig = Box<dyn Fn(&[u8]) -> Option<String> + Send + Sync>;

struct Srv {
    addr: String,
    blob: Arc<Mutex<Vec<u8>>>,
    etag: Arc<Mutex<String>>,
    sig: Arc<Mutex<Sig>>,
}

fn serve(blob: Vec<u8>, sig: Sig) -> Srv {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let (b, e, sg) = (Arc::new(Mutex::new(blob)), Arc::new(Mutex::new("\"a\"".to_string())), Arc::new(Mutex::new(sig)));
    let (b2, e2, s2) = (b.clone(), e.clone(), sg.clone());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            loop {
                let mut l = String::new();
                if r.read_line(&mut l).unwrap_or(0) == 0 || l.trim().is_empty() {
                    break;
                }
            }
            let body = b2.lock().unwrap().clone();
            let digest = sha256_digest(&body);
            let mut head = format!("HTTP/1.1 200 X\r\nConnection: close\r\nContent-Length: {}\r\nETag: {}\r\n", body.len(), e2.lock().unwrap());
            if let Some(h) = (s2.lock().unwrap())(&digest) {
                head.push_str(&format!("X-Attos-Signature: {}\r\n", h));
            }
            head.push_str("\r\n");
            let mut o = s;
            let _ = o.write_all(head.as_bytes());
            let _ = o.write_all(&body);
        }
    });
    Srv { addr, blob: b, etag: e, sig: sg }
}

fn signer(seed: [u8; 32], kid: &'static str, ds: &'static str) -> Sig {
    Box::new(move |d| Some(sign_artifact(&seed, kid, ds, d)))
}

fn cfg(url: &str, dir: &std::path::Path) -> SyncConfig {
    let mut c = SyncConfig::new(url, "test-key", "ds-1");
    c.cache_dir = dir.to_path_buf();
    c.poll_interval = Duration::ZERO;
    c.telemetry_interval = Duration::ZERO;
    c.node_id = Some("node-s".into());
    c.signature_keys.insert("k1".into(), public_key_for(&SEED_A));
    c
}

fn kv(n: usize) -> Vec<u8> {
    let rows: Vec<_> = (0..n).map(|i| (format!("k{}", i).into_bytes(), format!("v{}", i).into_bytes())).collect();
    common::build(&rows)
}
mod common;

fn get(s: &AttosSynchronizer, k: &str) -> Option<String> {
    let mut d = Vec::new();
    s.client().get_copy(k.as_bytes(), &mut d).ok().map(|_| String::from_utf8(d).unwrap())
}

#[test]
fn go_vector_verifies_and_matches() {
    let v = vector();
    let file = fx(&v["file"]);
    assert_eq!(attos_client::signature::sha256_digest_hex(&file), v["digest_hex"]);
    // Our signer reproduces Go's header byte for byte (Ed25519 is deterministic)
    let seed: [u8; 32] = base64_decode(&v["seed_b64"]).try_into().unwrap();
    assert_eq!(sign_artifact(&seed, &v["kid"], &v["dataset"], &sha256_digest(&file)), v["header"]);
    assert_eq!(sign_artifact(&seed, &v["kid"], "ds-2", &sha256_digest(&file)), v["header_other_dataset"]);
    // Public key forms: standard, URL-safe without padding, with stray padding/whitespace
    let want = public_key_for(&seed);
    assert_eq!(parse_public_key(&v["pub_b64"]).unwrap(), want);
    assert_eq!(parse_public_key(&v["pub_url_nopad"]).unwrap(), want);
    assert_eq!(parse_public_key(&format!(" {} ", v["pub_b64"])).unwrap(), want);
    assert!(parse_public_key("AAAA").is_err());
    assert!(parse_public_key("!!not base64").is_err());
}

fn base64_decode(s: &str) -> Vec<u8> {
    use std::io::Write as _;
    let _ = std::io::sink().flush();
    let t = s.trim_end_matches('=');
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in t.chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".find(c).unwrap() as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[test]
fn valid_signature_installs_and_is_persisted() {
    let srv = serve(kv(50), signer(SEED_A, "k1", "ds-1"));
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&srv.addr, dir.path())).unwrap();
    assert_eq!(get(&s, "k7").as_deref(), Some("v7"));
    assert_eq!(s.signature_errors(), 0);
    let sig = std::fs::read_to_string(dir.path().join("ds-1.attos.sig")).unwrap();
    assert!(sig.starts_with("alg=ed25519; kid=k1; sig="));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path().join("ds-1.attos.sig")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn bad_signatures_are_rejected() {
    let cases: Vec<(&str, Sig)> = vec![
        ("missing signature", Box::new(|_| None)),
        ("wrong key", signer(SEED_B, "k1", "ds-1")),
        ("unknown key id", signer(SEED_A, "nope", "ds-1")),
        ("other dataset", signer(SEED_A, "k1", "ds-2")),
        ("other algorithm", Box::new(|_| Some("alg=rsa; kid=k1; sig=AAAA".into()))),
        ("malformed signature", Box::new(|_| Some("alg=ed25519; kid=k1; sig=AAAA".into()))),
    ];
    for (name, sig) in cases {
        let srv = serve(kv(50), sig);
        let dir = tempfile::tempdir().unwrap();
        match AttosSynchronizer::start(cfg(&srv.addr, dir.path())) {
            Ok(_) => panic!("{}: expected the initial sync to fail", name),
            Err(AttosError::SignatureMissing) | Err(AttosError::SignatureInvalid(_)) => {}
            Err(e) => panic!("{}: wrong error {:?}", name, e),
        }
        assert!(!dir.path().join("ds-1.attos").exists(), "{}: rejected file was installed", name);
    }
}

#[test]
fn bad_update_keeps_serving_the_verified_file_and_counts_the_error() {
    let srv = serve(kv(50), signer(SEED_A, "k1", "ds-1"));
    let dir = tempfile::tempdir().unwrap();
    let s = AttosSynchronizer::start(cfg(&srv.addr, dir.path())).unwrap();
    *srv.blob.lock().unwrap() = kv(60);
    *srv.etag.lock().unwrap() = "\"b\"".into();
    *srv.sig.lock().unwrap() = signer(SEED_B, "k1", "ds-1");
    assert!(matches!(s.sync_now(), Err(AttosError::SignatureInvalid(_))));
    assert_eq!(s.signature_errors(), 1);
    assert_eq!(get(&s, "k55"), None, "new, unsigned file must not be served");
    assert_eq!(get(&s, "k7").as_deref(), Some("v7"), "old file must keep serving");
}

#[test]
fn cached_file_is_reverified_on_restart() {
    let srv = serve(kv(50), signer(SEED_A, "k1", "ds-1"));
    let dir = tempfile::tempdir().unwrap();
    AttosSynchronizer::start(cfg(&srv.addr, dir.path())).unwrap().shutdown();
    // Server now sends a signature that does not verify: restart still serves the verified cache.
    *srv.sig.lock().unwrap() = signer(SEED_B, "k1", "ds-1");
    let s2 = AttosSynchronizer::start(cfg(&srv.addr, dir.path())).unwrap();
    assert_eq!(get(&s2, "k7").as_deref(), Some("v7"));
    s2.shutdown();
    // Without the saved signature the cache is rejected (and the server also fails verification).
    std::fs::remove_file(dir.path().join("ds-1.attos.sig")).unwrap();
    assert!(AttosSynchronizer::start(cfg(&srv.addr, dir.path())).is_err());
}

#[test]
fn tampered_cache_is_rejected() {
    let srv = serve(kv(50), signer(SEED_A, "k1", "ds-1"));
    let dir = tempfile::tempdir().unwrap();
    AttosSynchronizer::start(cfg(&srv.addr, dir.path())).unwrap().shutdown();
    *srv.sig.lock().unwrap() = signer(SEED_B, "k1", "ds-1");
    let p = dir.path().join("ds-1.attos");
    let mut b = std::fs::read(&p).unwrap();
    let n = b.len() / 2;
    b[n] ^= 1;
    std::fs::write(&p, b).unwrap();
    assert!(AttosSynchronizer::start(cfg(&srv.addr, dir.path())).is_err());
}

#[test]
fn without_keys_signing_is_not_enforced() {
    let srv = serve(kv(50), Box::new(|_| None));
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(&srv.addr, dir.path());
    c.signature_keys.clear();
    let s = AttosSynchronizer::start(c).unwrap();
    assert_eq!(get(&s, "k7").as_deref(), Some("v7"));
    assert!(!dir.path().join("ds-1.attos.sig").exists());
}
