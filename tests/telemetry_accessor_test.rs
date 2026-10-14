//! Phase 3 regression: every lookup accessor (get, get_string, get_copy,
//! multi_lookup) feeds the sampled latency histogram and the lookup counter,
//! so telemetry p50/p95/p99 are > 0 whichever accessor a client uses.
mod common;
use attos_client::{AttosClient, AttosMap, OpenConfig};

#[test]
fn every_accessor_feeds_latency_stats() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("g0.attos");
    std::fs::write(&p, common::gen_blob(0)).unwrap();
    let client = AttosClient::new(AttosMap::open(&p).unwrap(), OpenConfig::default());
    let keys: Vec<String> = (0..100).map(|i| format!("key_{}", i)).collect();
    let n = 50_000usize;
    let accessors: Vec<(&str, Box<dyn Fn(&str)>)> = vec![
        ("get", Box::new(|k: &str| assert!(client.read().get(k.as_bytes()).is_ok()))),
        ("get_string", Box::new(|k: &str| assert!(client.read().get_string(k).is_ok()))),
        ("get_copy", Box::new(|k: &str| {
            let mut d = Vec::with_capacity(64);
            client.get_copy(k.as_bytes(), &mut d).unwrap();
        })),
        ("multi_lookup", Box::new(|k: &str| assert!(client.read().multi_lookup(&[k.as_bytes()]).is_ok()))),
    ];
    for (name, f) in &accessors {
        let _ = client.drain_latency();
        let before = client.lookups();
        for i in 0..n {
            f(&keys[i % keys.len()]);
        }
        let lat = client.drain_latency();
        assert_eq!(client.lookups() - before, n as u64, "{}: lookups", name);
        assert!(lat.samples > 0 && lat.p50 > 0 && lat.p95 > 0 && lat.p99 >= lat.p50, "{}: {:?}", name, lat);
        println!("{} only: lookups={} samples={} p50={} p95={} p99={}", name, n, lat.samples, lat.p50, lat.p95, lat.p99);
    }
}
