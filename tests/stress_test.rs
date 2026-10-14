//! Concurrency stress (SPEC §7 Track A): 32 reader threads doing continuous
//! lookups while the map is hot-swapped ≥ 1,000 times. Zero torn reads, zero
//! errors, ≤ 2 retired maps pending, and fds / mapped regions back to
//! baseline afterwards.
mod common;
use attos_client::{AttosClient, AttosMap, OpenConfig};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn hot_swap_stress_32_readers_1000_swaps() {
    let dir = tempfile::tempdir().unwrap();
    let needle = dir.path().to_str().unwrap().to_string();
    let gens = 4;
    let paths: Vec<_> = (0..gens)
        .map(|g| {
            let p = dir.path().join(format!("gen{}.attos", g));
            std::fs::write(&p, common::gen_blob(g)).unwrap();
            p
        })
        .collect();
    let fds0 = common::count_fds();
    let cfg = OpenConfig { validate_checksum: true, ..Default::default() };
    let client = AttosClient::new(AttosMap::open_with_config(&paths[0], cfg).unwrap(), cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));
    let lookups = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for r in 0..32u64 {
        let (client, stop, errors, lookups) = (client.clone(), stop.clone(), errors.clone(), lookups.clone());
        readers.push(std::thread::spawn(move || {
            let mut x = 0x9E3779B97F4A7C15u64 ^ (r + 1);
            let mut dst = Vec::new();
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                let key = format!("key_{}", x % common::GEN_KEYS as u64);
                {
                    let g = client.read();
                    match g.get(key.as_bytes()) {
                        Ok(v) => if let Err(e) = common::check_gen_value(&key, v) { eprintln!("{}", e); errors.fetch_add(1, Ordering::Relaxed); },
                        Err(e) => { eprintln!("get {}: {}", key, e); errors.fetch_add(1, Ordering::Relaxed); }
                    }
                }
                dst.clear();
                match client.get_copy(key.as_bytes(), &mut dst) {
                    Ok(()) => if common::check_gen_value(&key, &dst).is_err() { errors.fetch_add(1, Ordering::Relaxed); },
                    Err(_) => { errors.fetch_add(1, Ordering::Relaxed); }
                }
                n += 2;
            }
            lookups.fetch_add(n, Ordering::Relaxed);
        }));
    }
    let swaps = 1000;
    let start = Instant::now();
    let (mut max_pending, mut max_maps) = (0, 0);
    for i in 1..=swaps {
        client.reload(&paths[i % gens]).unwrap();
        max_pending = max_pending.max(client.pending_retired());
        if i % 50 == 0 {
            max_maps = max_maps.max(common::count_maps(&needle));
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    for r in readers { r.join().unwrap(); }
    assert_eq!(errors.load(Ordering::Relaxed), 0, "reader errors / torn reads");
    assert!(max_pending <= attos_client::sync::MAX_RETIRED, "pending {}", max_pending);
    assert!(max_maps <= 1 + attos_client::sync::MAX_RETIRED, "mapped regions {}", max_maps);
    assert_eq!(client.swaps(), swaps as u64);
    client.shutdown();
    assert_eq!(client.pending_retired(), 0);
    drop(client);
    assert_eq!(common::count_maps(&needle), 0, "mappings remain after shutdown");
    assert_eq!(common::count_fds(), fds0, "fd count after shutdown");
    println!(
        "swaps={} in {:?}, 32 readers, lookups={}, errors=0, max pending retired={}, max mapped regions={}, fds {}->{}, maps->0",
        swaps, elapsed, lookups.load(Ordering::Relaxed), max_pending, max_maps, fds0, common::count_fds()
    );
}
