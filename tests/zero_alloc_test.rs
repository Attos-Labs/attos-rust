//! Hot-path allocation check with a counting global allocator
//! (allocation-counter): `client.read().get()`, `get_string`, `multi_lookup`
//! and `get_copy` into a pre-sized buffer perform 0 heap allocations,
//! including across a hot swap.
mod common;
use attos_client::{AttosClient, AttosMap, OpenConfig};

#[test]
fn lookup_path_allocates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let p0 = dir.path().join("g0.attos");
    let p1 = dir.path().join("g1.attos");
    std::fs::write(&p0, common::gen_blob(0)).unwrap();
    std::fs::write(&p1, common::gen_blob(1)).unwrap();
    let client = AttosClient::new(AttosMap::open(&p0).unwrap(), OpenConfig::default());
    let keys: Vec<Vec<u8>> = (0..common::GEN_KEYS).map(|i| format!("key_{}", i).into_bytes()).collect();
    let mut dst = Vec::with_capacity(256);
    // Warm up thread-local arc-swap debt slots before measuring.
    let _ = client.read().get(&keys[0]);
    let info = allocation_counter::measure(|| {
        for round in 0..20 {
            for k in &keys {
                let g = client.read();
                assert!(g.get(k).is_ok());
                assert!(g.get_string(std::str::from_utf8(k).unwrap()).is_ok());
                assert!(g.multi_lookup(&[k]).is_ok());
                dst.clear();
                client.get_copy(k, &mut dst).unwrap();
            }
            assert!(client.read().get(b"absent").is_err());
            let _ = round;
        }
    });
    assert_eq!(info.count_total, 0, "lookup path allocated: {:?}", info);
    client.reload(&p1).unwrap();
    let info = allocation_counter::measure(|| {
        for k in &keys {
            assert!(client.read().get(k).is_ok());
        }
    });
    assert_eq!(info.count_total, 0, "after swap: {:?}", info);
    println!("0 allocations over {} lookups", keys.len() * 20 * 4 + keys.len());
}
