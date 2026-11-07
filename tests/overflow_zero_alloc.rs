//! The overflow probe adds no allocation to the lookup path: hits in the overflow, tombstones, main-table
//! keys and misses all perform 0 heap allocations.
use attos_client::{AttosClient, AttosMap, OpenConfig};

#[test]
fn overflow_lookups_allocate_nothing() {
    let p = format!("{}/tests/golden/overflow/v2_expected.attos", env!("CARGO_MANIFEST_DIR"));
    let client = AttosClient::new(AttosMap::open(&p).unwrap(), OpenConfig::default());
    let mut keys: Vec<Vec<u8>> = (0..1000).map(|i| format!("key_{}", i).into_bytes()).collect();
    keys.extend((0..50).map(|i| format!("ins_{}", i).into_bytes()));
    keys.push(b"absent".to_vec());
    let mut dst = Vec::with_capacity(256);
    let _ = client.read().get(&keys[0]); // warm up arc-swap debt slots
    let (mut ok, mut gone) = (0usize, 0usize);
    let info = allocation_counter::measure(|| {
        for _ in 0..20 {
            for k in &keys {
                let g = client.read();
                match g.get(k) {
                    Ok(_) => ok += 1,
                    Err(_) => gone += 1,
                }
                let _ = g.get_cow(k).map(|c| c.len());
                dst.clear();
                let _ = client.get_copy(k, &mut dst);
            }
        }
    });
    assert_eq!(info.count_total, 0, "overflow lookup path allocated: {:?}", info);
    assert_eq!(ok, 20 * 1048);
    assert_eq!(gone, 20 * 3); // key_100, key_200, absent
}
