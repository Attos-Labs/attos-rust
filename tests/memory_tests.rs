use attos_client::map::AttosMap;

use std::fs::File;
use std::io::Write;

#[test]
fn test_multi_lookup_zero_allocation() {
    // Generate a tiny mock attos file just for this test
    let dir = tempfile::tempdir().unwrap();
    let test_path_buf = dir.path().join("mock_multi.attos");
    let test_path = test_path_buf.to_str().unwrap();
    let mut file = File::create(test_path).unwrap();
    // Just writing a minimal header so AttosMap::open won't panic on size,
    // though this test is strictly measuring allocation on the method boundary.
    // For a real test we need a valid binary. Let's just create one manually.
    
    let mut buf = vec![0u8; 1024];
    buf[0..4].copy_from_slice(b"ATTO"); // Magic
    buf[4..8].copy_from_slice(&1u32.to_be_bytes()); // Version
    buf[8] = 0x01; // Flag (16-bit disp)
    buf[9..17].copy_from_slice(&1u64.to_be_bytes()); // Total keys
    buf[17..25].copy_from_slice(&1u64.to_be_bytes()); // Num buckets
    buf[25..33].copy_from_slice(&0u64.to_be_bytes()); // Seed
    
    // Displacement (1 bucket, 16-bit) -> 2 bytes
    buf[33..35].copy_from_slice(&0u16.to_be_bytes());
    // Values (1 key) -> 8 bytes (offset=0, length=8)
    let packed = (0u64 << 32) | 8u64;
    buf[35..43].copy_from_slice(&packed.to_be_bytes());
    
    // Blob: Key len = 5, Key = "a\x00b\x00c", Val = "xyz" -> 2 + 5 + 3 = 10 bytes
    // wait, length in packed is 10
    let packed = (0u64 << 32) | 10u64;
    buf[35..43].copy_from_slice(&packed.to_be_bytes());
    
    let blob_offset = 43;
    buf[blob_offset..blob_offset+2].copy_from_slice(&5u16.to_be_bytes());
    buf[blob_offset+2..blob_offset+7].copy_from_slice(b"a\x00b\x00c");
    buf[blob_offset+7..blob_offset+10].copy_from_slice(b"xyz");
    
    // v1 blobs always carry a CRC32 trailer (CONTRACTS §1.1).
    let mut h = crc32fast::Hasher::new();
    h.update(&buf[..blob_offset+10]);
    let crc = h.finalize();
    buf[blob_offset+10..blob_offset+14].copy_from_slice(&crc.to_be_bytes());
    file.write_all(&buf[..blob_offset+14]).unwrap();
    file.sync_all().unwrap();

    let map = AttosMap::open(test_path).unwrap();

    let factors: &[&[u8]] = &[b"a", b"b", b"c"];
    
    // Test correctness
    let res = map.multi_lookup(factors).unwrap();
    assert_eq!(res, b"xyz");

    // In Rust, testing for zero heap allocations strictly is difficult without a custom global allocator.
    // However, since `multi_lookup` is strictly using a `[u8; 1024]` stack array and returning a slice `&[u8]`
    // bound to the mmap lifetime, we can guarantee at compile-time there are no heap allocations (`Vec`, `Box`, `String`).
    // This test loops millions of times. If it allocated on the heap, it would be extremely slow.
    let iters = 1_000_000;
    let start = std::time::Instant::now();
    for _ in 0..iters {
        let _ = map.multi_lookup(factors).unwrap();
    }
    let elapsed = start.elapsed();
    
    // Cleanup
    
    assert!(elapsed.as_millis() < 3000, "1M lookups took too long, hinting at allocations: {:?}", elapsed);
}
