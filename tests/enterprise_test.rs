use attos_client::{AttosMap, OpenConfig, AttosClient};
use crc32fast::Hasher;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use twox_hash::XxHash64;
use std::hash::Hasher as StdHasher;

fn generate_test_attos(num_keys: usize, with_crc: bool) -> (tempfile::TempDir, String) {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.attos");
    let path_str = file_path.to_str().unwrap().to_string();

    let mut keys = Vec::with_capacity(num_keys);
    let mut values = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        keys.push(format!("key-{:04}", i).into_bytes());
        values.push(format!("value-{:04}", i).into_bytes());
    }

    let mut num_buckets = num_keys / 2;
    if num_buckets == 0 {
        num_buckets = 1;
    }

    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); num_buckets];
    for i in 0..num_keys {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&keys[i]);
        let h = hasher.finish();
        let high = (h >> 32) as u32;
        let b_idx = (high as u64) % (num_buckets as u64);
        buckets[b_idx as usize].push(i);
    }

    let mut displacements = vec![0u16; num_buckets];
    let mut final_mapping = vec![usize::MAX; num_keys];

    for (b_idx, b_keys) in buckets.iter().enumerate() {
        if b_keys.is_empty() {
            continue;
        }
        'outer: for d in 0..65536u32 {
            let mut temp_slots = Vec::with_capacity(b_keys.len());
            for &k_idx in b_keys {
                let mut hasher = XxHash64::with_seed(0);
                hasher.write(&keys[k_idx]);
                let h = hasher.finish();
                let low = (h & 0xFFFFFFFF) as u32;
                let f_idx = ((low as u64) ^ (d as u64)) % (num_keys as u64);
                if final_mapping[f_idx as usize] != usize::MAX {
                    continue 'outer;
                }
                if temp_slots.contains(&(f_idx as usize)) {
                    continue 'outer;
                }
                temp_slots.push(f_idx as usize);
            }
            displacements[b_idx] = d as u16;
            for (i, &k_idx) in b_keys.iter().enumerate() {
                final_mapping[temp_slots[i]] = k_idx;
            }
            break;
        }
    }

    let mut blob = Vec::new();
    let mut values_data = vec![0u64; num_keys];

    for i in 0..num_keys {
        let k_idx = final_mapping[i];
        if k_idx == usize::MAX {
            continue;
        }
        let offset = blob.len();
        let k = &keys[k_idx];
        let v = &values[k_idx];
        let k_len = k.len() as u16;
        blob.extend_from_slice(&k_len.to_be_bytes());
        blob.extend_from_slice(k);
        blob.extend_from_slice(v);
        let length = blob.len() - offset;
        values_data[i] = ((offset as u64) << 32) | (length as u64);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(b"ATTO");
    buf.extend_from_slice(&1u32.to_be_bytes()); // version
    buf.push(0x01); // flag
    buf.extend_from_slice(&(num_keys as u64).to_be_bytes());
    buf.extend_from_slice(&(num_buckets as u64).to_be_bytes());
    buf.extend_from_slice(&0u64.to_be_bytes()); // seed

    for d in displacements {
        buf.extend_from_slice(&d.to_be_bytes());
    }
    for v in values_data {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf.extend_from_slice(&blob);

    if with_crc {
        let mut hasher = Hasher::new();
        hasher.update(&buf);
        let crc = hasher.finalize();
        buf.extend_from_slice(&crc.to_be_bytes());
    }

    let mut file = File::create(&file_path).unwrap();
    file.write_all(&buf).unwrap();

    (dir, path_str)
}

fn generate_corrupt_attos(corruption: &str) -> (tempfile::TempDir, String) {
    let (dir, path) = generate_test_attos(10, true);
    let mut data = std::fs::read(&path).unwrap();
    match corruption {
        "bad_magic" => {
            data[0..4].copy_from_slice(b"BAAD");
        }
        "truncated_header" => {
            data.truncate(10);
        }
        "bad_crc" => {
            let len = data.len();
            data[len - 1] ^= 0xFF;
        }
        "random_garbage" => {
            data = vec![0; 100];
        }
        _ => {}
    }
    let mut file = File::create(&path).unwrap();
    file.write_all(&data).unwrap();
    (dir, path)
}

#[test]
fn test_concurrent_hot_reload() {
    let (_dir1, path1) = generate_test_attos(1000, true);
    let (_dir2, path2) = generate_test_attos(1000, true);

    let m = AttosMap::open(&path1).unwrap();
    let client = AttosClient::new(m, OpenConfig::default());
    let reader_client = std::sync::Arc::new(client);
    let path1_c = path1.clone();
    let path2_c = path2.clone();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_clone = done.clone();
    let rc_clone = reader_client.clone();
    let t = thread::spawn(move || {
        let mut use_path1 = false;
        while !done_clone.load(std::sync::atomic::Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
            let p = if use_path1 { &path1_c } else { &path2_c };
            use_path1 = !use_path1;
            let _ = rc_clone.reload(p);
        }
    });

    let mut handles = vec![];
    for _ in 0..100 { // 100 threads for stress test
        let client_clone = reader_client.clone();
        handles.push(thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(5);
            while Instant::now() < end {
                let map = client_clone.read();
                let _ = map.get_string("key-0500");
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    t.join().unwrap();
}

#[test]
fn test_adversarial_fuzzing() {
    let tests = vec![
        ("bad_magic", true),
        ("truncated_header", true),
        ("bad_crc", true),
        ("random_garbage", true),
    ];

    for (corruption, expect_err) in tests {
        let (_dir, path) = generate_corrupt_attos(corruption);
        let res = AttosMap::open_with_config(&path, OpenConfig { validate_checksum: true, pin_to_memory: false });
        assert_eq!(res.is_err(), expect_err, "failed on {}", corruption);
    }
}

#[test]
fn test_descriptor_leak() {
    let (_dir, path) = generate_test_attos(100, true);
    for _ in 0..10000 {
        let _m = AttosMap::open(&path).unwrap();
    }
}

#[test]
fn test_scan_iterator() {
    let (_dir, path) = generate_test_attos(100, true);
    let m = AttosMap::open(&path).unwrap();

    let mut expected = 0;
    m.scan(|_, _| {
        expected += 1;
        true
    });

    let mut count = 0;
    m.scan(|_k, _v| {
        count += 1;
        true
    });

    assert_eq!(count, expected);
    assert!(count > 0, "expected some keys");
}
