//! Serving-RSS regression test (Linux): opening a file, with or without CRC
//! validation, must not leave the mapping resident in the process.
#![cfg(target_os = "linux")]

use attos_client::map::{AttosMap, OpenConfig};

mod common;

/// Resident bytes of the first mapping of `path` in /proc/self/smaps.
fn mapped_rss(path: &str) -> u64 {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut inside = false;
    for l in smaps.lines() {
        if l.ends_with(path) {
            inside = true;
            continue;
        }
        if inside && l.starts_with("Rss:") {
            let kb: u64 = l.split_whitespace().nth(1).unwrap().parse().unwrap();
            return kb * 1024;
        }
    }
    panic!("mapping of {path} not found");
}

#[test]
fn open_leaves_mapping_mostly_non_resident() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("rss.attos");
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..50_000)
        .map(|i| (format!("key_{i}").into_bytes(), vec![(i % 251) as u8; 1000]))
        .collect();
    std::fs::write(&p, common::build(&rows)).unwrap();
    let path = p.to_str().unwrap();
    let size = std::fs::metadata(&p).unwrap().len();

    for (name, cfg) in [
        ("default", OpenConfig::default()),
        ("validate", OpenConfig { validate_checksum: true, ..Default::default() }),
    ] {
        let m = AttosMap::open_with_config(path, cfg).unwrap();
        let rss = mapped_rss(path);
        let frac = rss as f64 / size as f64;
        eprintln!("{name:8} resident {rss} of {size} bytes ({:.1}%)", frac * 100.0);
        assert!(frac < 0.10, "{name}: {:.1}% resident after open", frac * 100.0);
        assert_eq!(m.get(b"key_123").unwrap().len(), 1000);
        drop(m);
    }
}
