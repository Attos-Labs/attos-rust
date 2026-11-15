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
        (
            "validate",
            OpenConfig {
                validate_checksum: true,
                ..Default::default()
            },
        ),
    ] {
        let m = AttosMap::open_with_config(path, cfg).unwrap();
        let rss = mapped_rss(path);
        let frac = rss as f64 / size as f64;
        eprintln!(
            "{name:8} resident {rss} of {size} bytes ({:.1}%)",
            frac * 100.0
        );
        assert!(
            frac < 0.10,
            "{name}: {:.1}% resident after open",
            frac * 100.0
        );
        assert_eq!(m.get(b"key_123").unwrap().len(), 1000);
        drop(m);
    }
}

/// `OpenConfig::warm_up` makes the whole mapping resident before the map is exposed (the synchronizer's default),
/// while the plain validated open still releases the pages: resident memory equals the file size only when asked.
#[test]
fn warm_up_makes_the_mapping_resident() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("warm.attos");
    let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..50_000)
        .map(|i| (format!("key_{i}").into_bytes(), vec![(i % 251) as u8; 1000]))
        .collect();
    std::fs::write(&p, common::build(&rows)).unwrap();
    let path = p.to_str().unwrap();
    let size = std::fs::metadata(&p).unwrap().len();

    let cold = AttosMap::open_with_config(path, OpenConfig { validate_checksum: true, ..Default::default() }).unwrap();
    let cold_frac = mapped_rss(path) as f64 / size as f64;
    drop(cold);
    for (name, cfg) in [
        ("warm_up", OpenConfig { warm_up: true, ..Default::default() }),
        ("warm_up + validate", OpenConfig { warm_up: true, validate_checksum: true, ..Default::default() }),
    ] {
        let m = AttosMap::open_with_config(path, cfg).unwrap();
        let frac = mapped_rss(path) as f64 / size as f64;
        assert!(frac > 0.95, "{name}: {:.1}% of the file resident, want ~100%", frac * 100.0);
        assert!(cold_frac < 0.5, "the cold validated open should stay mostly non-resident (got {:.1}%)", cold_frac * 100.0);
        assert_eq!(m.get(b"key_77").unwrap().len(), 1000);
    }
}

#[test]
fn synchronizer_config_warms_by_default_and_can_opt_out() {
    let c = attos_client::SyncConfig::new("http://127.0.0.1:1", "k", "ds");
    assert!(c.open.warm_up, "the synchronizer pre-faults new mappings by default");
    assert!(!OpenConfig::default().warm_up, "a direct open stays lazy");
    let mut c = c;
    c.open.warm_up = false;
    assert!(!c.open.warm_up);
}
