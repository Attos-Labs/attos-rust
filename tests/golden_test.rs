//! Golden fixtures (CONTRACTS §2): every success blob opens with CRC
//! validation and resolves every key; absent probes miss; negative fixtures
//! fail with the typed errors from §1.6. Also checks the test builder in
//! tests/common matches the golden blobs byte-for-byte.
mod common;
use attos_client::{AttosError, AttosMap, OpenConfig};
use std::fs;

const SUCCESS: &[&str] = &[
    "empty.csv", "empty.ndjson", "one_row.csv", "small_1k.csv", "multidim.csv", "multidim.ndjson",
    "numbers.ndjson", "legacy.ndjson", "unicode.csv", "max_lengths.csv", "large_1m.csv",
];

fn manifest_rows(dir: &std::path::Path) -> Vec<(String, usize)> {
    let m = fs::read_to_string(dir.join("MANIFEST.md")).unwrap();
    let mut out = Vec::new();
    let mut in_success = false;
    for line in m.lines() {
        if line.starts_with("## ") {
            in_success = line.starts_with("## Success");
            continue;
        }
        if in_success && line.starts_with("| ") && !line.starts_with("| input") {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(|c| c.trim()).collect();
            out.push((cells[0].to_string(), cells[2].parse().unwrap()));
        }
    }
    out
}

#[test]
fn golden_success_fixtures() {
    let Some(dir) = common::golden_dir() else { return };
    let rows = manifest_rows(&dir);
    assert_eq!(rows.len(), SUCCESS.len(), "manifest success rows");
    let cfg = OpenConfig { validate_checksum: true, ..Default::default() };
    for (name, n) in rows {
        let exp = dir.join("expected");
        let map = AttosMap::open_with_config(exp.join(format!("{}.attos", name)), cfg)
            .unwrap_or_else(|e| panic!("{}: {}", name, e));
        let kv = fs::read_to_string(exp.join(format!("{}.kv", name))).unwrap();
        let mut count = 0;
        let mut kvrows = Vec::new();
        for line in kv.lines() {
            let (k, v) = line.split_once('\t').unwrap();
            let (k, v) = (common::unhex(k), common::unhex(v));
            assert_eq!(map.get(&k).unwrap_or_else(|e| panic!("{} {:?}: {}", name, k, e)), &v[..], "{}", name);
            let mut dst = Vec::new();
            map.get_copy(&k, &mut dst).unwrap();
            assert_eq!(dst, v);
            kvrows.push((k, v));
            count += 1;
        }
        assert_eq!(count, n, "{}: kv rows", name);
        assert_eq!(map.len(), n, "{}: len", name);
        let absent = fs::read_to_string(exp.join(format!("{}.absent", name))).unwrap();
        if !absent.is_empty() {
            for line in absent.trim_end_matches('\n').split('\n') {
                let k = common::unhex(line);
                assert!(matches!(map.get(&k), Err(AttosError::KeyNotFound)), "{}: absent {:?}", name, k);
            }
        }
        // The test builder reproduces the golden blob exactly (sanity for stress tests).
        if n <= 1000 {
            let want = fs::read(exp.join(format!("{}.attos", name))).unwrap();
            assert_eq!(common::build(&kvrows), want, "{}: test builder differs", name);
        }
        println!("{}: {} keys resolved, absent probes ok", name, n);
    }
}

#[test]
fn golden_negative_fixtures() {
    let Some(dir) = common::golden_dir() else { return };
    let cfg = OpenConfig { validate_checksum: true, ..Default::default() };
    let exp = dir.join("expected");
    let open = |f: &str| AttosMap::open_with_config(exp.join(f), cfg).map(|_| ());
    assert!(matches!(open("bad_magic.attos"), Err(AttosError::InvalidMagic)));
    // The fixture is a v1 body under version 2; v2 is a real format now, so it is a malformed v2 file.
    assert!(matches!(open("bad_version.attos"), Err(AttosError::CorruptedBinary(_))));
    assert!(matches!(open("bad_crc.attos"), Err(AttosError::ChecksumMismatch { .. })));
    assert!(matches!(open("bad_flag.attos"), Err(AttosError::CorruptedBinary(_))));
    assert!(matches!(open("truncated.attos"), Err(AttosError::CorruptedBinary(_))));
    for f in ["bad_magic.attos", "bad_version.attos", "bad_crc.attos", "bad_flag.attos", "truncated.attos"] {
        let e = AttosMap::validate_file(exp.join(f)).unwrap_err();
        println!("{} -> {}", f, e);
    }
}
