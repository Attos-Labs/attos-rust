use attos_client::{AttosError, AttosMap, OpenConfig};
use std::collections::HashMap;
use std::path::PathBuf;

const CASES: &[(&str, &str, bool)] = &[
    ("golden_v2_w5_1", "golden_v2_1", false),
    ("golden_v2_w5_1000", "golden_v2_1000", false),
    ("golden_v2_w5_5000", "golden_v2_5000", false),
    ("golden_v2_w5_lz4b16_1", "golden_v2_1", true),
    ("golden_v2_w5_lz4b16_1000", "golden_v2_1000", true),
];

fn golden(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn rows(stem: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    std::fs::read_to_string(golden(&format!("{stem}.tsv")))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once('\t').unwrap_or((l, ""));
            (unhex(k), unhex(v))
        })
        .collect()
}

fn crc() -> OpenConfig {
    OpenConfig { validate_checksum: true, ..Default::default() }
}

#[test]
fn width5_goldens_read_every_row() {
    for (file, tsv, lz4) in CASES {
        let map = AttosMap::open_with_config(golden(&format!("{file}.attos")), crc()).unwrap();
        assert_eq!(map.version, 2);
        assert_eq!(map.is_compressed(), *lz4, "{file}");
        let rows = rows(tsv);
        assert_eq!(map.total_keys as usize, rows.len(), "{file}");
        let mut expect = HashMap::new();
        let mut buf = Vec::new();
        for (k, v) in &rows {
            assert_eq!(map.get_owned(k).unwrap(), *v, "{file}");
            assert_eq!(&*map.get_cow(k).unwrap(), v.as_slice(), "{file}");
            buf.clear();
            map.get_copy(k, &mut buf).unwrap();
            assert_eq!(&buf, v, "{file} get_copy");
            if !lz4 {
                assert_eq!(map.get(k).unwrap(), v.as_slice(), "{file}");
            }
            expect.insert(k.clone(), v.clone());
        }
        let mut seen = 0;
        map.scan(|k, v| {
            assert_eq!(expect.get(k).map(Vec::as_slice), Some(v), "{file}");
            seen += 1;
            true
        });
        assert_eq!(seen, rows.len(), "{file}");
        for i in 0..500u32 {
            let k = format!("missing-key-{i}");
            if !expect.contains_key(k.as_bytes()) {
                assert!(matches!(map.get_owned(k.as_bytes()), Err(AttosError::KeyNotFound)), "{file}");
            }
        }
    }
}

#[test]
fn width5_checksum_detects_flip() {
    for file in ["golden_v2_w5_1000", "golden_v2_w5_lz4b16_1000"] {
        let mut d = std::fs::read(golden(&format!("{file}.attos"))).unwrap();
        let n = d.len();
        d[n - 100] ^= 1;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.attos");
        std::fs::write(&p, &d).unwrap();
        assert!(matches!(AttosMap::open_with_config(&p, crc()), Err(AttosError::ChecksumMismatch { .. })));
    }
}

#[test]
fn invalid_offset_width_is_corrupt() {
    for file in ["golden_v2_1000", "golden_v2_w5_1000", "golden_v2_lz4b16_1000"] {
        for w in [1u8, 3, 6, 7, 8, 255] {
            let mut d = std::fs::read(golden(&format!("{file}.attos"))).unwrap();
            assert!(d[52] == 0 || d[52] == 4 || d[52] == 5);
            d[52] = w;
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("bad.attos");
            std::fs::write(&p, &d).unwrap();
            match AttosMap::open(&p) {
                Err(AttosError::CorruptedBinary(_)) => {}
                other => panic!("{file} width {w}: expected CorruptedBinary, got {:?}", other.err()),
            }
        }
    }
}

#[test]
fn width4_files_still_read() {
    for file in ["golden_v2_1000", "golden_v2_lz4b16_1000"] {
        let d = std::fs::read(golden(&format!("{file}.attos"))).unwrap();
        assert!(d[52] == 0 || d[52] == 4, "{file}");
        let map = AttosMap::open_with_config(golden(&format!("{file}.attos")), crc()).unwrap();
        for (k, v) in rows("golden_v2_1000") {
            assert_eq!(map.get_owned(&k).unwrap(), v);
        }
    }
}

#[test]
fn get_copy_works_on_compressed_files() {
    let map = AttosMap::open(golden("golden_v2_lz4b16_1000.attos")).unwrap();
    let (k, v) = rows("golden_v2_1000").remove(0);
    let mut dst = b"pre".to_vec();
    map.get_copy(&k, &mut dst).unwrap();
    assert_eq!(&dst[..3], b"pre");
    assert_eq!(&dst[3..], v.as_slice());
    assert!(matches!(map.get_copy(b"nope-nope", &mut dst), Err(AttosError::KeyNotFound)));
}
