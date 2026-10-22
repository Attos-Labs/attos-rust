use attos_client::{AttosError, AttosMap, OpenConfig};
use std::collections::HashMap;
use std::path::PathBuf;

const CASES: &[(&str, &str)] = &[
    ("golden_v2_lz4b16_1", "golden_v2_1"),
    ("golden_v2_lz4b1_1000", "golden_v2_1000"),
    ("golden_v2_lz4b16_1000", "golden_v2_1000"),
    ("golden_v2_lz4b256_1000", "golden_v2_1000"),
    ("golden_v2_lz4b16_5000", "golden_v2_5000"),
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
fn every_row_of_every_compressed_golden() {
    for (file, tsv) in CASES {
        let map = AttosMap::open_with_config(golden(&format!("{file}.attos")), crc()).unwrap();
        assert_eq!(map.version, 2);
        assert!(map.is_compressed(), "{file}");
        let rows = rows(tsv);
        assert_eq!(map.total_keys as usize, rows.len(), "{file}");
        let mut expect = HashMap::new();
        for (k, v) in &rows {
            assert_eq!(map.get_owned(k).unwrap(), *v, "{file} key {:02x?}", k);
            assert_eq!(&*map.get_cow(k).unwrap(), v.as_slice());
            expect.insert(k.clone(), v.clone());
        }
        // zero-copy API is refused, not silently wrong
        assert!(matches!(map.get(&rows[0].0), Err(AttosError::CompressedRequiresOwned)));
        let mut seen = 0;
        map.scan(|k, v| {
            assert_eq!(expect.get(k).map(Vec::as_slice), Some(v), "{file}");
            seen += 1;
            true
        });
        assert_eq!(seen, rows.len(), "{file}");
        let mut c = 0;
        map.scan(|_, _| {
            c += 1;
            c < 3
        });
        assert_eq!(c, 3.min(rows.len()));
        for i in 0..1000u32 {
            let k = format!("missing-key-{i}");
            if !expect.contains_key(k.as_bytes()) {
                assert!(matches!(map.get_owned(k.as_bytes()), Err(AttosError::KeyNotFound)), "{file}");
            }
        }
        assert!(map.get_string_owned("zzz-not-there").is_err());
    }
}

#[test]
fn multi_lookup_cow_composite_key() {
    let map = AttosMap::open(golden("golden_v2_lz4b16_1000.attos")).unwrap();
    // find a row whose key contains a NUL and split it into factors
    let (k, v) = rows("golden_v2_1000")
        .into_iter()
        .find(|(k, _)| k.contains(&0) && k.len() < 1000)
        .expect("golden set contains NUL keys");
    let factors: Vec<&[u8]> = k.split(|b| *b == 0).collect();
    assert_eq!(&*map.multi_lookup_cow(&factors).unwrap(), v.as_slice());
    assert!(matches!(map.multi_lookup(&factors), Err(AttosError::CompressedRequiresOwned)));
}

#[test]
fn plain_files_work_through_cow_api() {
    let map = AttosMap::open(golden("golden_v2_1000.attos")).unwrap();
    assert!(!map.is_compressed());
    for (k, v) in rows("golden_v2_1000").iter().take(100) {
        assert_eq!(map.get_owned(k).unwrap(), *v);
    }
}

fn run(data: &[u8], keys: &[Vec<u8>], cfg: OpenConfig) -> Result<(), AttosError> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.attos");
    std::fs::write(&p, data).unwrap();
    let map = AttosMap::open_with_config(&p, cfg)?;
    for k in keys {
        let _ = map.get_owned(k);
    }
    map.scan(|_, _| true);
    Ok(())
}

#[test]
fn checksum_detects_flip() {
    let mut d = std::fs::read(golden("golden_v2_lz4b16_1000.attos")).unwrap();
    let n = d.len();
    d[n - 100] ^= 1;
    assert!(matches!(run(&d, &[], crc()), Err(AttosError::ChecksumMismatch { .. })));
}

#[test]
fn header_corruption() {
    let data = std::fs::read(golden("golden_v2_lz4b16_1000.attos")).unwrap();
    let keys: Vec<Vec<u8>> = rows("golden_v2_1000").into_iter().map(|r| r.0).take(100).collect();
    let corrupt = |name: &str, f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = data.clone();
        f(&mut d);
        match run(&d, &keys, OpenConfig::default()) {
            Err(AttosError::CorruptedBinary(_)) => {}
            other => panic!("{name}: expected CorruptedBinary, got {:?}", other.err()),
        }
    };
    corrupt("shift 9", &|d| d[11] = 9);
    corrupt("shift 255", &|d| d[11] = 255);
    for bit in 1..8 {
        corrupt("unknown flag", &|d| d[8] = 1 << bit);
        corrupt("unknown flag+lz4", &|d| d[8] = 1 | (1 << bit));
    }
    // shift 0 with a 16-block file: offsets table too short/long for layout; must not panic
    for shift in 0..=8u8 {
        let mut d = data.clone();
        d[11] = shift;
        let _ = run(&d, &keys, OpenConfig::default());
    }
    // clearing the compressed flag reinterprets blocks as records: must not panic
    let mut d = data.clone();
    d[8] = 0;
    let _ = run(&d, &keys, OpenConfig::default());
}

#[test]
fn truncation_and_random_flips_never_panic() {
    for file in ["golden_v2_lz4b16_1000", "golden_v2_lz4b1_1000", "golden_v2_lz4b256_1000"] {
        let data = std::fs::read(golden(&format!("{file}.attos"))).unwrap();
        let keys: Vec<Vec<u8>> = rows("golden_v2_1000").into_iter().map(|r| r.0).take(150).collect();
        let mut cuts: Vec<usize> = (0..data.len().min(150)).collect();
        cuts.extend((1..40).map(|i| data.len() * i / 40));
        cuts.extend([data.len() - 1, data.len() - 4, data.len() - 5]);
        for cut in cuts {
            assert!(run(&data[..cut], &keys, crc()).is_err(), "{file} cut {cut}");
            let _ = run(&data[..cut], &keys, OpenConfig::default());
        }
        let mut s = 0x2545F4914F6CDD1Du64;
        for _ in 0..400 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let mut d = data.clone();
            let pos = 4 + (s as usize) % (d.len() - 4);
            d[pos] ^= ((s >> 33) as u8) | 1;
            let _ = run(&d, &keys, OpenConfig::default());
            // multi-byte damage concentrated in the blob tail
            let tail = d.len() - 4;
            let at = tail - 1 - (s >> 20) as usize % tail.min(4000);
            for j in 0..8.min(tail - at) {
                d[at + j] = (s >> (j * 8)) as u8;
            }
            let _ = run(&d, &keys, OpenConfig::default());
        }
    }
}
