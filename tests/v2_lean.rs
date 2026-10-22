use attos_client::{AttosError, AttosMap, OpenConfig};
use std::collections::HashMap;
use std::path::PathBuf;

// (file, tsv stem, fingerprint width, compressed)
const CASES: &[(&str, &str, usize, bool)] = &[
    ("golden_v2_lean4_1", "golden_v2_1", 4, false),
    ("golden_v2_lean4_1000", "golden_v2_1000", 4, false),
    ("golden_v2_lean8_1000", "golden_v2_1000", 8, false),
    ("golden_v2_lean4_lz4b16_1000", "golden_v2_1000", 4, true),
    ("golden_v2_lean8_lz4b16_1000", "golden_v2_1000", 8, true),
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
fn every_row_of_every_lean_golden() {
    for (file, tsv, w, compressed) in CASES {
        let map = AttosMap::open_with_config(golden(&format!("{file}.attos")), crc()).unwrap();
        assert_eq!(map.version, 2);
        assert_eq!(map.is_compressed(), *compressed, "{file}");
        let rows = rows(tsv);
        assert_eq!(map.total_keys as usize, rows.len(), "{file}");
        for (k, v) in &rows {
            assert_eq!(map.get_owned(k).unwrap(), *v, "{file} key {:02x?}", k);
            assert_eq!(&*map.get_cow(k).unwrap(), v.as_slice(), "{file}");
            let mut dst = b"pre".to_vec();
            map.get_copy(k, &mut dst).unwrap();
            assert_eq!(&dst[3..], v.as_slice(), "{file}");
            if !compressed {
                assert_eq!(map.get(k).unwrap(), v.as_slice(), "{file}");
            }
            let mut absent = k.clone();
            absent.push(b'x');
            assert!(matches!(map.get_owned(&absent), Err(AttosError::KeyNotFound)), "{file}");
            if !compressed {
                assert!(matches!(map.get(&absent), Err(AttosError::KeyNotFound)), "{file}");
            }
        }
        let mut seen = 0;
        map.scan(|k, _| {
            assert_eq!(k.len(), *w, "{file}");
            seen += 1;
            true
        });
        assert_eq!(seen, rows.len(), "{file}");
        // scan values are exactly the set of row values
        let mut want: HashMap<Vec<u8>, usize> = HashMap::new();
        for (_, v) in &rows {
            *want.entry(v.clone()).or_default() += 1;
        }
        map.scan(|_, v| {
            *want.get_mut(v).expect("scan value present in rows") -= 1;
            true
        });
        assert!(want.values().all(|c| *c == 0), "{file}");
    }
}

fn open_mutated(file: &str, f: impl FnOnce(&mut Vec<u8>)) -> Result<AttosMap, AttosError> {
    let mut data = std::fs::read(golden(&format!("{file}.attos"))).unwrap();
    f(&mut data);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.attos");
    std::fs::write(&p, &data).unwrap();
    AttosMap::open(&p)
}

#[test]
fn bad_fingerprint_width_is_rejected() {
    let r = open_mutated("golden_v2_lean4_1000", |d| d[53] = 7);
    assert!(matches!(r, Err(AttosError::CorruptedBinary(_))));
    let r = open_mutated("golden_v2_lean8_lz4b16_1000", |d| d[53] = 0);
    assert!(matches!(r, Err(AttosError::CorruptedBinary(_))));
}

#[test]
fn unknown_flag_bit_is_rejected() {
    let r = open_mutated("golden_v2_lean4_1000", |d| d[8] |= 4);
    assert!(matches!(r, Err(AttosError::CorruptedBinary(_))));
}
