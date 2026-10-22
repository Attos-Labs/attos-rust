use attos_client::map::{pthash_hp, pthash_mix, pthash_reduce};
use attos_client::{AttosError, AttosMap, OpenConfig};
use std::collections::HashMap;
use std::path::PathBuf;

fn golden(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name)
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn rows(name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = std::fs::read_to_string(golden(name)).unwrap();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (k, v) = l.split_once('\t').unwrap_or((l, ""));
            (unhex(k), unhex(v))
        })
        .collect()
}

fn checksum_cfg() -> OpenConfig {
    OpenConfig { validate_checksum: true, ..Default::default() }
}

#[test]
fn golden_hash_constants() {
    assert_eq!(pthash_mix(1), 0x4179b061e0c0e0d0);
    assert_eq!(pthash_mix(0xDEADBEEF), 0x288344a3928b2668);
    assert_eq!(pthash_hp(0), 0xc5209269cd34c3fc);
    assert_eq!(pthash_reduce(1u64 << 63, 10), 5);
}

fn check_file(stem: &str) {
    let map = AttosMap::open_with_config(golden(&format!("{stem}.attos")), checksum_cfg()).unwrap();
    assert_eq!(map.version, 2);
    let rows = rows(&format!("{stem}.tsv"));
    assert_eq!(map.total_keys as usize, rows.len());
    let mut expect: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    for (k, v) in &rows {
        assert_eq!(map.get(k).unwrap(), v.as_slice(), "key {:02x?}", k);
        expect.insert(k.clone(), v.clone());
    }
    // scan visits every row exactly once
    let mut seen = 0usize;
    map.scan(|k, v| {
        assert_eq!(expect.get(k).map(|x| x.as_slice()), Some(v));
        seen += 1;
        true
    });
    assert_eq!(seen, rows.len());
    // early stop
    let mut c = 0;
    map.scan(|_, _| {
        c += 1;
        false
    });
    assert_eq!(c, 1);
    // missing keys
    for i in 0..2000u32 {
        let k = format!("definitely-missing-{i}");
        if !expect.contains_key(k.as_bytes()) {
            assert!(matches!(map.get(k.as_bytes()), Err(AttosError::KeyNotFound)));
        }
    }
    assert!(matches!(map.get(b""), Err(AttosError::KeyNotFound)) || expect.contains_key(&b""[..]));
}

#[test]
fn golden_1() {
    check_file("golden_v2_1");
}
#[test]
fn golden_1000() {
    check_file("golden_v2_1000");
}
#[test]
fn golden_5000() {
    check_file("golden_v2_5000");
}

#[test]
fn golden_without_checksum_validation() {
    let map = AttosMap::open(golden("golden_v2_1000.attos")).unwrap();
    for (k, v) in rows("golden_v2_1000.tsv") {
        assert_eq!(map.get(&k).unwrap(), v.as_slice());
    }
}

#[test]
fn flipped_byte_fails_checksum() {
    let mut data = std::fs::read(golden("golden_v2_1000.attos")).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.attos");
    std::fs::write(&p, &data).unwrap();
    assert!(matches!(
        AttosMap::open_with_config(&p, checksum_cfg()),
        Err(AttosError::ChecksumMismatch { .. })
    ));
}

/// Opens and exercises a (possibly hostile) file: must never panic.
fn exercise(data: &[u8], keys: &[Vec<u8>], cfg: OpenConfig) -> Result<(), AttosError> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.attos");
    std::fs::write(&p, data).unwrap();
    let map = AttosMap::open_with_config(&p, cfg)?;
    for k in keys {
        let _ = map.get(k);
    }
    map.scan(|_, _| true);
    Ok(())
}

#[test]
fn truncated_files_error_without_panic() {
    let data = std::fs::read(golden("golden_v2_1000.attos")).unwrap();
    let keys: Vec<Vec<u8>> = rows("golden_v2_1000.tsv").into_iter().map(|r| r.0).take(50).collect();
    let mut cuts: Vec<usize> = (0..data.len().min(200)).collect();
    cuts.extend([data.len() - 1, data.len() - 4, data.len() - 5, data.len() / 2, data.len() / 3]);
    for cut in cuts {
        let r = exercise(&data[..cut], &keys, checksum_cfg());
        assert!(r.is_err(), "truncation to {cut} must fail with checksum on");
        // without CRC verification: must still not panic (open may succeed or fail)
        let _ = exercise(&data[..cut], &keys, OpenConfig::default());
    }
    // truncated header region always reports corruption
    assert!(matches!(
        exercise(&data[..40], &keys, OpenConfig::default()),
        Err(AttosError::CorruptedBinary(_)) | Err(AttosError::InvalidMagic)
    ));
    assert!(matches!(
        exercise(&data[..data.len() - 100], &keys, OpenConfig::default()),
        Err(AttosError::CorruptedBinary(_))
    ));
}

#[test]
fn hostile_headers_report_corruption() {
    let data = std::fs::read(golden("golden_v2_1000.attos")).unwrap();
    let keys: Vec<Vec<u8>> = rows("golden_v2_1000.tsv").into_iter().map(|r| r.0).take(50).collect();
    let put64 = |d: &mut Vec<u8>, o: usize, v: u64| d[o..o + 8].copy_from_slice(&v.to_be_bytes());
    type Mutator = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Mutator)> = vec![
        ("n=0", Box::new(move |d| put64(d, 12, 0))),
        ("n=2^32", Box::new(move |d| put64(d, 12, 1 << 32))),
        ("n=max", Box::new(move |d| put64(d, 12, u64::MAX))),
        ("m<n", Box::new(move |d| put64(d, 20, 1))),
        ("m huge", Box::new(move |d| put64(d, 20, u64::MAX))),
        ("m>2n+16", Box::new(move |d| put64(d, 20, 5000))),
        ("nb=1", Box::new(move |d| put64(d, 28, 1))),
        ("nb huge", Box::new(move |d| put64(d, 28, u64::MAX))),
        ("nb=2^61", Box::new(move |d| put64(d, 28, 1 << 61))),
        ("p2=0", Box::new(move |d| put64(d, 36, 0))),
        ("p2>=nb", Box::new(move |d| put64(d, 36, u64::MAX))),
        ("p2 huge", Box::new(move |d| put64(d, 36, 1 << 62))),
        ("fw=0", Box::new(|d| d[9] = 0)),
        ("fw=33", Box::new(|d| d[9] = 33)),
        ("bw=0", Box::new(|d| d[10] = 0)),
        ("bw=255", Box::new(|d| d[10] = 255)),
    ];
    for (name, f) in cases {
        let mut d = data.clone();
        f(&mut d);
        match exercise(&d, &keys, OpenConfig::default()) {
            Err(AttosError::CorruptedBinary(_)) => {}
            other => panic!("{name}: expected CorruptedBinary, got {:?}", other.err()),
        }
    }
}

#[test]
fn hostile_body_never_panics() {
    let data = std::fs::read(golden("golden_v2_1000.attos")).unwrap();
    let keys: Vec<Vec<u8>> = rows("golden_v2_1000.tsv").into_iter().map(|r| r.0).take(200).collect();
    // deterministic xorshift corruption of single bytes / words anywhere past the magic
    let mut s = 0x9E3779B97F4A7C15u64;
    for _ in 0..300 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let mut d = data.clone();
        let pos = 4 + (s as usize) % (d.len() - 4);
        d[pos] = (s >> 40) as u8;
        let _ = exercise(&d, &keys, OpenConfig::default());
    }
    // blob/free/offset regions filled with 0xFF
    for start in [64usize, data.len() / 4, data.len() / 2, data.len() - 200] {
        let mut d = data.clone();
        for b in &mut d[start..data.len() - 4] {
            *b = 0xFF;
        }
        let _ = exercise(&d, &keys, OpenConfig::default());
    }
}

#[test]
fn bad_version_and_magic() {
    let mut d = std::fs::read(golden("golden_v2_1.attos")).unwrap();
    d[7] = 3;
    assert!(matches!(exercise(&d, &[], OpenConfig::default()), Err(AttosError::InvalidVersion(3))));
    d[7] = 2;
    d[0] = b'X';
    assert!(matches!(exercise(&d, &[], OpenConfig::default()), Err(AttosError::InvalidMagic)));
}

/// Hand-built single-key version 1 file: v1 must keep working unchanged.
#[test]
fn v1_still_readable() {
    let rec: Vec<u8> = [&[0u8, 1][..], b"k", b"value"].concat();
    let mut d = Vec::new();
    d.extend_from_slice(b"ATTO");
    d.extend_from_slice(&1u32.to_be_bytes());
    d.push(1); // 16-bit routing
    d.extend_from_slice(&1u64.to_be_bytes()); // keys
    d.extend_from_slice(&1u64.to_be_bytes()); // buckets
    d.extend_from_slice(&0u64.to_be_bytes()); // seed
    d.extend_from_slice(&0u16.to_be_bytes()); // displacement
    d.extend_from_slice(&(rec.len() as u64).to_be_bytes());
    d.extend_from_slice(&rec);
    let crc = {
        let mut h = crc32fast::Hasher::new();
        h.update(&d);
        h.finalize()
    };
    d.extend_from_slice(&crc.to_be_bytes());
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("v1.attos");
    std::fs::write(&p, &d).unwrap();
    let map = AttosMap::open_with_config(&p, checksum_cfg()).unwrap();
    assert_eq!(map.version, 1);
    assert_eq!(map.get(b"k").unwrap(), b"value");
    assert!(matches!(map.get(b"other"), Err(AttosError::KeyNotFound)));
}
