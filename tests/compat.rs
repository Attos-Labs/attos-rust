//! Fail-closed behaviour for files written by a newer format: an intact file that uses an
//! unknown feature must be rejected with an error that names it and says to upgrade; a damaged
//! file must still be reported as corrupted.
use attos_client::{AttosError, AttosMap};
use std::path::PathBuf;

fn open_patched(name: &str, fix_crc: bool, mutate: impl Fn(&mut Vec<u8>)) -> Result<AttosMap, AttosError> {
    let mut d = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name)).unwrap();
    mutate(&mut d);
    if fix_crc {
        let e = d.len() - 4;
        let c = crc32fast::hash(&d[..e]);
        d[e..].copy_from_slice(&c.to_be_bytes());
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.attos");
    std::fs::write(&p, &d).unwrap();
    AttosMap::open(&p)
}

#[test]
fn unsupported_features_fail_closed() {
    type M = fn(&mut Vec<u8>);
    let cases: [(&str, M); 3] = [
        ("flags", |d| d[8] |= 4),
        ("offset width 6", |d| d[52] = 6),
        ("fingerprint width 16", |d| {
            d[8] |= 2;
            d[53] = 16
        }),
    ];
    for (feature, m) in cases {
        match open_patched("golden_v2_1000.attos", true, m) {
            Err(e @ AttosError::UnsupportedFeature(_)) => {
                let msg = e.to_string();
                assert!(msg.contains(feature) && msg.contains("upgrade the Attos SDK"), "{msg}");
            }
            other => panic!("{feature}: expected UnsupportedFeature, got {:?}", other.err()),
        }
        assert!(matches!(open_patched("golden_v2_1000.attos", false, m), Err(AttosError::CorruptedBinary(_))), "{feature} damaged");
    }
}

#[test]
fn future_version_names_upgrade() {
    match open_patched("golden_v2_1000.attos", true, |d| d[7] = 3) {
        Err(e @ AttosError::InvalidVersion(3)) => {
            let msg = e.to_string();
            assert!(msg.contains("version 3") && msg.contains("upgrade the Attos SDK"), "{msg}");
        }
        other => panic!("expected InvalidVersion(3), got {:?}", other.err()),
    }
}
