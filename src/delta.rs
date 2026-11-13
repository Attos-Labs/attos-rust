//! Delta sync (attos-cloud/docs/DELTA_UPDATES.md, OVERFLOW_SHIPPED.md). A node that is one version behind
//! downloads an "ATDL" patch instead of the whole blob and rebuilds the new blob into a temp file from its
//! current file; the result then goes through the same CRC validation, rename and atomic publish as a full
//! download.
//!
//! Patch layout (big-endian): `"ATDL" | u32 version | u64 baseSize | u32 baseCRC (the base's CRC32 trailer)
//! | u64 targetSize | [32]byte targetSHA256 | ops | u32 CRC32 of all preceding bytes`.
//! Version 1 ops: `0x00` END, `0x01` COPY uvarint(baseOff) uvarint(len), `0x02` ADD uvarint(len) bytes.
//! Version 2 (tail patch) op: `0x01` TRUNCATE_AND_APPEND `u64 baseEnd | u64 payloadLen | payload`, then END.

use crate::error::AttosError;
use crate::overflow::FLAG_OVERFLOW;
use crate::sha256::Sha256;
use std::io::{Read, Write};

const MAGIC: &[u8; 4] = b"ATDL";
const HDR_LEN: usize = 60;
const OP_END: u8 = 0;
const OP_COPY: u8 = 1;
const OP_ADD: u8 = 2;
const OP_TRUNC_APPEND: u8 = 1;

pub(crate) fn corrupt(m: impl std::fmt::Display) -> AttosError {
    AttosError::Transport(format!("corrupt delta patch: {}", m))
}

fn wrong_base(m: impl std::fmt::Display) -> AttosError {
    AttosError::Transport(format!(
        "delta patch does not apply to the current file: {}",
        m
    ))
}

/// Reads exactly the bytes handed to the caller and CRCs them (no read-ahead is hashed).
struct CrcRead<R: Read> {
    r: R,
    crc: crc32fast::Hasher,
}

impl<R: Read> CrcRead<R> {
    fn exact(&mut self, buf: &mut [u8]) -> Result<(), AttosError> {
        self.r
            .read_exact(buf)
            .map_err(|e| corrupt(format!("truncated: {}", e)))?;
        self.crc.update(buf);
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, AttosError> {
        let mut b = [0u8];
        self.exact(&mut b)?;
        Ok(b[0])
    }

    fn uvarint(&mut self) -> Result<u64, AttosError> {
        let (mut x, mut s) = (0u64, 0u32);
        for i in 0..10 {
            let b = self.byte()?;
            if b < 0x80 {
                if i == 9 && b > 1 {
                    break;
                }
                return Ok(x | (b as u64) << s);
            }
            x |= ((b & 0x7f) as u64) << s;
            s += 7;
        }
        Err(corrupt("varint overflow"))
    }

    /// Copies exactly `n` patch bytes to `out`.
    fn copy_to(
        &mut self,
        n: u64,
        out: &mut impl FnMut(&[u8]) -> Result<(), AttosError>,
    ) -> Result<(), AttosError> {
        let mut buf = [0u8; 16 << 10];
        let mut left = n;
        while left > 0 {
            let m = left.min(buf.len() as u64) as usize;
            self.exact(&mut buf[..m])?;
            out(&buf[..m])?;
            left -= m as u64;
        }
        Ok(())
    }
}

/// Applies `patch` to `base` (the complete current file) and writes the rebuilt target to `dst`. Verifies the
/// patch CRC, base identity, op bounds, the produced size and the target SHA-256; on any error `dst` may hold
/// partial output and must be discarded. Returns the target SHA-256.
pub(crate) fn apply_delta<R: Read, W: Write>(
    dst: &mut W,
    base: &[u8],
    patch: R,
) -> Result<[u8; 32], AttosError> {
    let mut br = CrcRead {
        r: std::io::BufReader::with_capacity(1 << 16, patch),
        crc: crc32fast::Hasher::new(),
    };
    let mut hdr = [0u8; HDR_LEN];
    br.exact(&mut hdr).map_err(|_| corrupt("header"))?;
    let version = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
    if &hdr[..4] != MAGIC || (version != 1 && version != 2) {
        return Err(corrupt("bad magic or version"));
    }
    let tail_patch = version == 2;
    let base_size = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
    let base_crc = u32::from_be_bytes(hdr[16..20].try_into().unwrap());
    let target_size = u64::from_be_bytes(hdr[20..28].try_into().unwrap());
    let target_sha: [u8; 32] = hdr[28..60].try_into().unwrap();
    if base_size != base.len() as u64 {
        return Err(wrong_base(format!(
            "base size {}, patch expects {}",
            base.len(),
            base_size
        )));
    }
    if base.len() < 4 || u32::from_be_bytes(base[base.len() - 4..].try_into().unwrap()) != base_crc
    {
        return Err(wrong_base("base CRC differs"));
    }
    let mut sha = Sha256::new();
    let mut produced = 0u64;
    let emit = |b: &[u8], sha: &mut Sha256, dst: &mut W| -> Result<(), AttosError> {
        sha.update(b);
        dst.write_all(b).map_err(AttosError::IoError)
    };
    loop {
        let op = br.byte()?;
        if tail_patch && op == OP_TRUNC_APPEND {
            if produced != 0 {
                return Err(corrupt("second tail op"));
            }
            let mut ph = [0u8; 16];
            br.exact(&mut ph)?;
            let base_end = u64::from_be_bytes(ph[..8].try_into().unwrap());
            let plen = u64::from_be_bytes(ph[8..].try_into().unwrap());
            if base_end > base_size - 4
                || base_end < 64
                || plen > target_size
                || base_end != target_size - plen
            {
                return Err(corrupt("tail op bounds"));
            }
            // New file = the base's main part with the overflow flag set + the payload (overflow, footer, CRC).
            let mut first = [0u8; 64];
            first.copy_from_slice(&base[..64]);
            first[8] |= FLAG_OVERFLOW;
            emit(&first, &mut sha, dst)?;
            emit(&base[64..base_end as usize], &mut sha, dst)?;
            br.copy_to(plen, &mut |b| emit(b, &mut sha, dst))?;
            produced = base_end + plen;
            continue;
        }
        match op {
            OP_END => {
                let want = br.crc.clone().finalize();
                let mut t = [0u8; 4];
                br.r.read_exact(&mut t)
                    .map_err(|e| corrupt(format!("trailer: {}", e)))?;
                if u32::from_be_bytes(t) != want {
                    return Err(corrupt("patch CRC mismatch"));
                }
                let mut extra = [0u8; 1];
                if br.r.read(&mut extra).map_err(corrupt)? != 0 {
                    return Err(corrupt("trailing bytes"));
                }
                if produced != target_size {
                    return Err(corrupt(format!(
                        "produced {} of {} bytes",
                        produced, target_size
                    )));
                }
                if sha.finish() != target_sha {
                    return Err(corrupt("target SHA-256 mismatch"));
                }
                return Ok(target_sha);
            }
            OP_COPY | OP_ADD if !tail_patch => {
                let off = if op == OP_COPY { br.uvarint()? } else { 0 };
                let n = br.uvarint()?;
                if n > target_size - produced {
                    return Err(corrupt("op overruns target"));
                }
                if op == OP_COPY {
                    if off > base_size || n > base_size - off {
                        return Err(corrupt("copy outside base"));
                    }
                    emit(&base[off as usize..(off + n) as usize], &mut sha, dst)?;
                } else {
                    br.copy_to(n, &mut |b| emit(b, &mut sha, dst))?;
                }
                produced += n;
            }
            _ => return Err(corrupt(format!("unknown op {:#x}", op))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::AttosMap;
    use crate::sha256::{hex, Sha256};

    const BASE_SHA: &str = "ea20042415281fa1101e6fea5187e26abf40c6742b65c502efdbe4fa4aceb720";
    const PATCH_SHA: &str = "9f5aa0bae8d4c2b6b7de68f502605aebfa62fd4bee10394f1c5ab71812f500a2";
    const EXPECTED_SHA: &str = "3f1d70c6fe07303e162d50266ceb2c6d292df1c54227016114520bef216164ab";

    fn fx(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/golden/overflow/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
    }

    fn sha(b: &[u8]) -> String {
        let mut s = Sha256::new();
        s.update(b);
        hex(&s.finish())
    }

    fn open(bytes: &[u8]) -> (tempfile::TempDir, Result<AttosMap, crate::AttosError>) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.attos");
        std::fs::write(&p, bytes).unwrap();
        let m = AttosMap::open(&p);
        (dir, m)
    }

    fn rebuilt() -> Vec<u8> {
        let mut out = Vec::new();
        apply_delta(
            &mut out,
            &fx("v1_base.attos"),
            &fx("v1_to_v2_tail.patch")[..],
        )
        .unwrap();
        out
    }

    #[test]
    fn vectors_match_manifest() {
        assert_eq!(sha(&fx("v1_base.attos")), BASE_SHA);
        assert_eq!(sha(&fx("v1_to_v2_tail.patch")), PATCH_SHA);
        assert_eq!(sha(&fx("v2_expected.attos")), EXPECTED_SHA);
        // The constants above must be the ones the workspace manifest pins (checked when it is present).
        let m = format!(
            "{}/../testdata/golden/MANIFEST.md",
            env!("CARGO_MANIFEST_DIR")
        );
        if let Ok(text) = std::fs::read_to_string(m) {
            for (name, want) in [
                ("v1_base.attos", BASE_SHA),
                ("v1_to_v2_tail.patch", PATCH_SHA),
                ("v2_expected.attos", EXPECTED_SHA),
            ] {
                let line = text
                    .lines()
                    .find(|l| l.contains(&format!("overflow/{}", name)))
                    .expect(name);
                assert!(line.contains(want), "{}: manifest says {}", name, line);
            }
        }
    }

    #[test]
    fn tail_patch_rebuilds_expected_file_byte_for_byte() {
        assert_eq!(rebuilt(), fx("v2_expected.attos"));
    }

    #[test]
    fn expected_file_semantics() {
        let (_d, m) = open(&fx("v2_expected.attos"));
        let m = m.unwrap();
        assert_eq!(m.len(), 1048);
        for i in 0..1000 {
            let k = format!("key_{}", i);
            let got = m.get(k.as_bytes());
            match i {
                100 | 200 => assert!(
                    matches!(got, Err(crate::AttosError::KeyNotFound)),
                    "{} tombstone",
                    k
                ),
                10 | 20 | 30 | 40 | 50 => assert_eq!(
                    got.unwrap(),
                    format!("overwritten_{}", i).as_bytes(),
                    "{}",
                    k
                ),
                _ => assert_eq!(got.unwrap(), format!("val_{}", i).as_bytes(), "{}", k),
            }
        }
        for i in 0..50 {
            assert_eq!(
                m.get(format!("ins_{}", i).as_bytes()).unwrap(),
                format!("inserted_{}", i).as_bytes()
            );
        }
        assert!(matches!(
            m.get(b"nope"),
            Err(crate::AttosError::KeyNotFound)
        ));
        // get_cow / get_copy see the same answers.
        assert_eq!(&*m.get_cow(b"key_10").unwrap(), b"overwritten_10");
        assert!(m.get_cow(b"key_100").is_err());
        let mut dst = Vec::new();
        m.get_copy(b"ins_7", &mut dst).unwrap();
        assert_eq!(dst, b"inserted_7");
        // scan: live main entries (overridden/deleted skipped) + live overflow entries = every live key once.
        let mut seen = std::collections::HashMap::new();
        m.scan(|k, v| {
            assert!(
                seen.insert(k.to_vec(), v.to_vec()).is_none(),
                "duplicate {:?}",
                String::from_utf8_lossy(k)
            );
            true
        });
        assert_eq!(seen.len(), 1048);
        assert_eq!(seen[&b"key_20".to_vec()], b"overwritten_20");
        assert!(!seen.contains_key(b"key_200".as_slice()));
    }

    #[test]
    fn base_file_is_unchanged_by_the_feature() {
        let (_d, m) = open(&fx("v1_base.attos"));
        let m = m.unwrap();
        assert_eq!(m.len(), 1000);
        assert_eq!(m.get(b"key_100").unwrap(), b"val_100");
        assert!(m.get(b"ins_0").is_err());
    }

    #[test]
    fn damaged_or_misapplied_patches_are_rejected() {
        let base = fx("v1_base.attos");
        let patch = fx("v1_to_v2_tail.patch");
        let run = |b: &[u8], p: &[u8]| apply_delta(&mut Vec::new(), b, p);
        // every sampled byte flip is caught (patch CRC, base check or target SHA)
        for i in (0..patch.len())
            .step_by(37)
            .chain([0, 4, 8, 16, 20, 28, 60, patch.len() - 1])
        {
            let mut p = patch.clone();
            p[i] ^= 0x40;
            assert!(run(&base, &p).is_err(), "flip at {} accepted", i);
        }
        assert!(run(&base, &patch[..patch.len() - 1]).is_err(), "truncated");
        assert!(run(&base, &patch[..patch.len() - 5]).is_err(), "truncated");
        let mut extra = patch.clone();
        extra.push(0);
        assert!(run(&base, &extra).is_err(), "trailing byte");
        assert!(
            run(&base, b"").is_err()
                && run(&base, b"ATDL").is_err()
                && run(&base, &[0u8; 80]).is_err()
        );
        // wrong base: other size, or same size with a different CRC trailer
        assert!(run(&fx("v2_expected.attos"), &patch).is_err(), "wrong base");
        let mut b2 = base.clone();
        *b2.last_mut().unwrap() ^= 1;
        assert!(run(&b2, &patch).is_err(), "base CRC differs");
        // the good case still works
        assert!(run(&base, &patch).is_ok());
    }

    /// Rewrites the tail of the expected file with `edit` applied to the footer, fixing the CRC afterwards.
    fn with_footer(edit: impl Fn(&mut [u8])) -> Vec<u8> {
        let mut d = fx("v2_expected.attos");
        let n = d.len();
        edit(&mut d[n - 24..n - 4]);
        let crc = crc32fast::hash(&d[..n - 4]);
        d[n - 4..].copy_from_slice(&crc.to_be_bytes());
        d
    }

    #[test]
    fn hostile_overflow_footers_are_rejected() {
        let ok = with_footer(|_| {});
        assert!(open(&ok).1.is_ok());
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "K = 0",
                with_footer(|f| f[..8].copy_from_slice(&0u64.to_be_bytes())),
            ),
            (
                "K huge",
                with_footer(|f| f[..8].copy_from_slice(&u64::MAX.to_be_bytes())),
            ),
            (
                "K too big for region",
                with_footer(|f| f[..8].copy_from_slice(&1_000_000u64.to_be_bytes())),
            ),
            (
                "K off by one",
                with_footer(|f| f[..8].copy_from_slice(&56u64.to_be_bytes())),
            ),
            (
                "baseEnd wrong",
                with_footer(|f| f[8..16].copy_from_slice(&64u64.to_be_bytes())),
            ),
            (
                "baseEnd huge",
                with_footer(|f| f[8..16].copy_from_slice(&u64::MAX.to_be_bytes())),
            ),
            ("magic", with_footer(|f| f[16..].copy_from_slice(b"OVFX"))),
        ];
        for (what, d) in cases {
            assert!(
                matches!(open(&d).1, Err(crate::AttosError::CorruptedBinary(_))),
                "{} accepted",
                what
            );
        }
        // Unsorted hashes / bad offsets / bad record lengths inside the region, CRC fixed up.
        let base_end = fx("v1_base.attos").len() - 4; // the main blob end is where the old CRC sat
        let patched = |off: usize, v: &[u8]| {
            let mut d = fx("v2_expected.attos");
            d[off..off + v.len()].copy_from_slice(v);
            let n = d.len();
            let crc = crc32fast::hash(&d[..n - 4]);
            d[n - 4..].copy_from_slice(&crc.to_be_bytes());
            d
        };
        assert!(
            open(&patched(base_end, &[0xFF; 8])).1.is_err(),
            "first hash max → unsorted"
        );
        let off_start = base_end + 57 * 8;
        assert!(
            open(&patched(off_start, &[1, 0, 0, 0, 0, 0, 0, 0]))
                .1
                .is_err(),
            "offsets[0] != 0"
        );
        assert!(
            open(&patched(off_start + 8, &[0xFF; 8])).1.is_err(),
            "offset beyond data"
        );
        let data_start = off_start + 58 * 8;
        assert!(
            open(&patched(data_start, &[0xFF, 0xFF])).1.is_err(),
            "keyLen beyond record"
        );
    }

    #[test]
    fn unknown_flag_bit_is_still_unsupported() {
        let mut d = fx("v2_expected.attos");
        d[8] |= 8;
        let n = d.len();
        let crc = crc32fast::hash(&d[..n - 4]);
        d[n - 4..].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            open(&d).1,
            Err(crate::AttosError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn copy_add_patch_v1_applies() {
        // Hand-built ATDL v1: target = base[0..70] + "XY" + base[70..], with a recomputed trailer.
        let base = fx("v1_base.attos");
        let mut target = base.clone();
        target.splice(70..70, *b"XY");
        let mut p = Vec::new();
        p.extend_from_slice(b"ATDL");
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&(base.len() as u64).to_be_bytes());
        p.extend_from_slice(&base[base.len() - 4..]);
        p.extend_from_slice(&(target.len() as u64).to_be_bytes());
        let mut s = Sha256::new();
        s.update(&target);
        p.extend_from_slice(&s.finish());
        let uv = |p: &mut Vec<u8>, mut x: u64| {
            while x >= 0x80 {
                p.push((x as u8) | 0x80);
                x >>= 7;
            }
            p.push(x as u8);
        };
        p.push(OP_COPY);
        uv(&mut p, 0);
        uv(&mut p, 70);
        p.push(OP_ADD);
        uv(&mut p, 2);
        p.extend_from_slice(b"XY");
        p.push(OP_COPY);
        uv(&mut p, 70);
        uv(&mut p, base.len() as u64 - 70);
        p.push(OP_END);
        let c = crc32fast::hash(&p);
        p.extend_from_slice(&c.to_be_bytes());
        let mut out = Vec::new();
        apply_delta(&mut out, &base, &p[..]).unwrap();
        assert_eq!(out, target);
        // a mangled op stream with a valid patch CRC is still refused (bad op / bounds / SHA)
        let mut bad = p.clone();
        bad[HDR_LEN + 1] = 0xff;
        bad[HDR_LEN + 2] = 0x7f;
        let n = bad.len();
        let c = crc32fast::hash(&bad[..n - 4]);
        bad[n - 4..].copy_from_slice(&c.to_be_bytes());
        assert!(apply_delta(&mut Vec::new(), &base, &bad[..]).is_err());
    }
}
