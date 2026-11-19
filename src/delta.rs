//! Patch sync (attos-cloud/docs/PATCH_UPDATES.md). A node that holds the main blob of the server's overflow chain,
//! or any variant of it, downloads one small "ATDL" tail patch instead of the whole file and rebuilds the new file
//! into a temp file from its current file; the result then goes through the same CRC validation, rename and atomic
//! publish as a full download.
//!
//! Patch layout (big-endian): `"ATDL" | u32 version=2 | u64 baseSize | u32 baseCRC | u64 targetSize |
//! [32]byte targetSHA256 | op 0x01 TRUNCATE_AND_APPEND u64 baseEnd | u64 payloadLen | payload | op 0x00 END |
//! u32 CRC32 of all preceding bytes`. The new file is the first baseEnd bytes of the base (header flag bit set)
//! followed by the payload. baseSize and baseCRC describe the base the server built the patch from and are not
//! checked: the patch applies to any file that starts with the same main blob, and the target SHA-256 proves it did.

use crate::error::AttosError;
use crate::overflow::FLAG_OVERFLOW;
use crate::sha256::Sha256;
use std::io::{Read, Write};

const MAGIC: &[u8; 4] = b"ATDL";
const HDR_LEN: usize = 60;
const OP_END: u8 = 0;
const OP_TRUNC_APPEND: u8 = 1;

pub(crate) fn corrupt(m: impl std::fmt::Display) -> AttosError {
    AttosError::Transport(format!("corrupt delta patch: {}", m))
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
/// patch CRC, op bounds, the produced size and the target SHA-256; on any error `dst` may hold
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
    if &hdr[..4] != MAGIC || version != 2 {
        return Err(corrupt("bad magic or version"));
    }
    let base_size = base.len() as u64;
    let target_size = u64::from_be_bytes(hdr[20..28].try_into().unwrap());
    let target_sha: [u8; 32] = hdr[28..60].try_into().unwrap();
    let mut sha = Sha256::new();
    let mut produced = 0u64;
    let emit = |b: &[u8], sha: &mut Sha256, dst: &mut W| -> Result<(), AttosError> {
        sha.update(b);
        dst.write_all(b).map_err(AttosError::IoError)
    };
    loop {
        let op = br.byte()?;
        if op == OP_TRUNC_APPEND {
            if produced != 0 {
                return Err(corrupt("second tail op"));
            }
            let mut ph = [0u8; 16];
            br.exact(&mut ph)?;
            let base_end = u64::from_be_bytes(ph[..8].try_into().unwrap());
            let plen = u64::from_be_bytes(ph[8..].try_into().unwrap());
            if base_size < 4
                || base_end > base_size - 4
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
            "{}/../../testdata/golden/MANIFEST.md",
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
        // a different main blob rebuilds a file with another SHA-256: refused
        let mut b2 = base.clone();
        b2[100] ^= 1;
        assert!(run(&b2, &patch).is_err(), "a different main blob");
        // any file that starts with the same main blob is a base: the previous variant takes the same patch
        assert!(
            run(&fx("v2_expected.attos"), &patch).is_ok(),
            "a variant of the chain"
        );
        // version 1 (copy/add) patches no longer exist
        let mut v1 = patch.clone();
        v1[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert!(run(&base, &v1).is_err(), "version 1 patch");
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

    /// A v2 patch is one TRUNCATE_AND_APPEND op plus END; the v1 copy/add ops are not part of it, even when the rest of
    /// the patch is valid (same rule in Go, Java, Node and Python).
    #[test]
    fn v2_patch_refuses_version_1_ops() {
        const OP_COPY: u8 = 1;
        let _ = OP_COPY;
        let base = fx("v1_base.attos");
        let good = fx("v1_to_v2_tail.patch");
        let run = |p: &[u8]| apply_delta(&mut Vec::new(), &base, p);
        assert!(run(&good).is_ok());
        let with_op = |op: &[u8]| {
            let mut b = good[..good.len() - 5].to_vec(); // drop END + CRC
            b.extend_from_slice(op);
            b.push(OP_END);
            let c = crc32fast::hash(&b);
            b.extend_from_slice(&c.to_be_bytes());
            b
        };
        for (name, op) in [
            ("ADD 0 bytes", &[0x02u8, 0x00][..]),
            ("ADD 1 byte", &[0x02, 0x01, b'x']),
            ("COPY 0 bytes", &[0x01, 0x00, 0x00]),
        ] {
            assert!(
                run(&with_op(op)).is_err(),
                "{} inside a v2 patch was accepted",
                name
            );
        }
        let mut b = good[..HDR_LEN].to_vec();
        b.extend_from_slice(&[0x02, 0x00, 0x00]);
        let c = crc32fast::hash(&b);
        b.extend_from_slice(&c.to_be_bytes());
        assert!(
            run(&b).is_err(),
            "a v2 patch starting with ADD was accepted"
        );
    }

    /// Every overflow record is validated when the file is opened, so a mapping that opens never holds a malformed
    /// record (same rule in Go, Java, Node and Python).
    #[test]
    fn malformed_overflow_records_are_refused_at_open() {
        let d0 = fx("v2_expected.attos");
        let n = d0.len();
        let k = u64::from_be_bytes(d0[n - 24..n - 16].try_into().unwrap()) as usize;
        let base_end = u64::from_be_bytes(d0[n - 16..n - 8].try_into().unwrap()) as usize;
        let off_off = base_end + k * 8;
        let data_off = off_off + (k + 1) * 8;
        let rec = |d: &[u8], i: usize| {
            data_off
                + u64::from_le_bytes(d[off_off + i * 8..off_off + i * 8 + 8].try_into().unwrap())
                    as usize
        };
        let fix = |mut d: Vec<u8>| {
            let c = crc32fast::hash(&d[..d.len() - 4]);
            let l = d.len();
            d[l - 4..].copy_from_slice(&c.to_be_bytes());
            d
        };
        assert!(open(&fix(d0.clone())).1.is_ok());
        let first_value = (0..k)
            .find(|&i| d0[rec(&d0, i) + 2..rec(&d0, i) + 6] != [0xff; 4])
            .unwrap();
        let s = rec(&d0, 0);
        let v = rec(&d0, first_value);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("keyLen beyond the record", {
                let mut d = d0.clone();
                d[s] = 0xff;
                d[s + 1] = 0xff;
                d
            }),
            ("valLen beyond the record", {
                let mut d = d0.clone();
                d[s + 2..s + 6].copy_from_slice(&[0, 0x10, 0, 0]);
                d
            }),
            ("valLen one too long", {
                let mut d = d0.clone();
                d[s + 5] = d[s + 5].wrapping_add(1);
                d
            }),
            ("keyLen one too short", {
                let mut d = d0.clone();
                d[s + 1] = d[s + 1].wrapping_sub(1);
                d
            }),
            ("value record turned into a tombstone", {
                let mut d = d0.clone();
                d[v + 2..v + 6].copy_from_slice(&[0xff; 4]);
                d
            }),
        ];
        for (name, d) in cases {
            assert!(open(&fix(d)).1.is_err(), "{}: opened", name);
        }
    }
}
