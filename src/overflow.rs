//! LSM-lite overflow block (attos-cloud/docs/OVERFLOW_BLOCK.md). A v2 file with flags bit 2 carries a small
//! sorted side table between the main blob and the CRC trailer; lookups check it before the PTHash table.
//!
//! ```text
//! ... main blob (ends at baseEnd)
//! hashes   K*8      u64 LE, ascending, XXH64(key, 0)
//! offsets  (K+1)*8  u64 LE, relative to the start of data
//! data     per entry: u16 BE keyLen | u32 BE valLen | key | value   (valLen 0xFFFFFFFF = tombstone)
//! footer   20 B     u64 BE K | u64 BE baseEnd | "OVFL"
//! crc32    4 B      over everything before it
//! ```
//!
//! Everything is parsed and bounds-checked once at open; a lookup then only does in-bounds reads and
//! allocates nothing. A file without the flag has no `Overflow` and pays one predictable branch.

use crate::error::AttosError;

pub(crate) const FLAG_OVERFLOW: u8 = 4;
const FOOTER: usize = 20;
const MAGIC: &[u8; 4] = b"OVFL";
const TOMBSTONE: u32 = 0xFFFF_FFFF;

/// Parsed overflow block: where the arrays live plus the open-time reject filter.
pub(crate) struct Overflow {
    k: usize,
    hash_off: usize,
    off_off: usize,
    data_off: usize,
    /// One bit per `(hash >> 20) & mask`; no false negatives. 32 bits per key rounded up to a power of two.
    filter: Box<[u64]>,
    mask: u64,
}

/// Outcome of an overflow probe.
pub(crate) enum Probe<'a> {
    /// The overflow has no entry for the key: continue with the main table.
    Miss,
    /// The overflow holds a value.
    Value(&'a [u8]),
    /// The overflow holds a tombstone: the key is deleted.
    Tombstone,
}

#[inline(always)]
fn le64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

impl Overflow {
    /// Validates the overflow region of `d` (the whole file) whose main blob ends at `base_end`.
    pub(crate) fn parse(d: &[u8], base_end: u64) -> Result<Self, AttosError> {
        let bad = |m: &str| AttosError::CorruptedBinary(m.into());
        let sz = d.len() as u64;
        let tail = (FOOTER + 4) as u64;
        if sz < tail || base_end > sz - tail {
            return Err(bad("overflow footer does not fit"));
        }
        let f = &d[(sz - tail) as usize..(sz - 4) as usize];
        if &f[16..] != MAGIC {
            return Err(bad("missing overflow footer"));
        }
        let k = u64::from_be_bytes(f[..8].try_into().unwrap());
        if u64::from_be_bytes(f[8..16].try_into().unwrap()) != base_end {
            return Err(bad("overflow baseEnd does not match the main blob"));
        }
        let region = sz - tail - base_end;
        if k == 0 || k > region / 16 {
            return Err(bad("invalid overflow count"));
        }
        let hash_off = base_end;
        let off_off = hash_off + k * 8;
        let data_off = off_off + (k + 1) * 8;
        if data_off > sz - tail {
            return Err(bad("overflow arrays exceed the file"));
        }
        let data_len = sz - tail - data_off;
        let mut prev = 0u64;
        for i in 0..k {
            let h = le64(d, (hash_off + i * 8) as usize);
            if i > 0 && h < prev {
                return Err(bad("overflow hashes not sorted"));
            }
            prev = h;
        }
        let mut po = 0u64;
        for i in 0..=k {
            let o = le64(d, (off_off + i * 8) as usize);
            if (i == 0 && o != 0) || o < po || o > data_len {
                return Err(bad("invalid overflow offsets"));
            }
            po = o;
        }
        if po != data_len {
            return Err(bad("overflow data length mismatch"));
        }
        let mut bits = 64u64;
        while bits < k * 32 {
            bits <<= 1;
        }
        let mask = bits - 1;
        let mut filter = vec![0u64; (bits / 64) as usize].into_boxed_slice();
        for i in 0..k {
            let x = (le64(d, (hash_off + i * 8) as usize) >> 20) & mask;
            filter[(x >> 6) as usize] |= 1 << (x & 63);
        }
        let ov = Self {
            k: k as usize,
            hash_off: hash_off as usize,
            off_off: off_off as usize,
            data_off: data_off as usize,
            filter,
            mask,
        };
        // Every record must parse, so lookups never meet a malformed entry.
        for i in 0..ov.k {
            ov.entry(d, i)
                .ok_or_else(|| bad("invalid overflow entry"))?;
        }
        Ok(ov)
    }

    /// Number of overflow entries (values and tombstones).
    pub(crate) fn len(&self) -> usize {
        self.k
    }

    /// Record `i`: `(key, value, tombstone)`; `None` if malformed (rejected at open).
    #[inline(always)]
    pub(crate) fn entry<'a>(&self, d: &'a [u8], i: usize) -> Option<(&'a [u8], &'a [u8], bool)> {
        let s = self
            .data_off
            .checked_add(le64(d, self.off_off + i * 8) as usize)?;
        let e = self
            .data_off
            .checked_add(le64(d, self.off_off + (i + 1) * 8) as usize)?;
        let rec = d.get(s..e)?;
        if rec.len() < 6 {
            return None;
        }
        let kl = u16::from_be_bytes([rec[0], rec[1]]) as usize;
        let vl = u32::from_be_bytes([rec[2], rec[3], rec[4], rec[5]]);
        if vl == TOMBSTONE {
            return (6 + kl == rec.len()).then(|| (&rec[6..6 + kl], &rec[..0], true));
        }
        (6 + kl + vl as usize == rec.len()).then(|| (&rec[6..6 + kl], &rec[6 + kl..], false))
    }

    /// Probes the overflow for `key` (`h` = XXH64(key, 0)). No allocation.
    #[inline(always)]
    pub(crate) fn probe<'a>(&self, d: &'a [u8], h: u64, key: &[u8]) -> Probe<'a> {
        let x = (h >> 20) & self.mask;
        if self.filter[(x >> 6) as usize] & (1 << (x & 63)) == 0 {
            return Probe::Miss;
        }
        let (mut lo, mut hi) = (0usize, self.k);
        while lo < hi {
            let mid = (lo + hi) >> 1;
            if le64(d, self.hash_off + mid * 8) < h {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let mut i = lo;
        while i < self.k && le64(d, self.hash_off + i * 8) == h {
            // Equal hash, different key: keep looking, then fall through to the main table.
            if let Some((k, v, tomb)) = self.entry(d, i) {
                if k == key {
                    return if tomb {
                        Probe::Tombstone
                    } else {
                        Probe::Value(v)
                    };
                }
            }
            i += 1;
        }
        Probe::Miss
    }
}
