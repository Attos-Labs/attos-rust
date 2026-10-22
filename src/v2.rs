use crate::error::AttosError;

pub(crate) const V2_HEADER_SIZE: usize = 64;
const HP_OFFSET: u64 = 0x1234567;
const MIX_MUL: u64 = 0xD6E8_FEB8_6659_FD93;

/// PTHash 64-bit finalizer (xorshift-multiply, 3 rounds). Part of the v2 format.
#[inline(always)]
pub fn pthash_mix(mut x: u64) -> u64 {
    x ^= x >> 32;
    x = x.wrapping_mul(MIX_MUL);
    x ^= x >> 32;
    x = x.wrapping_mul(MIX_MUL);
    x ^= x >> 32;
    x
}

/// Pilot hash: `mix(p + 0x1234567)`.
#[inline(always)]
pub fn pthash_hp(p: u64) -> u64 {
    pthash_mix(p.wrapping_add(HP_OFFSET))
}

/// Maps a uniform 64-bit `h` to `[0, n)`: the high 64 bits of `h * n`.
#[inline(always)]
pub fn pthash_reduce(h: u64, n: u64) -> u64 {
    ((h as u128 * n as u128) >> 64) as u64
}

pub(crate) const MAX_BLOCK_RAW: u64 = 1 << 28;

/// Unsigned LEB128 (Go `binary.Uvarint`): returns (value, bytes consumed).
pub(crate) fn uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut shift = 0u32;
    for (i, &c) in b.iter().enumerate().take(10) {
        if c < 0x80 {
            if i == 9 && c > 1 {
                return None;
            }
            return Some((x | (c as u64) << shift, i + 1));
        }
        x |= ((c & 0x7f) as u64) << shift;
        shift += 7;
    }
    None
}

/// Bounds-checked LZ4 block decoder. `dst` must have exactly the decoded length.
pub(crate) fn lz4_decompress(dst: &mut [u8], src: &[u8]) -> Result<(), ()> {
    let (mut si, mut di) = (0usize, 0usize);
    loop {
        let tok = *src.get(si).ok_or(())?;
        si += 1;
        let mut lit = (tok >> 4) as usize;
        if lit == 15 {
            loop {
                let b = *src.get(si).ok_or(())?;
                si += 1;
                lit += b as usize;
                if b != 255 {
                    break;
                }
                if lit > dst.len() {
                    return Err(());
                }
            }
        }
        if lit > src.len() - si || lit > dst.len() - di {
            return Err(());
        }
        dst[di..di + lit].copy_from_slice(&src[si..si + lit]);
        si += lit;
        di += lit;
        if si == src.len() {
            return if di == dst.len() { Ok(()) } else { Err(()) };
        }
        if si + 2 > src.len() {
            return Err(());
        }
        let offset = src[si] as usize | (src[si + 1] as usize) << 8;
        si += 2;
        if offset == 0 || offset > di {
            return Err(());
        }
        let mut ml = (tok & 15) as usize;
        if ml == 15 {
            loop {
                let b = *src.get(si).ok_or(())?;
                si += 1;
                ml += b as usize;
                if b != 255 {
                    break;
                }
                if ml > dst.len() {
                    return Err(());
                }
            }
        }
        ml += 4;
        if ml > dst.len() - di {
            return Err(());
        }
        let from = di - offset;
        if offset >= ml {
            dst.copy_within(from..from + ml, di);
        } else {
            for i in 0..ml {
                dst[di + i] = dst[from + i];
            }
        }
        di += ml;
    }
}

/// Splits one uvarint-length-prefixed record at `pos`; returns (record range, next pos).
pub(crate) fn next_record(raw: &[u8], pos: usize) -> Option<(usize, usize)> {
    let (l, n) = uvarint(raw.get(pos..)?)?;
    let start = pos.checked_add(n)?;
    let end = start.checked_add(usize::try_from(l).ok()?)?;
    if end > raw.len() {
        return None;
    }
    Some((start, end))
}

pub(crate) fn packed_size(count: u64, w: u64) -> Option<u64> {
    // ceil(count*w / 64) * 8 + 8
    let bits = count.checked_mul(w)?;
    let words = bits.checked_add(63)? / 64;
    words.checked_mul(8)?.checked_add(8)
}

/// Parsed, validated v2 (PTHash) header. All section offsets are absolute file offsets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct V2Params {
    pub(crate) n: u64,
    pub(crate) m: u64,
    pub(crate) nb: u64,
    pub(crate) p2: u64,
    pub(crate) p1thr: u64,
    pub(crate) fw: u64,
    pub(crate) bw: u64,
    pub(crate) front_off: usize,
    pub(crate) back_off: usize,
    pub(crate) free_off: usize,
    pub(crate) offsets_off: usize,
    pub(crate) blob_off: usize,
    /// Last offsets entry: length of the blob in bytes.
    pub(crate) blob_len: usize,
    /// flags bit 0: records are grouped into `1 << block_shift` slot blocks.
    pub(crate) compressed: bool,
    pub(crate) block_shift: u32,
}

impl V2Params {
    pub(crate) fn parse(d: &[u8]) -> Result<Self, AttosError> {
        let bad = |m: &str| AttosError::CorruptedBinary(m.into());
        if d.len() < V2_HEADER_SIZE + 4 {
            return Err(bad("file too small for v2 header"));
        }
        let be64 = |o: usize| u64::from_be_bytes(d[o..o + 8].try_into().unwrap());
        let fw = d[9] as u64;
        let bw = d[10] as u64;
        let n = be64(12);
        let m = be64(20);
        let nb = be64(28);
        let p2 = be64(36);
        let p1thr = be64(44);
        if n == 0 || n > u32::MAX as u64 {
            return Err(bad("invalid v2 header: key count"));
        }
        if m < n || m > 2 * n + 16 {
            return Err(bad("invalid v2 header: table size"));
        }
        if nb < 2 || p2 < 1 || p2 >= nb {
            return Err(bad("invalid v2 header: bucket counts"));
        }
        if !(1..=32).contains(&fw) || !(1..=32).contains(&bw) {
            return Err(bad("invalid v2 header: pilot width"));
        }
        let fsz = packed_size(p2, fw).ok_or_else(|| bad("v2 front section overflow"))?;
        let bsz = packed_size(nb - p2, bw).ok_or_else(|| bad("v2 back section overflow"))?;
        let free = ((m - n) * 4).div_ceil(8) * 8;
        let flags = d[8];
        if flags & !1 != 0 {
            return Err(bad("unsupported v2 flags"));
        }
        let compressed = flags & 1 != 0;
        let mut block_shift = 0u32;
        let mut n_offsets = n + 1;
        if compressed {
            if d[11] > 8 {
                return Err(bad("invalid block shift"));
            }
            block_shift = d[11] as u32;
            n_offsets = n.div_ceil(1u64 << block_shift) + 1;
        }
        let off_bytes = (n_offsets * 4).div_ceil(8) * 8;
        let end = (V2_HEADER_SIZE as u64)
            .checked_add(fsz)
            .and_then(|v| v.checked_add(bsz))
            .and_then(|v| v.checked_add(free))
            .and_then(|v| v.checked_add(off_bytes))
            .ok_or_else(|| bad("v2 sections overflow"))?;
        let total = end.checked_add(4).ok_or_else(|| bad("v2 sections overflow"))?;
        if total > d.len() as u64 {
            return Err(bad("file too small for v2 sections"));
        }
        let front_off = V2_HEADER_SIZE;
        let back_off = front_off + fsz as usize;
        let free_off = back_off + bsz as usize;
        let offsets_off = free_off + free as usize;
        let blob_off = end as usize;
        let lo = offsets_off + (n_offsets as usize - 1) * 4;
        let blob_len = u32::from_le_bytes(d[lo..lo + 4].try_into().unwrap()) as u64;
        if (blob_off as u64) + blob_len + 4 > d.len() as u64 {
            return Err(bad("v2 blob size exceeds file"));
        }
        Ok(Self {
            n, m, nb, p2, p1thr, fw, bw,
            front_off, back_off, free_off, offsets_off, blob_off,
            blob_len: blob_len as usize,
            compressed,
            block_shift,
        })
    }
}

/// Reads pilot `i` of width `w` bits from `section` (which has 8 bytes of padding).
#[inline(always)]
pub(crate) fn get_bits(section: &[u8], i: u64, w: u64) -> Option<u64> {
    let off = i.checked_mul(w)?;
    let b = usize::try_from(off >> 3).ok()?;
    let chunk: [u8; 8] = section.get(b..b.checked_add(8)?)?.try_into().ok()?;
    Some((u64::from_le_bytes(chunk) >> (off & 7)) & ((1u64 << w) - 1))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_overlapping_match() {
        // literal a, match offset 1 len 9, then an empty final literal run
        let src = [0x15, b'a', 1, 0, 0x00];
        let mut dst = [0u8; 10];
        lz4_decompress(&mut dst, &src).unwrap();
        assert_eq!(&dst, b"aaaaaaaaaa");
    }

    #[test]
    fn lz4_rejects_bad_input() {
        let mut dst = [0u8; 10];
        assert!(lz4_decompress(&mut dst, &[0x15, b'a', 0, 0, 0]).is_err()); // offset 0
        assert!(lz4_decompress(&mut dst, &[0x15, b'a', 2, 0]).is_err()); // offset > produced
        assert!(lz4_decompress(&mut dst, &[0x15, b'a', 1]).is_err()); // truncated offset
        assert!(lz4_decompress(&mut dst, &[0x1f, b'a', 1, 0, 255, 255]).is_err()); // runaway length
        assert!(lz4_decompress(&mut dst, &[0xf0, 255, 255, 255]).is_err());
        assert!(lz4_decompress(&mut dst, &[]).is_err());
        assert!(lz4_decompress(&mut dst, &[0x20, b'a', b'b']).is_err()); // short output
        let mut small = [0u8; 1];
        assert!(lz4_decompress(&mut small, &[0x20, b'a', b'b']).is_err()); // dst overflow
    }

    #[test]
    fn uvarint_cases() {
        assert_eq!(uvarint(&[0]), Some((0, 1)));
        assert_eq!(uvarint(&[0xac, 0x02]), Some((300, 2)));
        assert_eq!(uvarint(&[0x80]), None);
        assert_eq!(uvarint(&[0xff; 11]), None);
        assert_eq!(uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]), None);
        assert!(uvarint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).is_some());
    }
}
