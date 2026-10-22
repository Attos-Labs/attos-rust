use memmap2::{Mmap, MmapOptions};
use std::borrow::Cow;
use std::fs::File;
use std::hash::Hasher;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use twox_hash::XxHash64;

use crc32fast::Hasher as Crc32Hasher;
use tracing::{debug, info, instrument, warn};

use crate::error::AttosError;
use crate::stats::LatencyHistogram;
use crate::v2::{lz4_decompress, next_record, uvarint, get_bits, V2Params, MAX_BLOCK_RAW};
pub use crate::v2::{pthash_hp, pthash_mix, pthash_reduce};

const MAGIC_ATTO: &[u8; 4] = b"ATTO";
/// Fixed v1 header length (CONTRACTS.md §1.1).
pub const HEADER_SIZE: usize = 33;

/// Configuration applied when opening a `.attos` / `.nh` binary file.
///
/// All fields are optional; zero/`false`/`None` selects safe production defaults.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenConfig {
    /// Verify the CRC32-IEEE trailer before the map is exposed.
    /// The synchronizer always validates downloaded blobs regardless of this flag.
    /// Default: `false` (direct `open` only).
    pub validate_checksum: bool,

    /// Call `mlock(2)` on the mapped region to prevent OS page-outs.
    /// Failure is non-fatal (a warning is logged), matching the Go and Java SDKs.
    /// Default: `false`.
    pub pin_to_memory: bool,

    /// Polling interval for background cloud sync used by `AttosSynchronizer`.
    /// `None` selects the default (`DEFAULT_SYNC_INTERVAL`, 30 s, identical in all
    /// SDKs); `Some(Duration::ZERO)` disables polling.
    pub poll_interval: Option<Duration>,
}

const STRIPES: usize = 32;
const SAMPLE_MASK: u64 = 255;

#[repr(align(64))]
#[derive(Default)]
struct Stripe(AtomicU64);

/// A read-only memory-mapped view of a compiled `.attos` binary.
///
/// Lookups are O(1), lock-free and zero-allocation. The struct is `Send + Sync`;
/// concurrent reads from multiple threads are safe without locking.
///
/// Memory is unmapped via `Drop`. When held inside an `Arc` (as used by
/// `AttosClient`), the munmap is deferred until the last `Guard`/`Arc`
/// reference is dropped, so a lookup in progress always completes against the
/// map it loaded. Zero-copy values (`&[u8]` / `&str`) borrow the map (or the
/// guard holding it) and cannot outlive it — the validity window is enforced
/// by the borrow checker.
pub struct AttosMap {
    mmap: Mmap,
    pub version: u32,
    is_32bit: bool,
    /// Number of slots (S).
    pub total_keys: u64,
    num_buckets: u64,
    routing_offset: usize,
    values_offset: usize,
    blob_offset: usize,
    data_end: usize,
    pinned: bool,
    closed: bool,
    v2: Option<V2Params>,
    // Telemetry: striped lookup counters (indexed by key hash, so concurrent
    // readers rarely share a cache line) and a 1/256-sampled latency histogram.
    lookups: [Stripe; STRIPES],
    pub(crate) latency: LatencyHistogram,
}

impl std::fmt::Debug for AttosMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttosMap")
            .field("version", &self.version)
            .field("is_32bit", &self.is_32bit)
            .field("total_keys", &self.total_keys)
            .field("num_buckets", &self.num_buckets)
            .field("size", &self.mmap.len())
            .field("pinned", &self.pinned)
            .field("closed", &self.closed)
            .finish()
    }
}

/// Parsed and validated header layout.
pub(crate) struct Layout {
    is_32bit: bool,
    slots: u64,
    buckets: u64,
    routing_offset: usize,
    values_offset: usize,
    blob_offset: usize,
    data_end: usize,
}

/// Validate a complete v1 blob (CONTRACTS.md §1.1 / §1.6).
pub(crate) fn parse_layout(data: &[u8], check_crc: bool) -> Result<Layout, AttosError> {
    let sz = data.len() as u64;
    if sz < 4 {
        return Err(AttosError::CorruptedBinary(format!("file too small ({} bytes)", sz)));
    }
    if &data[0..4] != MAGIC_ATTO {
        return Err(AttosError::InvalidMagic);
    }
    if sz < 8 {
        return Err(AttosError::CorruptedBinary("file too small for version".into()));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 1 {
        return Err(AttosError::InvalidVersion(version));
    }
    if sz < HEADER_SIZE as u64 {
        return Err(AttosError::CorruptedBinary(format!("file too small for header ({} bytes)", sz)));
    }
    let w: u64 = match data[8] {
        0x01 => 2,
        0x02 => 4,
        f => return Err(AttosError::CorruptedBinary(format!("invalid routing flag 0x{:02x}", f))),
    };
    let slots = u64::from_be_bytes(data[9..17].try_into().unwrap());
    let buckets = u64::from_be_bytes(data[17..25].try_into().unwrap());
    if slots == 0 || buckets == 0 {
        return Err(AttosError::CorruptedBinary("zero slots or buckets".into()));
    }
    let r = buckets
        .checked_mul(w)
        .and_then(|v| v.checked_add(HEADER_SIZE as u64));
    let d = r.and_then(|r| slots.checked_mul(8).and_then(|v| v.checked_add(r)));
    let d = match d {
        Some(d) if d.checked_add(4).map_or(false, |e| e <= sz) => d,
        _ => {
            return Err(AttosError::CorruptedBinary(format!(
                "header counts (S={}, B={}) exceed file size {}",
                slots, buckets, sz
            )))
        }
    };
    let r = r.unwrap();
    if check_crc {
        let end = data.len() - 4;
        let mut hasher = Crc32Hasher::new();
        hasher.update(&data[..end]);
        let actual = hasher.finalize();
        let expected = u32::from_be_bytes(data[end..].try_into().unwrap());
        if expected != actual {
            return Err(AttosError::ChecksumMismatch { expected, actual });
        }
    }
    Ok(Layout {
        is_32bit: w == 4,
        slots,
        buckets,
        routing_offset: HEADER_SIZE,
        values_offset: r as usize,
        blob_offset: d as usize,
        data_end: data.len() - 4,
    })
}

/// Validate a complete v2 blob: header/section arithmetic plus the optional CRC32 trailer.
fn parse_v2(data: &[u8], check_crc: bool) -> Result<V2Params, AttosError> {
    let p = V2Params::parse(data)?;
    if check_crc {
        let end = data.len() - 4;
        let mut hasher = Crc32Hasher::new();
        hasher.update(&data[..end]);
        let actual = hasher.finalize();
        let expected = u32::from_be_bytes(data[end..].try_into().unwrap());
        if expected != actual {
            return Err(AttosError::ChecksumMismatch { expected, actual });
        }
    }
    Ok(p)
}

#[inline(always)]
fn hash_key(key: &[u8]) -> u64 {
    let mut hasher = XxHash64::with_seed(0);
    hasher.write(key);
    hasher.finish()
}

#[inline(always)]
fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
#[inline(always)]
fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline(always)]
fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().unwrap())
}

impl AttosMap {
    /// Open with default config (no checksum, no mlock).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AttosError> {
        Self::open_with_config(path, OpenConfig::default())
    }

    /// Open with explicit configuration.
    ///
    /// Returns a typed `AttosError` on every known failure mode:
    /// `InvalidMagic`, `InvalidVersion(v)`, `CorruptedBinary`, `ChecksumMismatch`.
    #[instrument(skip(path), fields(path = %path.as_ref().display()))]
    pub fn open_with_config<P: AsRef<Path>>(path: P, config: OpenConfig) -> Result<Self, AttosError> {
        Self::open_inner(path.as_ref(), config, config.validate_checksum)
    }

    /// Fully validate a blob on disk (magic, version, flag, size arithmetic and
    /// CRC32) — the validation the sync path applies before publishing.
    pub fn validate_file<P: AsRef<Path>>(path: P) -> Result<(), AttosError> {
        Self::open_inner(path.as_ref(), OpenConfig::default(), true).map(|_| ())
    }

    pub(crate) fn open_inner(path: &Path, config: OpenConfig, check_crc: bool) -> Result<Self, AttosError> {
        debug!("Opening AttosMap file");
        let file = File::open(path).map_err(AttosError::IoError)?;
        let len = file.metadata().map_err(AttosError::IoError)?.len();
        if len < 4 {
            return Err(AttosError::CorruptedBinary(format!("file too small ({} bytes)", len)));
        }
        // SAFETY: memmap2 requires that the file is not modified or truncated
        // while mapped. The SDK only maps files it owns: the synchronizer writes
        // a new blob to a fresh temp file and atomically renames it over the
        // live path, so a mapped inode is never written again; callers of
        // `open` must likewise treat blobs as immutable (documented contract).
        // The mapping is read-only (PROT_READ) and `file` may be closed after
        // mapping without invalidating it.
        let mmap = unsafe { MmapOptions::new().map(&file).map_err(AttosError::IoError)? };
        drop(file);
        let v2 = if mmap.len() >= 8 && &mmap[0..4] == MAGIC_ATTO && mmap[4..8] == [0, 0, 0, 2] {
            Some(parse_v2(&mmap, check_crc)?)
        } else {
            None
        };
        let layout = match &v2 {
            Some(p) => Layout {
                is_32bit: false,
                slots: p.n,
                buckets: p.nb,
                routing_offset: p.front_off,
                values_offset: p.offsets_off,
                blob_offset: p.blob_off,
                data_end: mmap.len() - 4,
            },
            None => parse_layout(&mmap, check_crc)?,
        };

        let mut pinned = false;
        if config.pin_to_memory {
            #[cfg(unix)]
            {
                // SAFETY: the pointer/length describe the live mapping owned by
                // `mmap`; mlock does not access the memory.
                let rc = unsafe { libc::mlock(mmap.as_ptr() as *const libc::c_void, mmap.len()) };
                if rc != 0 {
                    warn!(
                        "mlock failed (non-fatal): {}",
                        std::io::Error::last_os_error()
                    );
                } else {
                    pinned = true;
                }
            }
        }

        // Advise the kernel that access patterns are random (not sequential).
        #[cfg(unix)]
        {
            let _ = mmap.advise(memmap2::Advice::Random);
        }

        info!(
            is_32bit = layout.is_32bit,
            slots = layout.slots,
            buckets = layout.buckets,
            pinned,
            "Successfully opened AttosMap"
        );

        Ok(Self {
            mmap,
            version: if v2.is_some() { 2 } else { 1 },
            is_32bit: layout.is_32bit,
            total_keys: layout.slots,
            num_buckets: layout.buckets,
            routing_offset: layout.routing_offset,
            values_offset: layout.values_offset,
            blob_offset: layout.blob_offset,
            data_end: layout.data_end,
            pinned,
            closed: false,
            v2,
            lookups: Default::default(),
            latency: LatencyHistogram::default(),
        })
    }

    /// A sentinel map installed by `AttosClient::shutdown`: every lookup
    /// returns `AttosError::MapClosed`.
    pub(crate) fn closed_sentinel() -> Self {
        let anon = MmapOptions::new()
            .len(HEADER_SIZE + 2 + 8 + 4)
            .map_anon()
            .and_then(|m| m.make_read_only())
            .expect("anonymous mapping");
        Self {
            mmap: anon,
            version: 1,
            is_32bit: false,
            total_keys: 1,
            num_buckets: 1,
            routing_offset: HEADER_SIZE,
            values_offset: HEADER_SIZE + 2,
            blob_offset: HEADER_SIZE + 10,
            data_end: HEADER_SIZE + 10,
            pinned: false,
            closed: true,
            v2: None,
            lookups: Default::default(),
            latency: LatencyHistogram::default(),
        }
    }

    /// True for the shutdown sentinel.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Size of the mapped blob in bytes.
    pub fn size(&self) -> usize {
        if self.closed {
            0
        } else {
            self.mmap.len()
        }
    }

    /// Number of keys stored (O(S) scan of the offset table).
    pub fn len(&self) -> usize {
        if self.closed {
            return 0;
        }
        if self.v2.is_some() {
            return self.total_keys as usize;
        }
        (0..self.total_keys as usize)
            .filter(|i| read_u64(&self.mmap, self.values_offset + i * 8) & 0xFFFF_FFFF != 0)
            .count()
    }

    /// True if the map holds no keys.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total lookups served by this map (telemetry).
    pub fn lookups(&self) -> u64 {
        self.lookups.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
    }

    #[inline(always)]
    fn entry(&self, h: u64, key: &[u8]) -> Result<&[u8], AttosError> {
        if let Some(p) = &self.v2 {
            if p.compressed {
                return Err(AttosError::CompressedRequiresOwned);
            }
            let slot = self.v2_slot(p, h)?;
            let payload = self.v2_record(p, slot)?;
            return Self::split_record(payload, key);
        }
        let data: &[u8] = &self.mmap;
        let bucket = ((h >> 32) as u32 as u64) % self.num_buckets;
        let d = if self.is_32bit {
            read_u32(data, self.routing_offset + bucket as usize * 4) as u64
        } else {
            read_u16(data, self.routing_offset + bucket as usize * 2) as u64
        };
        let slot = ((h as u32 as u64) ^ d) % self.total_keys;
        let word = read_u64(data, self.values_offset + slot as usize * 8);
        let len = (word & 0xFFFF_FFFF) as usize;
        if len == 0 {
            return Err(if self.closed { AttosError::MapClosed } else { AttosError::KeyNotFound });
        }
        let start = self.blob_offset + (word >> 32) as usize;
        let end = start + len;
        if len < 2 || end > self.data_end {
            return Err(AttosError::CorruptedBinary("entry out of bounds".into()));
        }
        let e = &data[start..end];
        let kl = read_u16(e, 0) as usize;
        if 2 + kl > len {
            return Err(AttosError::CorruptedBinary("key length exceeds entry".into()));
        }
        if &e[2..2 + kl] != key {
            return Err(AttosError::KeyNotFound);
        }
        Ok(&e[2 + kl..])
    }

    /// O(1) lookup by raw byte slice key.
    ///
    /// Returns a zero-copy slice into the mmap region, valid for the lifetime of
    /// this `AttosMap` (or the `Guard` holding it). Use [`AttosMap::get_copy`] to
    /// keep a value beyond that. Allocation profile: **0 B/op**.
    #[inline(always)]
    pub fn get<'a>(&'a self, key: &[u8]) -> Result<&'a [u8], AttosError> {
        let h = hash_key(key);
        let n = self.lookups[(h as usize) & (STRIPES - 1)]
            .0
            .fetch_add(1, Ordering::Relaxed);
        if n & SAMPLE_MASK == 0 {
            let t0 = Instant::now();
            let r = self.entry(h, key);
            self.latency.record(t0.elapsed());
            return r;
        }
        self.entry(h, key)
    }

    /// Copying lookup: appends the value to `dst` (no allocation if `dst` has
    /// capacity). The result does not borrow the map.
    #[inline]
    pub fn get_copy(&self, key: &[u8], dst: &mut Vec<u8>) -> Result<(), AttosError> {
        let v = self.get(key)?;
        dst.extend_from_slice(v);
        Ok(())
    }

    /// O(1) lookup returning a zero-copy `&str`.
    ///
    /// Returns `AttosError::Utf8Error` if the stored value is not valid UTF-8.
    /// Allocation profile: **0 B/op**.
    #[inline(always)]
    pub fn get_string<'a>(&'a self, key: &str) -> Result<&'a str, AttosError> {
        let bytes = self.get(key.as_bytes())?;
        std::str::from_utf8(bytes).map_err(Into::into)
    }

    /// Multi-dimensional O(1) lookup.
    ///
    /// `factors` are dimension values sorted by column name (matching the
    /// builder's sort order). They are concatenated with a `\x00` separator
    /// into a 1 KiB stack buffer — zero heap allocation.
    ///
    /// Returns `AttosError::KeyNotFound` if the composite key is absent or
    /// if the concatenated key exceeds 1 024 bytes.
    #[inline(always)]
    pub fn multi_lookup<'a>(&'a self, factors: &[&[u8]]) -> Result<&'a [u8], AttosError> {
        let mut buf = [0u8; 1024];
        let offset = Self::fill_composite(&mut buf, factors)?;
        self.get(&buf[..offset])
    }

    /// Iterates all non-empty slots in the values table.
    ///
    /// Order is determined by MPHF slot assignment (not insertion order).
    /// The callback receives zero-copy references into the mmap. Return
    /// `false` to halt early.
    pub fn scan<F>(&self, mut callback: F)
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        if self.closed {
            return;
        }
        if let Some(p) = &self.v2 {
            self.scan_v2(p, &mut callback);
            return;
        }
        for i in 0..self.total_keys as usize {
            let word = read_u64(&self.mmap, self.values_offset + i * 8);
            let len = (word & 0xFFFF_FFFF) as usize;
            if len == 0 {
                continue;
            }
            let start = self.blob_offset + (word >> 32) as usize;
            let end = start + len;
            if len < 2 || end > self.data_end {
                continue;
            }
            let e = &self.mmap[start..end];
            let kl = read_u16(e, 0) as usize;
            if 2 + kl > len {
                continue;
            }
            if !callback(&e[2..2 + kl], &e[2 + kl..]) {
                break;
            }
        }
    }
}

impl AttosMap {
    /// PTHash slot for key hash `x`, in `[0, n)`. Never panics on hostile data.
    #[inline(always)]
    fn v2_slot(&self, p: &V2Params, x: u64) -> Result<u64, AttosError> {
        let corrupt = || AttosError::CorruptedBinary("v2 table out of bounds".into());
        let r = x.rotate_left(32);
        let pilot = if x < p.p1thr {
            let sec = self.mmap.get(p.front_off..p.back_off).ok_or_else(corrupt)?;
            get_bits(sec, pthash_reduce(r, p.p2), p.fw)
        } else {
            let sec = self.mmap.get(p.back_off..p.free_off).ok_or_else(corrupt)?;
            get_bits(sec, pthash_reduce(r, p.nb - p.p2), p.bw)
        }
        .ok_or_else(corrupt)?;
        let mut q = pthash_reduce(pthash_mix(x ^ pthash_hp(pilot)), p.m);
        if q >= p.n {
            let o = p.free_off + (q - p.n) as usize * 4;
            let b = self.mmap.get(o..o + 4).ok_or_else(corrupt)?;
            q = u32::from_le_bytes(b.try_into().unwrap()) as u64;
        }
        if q >= p.n {
            return Err(corrupt());
        }
        Ok(q)
    }

    /// Returns the record bytes (`u16 keyLen | key | value`) of slot `slot`.
    #[inline(always)]
    fn v2_record(&self, p: &V2Params, slot: u64) -> Result<&[u8], AttosError> {
        let corrupt = || AttosError::CorruptedBinary("payload index out of bounds".into());
        let o = p.offsets_off + slot as usize * 4;
        let b = self.mmap.get(o..o + 8).ok_or_else(corrupt)?;
        let start = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
        let end = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        if start > end || end > p.blob_len {
            return Err(corrupt());
        }
        self.mmap.get(p.blob_off + start..p.blob_off + end).ok_or_else(corrupt)
    }

    /// Splits a record and returns its value if the stored key equals `key`.
    #[inline(always)]
    fn split_record<'a>(payload: &'a [u8], key: &[u8]) -> Result<&'a [u8], AttosError> {
        if payload.len() < 2 {
            return Err(AttosError::CorruptedBinary("payload too small for key length".into()));
        }
        let key_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let key_bytes = payload
            .get(2..2 + key_len)
            .ok_or_else(|| AttosError::CorruptedBinary("payload too small for key".into()))?;
        if key_bytes != key {
            return Err(AttosError::KeyNotFound);
        }
        Ok(&payload[2 + key_len..])
    }

    /// Whether the file stores records in (optionally LZ4-compressed) blocks (v2 flags bit 0).
    /// For such files `get` / `get_string` / `multi_lookup` return
    /// `AttosError::CompressedRequiresOwned`; use `get_cow`, `get_owned` and friends.
    pub fn is_compressed(&self) -> bool {
        self.v2.map(|p| p.compressed).unwrap_or(false)
    }

    /// Returns the (blob-relative checked) bytes of block `b`, method byte included.
    fn v2_block(&self, p: &V2Params, b: u64) -> Result<&[u8], AttosError> {
        let corrupt = || AttosError::CorruptedBinary("block index out of bounds".into());
        let o = p.offsets_off.checked_add((b as usize).checked_mul(4).ok_or_else(corrupt)?).ok_or_else(corrupt)?;
        let w = self.mmap.get(o..o + 8).ok_or_else(corrupt)?;
        let start = u32::from_le_bytes(w[0..4].try_into().unwrap()) as usize;
        let end = u32::from_le_bytes(w[4..8].try_into().unwrap()) as usize;
        if end <= start || end > p.blob_len {
            return Err(corrupt());
        }
        self.mmap.get(p.blob_off + start..p.blob_off + end).ok_or_else(corrupt)
    }

    /// Decodes a block into `uvarint(len) | record` sequences. Stored blocks borrow the mapping.
    fn decode_block(blk: &[u8]) -> Result<Cow<'_, [u8]>, AttosError> {
        let corrupt = || AttosError::CorruptedBinary("invalid compressed block".into());
        let (raw_len, n) = uvarint(blk.get(1..).ok_or_else(corrupt)?).ok_or_else(corrupt)?;
        if raw_len > MAX_BLOCK_RAW {
            return Err(corrupt());
        }
        let payload = &blk[1 + n..];
        match blk[0] {
            0 => {
                if payload.len() as u64 != raw_len {
                    return Err(corrupt());
                }
                Ok(Cow::Borrowed(payload))
            }
            1 => {
                if raw_len > (payload.len() as u64) * 255 + 16 {
                    return Err(corrupt());
                }
                let mut raw = vec![0u8; raw_len as usize];
                lz4_decompress(&mut raw, payload).map_err(|_| corrupt())?;
                Ok(Cow::Owned(raw))
            }
            _ => Err(corrupt()),
        }
    }

    /// Lookup that works for every file kind. Plain files return a borrowed view of the mapping;
    /// compressed files return a stored-block view or a copy (LZ4 blocks must be decoded).
    pub fn get_cow<'a>(&'a self, key: &[u8]) -> Result<Cow<'a, [u8]>, AttosError> {
        let p = match &self.v2 {
            Some(p) if p.compressed => p,
            _ => return self.get(key).map(Cow::Borrowed),
        };
        let h = hash_key(key);
        self.lookups[(h as usize) & (STRIPES - 1)].0.fetch_add(1, Ordering::Relaxed);
        let slot = self.v2_slot(p, h)?;
        let blk = self.v2_block(p, slot >> p.block_shift)?;
        let raw = Self::decode_block(blk)?;
        let corrupt = || AttosError::CorruptedBinary("bad record in block".into());
        let mut pos = 0usize;
        let mut rec = (0, 0);
        for _ in 0..=(slot & ((1u64 << p.block_shift) - 1)) {
            let (s, e) = next_record(&raw, pos).ok_or_else(corrupt)?;
            rec = (s, e);
            pos = e;
        }
        let value_range = {
            let r = &raw[rec.0..rec.1];
            let v = Self::split_record(r, key)?;
            let off = rec.1 - v.len();
            off..rec.1
        };
        Ok(match raw {
            Cow::Borrowed(b) => Cow::Borrowed(&b[value_range]),
            Cow::Owned(v) => Cow::Owned(v[value_range].to_vec()),
        })
    }

    /// Lookup returning an owned copy of the value; works for every file kind.
    pub fn get_owned(&self, key: &[u8]) -> Result<Vec<u8>, AttosError> {
        self.get_cow(key).map(Cow::into_owned)
    }

    /// Like `get_string` but works for compressed files (returns a `String`).
    pub fn get_string_owned(&self, key: &str) -> Result<String, AttosError> {
        String::from_utf8(self.get_owned(key.as_bytes())?)
            .map_err(|e| e.utf8_error().into())
    }

    /// Like `multi_lookup` but works for every file kind.
    pub fn multi_lookup_cow<'a>(&'a self, factors: &[&[u8]]) -> Result<Cow<'a, [u8]>, AttosError> {
        let mut buf = [0u8; 1024];
        let len = Self::fill_composite(&mut buf, factors)?;
        self.get_cow(&buf[..len])
    }

    fn fill_composite(buf: &mut [u8; 1024], factors: &[&[u8]]) -> Result<usize, AttosError> {
        let mut offset = 0;
        for (i, factor) in factors.iter().enumerate() {
            if i > 0 {
                if offset >= buf.len() {
                    return Err(AttosError::KeyNotFound);
                }
                buf[offset] = 0x00;
                offset += 1;
            }
            let end = offset + factor.len();
            if end > buf.len() {
                return Err(AttosError::KeyNotFound);
            }
            buf[offset..end].copy_from_slice(factor);
            offset = end;
        }
        Ok(offset)
    }

    fn scan_compressed<F: FnMut(&[u8], &[u8]) -> bool>(&self, p: &V2Params, callback: &mut F) {
        let per = 1u64 << p.block_shift;
        for b in 0..p.n.div_ceil(per) {
            let Ok(blk) = self.v2_block(p, b) else { return };
            let Ok(raw) = Self::decode_block(blk) else { return };
            let count = per.min(p.n - b * per);
            let mut pos = 0usize;
            for _ in 0..count {
                let Some((s, e)) = next_record(&raw, pos) else { return };
                pos = e;
                let rec = &raw[s..e];
                if rec.len() < 2 {
                    return;
                }
                let kl = u16::from_be_bytes([rec[0], rec[1]]) as usize;
                let Some(k) = rec.get(2..2 + kl) else { return };
                if !callback(k, &rec[2 + kl..]) {
                    return;
                }
            }
        }
    }

    fn scan_v2<F: FnMut(&[u8], &[u8]) -> bool>(&self, p: &V2Params, callback: &mut F) {
        if p.compressed {
            return self.scan_compressed(p, callback);
        }
        for i in 0..p.n {
            if let Ok(payload) = self.v2_record(p, i) {
                if payload.len() >= 2 {
                    let key_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                    if let Some(k) = payload.get(2..2 + key_len) {
                        if !callback(k, &payload[2 + key_len..]) {
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl Drop for AttosMap {
    fn drop(&mut self) {
        if self.pinned {
            #[cfg(unix)]
            {
                // SAFETY: pointer/length describe the mapping still owned by
                // `self.mmap` (dropped after this block); munlock does not
                // dereference it.
                unsafe {
                    libc::munlock(self.mmap.as_ptr() as *const libc::c_void, self.mmap.len());
                }
            }
        }
        // `self.mmap` is dropped here, triggering munmap(2).
    }
}

// `AttosMap` is `Send + Sync` automatically: `Mmap` is `Send + Sync` (the
// mapping is read-only) and the telemetry counters are atomics.
#[allow(dead_code)]
fn _assert_send_sync() {
    fn is<T: Send + Sync>() {}
    is::<AttosMap>();
}
