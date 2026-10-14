use memmap2::{Mmap, MmapOptions};
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
        let layout = parse_layout(&mmap, check_crc)?;

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
            version: 1,
            is_32bit: layout.is_32bit,
            total_keys: layout.slots,
            num_buckets: layout.buckets,
            routing_offset: layout.routing_offset,
            values_offset: layout.values_offset,
            blob_offset: layout.blob_offset,
            data_end: layout.data_end,
            pinned,
            closed: false,
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
