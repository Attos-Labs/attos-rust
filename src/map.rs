use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::path::Path;
use std::time::Duration;
use twox_hash::XxHash64;
use std::hash::Hasher;
use crc32fast::Hasher as Crc32Hasher;

use tracing::{debug, error, info, instrument, warn};

use crate::error::AttosError;

const MAGIC_ATTO: &[u8; 4] = b"ATTO";

/// Configuration applied when opening a `.attos` / `.nh` binary file.
///
/// All fields are optional; zero/`false`/`None` selects safe production defaults.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenConfig {
    /// Verify the CRC32-IEEE trailer appended by the Go builder.
    /// Enable on startup; disable on the hot path.
    /// Default: `false`.
    pub validate_checksum: bool,

    /// Call `mlock(2)` on the mapped region to prevent OS page-outs.
    /// Recommended for latency-critical deployments.
    /// Default: `false`.
    pub pin_to_memory: bool,

    /// Polling interval for background cloud sync used by `AttosClient::start_sync`.
    /// `None` disables automatic polling (manual `reload` calls only).
    /// Default: `None`.
    pub poll_interval: Option<Duration>,
}

/// A read-only memory-mapped view of a compiled `.attos` binary.
///
/// Lookups are O(1) and zero-allocation. The struct is `Send + Sync`;
/// concurrent reads from multiple threads are safe without locking.
///
/// Memory is unmapped via `Drop`. When held inside an `Arc` (as used by
/// `AttosClient`), the munmap is deferred until the last `Guard` reference
/// from `ArcSwap::load()` is dropped, guaranteeing readers observe coherent
/// data at all times.
#[derive(Debug)]
pub struct AttosMap {
    mmap: Mmap,
    pub version: u32,
    is_32bit: bool,
    pub total_keys: u64,
    num_buckets: u64,
    #[allow(dead_code)]
    global_seed: u64,

    routing_offset: usize,
    values_offset: usize,
    blob_offset: usize,
    pinned: bool,
}

impl AttosMap {
    /// Open with default config (no checksum, no mlock, no polling).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AttosError> {
        Self::open_with_config(path, OpenConfig::default())
    }

    /// Open with explicit configuration.
    ///
    /// Returns a typed `AttosError` on every known failure mode. Callers should
    /// match on the error variant rather than converting to a string.
    #[instrument(skip(path), fields(path = %path.as_ref().display()))]
    pub fn open_with_config<P: AsRef<Path>>(path: P, config: OpenConfig) -> Result<Self, AttosError> {
        debug!("Opening AttosMap file");
        let file = File::open(&path).map_err(AttosError::IoError)?;

        let mmap_opts = MmapOptions::new();
        let mmap = unsafe { mmap_opts.map(&file).map_err(AttosError::IoError)? };

        if mmap.len() < 33 {
            error!("File too small for header: {} bytes", mmap.len());
            return Err(AttosError::CorruptedBinary("file too small for header".into()));
        }

        if &mmap[0..4] != MAGIC_ATTO {
            return Err(AttosError::InvalidMagic);
        }

        let version = u32::from_be_bytes(mmap[4..8].try_into().unwrap());
        if version != 1 {
            return Err(AttosError::InvalidVersion(version));
        }

        let flag = mmap[8];
        let is_32bit = flag == 0x02;
        let total_keys = u64::from_be_bytes(mmap[9..17].try_into().unwrap());
        let num_buckets = u64::from_be_bytes(mmap[17..25].try_into().unwrap());
        let global_seed = u64::from_be_bytes(mmap[25..33].try_into().unwrap());

        let routing_offset = 33;
        let routing_byte_size = if is_32bit {
            (num_buckets * 4) as usize
        } else {
            (num_buckets * 2) as usize
        };

        let values_offset = routing_offset + routing_byte_size;
        let blob_offset = values_offset + (total_keys as usize * 8);

        if mmap.len() < blob_offset {
            return Err(AttosError::CorruptedBinary("file too small for offsets".into()));
        }

        if config.validate_checksum {
            if mmap.len() >= 4 {
                let crc_offset = mmap.len() - 4;
                let mut hasher = Crc32Hasher::new();
                hasher.update(&mmap[..crc_offset]);
                let expected = hasher.finalize();
                let actual = u32::from_be_bytes(mmap[crc_offset..].try_into().unwrap());
                if expected != actual {
                    return Err(AttosError::ChecksumMismatch { expected, actual });
                }
            } else {
                return Err(AttosError::CorruptedBinary("file too small for checksum".into()));
            }
        }

        let mut pinned = false;
        if config.pin_to_memory {
            #[cfg(unix)]
            {
                let ptr = mmap.as_ptr() as *const libc::c_void;
                let len = mmap.len();
                unsafe {
                    if libc::mlock(ptr, len) != 0 {
                        return Err(AttosError::MlockFailed(std::io::Error::last_os_error()));
                    }
                }
                pinned = true;
            }
        }

        // Advise the kernel that access patterns are random (not sequential).
        // This suppresses read-ahead and reduces OS cache pressure.
        #[cfg(unix)]
        {
            let ptr = mmap.as_ptr() as *mut libc::c_void;
            let len = mmap.len();
            unsafe {
                libc::madvise(ptr, len, libc::MADV_RANDOM);
            }
        }

        info!(
            version, is_32bit, total_keys, num_buckets, pinned,
            "Successfully opened AttosMap"
        );

        Ok(Self {
            mmap,
            version,
            is_32bit,
            total_keys,
            num_buckets,
            global_seed,
            routing_offset,
            values_offset,
            blob_offset,
            pinned,
        })
    }

    /// Core MPHF routing: returns (blob_relative_offset, payload_length).
    ///
    /// A length of 0 means the slot is empty (MPHF padding). Callers must
    /// additionally verify key bytes against the blob before accepting a hit.
    #[inline(always)]
    fn find_index(&self, key_hash: u64) -> (usize, usize) {
        if self.num_buckets == 0 || self.total_keys == 0 {
            return (0, 0);
        }

        let high = (key_hash >> 32) as u32;
        let low = (key_hash & 0xFFFFFFFF) as u32;

        let segment_idx = (high as u64) % self.num_buckets;

        let d = if self.is_32bit {
            let disp_off = self.routing_offset + (segment_idx as usize * 4);
            u32::from_be_bytes(self.mmap[disp_off..disp_off + 4].try_into().unwrap())
        } else {
            let disp_off = self.routing_offset + (segment_idx as usize * 2);
            u16::from_be_bytes(self.mmap[disp_off..disp_off + 2].try_into().unwrap()) as u32
        };

        let final_index = ((low as u64) ^ (d as u64)) % self.total_keys;

        let value_off = self.values_offset + (final_index as usize * 8);
        let packed = u64::from_be_bytes(self.mmap[value_off..value_off + 8].try_into().unwrap());

        let offset = (packed >> 32) as usize;
        let length = (packed & 0xFFFFFFFF) as usize;

        (offset, length)
    }

    /// O(1) lookup by raw byte slice key.
    ///
    /// Returns a zero-copy slice into the mmap region. The slice is valid
    /// for the lifetime of this `AttosMap` (or the `Guard` holding it).
    /// Allocation profile: **0 B/op**.
    #[inline(always)]
    pub fn get<'a>(&'a self, key: &[u8]) -> Result<&'a [u8], AttosError> {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(key);
        let key_hash = hasher.finish();

        let (offset, length) = self.find_index(key_hash);

        if length == 0 {
            return Err(AttosError::KeyNotFound);
        }

        let start = self.blob_offset + offset;
        let end = start + length;

        if end > self.mmap.len() || start > end {
            return Err(AttosError::CorruptedBinary("payload index out of bounds".into()));
        }

        let payload = &self.mmap[start..end];

        if payload.len() < 2 {
            return Err(AttosError::CorruptedBinary("payload too small for key length".into()));
        }

        let key_len = u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;

        if payload.len() < 2 + key_len {
            return Err(AttosError::CorruptedBinary("payload too small for key".into()));
        }

        let key_bytes = &payload[2..2 + key_len];
        if key_bytes != key {
            return Err(AttosError::KeyNotFound);
        }

        Ok(&payload[2 + key_len..])
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
    /// `factors` are dimension values sorted alphabetically by column name
    /// (matching the builder's sort order). They are concatenated with a
    /// `\x00` separator into a 1 KiB stack buffer — zero heap allocation.
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
        for i in 0..self.total_keys {
            let value_off = self.values_offset + (i as usize * 8);
            let packed = u64::from_be_bytes(self.mmap[value_off..value_off + 8].try_into().unwrap());

            let offset = (packed >> 32) as usize;
            let length = (packed & 0xFFFFFFFF) as usize;

            if length == 0 {
                continue;
            }

            let start = self.blob_offset + offset;
            let end = start + length;
            if end <= self.mmap.len() && start <= end {
                let payload = &self.mmap[start..end];
                if payload.len() >= 2 {
                    let key_len = u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;
                    if payload.len() >= 2 + key_len {
                        let k = &payload[2..2 + key_len];
                        let v = &payload[2 + key_len..];
                        if !callback(k, v) {
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
                let ptr = self.mmap.as_ptr() as *const libc::c_void;
                let len = self.mmap.len();
                unsafe {
                    libc::munlock(ptr, len);
                }
            }
        }
        // `self.mmap` is dropped here, triggering munmap(2).
    }
}

// AttosMap is safe to share across threads: the mmap is read-only and all
// fields are immutable after construction.
unsafe impl Send for AttosMap {}
unsafe impl Sync for AttosMap {}
