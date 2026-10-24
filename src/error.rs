use std::fmt;
use std::io;
use std::time::Duration;

#[derive(Debug)]
pub enum AttosError {
    KeyNotFound,
    CorruptedBinary(String),
    InvalidMagic,
    InvalidVersion(u32),
    /// The file is intact (CRC verifies) but uses a format feature newer than this SDK; upgrade the SDK.
    UnsupportedFeature(String),
    ChecksumMismatch { expected: u32, actual: u32 },
    MapClosed,
    /// The file stores compressed blocks; use `get_cow` / `get_owned` instead of the zero-copy API.
    CompressedRequiresOwned,
    MlockFailed(io::Error),
    IoError(io::Error),
    Utf8Error(std::str::Utf8Error),
    /// Sync endpoint answered with a non-200/304 status. `retry_after` is set
    /// for 402/429 when the server sent `Retry-After`.
    HttpStatus { code: u16, retry_after: Option<Duration> },
    /// Network/transport failure or a body shorter than `Content-Length`.
    Transport(String),
    /// Configuration error (e.g. invalid node id).
    Config(String),
}

impl AttosError {
    /// 402 / 429: node or quota limit.
    pub fn is_quota(&self) -> bool {
        matches!(self, AttosError::HttpStatus { code: 402 | 429, .. })
    }
}

impl fmt::Display for AttosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttosError::KeyNotFound => write!(f, "key not found"),
            AttosError::CorruptedBinary(msg) => write!(f, "corrupted binary: {}", msg),
            AttosError::InvalidMagic => write!(f, "invalid magic bytes"),
            AttosError::InvalidVersion(v) => write!(
                f,
                "invalid version: unsupported format version {} (attos-client {} reads versions 1-2); upgrade the Attos SDK",
                v,
                crate::VERSION
            ),
            AttosError::UnsupportedFeature(feat) => write!(
                f,
                "unsupported format feature: {} (attos-client {} does not support it); upgrade the Attos SDK",
                feat,
                crate::VERSION
            ),
            AttosError::ChecksumMismatch { expected, actual } => {
                write!(f, "checksum mismatch: trailer {:#010x}, computed {:#010x}", expected, actual)
            }
            AttosError::MapClosed => write!(f, "map closed"),
            AttosError::CompressedRequiresOwned => {
                write!(f, "file uses compressed blocks: use get_cow/get_owned")
            }
            AttosError::MlockFailed(e) => write!(f, "mlock failed: {}", e),
            AttosError::IoError(e) => write!(f, "io error: {}", e),
            AttosError::Utf8Error(e) => write!(f, "utf-8 error: {}", e),
            AttosError::HttpStatus { code, retry_after } => match retry_after {
                Some(d) => write!(f, "sync: HTTP {} (retry after {:?})", code, d),
                None => write!(f, "sync: HTTP {}", code),
            },
            AttosError::Transport(e) => write!(f, "sync transport error: {}", e),
            AttosError::Config(e) => write!(f, "configuration error: {}", e),
        }
    }
}

impl std::error::Error for AttosError {}

impl From<io::Error> for AttosError {
    fn from(e: io::Error) -> Self {
        AttosError::IoError(e)
    }
}

impl From<std::str::Utf8Error> for AttosError {
    fn from(e: std::str::Utf8Error) -> Self {
        AttosError::Utf8Error(e)
    }
}
