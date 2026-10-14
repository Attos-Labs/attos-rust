use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AttosError {
    KeyNotFound,
    CorruptedBinary(String),
    InvalidMagic,
    InvalidVersion(u32),
    ChecksumMismatch { expected: u32, actual: u32 },
    MapClosed,
    MlockFailed(io::Error),
    IoError(io::Error),
    Utf8Error(std::str::Utf8Error),
}

impl fmt::Display for AttosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttosError::KeyNotFound => write!(f, "key not found"),
            AttosError::CorruptedBinary(msg) => write!(f, "corrupted binary: {}", msg),
            AttosError::InvalidMagic => write!(f, "invalid magic bytes"),
            AttosError::InvalidVersion(v) => write!(f, "invalid version: {}", v),
            AttosError::ChecksumMismatch { expected, actual } => {
                write!(f, "checksum mismatch: expected {}, got {}", expected, actual)
            }
            AttosError::MapClosed => write!(f, "map closed"),
            AttosError::MlockFailed(e) => write!(f, "mlock failed: {}", e),
            AttosError::IoError(e) => write!(f, "io error: {}", e),
            AttosError::Utf8Error(e) => write!(f, "utf-8 error: {}", e),
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
