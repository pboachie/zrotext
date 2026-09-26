// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant bounded console transport. No CLI, recovery codec, reveal or network.

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported console session")]
    Unsupported,
    #[error("console input is already in use or queued")]
    Busy,
    #[error("console input rejected")]
    Rejected,
    #[error("console input cancelled")]
    Cancelled,
    #[error("console input timed out")]
    TimedOut,
    #[error("console operation failed")]
    Io,
    #[error("console cleanup failed; input was discarded")]
    RestorationFailed,
    #[error("console adapter unavailable after cleanup failure")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Exact printable ASCII input. No implicit formatting, cloning or serialization.
pub struct SensitiveLine {
    bytes: Zeroizing<[u8; 128]>,
    length: usize,
}
impl SensitiveLine {
    pub fn expose_ascii(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
impl std::fmt::Debug for SensitiveLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SensitiveLine([REDACTED])")
    }
}

#[cfg(any(windows, test))]
mod input;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Session;
