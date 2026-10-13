//! Verify exact raw webhook bodies before parsing or acting on them.
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Default symmetric replay window, in seconds.
pub const TOLERANCE_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    BadTimestamp,
    TimestampOutOfWindow,
    BadSignatureFormat,
    SignatureMismatch,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "webhook verification failed: {self:?}")
    }
}
impl std::error::Error for VerificationError {}

/// Verify with an explicit clock and tolerance. Event-ID deduplication remains
/// the receiver's responsibility. The key is the decoded signing secret.
pub fn verify(
    key: &[u8],
    timestamp: &str,
    signature: &str,
    body: &[u8],
    now_seconds: u64,
    tolerance_seconds: u64,
) -> Result<(), VerificationError> {
    if timestamp.is_empty()
        || timestamp.len() > 16
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
        || (timestamp.len() > 1 && timestamp.starts_with('0'))
    {
        return Err(VerificationError::BadTimestamp);
    }
    let seconds = timestamp
        .parse::<u64>()
        .map_err(|_| VerificationError::BadTimestamp)?;
    if now_seconds.abs_diff(seconds) > tolerance_seconds {
        return Err(VerificationError::TimestampOutOfWindow);
    }
    let hex = signature
        .strip_prefix("v1=")
        .ok_or(VerificationError::BadSignatureFormat)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(VerificationError::BadSignatureFormat);
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| VerificationError::BadSignatureFormat)?;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&digest)
        .map_err(|_| VerificationError::SignatureMismatch)
}
