//! Candidate ZTSE body text rules, applied only after authentication.
//! This module does not authenticate envelopes or authorize any action.
pub const MAX_BODY_TEXT_BYTES: usize = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyTextError {
    Length,
    Nul,
    Bom,
    Utf8,
}
impl std::fmt::Display for BodyTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "length",
            Self::Nul => "nul",
            Self::Bom => "bom",
            Self::Utf8 => "utf8",
        })
    }
}
impl std::error::Error for BodyTextError {}

/// Borrow strict UTF-8 without normalization or BOM stripping.
/// Accepts 1..=32768 bytes, with no NUL and no leading UTF-8 BOM.
/// The caller must authenticate ciphertext and enforce trust/context first.
pub fn validate(bytes: &[u8]) -> Result<&str, BodyTextError> {
    if bytes.is_empty() || bytes.len() > MAX_BODY_TEXT_BYTES {
        return Err(BodyTextError::Length);
    }
    if bytes.contains(&0) {
        return Err(BodyTextError::Nul);
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(BodyTextError::Bom);
    }
    std::str::from_utf8(bytes).map_err(|_| BodyTextError::Utf8)
}
