//! Candidate symmetric primitive only, never an envelope authority verifier.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    Shape,
    Authentication,
    Length,
    Nul,
    Bom,
    Utf8,
}
impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Shape => "shape",
            Self::Authentication => "authentication",
            Self::Length => "length",
            Self::Nul => "nul",
            Self::Bom => "bom",
            Self::Utf8 => "utf8",
        })
    }
}
impl std::error::Error for BodyError {}
/// Check plaintext rules only; establishes no authentication or authority.
pub fn decode(bytes: &[u8]) -> Result<&str, BodyError> {
    if bytes.is_empty() || bytes.len() > 32768 {
        return Err(BodyError::Length);
    }
    if bytes.contains(&0) {
        return Err(BodyError::Nul);
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(BodyError::Bom);
    }
    std::str::from_utf8(bytes).map_err(|_| BodyError::Utf8)
}
/// Caller must independently verify envelope authority, signer, routing, expiry
/// and replay, and recover the authorized CEK first. AAD is the exact verified
/// transcript. Authentication completes before decoding or returning plaintext.
/// Caller-owned key bytes are not consumed; returned text is zeroized on drop.
pub fn open(
    key: &[u8],
    nonce: &[u8],
    verified_aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<String>, BodyError> {
    if key.len() != 32
        || nonce.len() != 12
        || verified_aad.is_empty()
        || verified_aad.len() > 36864
        || !(17..=32784).contains(&ciphertext.len())
    {
        return Err(BodyError::Shape);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BodyError::Shape)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| BodyError::Shape)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: verified_aad,
                },
            )
            .map_err(|_| BodyError::Authentication)?,
    );
    Ok(Zeroizing::new(decode(&plaintext)?.to_owned()))
}
