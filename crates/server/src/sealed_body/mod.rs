// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant sealed body receiver rules; no transport calls this module.
//!
//! The ZT-009 Q9 decision accepts strict UTF-8 body text of 1..=32,768 bytes
//! with no BOM, no NUL and no Unicode normalization. Envelope parsing and
//! signature verification only ever see ciphertext, so these rules bind at the
//! moment a receiver holds authenticated body plaintext. [`validate_body_text`]
//! is that rule for any receiver of body text, plain or sealed; [`open`] is
//! the sealed receiver step: it decrypts the AES-256-GCM body under the exact
//! received envelope transcript and only then applies the text rules, failing
//! closed with stable errors. The 32-byte CEK is used as the AES-GCM body key,
//! exactly like the TypeScript and Android receivers; the HPKE wrap's own
//! AES-128-GCM AEAD is a different key schedule. CEK, key schedule and
//! plaintext buffer are cleared on every path. Nothing here authorizes
//! admission, persistence, webhooks or radio effects, and no production route
//! may call it yet.

use crate::sealed_envelope::{Profile, SignatureVerifiedEnvelope};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use zeroize::Zeroizing;

/// Q9 body-text bound: at least one and at most 32,768 plaintext bytes.
pub const MAX_BODY_TEXT_BYTES: usize = 32_768;

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum BodyTextError {
    #[error("body text length outside 1..=32768 bytes")]
    Length,
    #[error("body text contains a NUL byte")]
    Nul,
    #[error("body text starts with a UTF-8 BOM")]
    Bom,
    #[error("body text is not strict UTF-8")]
    Utf8,
}

/// The Q9 receive rule for authenticated body plaintext. Strict UTF-8 only:
/// no normalization, no BOM stripping, no NUL byte, 1..=32,768 bytes. The
/// returned borrow keeps the exact received bytes; callers must not reserialize.
pub fn validate_body_text(bytes: &[u8]) -> Result<&str, BodyTextError> {
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

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum BodyOpenError {
    #[error("sealed body authentication failed")]
    Authentication,
    #[error(transparent)]
    Text(#[from] BodyTextError),
}

/// Open the body of an envelope whose signature and context already verified,
/// then apply the Q9 text rules. The AAD is rebuilt from the exact received
/// `unsigned` header and protected bytes, never a reserialization, using the
/// profile's `ZTSE/body/v1|v2\0` label. `std::str::from_utf8` is strict and
/// would decode a leading BOM as U+FEFF, so the BOM is rejected by the explicit
/// byte check exactly like the TypeScript and Android receivers. The CEK is
/// consumed and cleared on every path; the caller must not retain another
/// copy. The returned text is cleared on drop.
pub fn open(
    verified: &SignatureVerifiedEnvelope<'_>,
    cek: [u8; 32],
) -> Result<Zeroizing<String>, BodyOpenError> {
    let envelope = verified.envelope();
    let label = match envelope.profile {
        Profile::Draft01Proof => b"ZTSE/body/v1\0".as_slice(),
        Profile::Draft02Candidate => b"ZTSE/body/v2\0".as_slice(),
    };
    let aad = [label, &envelope.unsigned[..10], envelope.protected].concat();
    let nonce = Nonce::try_from(envelope.nonce).map_err(|_| BodyOpenError::Authentication)?;
    let cek = Zeroizing::new(cek);
    // The key schedule is zeroized on drop through the crate's zeroize feature.
    let cipher = Aes256Gcm::new_from_slice(&cek[..]).map_err(|_| BodyOpenError::Authentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: envelope.body_ct,
                    aad: &aad,
                },
            )
            .map_err(|_| BodyOpenError::Authentication)?,
    );
    let text = validate_body_text(&plaintext)?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests;
