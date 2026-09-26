// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate pure recovery-token/public-card grammar. No I/O, reveal or trust ceremony.
//! A valid transcription checksum is not authentication; verify the backup AEAD and
//! independently compare the full intended identity before using any restored root.

use crate::{
    root_backup::{ExpectedIdentity, RecoverySecret},
    sealed_root_enrollment::{canonical_origin, root_fingerprint},
};
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const TOKEN_LEN: usize = 79;
const CARD_FIXED: usize = 133;
const MAX_CARD: usize = CARD_FIXED + 512;
const CHECKSUM_DOMAIN: &[u8] = b"ZTSE/recovery-kit/v1\0";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KitError {
    #[error("invalid recovery kit context")]
    InvalidContext,
    #[error("recovery token rejected")]
    TokenRejected,
    #[error("public root card rejected")]
    CardRejected,
}

fn validate_pin(pin: &[u8], expected: &ExpectedIdentity) -> Result<(), KitError> {
    if !canonical_origin(&expected.origin)
        || root_fingerprint(pin, &expected.account_id).map_err(|_| KitError::InvalidContext)?
            != expected.root_fingerprint
    {
        return Err(KitError::InvalidContext);
    }
    Ok(())
}

/// Caller-supplied, independently intended identity, not inferred trust from a card/backup.
/// Construction validates syntax and the genesis pin, not an independent comparison.
pub struct KitContext {
    expected: ExpectedIdentity,
    backup_id: [u8; 16],
}

impl KitContext {
    pub fn new(
        expected: ExpectedIdentity,
        root_pin: &[u8],
        backup_id: [u8; 16],
    ) -> Result<Self, KitError> {
        validate_pin(root_pin, &expected)?;
        if backup_id == [0; 16] {
            return Err(KitError::InvalidContext);
        }
        Ok(Self {
            expected,
            backup_id,
        })
    }
}

/// Contains secret recovery material. No Display, Clone, serialization or implicit string conversion.
pub struct RecoveryToken(Zeroizing<[u8; TOKEN_LEN]>);

impl std::fmt::Debug for RecoveryToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryToken([REDACTED])")
    }
}

impl RecoveryToken {
    /// Explicit borrowed exposure for a future reviewed custody layer. Not permission to
    /// reveal, log, persist or copy real secret material. This crate performs no output.
    pub fn expose_ascii(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }
}

fn checksum(secret: &RecoverySecret, context: &KitContext) -> Zeroizing<[u8; 4]> {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(context.expected.account_id);
    hash.update(1_u64.to_be_bytes());
    hash.update(context.backup_id);
    hash.update(context.expected.root_fingerprint);
    hash.update((context.expected.origin.len() as u16).to_be_bytes());
    hash.update(context.expected.origin.as_bytes());
    hash.update(secret.encoding_bytes());
    let digest: Zeroizing<[u8; 32]> = Zeroizing::new(hash.finalize().into());
    let mut result = Zeroizing::new([0; 4]);
    result.copy_from_slice(&digest[..4]);
    result
}

/// Format only; caller is responsible for supplying uniformly random recovery material.
pub fn encode_token(secret: &RecoverySecret, context: &KitContext) -> RecoveryToken {
    let mut base32 = Zeroizing::new([0; 52]);
    BASE32_NOPAD.encode_mut(secret.encoding_bytes(), base32.as_mut());
    let mut token = Zeroizing::new([b'-'; TOKEN_LEN]);
    token[..6].copy_from_slice(b"ZTRK1-");
    for group in 0..13 {
        token[6 + group * 5..10 + group * 5].copy_from_slice(&base32[group * 4..group * 4 + 4]);
    }
    for (index, byte) in checksum(secret, context).iter().enumerate() {
        token[71 + index * 2] = HEX[(byte >> 4) as usize];
        token[72 + index * 2] = HEX[(byte & 15) as usize];
    }
    RecoveryToken(token)
}

/// Strict transcription decoding, not authentication or evidence of entropy/trust.
/// The caller owns the input buffer and must also protect/zeroize it. Internal copies
/// zeroize on success and every error; errors never include input or decoder details.
pub fn decode_token(input: &[u8], context: &KitContext) -> Result<RecoverySecret, KitError> {
    if input.len() != TOKEN_LEN || &input[..6] != b"ZTRK1-" {
        return Err(KitError::TokenRejected);
    }
    let mut base32 = Zeroizing::new([0; 52]);
    for group in 0..13 {
        let start = 6 + group * 5;
        if input[start + 4] != b'-' {
            return Err(KitError::TokenRejected);
        }
        base32[group * 4..group * 4 + 4].copy_from_slice(&input[start..start + 4]);
    }
    let mut decoded = Zeroizing::new([0; 32]);
    if BASE32_NOPAD
        .decode_mut(base32.as_ref(), decoded.as_mut())
        .map_err(|_| KitError::TokenRejected)?
        != 32
    {
        return Err(KitError::TokenRejected);
    }
    let secret = RecoverySecret::new(decoded);
    // Re-encoding pins case, alphabet, unused pad bits, separators and checksum case.
    // This public-input comparison is typo checking only, never an authentication MAC.
    if encode_token(&secret, context).expose_ascii().as_slice() != input {
        return Err(KitError::TokenRejected);
    }
    Ok(secret)
}

/// Validated public syntax matching caller-supplied identity/digest. Not a trust receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicCard {
    origin: String,
    root_pin: [u8; 94],
    encrypted_backup_sha256: [u8; 32],
}

impl PublicCard {
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn root_pin(&self) -> &[u8; 94] {
        &self.root_pin
    }
    pub fn encrypted_backup_sha256(&self) -> &[u8; 32] {
        &self.encrypted_backup_sha256
    }
}

/// Public bytes only. The digest binds one encrypted backup, not its authenticity/freshness.
pub fn encode_public_card(
    root_pin: &[u8],
    expected: &ExpectedIdentity,
    encrypted_backup_sha256: &[u8; 32],
) -> Result<Vec<u8>, KitError> {
    validate_pin(root_pin, expected)?;
    let mut bytes = Vec::with_capacity(CARD_FIXED + expected.origin.len());
    bytes.extend_from_slice(b"ZTRC\x01");
    bytes.extend_from_slice(&(expected.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(expected.origin.as_bytes());
    bytes.extend_from_slice(root_pin);
    bytes.extend_from_slice(encrypted_backup_sha256);
    Ok(bytes)
}

/// Reject aliases/trailing data before returning fields. Expected identity must come
/// from independent intent/comparison, never solely from this card's own metadata.
pub fn decode_public_card(
    bytes: &[u8],
    expected: &ExpectedIdentity,
    encrypted_backup_sha256: &[u8; 32],
) -> Result<PublicCard, KitError> {
    if !(CARD_FIXED + 1..=MAX_CARD).contains(&bytes.len()) || &bytes[..5] != b"ZTRC\x01" {
        return Err(KitError::CardRejected);
    }
    let n = u16::from_be_bytes(bytes[5..7].try_into().unwrap()) as usize;
    if !(1..=512).contains(&n)
        || bytes.len() != CARD_FIXED + n
        || &bytes[7..7 + n] != expected.origin.as_bytes()
    {
        return Err(KitError::CardRejected);
    }
    let root_pin: [u8; 94] = bytes[7 + n..101 + n].try_into().unwrap();
    validate_pin(&root_pin, expected).map_err(|_| KitError::CardRejected)?;
    if &bytes[101 + n..] != encrypted_backup_sha256 {
        return Err(KitError::CardRejected);
    }
    Ok(PublicCard {
        origin: expected.origin.clone(),
        root_pin,
        encrypted_backup_sha256: *encrypted_backup_sha256,
    })
}

#[cfg(test)]
mod tests;
