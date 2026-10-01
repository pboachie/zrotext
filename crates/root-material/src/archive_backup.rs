// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant archive-only backup of an EXISTING scalar. No key generation, rotation or I/O.
//! Secrets are caller-supplied zeroizing values, never generated kits or file output.
//! ZTAB01: H(177+N) = magic/version/suite, backupID16, account16, rootGeneration8,
//! rootFingerprint32, archiveID32, actualPoint65, originLength2, originN (canonical HTTPS).
//! Tail156 = salt32, wrapNonce12, wrappedVault48, bodyNonce12, bodyLength4(48), body48.
//! Recovery material MUST be separate from root recovery; no password KDF or root-token conversion.
//! Identity is independently supplied by authorized existing custody; header fields never confer trust.
//! Browser unlock transiently exposes the archive scalar; its final key is memory-only nonextractable.
//! This is account-wide archive decryption, never a new line-scoped key or history reconstruction.

use crate::sealed_root_enrollment::canonical_origin;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInOut, KeyInit},
};
use hkdf::Hkdf;
use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::{TryCryptoRng, rngs::SysRng};
use sha2::Sha256;
use zeroize::Zeroizing;

const HEADER_FIXED: usize = 177;
const TAIL: usize = 156;
const MAX_FILE: usize = 845;
const WRAP_INFO: &[u8] = b"ZTSE/archive-vault-wrap/v1\0";
const WRAP_AAD: &[u8] = b"ZTSE/archive-vault-key-wrap/v1\0";
const ARCHIVE_AAD: &[u8] = b"ZTSE/archive-backup/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveBackupError {
    #[error("invalid archive backup input")]
    InvalidInput,
    #[error("archive backup authentication or identity failed")]
    Rejected,
    #[error("archive backup randomness unavailable")]
    Randomness,
    #[error("archive backup cryptographic operation failed")]
    Crypto,
}

/// Independently supplied identity; never obtain it solely from a backup header.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub account_id: [u8; 16],
    pub origin: String,
    pub root_fingerprint: [u8; 32],
    pub generation: u64,
    pub archive_id: [u8; 32],
    pub archive_point: [u8; 65],
}
impl ArchiveIdentity {
    fn validate(&self) -> Result<(), ArchiveBackupError> {
        if self.account_id == [0; 16]
            || !canonical_origin(&self.origin)
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.root_fingerprint == [0; 32]
            || self.archive_id == [0; 32]
            || self.archive_point[0] != 4
        {
            return Err(ArchiveBackupError::InvalidInput);
        }
        Ok(())
    }
}

/// Uniformly random 32-byte recovery material must come from the future custody
/// layer. Width validation cannot establish entropy. This is not a password KDF.
pub struct ArchiveRecoverySecret(Zeroizing<[u8; 32]>);
impl ArchiveRecoverySecret {
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}
impl std::fmt::Debug for ArchiveRecoverySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveRecoverySecret([REDACTED])")
    }
}

/// Existing canonical archive P-256 scalar. No Clone, serialization, Display or unredacted Debug.
/// The caller is responsible for any deliberate access to its borrowed bytes.
pub struct ArchiveSecret(Zeroizing<[u8; 32]>);
impl ArchiveSecret {
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Result<Self, ArchiveBackupError> {
        SecretKey::from_slice(bytes.as_slice()).map_err(|_| ArchiveBackupError::InvalidInput)?;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for ArchiveSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveSecret([REDACTED])")
    }
}

fn check_archive(
    secret: &ArchiveSecret,
    expected: &ArchiveIdentity,
) -> Result<(), ArchiveBackupError> {
    let key = SecretKey::from_slice(secret.as_bytes()).map_err(|_| ArchiveBackupError::Rejected)?;
    let point = key.public_key().to_sec1_point(false);
    let id: [u8; 32] = <Sha256 as sha2::Digest>::digest(
        [b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat(),
    )
    .into();
    if point.as_bytes() != expected.archive_point || id != expected.archive_id {
        return Err(ArchiveBackupError::Rejected);
    }
    Ok(())
}

fn header(expected: &ArchiveIdentity, backup_id: &[u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_FIXED + expected.origin.len());
    bytes.extend_from_slice(b"ZTAB\x01\x01");
    bytes.extend_from_slice(backup_id);
    bytes.extend_from_slice(&expected.account_id);
    bytes.extend_from_slice(&expected.generation.to_be_bytes());
    bytes.extend_from_slice(&expected.root_fingerprint);
    bytes.extend_from_slice(&expected.archive_id);
    bytes.extend_from_slice(&expected.archive_point);
    bytes.extend_from_slice(&(expected.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(expected.origin.as_bytes());
    bytes
}

fn parse_header(bytes: &[u8], expected: &ArchiveIdentity) -> Result<usize, ArchiveBackupError> {
    expected.validate()?;
    if !(HEADER_FIXED + TAIL + 1..=MAX_FILE).contains(&bytes.len())
        || &bytes[..6] != b"ZTAB\x01\x01"
        || bytes[6..22] == [0; 16]
        || bytes[22..38] != expected.account_id
        || bytes[38..46] != expected.generation.to_be_bytes()
        || bytes[46..78] != expected.root_fingerprint
        || bytes[78..110] != expected.archive_id
        || bytes[110..175] != expected.archive_point
    {
        return Err(ArchiveBackupError::Rejected);
    }
    let length = u16::from_be_bytes(bytes[175..177].try_into().unwrap()) as usize;
    if !(1..=512).contains(&length)
        || bytes.len() != HEADER_FIXED + length + TAIL
        || &bytes[177..177 + length] != expected.origin.as_bytes()
    {
        return Err(ArchiveBackupError::Rejected);
    }
    let h = HEADER_FIXED + length;
    if bytes[h + 104..h + 108] != 48_u32.to_be_bytes() {
        return Err(ArchiveBackupError::Rejected);
    }
    Ok(h)
}

/// Check bounded public framing and identity, returning the public backup ID.
/// This does not authenticate ciphertext or establish that an archive scalar can be restored.
/// Call `open` with independently supplied recovery material for authentication.
pub fn validate_public_header(
    bytes: &[u8],
    expected: &ArchiveIdentity,
) -> Result<[u8; 16], ArchiveBackupError> {
    parse_header(bytes, expected)?;
    Ok(bytes[6..22].try_into().unwrap())
}

fn wrapping_key(
    recovery: &ArchiveRecoverySecret,
    salt: &[u8],
    expected: &ArchiveIdentity,
) -> Result<Zeroizing<[u8; 32]>, ArchiveBackupError> {
    let info = [
        WRAP_INFO,
        &expected.account_id,
        &expected.generation.to_be_bytes(),
        &expected.archive_id,
    ]
    .concat();
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), recovery.0.as_slice())
        .expand(&info, key.as_mut())
        .map_err(|_| ArchiveBackupError::Crypto)?;
    Ok(key)
}

fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    secret: &[u8; 32],
) -> Result<Vec<u8>, ArchiveBackupError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ArchiveBackupError::Crypto)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| ArchiveBackupError::Crypto)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(48));
    buffer.extend_from_slice(secret);
    cipher
        .encrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| ArchiveBackupError::Crypto)?;
    Ok(buffer.to_vec()) // only fully authenticated ciphertext leaves this scope
}

fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ArchiveBackupError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ArchiveBackupError::Rejected)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| ArchiveBackupError::Rejected)?;
    let mut buffer = Zeroizing::new(encrypted.to_vec());
    cipher
        .decrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| ArchiveBackupError::Rejected)?;
    if buffer.len() != 32 {
        return Err(ArchiveBackupError::Rejected);
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&buffer);
    Ok(secret)
}

/// Seal only caller-owned EXISTING archive material with fresh encryption randomness. Never updates an
/// existing backup. RNG failure returns no partial ciphertext or secret values.
pub fn seal(
    archive: &ArchiveSecret,
    recovery: &ArchiveRecoverySecret,
    expected: &ArchiveIdentity,
) -> Result<Vec<u8>, ArchiveBackupError> {
    seal_with_rng(archive, recovery, expected, &mut SysRng)
}

fn seal_with_rng<R: TryCryptoRng>(
    archive: &ArchiveSecret,
    recovery: &ArchiveRecoverySecret,
    expected: &ArchiveIdentity,
    rng: &mut R,
) -> Result<Vec<u8>, ArchiveBackupError> {
    expected.validate()?;
    check_archive(archive, expected)?;
    let mut backup_id = [0; 16];
    let mut vault_key = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut backup_id)
        .map_err(|_| ArchiveBackupError::Randomness)?;
    rng.try_fill_bytes(vault_key.as_mut_slice())
        .map_err(|_| ArchiveBackupError::Randomness)?;
    let salt =
        <[u8; 32]>::try_generate_from_rng(rng).map_err(|_| ArchiveBackupError::Randomness)?;
    let wrap_nonce =
        <[u8; 12]>::try_generate_from_rng(rng).map_err(|_| ArchiveBackupError::Randomness)?;
    let body_nonce =
        <[u8; 12]>::try_generate_from_rng(rng).map_err(|_| ArchiveBackupError::Randomness)?;
    if backup_id == [0; 16] {
        return Err(ArchiveBackupError::Randomness);
    }
    let mut bytes = header(expected, &backup_id);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&wrap_nonce);
    let key = wrapping_key(recovery, &salt, expected)?;
    let wrapped = encrypt(
        key.as_slice(),
        &wrap_nonce,
        &[WRAP_AAD, &bytes].concat(),
        &vault_key,
    )?;
    bytes.extend_from_slice(&wrapped);
    bytes.extend_from_slice(&body_nonce);
    bytes.extend_from_slice(&48_u32.to_be_bytes());
    let ciphertext = encrypt(
        vault_key.as_slice(),
        &body_nonce,
        &[ARCHIVE_AAD, &bytes].concat(),
        archive.as_bytes(),
    )?;
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

/// Open only after both tags and the explicit expected identity match. Does not
/// establish freshness, server registration, recovery policy or client trust.
pub fn open(
    bytes: &[u8],
    recovery: &ArchiveRecoverySecret,
    expected: &ArchiveIdentity,
) -> Result<ArchiveSecret, ArchiveBackupError> {
    let h = parse_header(bytes, expected)?;
    let key = wrapping_key(recovery, &bytes[h..h + 32], expected)?;
    let vault_key = decrypt(
        key.as_slice(),
        &bytes[h + 32..h + 44],
        &[WRAP_AAD, &bytes[..h + 44]].concat(),
        &bytes[h + 44..h + 92],
    )?;
    let scalar = decrypt(
        vault_key.as_slice(),
        &bytes[h + 92..h + 104],
        &[ARCHIVE_AAD, &bytes[..h + 108]].concat(),
        &bytes[h + 108..],
    )?;
    let archive = ArchiveSecret::new(scalar).map_err(|_| ArchiveBackupError::Rejected)?;
    check_archive(&archive, expected)?;
    Ok(archive)
}

#[cfg(test)]
#[path = "archive_backup/tests.rs"]
mod tests;
