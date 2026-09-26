// SPDX-License-Identifier: AGPL-3.0-only
//! Proposed, dormant generation-one encrypted root backup. No custody or runtime caller.
//! Secrets are caller-supplied zeroizing values, never generated kits or file output.

use crate::sealed_root_enrollment::{canonical_origin, root_fingerprint};
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

const HEADER_FIXED: usize = 80;
const TAIL: usize = 156;
const MAX_FILE: usize = 748;
const WRAP_INFO: &[u8] = b"ZTSE/vault-wrap/v1\0";
const WRAP_AAD: &[u8] = b"ZTSE/vault-key-wrap/v1\0";
const ROOT_AAD: &[u8] = b"ZTSE/root-backup/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    #[error("invalid root backup input")]
    InvalidInput,
    #[error("root backup authentication or identity failed")]
    Rejected,
    #[error("root backup randomness unavailable")]
    Randomness,
    #[error("root backup cryptographic operation failed")]
    Crypto,
}

/// Independently supplied identity; never obtain it solely from a backup header.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub account_id: [u8; 16],
    pub origin: String,
    pub root_fingerprint: [u8; 32],
}
impl ExpectedIdentity {
    fn validate(&self) -> Result<(), BackupError> {
        if self.account_id == [0; 16] || !canonical_origin(&self.origin) {
            return Err(BackupError::InvalidInput);
        }
        Ok(())
    }
}

/// Uniformly random 32-byte recovery material must come from the future custody
/// layer. Width validation cannot establish entropy. This is not a password KDF.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);
impl RecoverySecret {
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Internal explicit borrow for the pure recovery-token encoder; never a reveal operation.
    pub(crate) fn encoding_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySecret([REDACTED])")
    }
}

/// Canonical P-256 scalar. No Clone, serialization, Display or unredacted Debug.
/// The caller is responsible for any deliberate access to its borrowed bytes.
pub struct RootSecret(Zeroizing<[u8; 32]>);
impl RootSecret {
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Result<Self, BackupError> {
        SecretKey::from_slice(bytes.as_slice()).map_err(|_| BackupError::InvalidInput)?;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootSecret([REDACTED])")
    }
}

fn check_root(root: &RootSecret, expected: &ExpectedIdentity) -> Result<(), BackupError> {
    let key = SecretKey::from_slice(root.0.as_slice()).map_err(|_| BackupError::Rejected)?;
    let public = key.public_key().to_sec1_point(false);
    let mut pin = Vec::with_capacity(94);
    pin.extend_from_slice(b"ZTRP\x02");
    pin.extend_from_slice(&expected.account_id);
    pin.extend_from_slice(&1_u64.to_be_bytes());
    // RootPin02 requires an explicitly uncompressed public point.
    pin.extend_from_slice(public.as_bytes());
    let fingerprint =
        root_fingerprint(&pin, &expected.account_id).map_err(|_| BackupError::Rejected)?;
    if fingerprint != expected.root_fingerprint {
        return Err(BackupError::Rejected);
    }
    Ok(())
}

fn header(expected: &ExpectedIdentity, backup_id: &[u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_FIXED + expected.origin.len());
    bytes.extend_from_slice(b"ZTRB\x01\x01");
    bytes.extend_from_slice(backup_id);
    bytes.extend_from_slice(&expected.account_id);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&expected.root_fingerprint);
    bytes.extend_from_slice(&(expected.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(expected.origin.as_bytes());
    bytes
}

fn parse_header(bytes: &[u8], expected: &ExpectedIdentity) -> Result<usize, BackupError> {
    expected.validate()?;
    if !(HEADER_FIXED + TAIL + 1..=MAX_FILE).contains(&bytes.len())
        || &bytes[..6] != b"ZTRB\x01\x01"
        || bytes[6..22] == [0; 16]
        || bytes[22..38] != expected.account_id
        || bytes[38..46] != 1_u64.to_be_bytes()
        || bytes[46..78] != expected.root_fingerprint
    {
        return Err(BackupError::Rejected);
    }
    let length = u16::from_be_bytes(bytes[78..80].try_into().unwrap()) as usize;
    if !(1..=512).contains(&length)
        || bytes.len() != HEADER_FIXED + length + TAIL
        || &bytes[80..80 + length] != expected.origin.as_bytes()
    {
        return Err(BackupError::Rejected);
    }
    let h = HEADER_FIXED + length;
    if bytes[h + 104..h + 108] != 48_u32.to_be_bytes() {
        return Err(BackupError::Rejected);
    }
    Ok(h)
}

fn wrapping_key(
    recovery: &RecoverySecret,
    salt: &[u8],
    expected: &ExpectedIdentity,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let info = [WRAP_INFO, &expected.account_id, &1_u64.to_be_bytes()].concat();
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), recovery.0.as_slice())
        .expand(&info, key.as_mut())
        .map_err(|_| BackupError::Crypto)?;
    Ok(key)
}

fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    secret: &[u8; 32],
) -> Result<Vec<u8>, BackupError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BackupError::Crypto)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| BackupError::Crypto)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(48));
    buffer.extend_from_slice(secret);
    cipher
        .encrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| BackupError::Crypto)?;
    Ok(buffer.to_vec()) // only fully authenticated ciphertext leaves this scope
}

fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    encrypted: &[u8],
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BackupError::Rejected)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| BackupError::Rejected)?;
    let mut buffer = Zeroizing::new(encrypted.to_vec());
    cipher
        .decrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| BackupError::Rejected)?;
    if buffer.len() != 32 {
        return Err(BackupError::Rejected);
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&buffer);
    Ok(secret)
}

/// Seal a new immutable backup with fresh system randomness. Never updates an
/// existing backup. RNG failure returns no partial ciphertext or secret values.
pub fn seal(
    root: &RootSecret,
    recovery: &RecoverySecret,
    expected: &ExpectedIdentity,
) -> Result<Vec<u8>, BackupError> {
    seal_with_rng(root, recovery, expected, &mut SysRng)
}

fn seal_with_rng<R: TryCryptoRng>(
    root: &RootSecret,
    recovery: &RecoverySecret,
    expected: &ExpectedIdentity,
    rng: &mut R,
) -> Result<Vec<u8>, BackupError> {
    expected.validate()?;
    check_root(root, expected)?;
    let mut backup_id = [0; 16];
    let mut vault_key = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut backup_id)
        .map_err(|_| BackupError::Randomness)?;
    rng.try_fill_bytes(vault_key.as_mut_slice())
        .map_err(|_| BackupError::Randomness)?;
    let salt = <[u8; 32]>::try_generate_from_rng(rng).map_err(|_| BackupError::Randomness)?;
    let wrap_nonce = <[u8; 12]>::try_generate_from_rng(rng).map_err(|_| BackupError::Randomness)?;
    let body_nonce = <[u8; 12]>::try_generate_from_rng(rng).map_err(|_| BackupError::Randomness)?;
    if backup_id == [0; 16] {
        return Err(BackupError::Randomness);
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
        &[ROOT_AAD, &bytes].concat(),
        root.as_bytes(),
    )?;
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

/// Open only after both tags and the explicit expected identity match. Does not
/// establish freshness, server registration, recovery policy or client trust.
pub fn open(
    bytes: &[u8],
    recovery: &RecoverySecret,
    expected: &ExpectedIdentity,
) -> Result<RootSecret, BackupError> {
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
        &[ROOT_AAD, &bytes[..h + 108]].concat(),
        &bytes[h + 108..],
    )?;
    let root = RootSecret::new(scalar).map_err(|_| BackupError::Rejected)?;
    check_root(&root, expected)?;
    Ok(root)
}

#[cfg(test)]
mod tests;
