// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded creation snapshot from caller-owned, separately generated material.
//! Reuses ZTAB01 only. No generation, file I/O, root signing or enrollment.
use super::*;
use crate::{root_backup::ExpectedIdentity, sealed_root_enrollment::root_fingerprint};
use sha2::Digest;

pub const MAX_RECEIPT: usize = 1536;
/// Verified public archive and a separate private recovery secret. No Clone,
/// Debug, serialization or implicit secret formatting. Scalar is dropped after
/// authenticated recovery testing, before this object reaches a storage caller.
pub struct PreparedArchive {
    encrypted: Vec<u8>,
    identity: ArchiveIdentity,
    backup_id: [u8; 16],
    recovery: ArchiveRecoverySecret,
}

pub fn prepare(
    archive: ArchiveSecret,
    recovery: ArchiveRecoverySecret,
    expected_root: &ExpectedIdentity,
    root_pin: &[u8],
) -> Result<PreparedArchive, ArchiveBackupError> {
    if expected_root.origin.len() > 512
        || !canonical_origin(&expected_root.origin)
        || root_fingerprint(root_pin, &expected_root.account_id)
            .map_err(|_| ArchiveBackupError::Rejected)?
            != expected_root.root_fingerprint
    {
        return Err(ArchiveBackupError::Rejected);
    }
    let key =
        SecretKey::from_slice(archive.as_bytes()).map_err(|_| ArchiveBackupError::Rejected)?;
    let point = key.public_key().to_sec1_point(false);
    let archive_point: [u8; 65] = point
        .as_bytes()
        .try_into()
        .map_err(|_| ArchiveBackupError::Rejected)?;
    drop(key);
    if archive_point.as_slice() == &root_pin[29..] || *recovery.0 == [0; 32] {
        return Err(ArchiveBackupError::Rejected);
    }
    let archive_id =
        Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &archive_point].concat()).into();
    let identity = ArchiveIdentity {
        account_id: expected_root.account_id,
        origin: expected_root.origin.clone(),
        root_fingerprint: expected_root.root_fingerprint,
        generation: 1,
        archive_id,
        archive_point,
    };
    let encrypted = seal(&archive, &recovery, &identity)?;
    let backup_id = validate_public_header(&encrypted, &identity)?;
    let restored = open(&encrypted, &recovery, &identity)?;
    if restored.as_bytes() != archive.as_bytes() {
        return Err(ArchiveBackupError::Rejected);
    }
    drop(restored);
    drop(archive);
    Ok(PreparedArchive {
        encrypted,
        identity,
        backup_id,
        recovery,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl PreparedArchive {
    pub fn encrypted_backup(&self) -> &[u8] {
        &self.encrypted
    }
    pub fn identity(&self) -> &ArchiveIdentity {
        &self.identity
    }
    pub fn backup_id(&self) -> &[u8; 16] {
        &self.backup_id
    }
    /// Explicit borrowed exposure only for the reviewed private-file publication
    /// boundary. This is NOT public display/logging permission or a root token.
    pub fn recovery_bytes(&self) -> &[u8; 32] {
        &self.recovery.0
    }
    /// Human-readable public receipt. Preserve and independently compare its
    /// archive ID/point; the receipt itself grants no server authority.
    pub fn public_receipt(&self) -> Vec<u8> {
        format!("ZROtext archive receipt v1\nAccount hex: {}\nOrigin: {}\nRoot generation: 1\nRoot fingerprint: {}\nArchive key ID: {}\nArchive point SEC1: {}\nArchive backup ID: {}\nEncrypted archive SHA256: {}\n",
            hex(&self.identity.account_id),self.identity.origin,hex(&self.identity.root_fingerprint),hex(&self.identity.archive_id),hex(&self.identity.archive_point),hex(&self.backup_id),hex(&Sha256::digest(&self.encrypted))).into_bytes()
    }
    /// Authenticate the exact stored ciphertext against a separately read-back
    /// recovery file before confirming publication. Never infer restore success
    /// from public header/receipt checks alone.
    pub fn verify_recovery(
        &self,
        encrypted: &[u8],
        recovery: ArchiveRecoverySecret,
    ) -> Result<(), ArchiveBackupError> {
        if encrypted != self.encrypted {
            return Err(ArchiveBackupError::Rejected);
        }
        let restored = open(encrypted, &recovery, &self.identity)?;
        drop(restored);
        Ok(())
    }
}

#[cfg(test)]
#[path = "archive_init/tests.rs"]
mod tests;
