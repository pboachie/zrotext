// SPDX-License-Identifier: AGPL-3.0-only
//! Closed account-only first-manifest signing; available only with `unlock`.
//! Independent public expectations are mandatory. This leaf does not establish
//! archive custody, authenticated time, server admission or restore protection.
use crate::{
    archive_backup::ArchiveIdentity,
    root_backup::{ExpectedIdentity, RootSecret},
    sealed_root_enrollment::{canonical_origin, root_fingerprint},
};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use sha2::{Digest, Sha256};

pub const UNSIGNED_LEN: usize = 449;
pub const SIGNED_LEN: usize = 513;
const MAX_INTERVAL_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("account genesis review or signing refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Supply these from independent owner review, never from the proposed bytes.
/// A structural archive identity alone proves neither custody nor enrollment.
#[derive(Clone)]
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub root_pin: [u8; 94],
    pub archive: ArchiveIdentity,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

/// Private immutable public review, consumed once by signing. No secret, Clone,
/// Debug, arbitrary-byte constructor or accepted-authority conversion is exposed.
pub struct ReviewedGenesis {
    unsigned: [u8; UNSIGNED_LEN],
    root_point: [u8; 65],
    issued_ms: u64,
    expires_ms: u64,
    inspected_ms: u64,
}

fn current(issued: u64, expires: u64, now: u64) -> Result<()> {
    if issued == 0
        || expires > i64::MAX as u64
        || expires <= issued
        || expires - issued > MAX_INTERVAL_MS
        || now < issued
        || now >= expires
    {
        return Err(Error);
    }
    Ok(())
}

fn key_id(algorithm: [u8; 2], point: &[u8; 65]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ZTSE/key/v1\0");
    hash.update(algorithm);
    hash.update(point);
    hash.finalize().into()
}

fn reconstruct(e: &Expected, root_point: &[u8; 65]) -> Result<[u8; UNSIGNED_LEN]> {
    let mut bytes = Vec::with_capacity(UNSIGNED_LEN);
    bytes.extend_from_slice(b"ZTMA\x02");
    bytes.extend_from_slice(&e.identity.account_id);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&e.issued_ms.to_be_bytes());
    bytes.extend_from_slice(&e.expires_ms.to_be_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(root_point);
    bytes.push(2);
    for (role, algorithm, scope, point) in [
        (2, [0, 16], 12u16, &e.archive.archive_point),
        (6, [1, 1], 0u16, root_point),
    ] {
        bytes.push(role);
        bytes.extend_from_slice(&key_id(algorithm, point));
        bytes.extend_from_slice(point);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&scope.to_be_bytes());
        bytes.extend_from_slice(&e.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&e.expires_ms.to_be_bytes());
        bytes.push(1);
    }
    // The fixed header and the two fixed records have no caller-selected width.
    bytes.try_into().map_err(|_| Error)
}

/// Compare the entire existing unsigned first-manifest transcript. `now_ms`
/// must be genuinely fresh trusted caller input; this function authenticates no
/// clock or source. No proposal framing or new protocol is introduced.
pub fn inspect(unsigned: &[u8], e: &Expected, now_ms: u64) -> Result<ReviewedGenesis> {
    if unsigned.len() != UNSIGNED_LEN {
        return Err(Error);
    }
    current(e.issued_ms, e.expires_ms, now_ms)?;
    let identity = &e.identity;
    let archive = &e.archive;
    if identity.account_id == [0; 16]
        || identity.root_fingerprint == [0; 32]
        || identity.origin.len() > 512
        || !canonical_origin(&identity.origin)
        || root_fingerprint(&e.root_pin, &identity.account_id).map_err(|_| Error)?
            != identity.root_fingerprint
        || archive.account_id != identity.account_id
        || archive.origin != identity.origin
        || archive.root_fingerprint != identity.root_fingerprint
        || archive.generation != 1
        || archive.archive_id != key_id([0, 16], &archive.archive_point)
    {
        return Err(Error);
    }
    let root_point: [u8; 65] = e.root_pin[29..].try_into().map_err(|_| Error)?;
    if archive.archive_point == root_point {
        return Err(Error);
    }
    for point in [&root_point, &archive.archive_point] {
        if point[0] != 4 {
            return Err(Error);
        }
        VerifyingKey::from_sec1_bytes(point).map_err(|_| Error)?;
    }
    let expected = reconstruct(e, &root_point)?;
    if unsigned != expected {
        return Err(Error);
    }
    Ok(ReviewedGenesis {
        unsigned: expected,
        root_point,
        issued_ms: e.issued_ms,
        expires_ms: e.expires_ms,
        inspected_ms: now_ms,
    })
}

impl ReviewedGenesis {
    /// Consume the reviewed transcript after genuine root recovery. The caller
    /// supplies fresh final time after secret entry; regression from inspection
    /// is refused. Internal P-256 key copies are scoped and zeroized on drop;
    /// no additional scalar-return or caller-visible secret clone API is added.
    pub fn sign(self, root: &RootSecret, now_ms: u64) -> Result<[u8; SIGNED_LEN]> {
        current(self.issued_ms, self.expires_ms, now_ms)?;
        if now_ms < self.inspected_ms {
            return Err(Error);
        }
        let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if key.verifying_key().to_sec1_point(false).as_bytes() != self.root_point {
            return Err(Error);
        }
        let transcript = [
            b"ZTSE/manifest/v2\0".as_slice(),
            &(UNSIGNED_LEN as u32).to_be_bytes(),
            &self.unsigned,
        ]
        .concat();
        let signature: Signature = key.sign(&transcript);
        let mut signed = [0; SIGNED_LEN];
        signed[..UNSIGNED_LEN].copy_from_slice(&self.unsigned);
        signed[UNSIGNED_LEN..].copy_from_slice(&signature.normalize_s().to_bytes());
        Ok(signed)
    }
}

#[cfg(test)]
mod tests;
