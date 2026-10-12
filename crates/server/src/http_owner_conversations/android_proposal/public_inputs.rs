// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded public phone export and encrypted archive framing. Successful framing
//! is not ciphertext authentication, recoverability, phone consent or activation.
use super::super::ConversationError;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Expected binding comes from the current authenticated server selection,
/// paired device key and independently enrolled root, never the export header.
pub struct GenesisInputs {
    pub phone_reader: [u8; 65],
    pub phone_signer: [u8; 65],
    pub archive_reader: [u8; 65],
    pub archive_backup_sha256: [u8; 32],
    pub phone_export_sha256: [u8; 32],
}
pub struct Binding<'a> {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub generation: i64,
    pub origin: &'a str,
    pub root_pin: &'a [u8; 94],
    pub root_fingerprint: &'a [u8; 32],
    pub paired_signing_point: &'a [u8; 65],
    pub paired_signing_fingerprint: &'a [u8; 32],
}

fn reject() -> ConversationError {
    ConversationError::Forbidden
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn point(bytes: &[u8]) -> Result<[u8; 65], ConversationError> {
    let p: [u8; 65] = bytes.try_into().map_err(|_| reject())?;
    if p[0] != 4 || VerifyingKey::from_sec1_bytes(&p).is_err() {
        return Err(reject());
    }
    Ok(p)
}

/// Bind exact ciphertext/public inputs to independently checked current identity.
/// The native custodian must additionally compare its own retained phone points
/// and archive digest, and prove archive recovery before signing GENESIS.
pub fn inspect_genesis_inputs(
    b: Binding<'_>,
    phone: &[u8],
    archive: &[u8],
) -> Result<GenesisInputs, ConversationError> {
    if [b.account, b.device, b.line].iter().any(Uuid::is_nil)
        || b.generation <= 0
        || !zrotext_root_material::sealed_root_enrollment::canonical_origin(b.origin)
        || zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            b.root_pin,
            b.account.as_bytes(),
        )
        .map_err(|_| reject())?
            != *b.root_fingerprint
        || hash(b.paired_signing_point) != *b.paired_signing_fingerprint
        || phone.len() != 223
        || &phone[..5] != b"ZTPK\x01"
        || phone[5..21] != *b.account.as_bytes()
        || phone[21..37] != *b.device.as_bytes()
        || phone[37..53] != *b.line.as_bytes()
        || phone[53..85] != *b.paired_signing_fingerprint
        || phone[85..93] != b.generation.to_be_bytes()
        || !(334..=845).contains(&archive.len())
        || &archive[..6] != b"ZTAB\x01\x01"
        || archive[6..22] == [0; 16]
        || archive[22..38] != *b.account.as_bytes()
        || archive[38..46] != 1u64.to_be_bytes()
        || archive[46..78] != *b.root_fingerprint
    {
        return Err(reject());
    }
    let phone_reader = point(&phone[93..158])?;
    let phone_signer = point(&phone[158..223])?;
    if phone_signer != *b.paired_signing_point {
        return Err(reject());
    }
    let archive_reader = point(&archive[110..175])?;
    let archive_id = hash(&[b"ZTSE/key/v1\0".as_slice(), &[0, 16], &archive_reader].concat());
    if archive[78..110] != archive_id {
        return Err(reject());
    }
    let n = usize::from(u16::from_be_bytes(
        archive[175..177].try_into().map_err(|_| reject())?,
    ));
    if !(1..=512).contains(&n)
        || archive.len() != 177 + n + 156
        || archive[177..177 + n] != *b.origin.as_bytes()
        || archive[177 + n + 104..177 + n + 108] != 48u32.to_be_bytes()
    {
        return Err(reject());
    }
    let root = point(&b.root_pin[29..94])?;
    let points = [phone_reader, phone_signer, archive_reader, root];
    for (i, p) in points.iter().enumerate() {
        if points[..i].contains(p) {
            return Err(reject());
        }
    }
    Ok(GenesisInputs {
        phone_reader,
        phone_signer,
        archive_reader,
        archive_backup_sha256: hash(archive),
        phone_export_sha256: hash(phone),
    })
}

#[cfg(test)]
mod tests;
