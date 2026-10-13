// SPDX-License-Identifier: AGPL-3.0-only
//! Pure candidate03 cryptographic verification. Trusted checkpoints must come
//! from authenticated durable storage; these types do not prove that provenance.
//! No enrollment, storage/CAS, session permission, admission or radio effects.

use crate::sealed_manifest::{self, ChainPosition, ManifestTrust};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) type Check<T> = Result<T, &'static str>;
pub(crate) const MAX: u64 = i64::MAX as u64;
const DAY: u64 = 86_400_000;

pub(crate) fn time(value: u64) -> Check<()> {
    if value == 0 || value > MAX {
        return Err("comparison range");
    }
    Ok(())
}
pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn framed(label: &[u8], bytes: &[u8]) -> Check<Vec<u8>> {
    let len = u32::try_from(bytes.len()).map_err(|_| "transcript size")?;
    Ok([label, &len.to_be_bytes(), bytes].concat())
}
pub(crate) fn signature(point: &[u8], raw: &[u8], transcript: &[u8]) -> Check<()> {
    if point.len() != 65 || point[0] != 4 {
        return Err("point shape");
    }
    let sig = Signature::from_slice(raw).map_err(|_| "signature scalar/width")?;
    if sig.normalize_s().to_bytes().as_slice() != raw {
        return Err("high-s signature");
    }
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| "point curve")?
        .verify(transcript, &sig)
        .map_err(|_| "signature verification")
}
pub(crate) fn number(bytes: &[u8]) -> Check<u64> {
    let n = u64::from_be_bytes(bytes.try_into().map_err(|_| "integer width")?);
    if n > MAX {
        return Err("signed storage range");
    }
    Ok(n)
}
fn fresh(issued: u64, expires: u64, now: u64) -> Check<()> {
    time(now)?;
    if issued == 0
        || expires <= issued
        || expires - issued > DAY
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err("manifest freshness");
    }
    Ok(())
}

/// Explicit authenticated stored context, not a self-authenticating wire object.
/// The actual retained anchor is mandatory, even when the chain position is
/// Current. Never infer it from a later manifest's immediate predecessor digest.
pub struct AuthenticatedCheckpoint02 {
    pub trust: ManifestTrust,
    pub anchor_digest: [u8; 32],
    pub accepted_at_ms: u64,
    pub last_verified_ms: u64,
}

/// A fresh, independently reverified02 snapshot. No public constructor or mutable
/// projection can fabricate this proof. It does not attest storage provenance.
pub struct VerifiedCheckpoint02 {
    pin: Vec<u8>,
    signed: Vec<u8>,
    trust: ManifestTrust,
    anchor: [u8; 32],
    comparison: u64,
    accepted_at: u64,
}

pub fn verify_checkpoint02(
    pin: &[u8],
    signed: &[u8],
    checkpoint: &AuthenticatedCheckpoint02,
    comparison_ms: u64,
) -> Check<VerifiedCheckpoint02> {
    time(comparison_ms)?;
    time(checkpoint.accepted_at_ms)?;
    time(checkpoint.last_verified_ms)?;
    if checkpoint.trust.generation != 1
        || checkpoint.anchor_digest != [0; 32]
        || checkpoint.accepted_at_ms > checkpoint.last_verified_ms
        || checkpoint.last_verified_ms > comparison_ms
        || !matches!(
            checkpoint.trust.position,
            ChainPosition::Current { version: 1.., .. }
        )
    {
        return Err("unsupported02 checkpoint/anchor/clock");
    }
    // Independently verify exact evidence both at the authenticated original
    // acceptance checkpoint and for the bounded fresh02 upgrade subset.
    sealed_manifest::verify(pin, signed, &checkpoint.trust, checkpoint.accepted_at_ms)?;
    sealed_manifest::verify(pin, signed, &checkpoint.trust, comparison_ms)?;
    Ok(VerifiedCheckpoint02 {
        pin: pin.to_vec(),
        signed: signed.to_vec(),
        trust: checkpoint.trust.clone(),
        anchor: checkpoint.anchor_digest,
        comparison: comparison_ms,
        accepted_at: checkpoint.accepted_at_ms,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestIdentity03 {
    pub predecessor_profile: u8,
    pub account_id: [u8; 16],
    pub generation: u64,
    pub version: u64,
    pub digest: [u8; 32],
    pub root_point: [u8; 65],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub comparison_ms: u64,
}
struct Role {
    role: u8,
    id: [u8; 32],
    point: [u8; 65],
    device: [u8; 16],
    line: [u8; 16],
    scope: u16,
    from: u64,
    until: u64,
    state: u8,
}
impl Role {
    fn active(&self, now: u64) -> bool {
        self.state == 1 && self.from <= now && now < self.until
    }
}

/// Immutable cryptographic evidence, not current durable permission or a CAS.
pub struct VerifiedManifest03 {
    identity: ManifestIdentity03,
    previous: [u8; 32],
    anchor: [u8; 32],
    signed_sha256: [u8; 32],
    roles: Vec<Role>,
}
pub(crate) struct Authorization03<'a> {
    pub kind: u8,
    pub account: &'a [u8; 16],
    pub device: &'a [u8; 16],
    pub line: &'a [u8; 16],
    pub signer_id: &'a [u8; 32],
    pub readers: &'a [(u8, [u8; 32])],
}
impl std::fmt::Debug for VerifiedManifest03 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedManifest03").finish_non_exhaustive()
    }
}
impl VerifiedManifest03 {
    fn comparison(&self, now: u64) -> Check<()> {
        time(now)?;
        if now < self.identity.comparison_ms {
            return Err("comparison regression");
        }
        Ok(())
    }
    /// Owned metadata; original verification comparison is never advanced here.
    pub fn identity_at(&self, now: u64) -> Check<ManifestIdentity03> {
        self.comparison(now)?;
        fresh(self.identity.issued_ms, self.identity.expires_ms, now)?;
        Ok(self.identity)
    }
    pub(crate) fn signed_sha256(&self) -> [u8; 32] {
        self.signed_sha256
    }
    pub(crate) fn authorize(
        &self,
        request: &Authorization03<'_>,
        now: u64,
    ) -> Check<([u8; 65], u64, u64)> {
        let Authorization03 {
            kind,
            account,
            device,
            line,
            signer_id,
            readers,
        } = *request;
        self.identity_at(now)?;
        if ![1, 2].contains(&kind)
            || *account != self.identity.account_id
            || *device == [0; 16]
            || *line == [0; 16]
        {
            return Err("routing identity");
        }
        let inbound = kind == 2;
        let signer = self
            .roles
            .iter()
            .find(|r| r.role == if inbound { 4 } else { 5 } && r.id == *signer_id)
            .ok_or("signer authority")?;
        if !signer.active(now)
            || signer.scope != if inbound { 2 } else { 1 }
            || signer.line != *line
            || inbound && signer.device != *device
        {
            return Err("signer authority");
        }
        if readers.is_empty() || readers.len() > if inbound { 7 } else { 8 } {
            return Err("reader count");
        }
        let mut deadline = self.identity.expires_ms.min(signer.until);
        let mut not_before = signer.from;
        let (mut devices, mut archives, mut integrations) = (0, 0, 0);
        let mut previous = None;
        for &(role, id) in readers {
            if previous.is_some_and(|p| p >= (role, id)) {
                return Err("reader order");
            }
            previous = Some((role, id));
            let r = self
                .roles
                .iter()
                .find(|r| r.role == role && r.id == id)
                .ok_or("reader authority")?;
            if !r.active(now) || r.scope & if inbound { 8 } else { 4 } == 0 {
                return Err("reader authority");
            }
            match role {
                1 if !inbound && r.device == *device && r.line == *line => devices += 1,
                2 => archives += 1,
                3 => integrations += 1,
                _ => return Err("reader role/subject"),
            }
            deadline = deadline.min(r.until);
            not_before = not_before.max(r.from);
        }
        if devices != usize::from(!inbound) || archives != 1 || integrations > 6 {
            return Err("reader set");
        }
        Ok((signer.point, not_before, deadline))
    }
}

fn parse(bytes: &[u8], anchor: [u8; 32], now: u64) -> Check<VerifiedManifest03> {
    time(now)?;
    if !(366..=9753).contains(&bytes.len())
        || &bytes[..6] != b"ZTMA\x03\x03"
        || ![2, 3].contains(&bytes[6])
    {
        return Err("manifest shape/profile");
    }
    let count = usize::from(bytes[152]);
    if !(1..=64).contains(&count) || bytes.len() != 217 + 149 * count {
        return Err("manifest count/size");
    }
    let account: [u8; 16] = bytes[7..23].try_into().unwrap();
    let generation = number(&bytes[23..31])?;
    let version = number(&bytes[31..39])?;
    let issued = number(&bytes[39..47])?;
    let expires = number(&bytes[47..55])?;
    if account == [0; 16] || generation != 1 || version == 0 || anchor != [0; 32] {
        return Err("unsupported manifest identity/anchor");
    }
    fresh(issued, expires, now)?;
    let root: [u8; 65] = bytes[87..152].try_into().unwrap();
    if root[0] != 4 {
        return Err("root point shape");
    }
    VerifyingKey::from_sec1_bytes(&root).map_err(|_| "root curve")?;
    let mut roles: Vec<Role> = Vec::with_capacity(count);
    let mut points = HashSet::new();
    let (mut roots, mut archives) = (0, 0);
    for i in 0..count {
        let at = 153 + 149 * i;
        let role = bytes[at];
        let id: [u8; 32] = bytes[at + 1..at + 33].try_into().unwrap();
        let point: [u8; 65] = bytes[at + 33..at + 98].try_into().unwrap();
        let device = bytes[at + 98..at + 114].try_into().unwrap();
        let line = bytes[at + 114..at + 130].try_into().unwrap();
        let scope = u16::from_be_bytes(bytes[at + 130..at + 132].try_into().unwrap());
        let from = number(&bytes[at + 132..at + 140])?;
        let until = number(&bytes[at + 140..at + 148])?;
        let state = bytes[at + 148];
        let valid = match role {
            1 => scope == 4 && device != [0; 16] && line != [0; 16],
            2 => scope == 12 && device == [0; 16] && line == [0; 16],
            3 => [4, 8, 12].contains(&scope) && device == [0; 16] && line == [0; 16],
            4 => scope == 2 && device != [0; 16] && line != [0; 16],
            5 => scope == 1 && device == [0; 16] && line != [0; 16],
            6 => scope == 0 && device == [0; 16] && line == [0; 16],
            _ => false,
        };
        if !valid || from > until || ![1, 2].contains(&state) {
            return Err("role/scope/subject/interval/state");
        }
        if roles.last().is_some_and(|r| (r.role, r.id) >= (role, id)) {
            return Err("record order");
        }
        if point[0] != 4 {
            return Err("record point shape");
        }
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| "record curve")?;
        if id != sealed_manifest::key_id(role, &point) || !points.insert(point) {
            return Err("record key identity/reuse");
        }
        if role == 6 {
            roots += 1;
            if point != root || state != 1 || from > issued || until < expires {
                return Err("root record");
            }
        }
        if role == 2 && state == 1 {
            archives += 1;
        }
        roles.push(Role {
            role,
            id,
            point,
            device,
            line,
            scope,
            from,
            until,
            state,
        });
    }
    if roots != 1 || archives != 1 {
        return Err("root/archive cardinality");
    }
    let unsigned = &bytes[..bytes.len() - 64];
    signature(
        &root,
        &bytes[unsigned.len()..],
        &framed(b"ZTSE/manifest/v3\0", unsigned)?,
    )?;
    Ok(VerifiedManifest03 {
        identity: ManifestIdentity03 {
            predecessor_profile: bytes[6],
            account_id: account,
            generation,
            version,
            digest: sha(unsigned),
            root_point: root,
            issued_ms: issued,
            expires_ms: expires,
            comparison_ms: now,
        },
        previous: bytes[55..87].try_into().unwrap(),
        anchor,
        signed_sha256: sha(bytes),
        roles,
    })
}
fn successor(value: &VerifiedManifest03, prior: ManifestIdentity03, profile: u8) -> Check<()> {
    if value.identity.account_id != prior.account_id
        || value.identity.generation != prior.generation
        || value.identity.root_point != prior.root_point
        || prior.version.checked_add(1) != Some(value.identity.version)
        || value.identity.predecessor_profile != profile
        || value.previous != prior.digest
    {
        return Err("successor identity/chain");
    }
    Ok(())
}
pub fn verify_from_02(
    bytes: &[u8],
    prior: &VerifiedCheckpoint02,
    now: u64,
) -> Check<VerifiedManifest03> {
    time(now)?;
    if now < prior.comparison {
        return Err("comparison regression");
    }
    let old = sealed_manifest::verify(&prior.pin, &prior.signed, &prior.trust, now)?;
    let value = parse(bytes, prior.anchor, now)?;
    let root = prior.pin[29..94].try_into().unwrap();
    successor(
        &value,
        ManifestIdentity03 {
            predecessor_profile: 2,
            account_id: *old.account_id(),
            generation: old.generation(),
            version: old.version(),
            digest: *old.digest(),
            root_point: root,
            issued_ms: 0,
            expires_ms: 0,
            comparison_ms: prior.comparison,
        },
        2,
    )?;
    Ok(value)
}
pub fn verify_successor(
    bytes: &[u8],
    prior: &VerifiedManifest03,
    now: u64,
) -> Check<VerifiedManifest03> {
    prior.comparison(now)?;
    let value = parse(bytes, prior.anchor, now)?;
    successor(&value, prior.identity, 3)?;
    Ok(value)
}
pub fn verify_current(
    bytes: &[u8],
    current: &VerifiedManifest03,
    now: u64,
) -> Check<VerifiedManifest03> {
    current.comparison(now)?;
    let value = parse(bytes, current.anchor, now)?;
    if value.identity.account_id != current.identity.account_id
        || value.identity.generation != current.identity.generation
        || value.identity.root_point != current.identity.root_point
        || value.identity.version != current.identity.version
        || value.identity.digest != current.identity.digest
        || value.identity.predecessor_profile != current.identity.predecessor_profile
    {
        return Err("current identity/fork");
    }
    Ok(value)
}

impl VerifiedCheckpoint02 {
    pub(crate) fn signed_sha256(&self) -> [u8; 32] {
        sha(&self.signed)
    }
    pub(crate) fn original_accepted_at(&self) -> u64 {
        self.accepted_at
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.trust.root_fingerprint
    }
    pub(crate) fn identity(&self) -> Check<(u64, [u8; 32])> {
        match self.trust.position {
            ChainPosition::Current { version, digest } => Ok((version, digest)),
            _ => Err("02 checkpoint position"),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
