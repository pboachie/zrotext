// SPDX-License-Identifier: AGPL-3.0-only
//! Typed first manifest signing after independent phone/archive point comparison.
//! Session, peer and paired signing fingerprint are review context, not manifest-signed
//! consent. Server authorization and separate phone approval remain required.
use crate::{
    root_backup::{ExpectedIdentity, RootSecret},
    sealed_root_enrollment,
};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use sha2::{Digest, Sha256};

pub const MAX_PROPOSAL: usize = 2_048;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("offline conversation genesis refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 16],
    pub session: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub device_signing_fingerprint: [u8; 32],
    pub generation: u64,
    pub peer: String,
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}
/// Never copy these expected points or scope from the proposal. Phone points
/// require independent owner comparison; UUID equality establishes no provenance.
#[derive(Clone)]
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub scope: Scope,
    pub root_pin: [u8; 94],
    pub phone_reader: [u8; 65],
    pub archive_reader: [u8; 65],
    pub phone_signer: [u8; 65],
}
pub struct Proposal {
    scope: Scope,
    pin: [u8; 94],
    unsigned: Vec<u8>,
}
/// Immutable public review. Consumed by signing, and contains no secrets.
pub struct ReviewedGenesis {
    scope: Scope,
    root_point: [u8; 65],
    unsigned: Vec<u8>,
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error)?;
        let b = self.bytes.get(self.at..end).ok_or(Error)?;
        self.at = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error)
    }
    fn num(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn sized(&mut self) -> Result<Vec<u8>> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        Ok(self.take(n)?.to_vec())
    }
}
/// Exact bounded ZTCG01 framing; rejects trailing or truncated bytes.
pub fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_PROPOSAL {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(5)? != b"ZTCG\x01" {
        return Err(Error);
    }
    let account = c.array()?;
    let session = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let device_signing_fingerprint = c.array()?;
    let generation = c.num()?;
    let n = c.take(1)?[0] as usize;
    let peer = String::from_utf8(c.take(n)?.to_vec()).map_err(|_| Error)?;
    let origin = String::from_utf8(c.sized()?).map_err(|_| Error)?;
    let fingerprint = c.array()?;
    let pin = c.array()?;
    let issued_ms = c.num()?;
    let expires_ms = c.num()?;
    let unsigned = c.sized()?;
    if c.at != bytes.len() {
        return Err(Error);
    }
    let scope = Scope {
        account,
        session,
        device,
        line,
        device_signing_fingerprint,
        generation,
        peer,
        origin,
        fingerprint,
        issued_ms,
        expires_ms,
    };
    validate_scope(&scope)?;
    Ok(Proposal {
        scope,
        pin,
        unsigned,
    })
}
fn validate_scope(s: &Scope) -> Result<()> {
    if [s.account, s.session, s.device, s.line].contains(&[0; 16])
        || [s.fingerprint, s.device_signing_fingerprint].contains(&[0; 32])
        || [s.generation, s.issued_ms, s.expires_ms]
            .iter()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
        || s.expires_ms <= s.issued_ms
        || s.expires_ms - s.issued_ms > 86_400_000
        || s.peer.len() < 3
        || s.peer.len() > 16
        || !s.peer.starts_with('+')
        || s.peer.as_bytes()[1] == b'0'
        || !s.peer.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        || !sealed_root_enrollment::canonical_origin(&s.origin)
        || s.origin.len() > 512
    {
        return Err(Error);
    }
    Ok(())
}
fn current(s: &Scope, now: u64) -> Result<()> {
    validate_scope(s)?;
    if now < s.issued_ms || now >= s.expires_ms || now > i64::MAX as u64 {
        return Err(Error);
    }
    Ok(())
}
fn key_id(role: u8, point: &[u8; 65]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ZTSE/key/v1\0");
    hash.update(if role <= 3 { [0, 16] } else { [1, 1] });
    hash.update(point);
    hash.finalize().into()
}
pub fn inspect(p: &Proposal, e: &Expected, now: u64) -> Result<ReviewedGenesis> {
    current(&e.scope, now)?;
    let s = &e.scope;
    if p.scope != *s
        || s.account != e.identity.account_id
        || s.origin != e.identity.origin
        || s.fingerprint != e.identity.root_fingerprint
        || p.pin != e.root_pin
        || sealed_root_enrollment::root_fingerprint(&e.root_pin, &s.account).map_err(|_| Error)?
            != s.fingerprint
    {
        return Err(Error);
    }
    let paired: [u8; 32] = Sha256::digest(e.phone_signer).into();
    if paired != s.device_signing_fingerprint {
        return Err(Error);
    }
    let root_point: [u8; 65] = e.root_pin[29..].try_into().map_err(|_| Error)?;
    let points = [e.phone_reader, e.archive_reader, e.phone_signer, root_point];
    for (index, point) in points.iter().enumerate() {
        if point[0] != 4 || points[..index].contains(point) {
            return Err(Error);
        }
        VerifyingKey::from_sec1_bytes(point).map_err(|_| Error)?;
    }
    // Reconstruct the ONLY accepted manifest: generation/version one, zero
    // predecessor, four active roles and exactly independently intended points.
    let mut unsigned = b"ZTMA\x02".to_vec();
    unsigned.extend_from_slice(&s.account);
    unsigned.extend_from_slice(&1u64.to_be_bytes());
    unsigned.extend_from_slice(&1u64.to_be_bytes());
    unsigned.extend_from_slice(&s.issued_ms.to_be_bytes());
    unsigned.extend_from_slice(&s.expires_ms.to_be_bytes());
    unsigned.extend_from_slice(&[0; 32]);
    unsigned.extend_from_slice(&root_point);
    unsigned.push(4);
    for ((role, scope), point) in [(1u8, 4u16), (2, 12), (4, 2), (6, 0)]
        .into_iter()
        .zip(points)
    {
        unsigned.push(role);
        unsigned.extend_from_slice(&key_id(role, &point));
        unsigned.extend_from_slice(&point);
        unsigned.extend_from_slice(if matches!(role, 1 | 4) {
            &s.device
        } else {
            &[0; 16]
        });
        unsigned.extend_from_slice(if matches!(role, 1 | 4) {
            &s.line
        } else {
            &[0; 16]
        });
        unsigned.extend_from_slice(&scope.to_be_bytes());
        unsigned.extend_from_slice(&s.issued_ms.to_be_bytes());
        unsigned.extend_from_slice(&s.expires_ms.to_be_bytes());
        unsigned.push(1);
    }
    if unsigned != p.unsigned {
        return Err(Error);
    }
    Ok(ReviewedGenesis {
        scope: s.clone(),
        root_point,
        unsigned,
    })
}
impl ReviewedGenesis {
    /// Fresh clock after secret entry; root key must equal the independently
    /// compared pin. No arbitrary bytes, replacement keys or generation occur.
    pub fn sign(self, root: &RootSecret, now: u64) -> Result<Vec<u8>> {
        current(&self.scope, now)?;
        let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if key.verifying_key().to_sec1_point(false).as_bytes() != self.root_point {
            return Err(Error);
        }
        let mut transcript = b"ZTSE/manifest/v2\0".to_vec();
        transcript.extend_from_slice(&(self.unsigned.len() as u32).to_be_bytes());
        transcript.extend_from_slice(&self.unsigned);
        let signature: Signature = key.sign(&transcript);
        let mut out = self.unsigned;
        out.extend_from_slice(&signature.normalize_s().to_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
