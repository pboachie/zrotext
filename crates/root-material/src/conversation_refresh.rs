// SPDX-License-Identifier: AGPL-3.0-only
//! One typed offline role-5 refresh, using an already recovered generation-one root.
//! No generic signing, network, root generation, archive replacement or persistence.
//! Scope is independently reviewed metadata: the manifest signature itself does not
//! encode peer/session. Live owner-session/interval CAS remains an installation obligation.
use crate::{
    root_backup::{ExpectedIdentity, RootSecret},
    sealed_root_enrollment,
};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_PROPOSAL: usize = 20_480;
const HEADER: usize = 151;
const RECORD: usize = 149;
const MAX_MANIFEST: usize = 9751;
const ROLE5_LIFETIME: u64 = 1_800_000; // Existing conversation-enrollment.ts bound.

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 16],
    pub session: [u8; 16],
    pub interval: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub line_generation: u64,
    pub peer: String,
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub phone_reader: [u8; 32],
    pub archive_reader: [u8; 32],
    pub signer: [u8; 32],
    pub point: [u8; 65],
    pub until_ms: u64,
}
/// Every value comes from independently intended context/high-water and the root kit,
/// never by copying the downloaded proposal into the expected input.
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub scope: Scope,
}
pub struct Proposal {
    pub scope: Scope,
    predecessor: Vec<u8>,
    unsigned: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("offline conversation refresh refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;
fn number(bytes: &[u8]) -> Result<u64> {
    let n = u64::from_be_bytes(bytes.try_into().map_err(|_| Error)?);
    if n == 0 || n > i64::MAX as u64 {
        return Err(Error);
    }
    Ok(n)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn key_id(role: u8, point: &[u8]) -> [u8; 32] {
    hash(
        &[
            b"ZTSE/key/v1\0".as_slice(),
            if role <= 3 { &[0, 16] } else { &[1, 1] },
            point,
        ]
        .concat(),
    )
}
fn transcript(unsigned: &[u8]) -> Vec<u8> {
    [
        b"ZTSE/manifest/v2\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        unsigned,
    ]
    .concat()
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error)?;
        let v = self.bytes.get(self.at..end).ok_or(Error)?;
        self.at = end;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error)
    }
    fn num(&mut self) -> Result<u64> {
        number(self.take(8)?)
    }
    fn sized(&mut self) -> Result<Vec<u8>> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        Ok(self.take(n)?.to_vec())
    }
}
/// Canonical public ZTCF01 framing; no JSON parser or secret input is involved.
/// Layout: magic(5), account/session/interval/device/line(16 each), line-generation(u64),
/// peer(u8 length + ASCII), origin(u16 length + canonical HTTPS origin), fingerprint(32),
/// predecessor-version(u64), predecessor-digest/phone-reader/archive-reader/signer(32 each),
/// signer-point(65), until(u64), predecessor-signed-manifest(u16 length + bytes),
/// successor-unsigned-manifest(u16 length + bytes). Integers are big-endian; no trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_PROPOSAL {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(5)? != b"ZTCF\x01" {
        return Err(Error);
    }
    let account = c.array()?;
    let session = c.array()?;
    let interval = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let line_generation = c.num()?;
    let peer_len = c.take(1)?[0] as usize;
    let peer = String::from_utf8(c.take(peer_len)?.to_vec()).map_err(|_| Error)?;
    let origin = String::from_utf8(c.sized()?).map_err(|_| Error)?;
    let fingerprint = c.array()?;
    let predecessor_version = c.num()?;
    let predecessor_digest = c.array()?;
    let phone_reader = c.array()?;
    let archive_reader = c.array()?;
    let signer = c.array()?;
    let point = c.array()?;
    let until_ms = c.num()?;
    let predecessor = c.sized()?;
    let unsigned = c.sized()?;
    if c.at != bytes.len() {
        return Err(Error);
    }
    let scope = Scope {
        account,
        session,
        interval,
        device,
        line,
        line_generation,
        peer,
        origin,
        fingerprint,
        predecessor_version,
        predecessor_digest,
        phone_reader,
        archive_reader,
        signer,
        point,
        until_ms,
    };
    validate_scope(&scope)?;
    Ok(Proposal {
        scope,
        predecessor,
        unsigned,
    })
}
fn validate_scope(s: &Scope) -> Result<()> {
    if [s.account, s.session, s.interval, s.device, s.line].contains(&[0; 16])
        || [
            s.fingerprint,
            s.predecessor_digest,
            s.phone_reader,
            s.archive_reader,
            s.signer,
        ]
        .contains(&[0; 32])
        || s.peer.len() < 3
        || s.peer.len() > 16
        || !s.peer.starts_with('+')
        || !s.peer.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        || s.peer.as_bytes()[1] == b'0'
        || !sealed_root_enrollment::canonical_origin(&s.origin)
        || s.origin.len() > 512
        || [s.line_generation, s.predecessor_version, s.until_ms]
            .iter()
            .any(|v| *v == 0 || *v > i64::MAX as u64)
        || s.point[0] != 4
        || key_id(5, &s.point) != s.signer
    {
        return Err(Error);
    }
    VerifyingKey::from_sec1_bytes(&s.point).map_err(|_| Error)?;
    Ok(())
}
struct Manifest<'a> {
    bytes: &'a [u8],
    records: Vec<&'a [u8]>,
    version: u64,
    issued: u64,
    expires: u64,
}
/// Validate the existing profile-02 grammar before restricting the delta. This
/// does not infer a chain anchor: expected current digest/version are mandatory.
fn manifest<'a>(
    bytes: &'a [u8],
    signed: bool,
    identity: &ExpectedIdentity,
    now: u64,
) -> Result<Manifest<'a>> {
    if now == 0
        || now > i64::MAX as u64
        || bytes.len() < HEADER
        || bytes.len() > MAX_MANIFEST
        || &bytes[..5] != b"ZTMA\x02"
    {
        return Err(Error);
    }
    let count = usize::from(bytes[150]);
    if count == 0
        || count > 64
        || bytes.len() != HEADER + count * RECORD + if signed { 64 } else { 0 }
        || bytes[5..21] != identity.account_id
        || number(&bytes[21..29])? != 1
    {
        return Err(Error);
    }
    let version = number(&bytes[29..37])?;
    let issued = number(&bytes[37..45])?;
    let expires = number(&bytes[45..53])?;
    if expires <= issued
        || expires - issued > 86_400_000
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err(Error);
    }
    let root = &bytes[85..150];
    let pin = [
        b"ZTRP\x02".as_slice(),
        &identity.account_id,
        &1u64.to_be_bytes(),
        root,
    ]
    .concat();
    if sealed_root_enrollment::root_fingerprint(&pin, &identity.account_id).map_err(|_| Error)?
        != identity.root_fingerprint
    {
        return Err(Error);
    }
    let root_key = VerifyingKey::from_sec1_bytes(root).map_err(|_| Error)?;
    let mut records: Vec<&[u8]> = Vec::new();
    let mut points = HashSet::new();
    let mut owner = 0;
    let mut archive = 0;
    for n in 0..count {
        let r = &bytes[HEADER + n * RECORD..HEADER + (n + 1) * RECORD];
        let role = r[0];
        let point = &r[33..98];
        let device = &r[98..114];
        let line = &r[114..130];
        let scope = u16::from_be_bytes(r[130..132].try_into().map_err(|_| Error)?);
        let from = u64::from_be_bytes(r[132..140].try_into().map_err(|_| Error)?);
        let until = u64::from_be_bytes(r[140..148].try_into().map_err(|_| Error)?);
        let valid = match role {
            1 => scope == 4 && device != [0; 16] && line != [0; 16],
            2 => scope == 12 && device == [0; 16] && line == [0; 16],
            3 => [4, 8, 12].contains(&scope) && device == [0; 16] && line == [0; 16],
            4 => scope == 2 && device != [0; 16] && line != [0; 16],
            5 => scope == 1 && device == [0; 16] && line != [0; 16],
            6 => scope == 0 && device == [0; 16] && line == [0; 16],
            _ => false,
        };
        if !valid
            || from > until
            || from > i64::MAX as u64
            || until > i64::MAX as u64
            || ![1, 2].contains(&r[148])
            || key_id(role, point) != r[1..33]
            || records.last().is_some_and(|p| p[..33] >= r[..33])
            || !points.insert(point.to_vec())
        {
            return Err(Error);
        }
        VerifyingKey::from_sec1_bytes(point).map_err(|_| Error)?;
        if role == 6 {
            owner += 1;
            if point != root || r[148] != 1 || from > issued || until < expires {
                return Err(Error);
            }
        }
        if role == 2 && r[148] == 1 {
            archive += 1;
        }
        records.push(r);
    }
    if owner != 1 || archive != 1 {
        return Err(Error);
    }
    if signed {
        let unsigned = &bytes[..bytes.len() - 64];
        let signature = Signature::from_slice(&bytes[unsigned.len()..]).map_err(|_| Error)?;
        if signature.normalize_s().to_bytes() != signature.to_bytes() {
            return Err(Error);
        }
        root_key
            .verify(&transcript(unsigned), &signature)
            .map_err(|_| Error)?;
    }
    Ok(Manifest {
        bytes,
        records,
        version,
        issued,
        expires,
    })
}
pub fn inspect<'a>(proposal: &'a Proposal, expected: &Expected, now: u64) -> Result<&'a Scope> {
    validate_scope(&expected.scope)?;
    if proposal.scope != expected.scope
        || expected.scope.account != expected.identity.account_id
        || expected.scope.origin != expected.identity.origin
        || expected.scope.fingerprint != expected.identity.root_fingerprint
    {
        return Err(Error);
    }
    let s = &proposal.scope;
    let before = manifest(&proposal.predecessor, true, &expected.identity, now)?;
    let after = manifest(&proposal.unsigned, false, &expected.identity, now)?;
    if before.version != s.predecessor_version
        || hash(&before.bytes[..before.bytes.len() - 64]) != s.predecessor_digest
        || before.version.checked_add(1) != Some(after.version)
        || after.bytes[53..85] != s.predecessor_digest
        || before.bytes[5..29] != after.bytes[5..29]
        || before.bytes[85..150] != after.bytes[85..150]
        || before.expires != after.expires
        || after.issued < before.issued
        || after.issued > now
        || after.records.len() != before.records.len() + 1
    {
        return Err(Error);
    }
    let added = after
        .records
        .iter()
        .find(|r| r[1..33] == s.signer)
        .ok_or(Error)?;
    if added[0] != 5
        || added[33..98] != s.point
        || added[98..114] != [0; 16]
        || added[114..130] != s.line
        || added[130..132] != [0, 1]
        || number(&added[132..140])? != after.issued
        || number(&added[140..148])? != s.until_ms
        || added[148] != 1
        || s.until_ms <= now
        || s.until_ms > after.expires
        || s.until_ms.saturating_sub(after.issued) > ROLE5_LIFETIME
    {
        return Err(Error);
    }
    for r in &before.records {
        if !after.records.contains(r) || r[1..33] == s.signer {
            return Err(Error);
        }
    }
    for (role, id) in [(1, s.phone_reader), (2, s.archive_reader)] {
        let r = before
            .records
            .iter()
            .find(|r| r[0] == role && r[1..33] == id)
            .ok_or(Error)?;
        if r[148] != 1
            || u64::from_be_bytes(r[132..140].try_into().map_err(|_| Error)?) > now
            || number(&r[140..148])? <= now
            || role == 1 && (r[98..114] != s.device || r[114..130] != s.line)
        {
            return Err(Error);
        }
    }
    Ok(s)
}
/// Re-inspect at fresh time after console approval/recovery. Root remains caller-owned.
/// The returned public manifest requires owner/session/consent/predecessor CAS before use.
pub fn sign(
    root: &RootSecret,
    proposal: &Proposal,
    expected: &Expected,
    now: u64,
) -> Result<Vec<u8>> {
    inspect(proposal, expected, now)?;
    let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
    if key.verifying_key().to_sec1_point(false).as_bytes() != &proposal.unsigned[85..150] {
        return Err(Error);
    }
    let signature: Signature = key.sign(&transcript(&proposal.unsigned));
    let signature = signature.normalize_s();
    let mut signed = proposal.unsigned.clone();
    signed.extend_from_slice(&signature.to_bytes());
    Ok(signed)
}
#[cfg(test)]
mod tests;
