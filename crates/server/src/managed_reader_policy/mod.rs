// SPDX-License-Identifier: AGPL-3.0-only
//! Pure proposed signed-evidence consistency. No configured issuer, installed
//! authority, truthful custody, grants, database, signing or receiver operation.

use crate::sealed_manifest::VerifiedManifest;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

pub type Error = &'static str;
const POLICY: &[u8] = b"ZT/managed-reader/operator-policy/v1\0";
const ENROLLMENT: &[u8] = b"ZT/managed-reader/enrollment/v1\0";
const ATTESTATION: &[u8] = b"ZT/managed-reader/custody-policy/v1\0";

macro_rules! redacted {
    ($($name:ident),+) => {$ (
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+};
}

#[derive(Clone, PartialEq, Eq)]
pub struct Runtime {
    pub id: [u8; 16],
    pub evidence_contract: [u8; 32],
    /// Signed policy label only; does not establish custody truth.
    pub assurance: u8,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Policy {
    pub account: [u8; 16],
    pub origin: String,
    pub issuer: [u8; 16],
    pub issuer_key_id: [u8; 32],
    pub issuer_point: [u8; 65],
    pub id: [u8; 16],
    pub version: u64,
    pub max_lifetime_ms: u64,
    pub retention_contract: [u8; 32],
    pub from_ms: u64,
    pub until_ms: u64,
    pub minimum_assurance: u8,
    pub runtimes: Vec<Runtime>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub id: [u8; 16],
    pub account: [u8; 16],
    pub owner_user: [u8; 16],
    pub owner_session: [u8; 16],
    pub approval: [u8; 16],
    pub origin: String,
    pub issued_ms: u64,
    pub deadline_ms: u64,
    pub root_generation: u64,
    pub root_fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub successor_version: u64,
    pub successor_digest: [u8; 32],
    pub reader: [u8; 16],
    pub reader_generation: u64,
    pub reader_key_id: [u8; 32],
    pub reader_point: [u8; 65],
    pub workload: [u8; 16],
    pub auth_point: [u8; 65],
    pub auth_key_id: [u8; 32],
    pub issuer: [u8; 16],
    pub policy: [u8; 16],
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub runtime: [u8; 16],
    pub evidence_digest: [u8; 32],
    pub recipient_from_ms: u64,
    pub recipient_until_ms: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Attestation {
    pub enrollment: [u8; 16],
    pub account: [u8; 16],
    pub root_generation: u64,
    pub root_fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub reader: [u8; 16],
    pub reader_generation: u64,
    pub reader_key_id: [u8; 32],
    pub reader_point: [u8; 65],
    pub workload: [u8; 16],
    pub auth_key_id: [u8; 32],
    pub issuer: [u8; 16],
    pub policy: [u8; 16],
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub runtime: [u8; 16],
    pub raw_evidence_digest: [u8; 32],
    pub assurance: u8,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub recipient_from_ms: u64,
    pub recipient_until_ms: u64,
}
redacted!(Runtime, Policy, Enrollment, Attestation);

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(
        bytes: &'a [u8],
        tag: &[u8; 6],
        bounds: std::ops::RangeInclusive<usize>,
    ) -> Result<Self, Error> {
        if !bounds.contains(&bytes.len()) || bytes.get(..6) != Some(tag.as_slice()) {
            return Err("evidence shape");
        }
        Ok(Self { bytes, at: 6 })
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.at.checked_add(N).ok_or("evidence width")?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or("evidence width")?
            .try_into()
            .map_err(|_| "evidence width")?;
        self.at = end;
        Ok(out)
    }
    fn id<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let out = self.take()?;
        if out == [0; N] {
            return Err("evidence identity");
        }
        Ok(out)
    }
    fn number(&mut self) -> Result<u64, Error> {
        let n = u64::from_be_bytes(self.take()?);
        if n == 0 || n > i64::MAX as u64 {
            return Err("evidence integer");
        }
        Ok(n)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }
    fn point(&mut self) -> Result<[u8; 65], Error> {
        let point = self.take()?;
        if point[0] != 4 || VerifyingKey::from_sec1_bytes(&point).is_err() {
            return Err("evidence point");
        }
        Ok(point)
    }
    fn origin(&mut self) -> Result<String, Error> {
        let n = usize::from(u16::from_be_bytes(self.take()?));
        if !(9..=512).contains(&n) {
            return Err("evidence origin");
        }
        let end = self.at.checked_add(n).ok_or("evidence origin")?;
        let out = std::str::from_utf8(self.bytes.get(self.at..end).ok_or("evidence origin")?)
            .map_err(|_| "evidence origin")?;
        if !out.bytes().all(|b| (33..=126).contains(&b))
            || !zrotext_root_material::sealed_root_enrollment::canonical_origin(out)
        {
            return Err("evidence origin");
        }
        self.at = end;
        Ok(out.to_owned())
    }
    fn scope(&mut self) -> Result<(), Error> {
        if self.take::<2>()? != [0, 8] {
            return Err("evidence scope");
        }
        Ok(())
    }
    fn finish(self) -> Result<(), Error> {
        if self.at != self.bytes.len() {
            return Err("evidence trailing bytes");
        }
        Ok(())
    }
}
fn interval(from: u64, until: u64) -> Result<(), Error> {
    if from >= until {
        return Err("evidence interval");
    }
    Ok(())
}
// Existing candidate-02 purpose-key identity, kept private to this inert codec.
// Call sites select only the maintained ECDH (0010) or signature (0101) algorithm.
fn purpose_key_id(algorithm: [u8; 2], point: &[u8; 65]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ZTSE/key/v1\0");
    digest.update(algorithm);
    digest.update(point);
    digest.finalize().into()
}
fn keyed(point: &[u8; 65], id: &[u8; 32], algorithm: [u8; 2]) -> Result<(), Error> {
    if purpose_key_id(algorithm, point) != *id {
        return Err("evidence key purpose");
    }
    Ok(())
}

/// Public framing only; does not authenticate operator configuration.
pub fn decode_policy(bytes: &[u8]) -> Result<Policy, Error> {
    let mut c = Cursor::new(bytes, b"ZMPC\x01\x01", 286..=1524)?;
    let account = c.id()?;
    let origin = c.origin()?;
    let issuer = c.id()?;
    let issuer_key_id = c.id()?;
    let issuer_point = c.point()?;
    let id = c.id()?;
    let version = c.number()?;
    if c.take::<9>()? != [3, 0, 8, 0, 16, 0, 1, 0, 1] {
        return Err("evidence policy suite");
    }
    let max_lifetime_ms = c.number()?;
    let retention_contract = c.id()?;
    let from_ms = c.number()?;
    let until_ms = c.number()?;
    let minimum_assurance = c.byte()?;
    let count = c.byte()?;
    if max_lifetime_ms > 86_400_000 || minimum_assurance > 2 || !(1..=16).contains(&count) {
        return Err("evidence policy bounds");
    }
    let mut runtimes: Vec<Runtime> = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let r = Runtime {
            id: c.id()?,
            evidence_contract: c.id()?,
            assurance: c.byte()?,
        };
        if r.assurance > 2
            || r.assurance < minimum_assurance
            || runtimes.last().is_some_and(|last| last.id >= r.id)
        {
            return Err("evidence runtime order");
        }
        runtimes.push(r);
    }
    c.finish()?;
    interval(from_ms, until_ms)?;
    keyed(&issuer_point, &issuer_key_id, [1, 1])?;
    Ok(Policy {
        account,
        origin,
        issuer,
        issuer_key_id,
        issuer_point,
        id,
        version,
        max_lifetime_ms,
        retention_contract,
        from_ms,
        until_ms,
        minimum_assurance,
        runtimes,
    })
}

pub fn decode_enrollment(bytes: &[u8]) -> Result<Enrollment, Error> {
    let mut c = Cursor::new(bytes, b"ZMRE\x01\x01", 605..=1108)?;
    let e = Enrollment {
        id: c.id()?,
        account: c.id()?,
        owner_user: c.id()?,
        owner_session: c.id()?,
        approval: c.id()?,
        origin: c.origin()?,
        issued_ms: c.number()?,
        deadline_ms: c.number()?,
        root_generation: c.number()?,
        root_fingerprint: c.id()?,
        predecessor_version: c.number()?,
        predecessor_digest: c.id()?,
        successor_version: c.number()?,
        successor_digest: c.id()?,
        reader: c.id()?,
        reader_generation: c.number()?,
        reader_key_id: c.id()?,
        reader_point: c.point()?,
        workload: c.id()?,
        auth_point: c.point()?,
        auth_key_id: c.id()?,
        issuer: c.id()?,
        policy: c.id()?,
        policy_version: c.number()?,
        policy_digest: c.id()?,
        runtime: c.id()?,
        evidence_digest: c.id()?,
        recipient_from_ms: {
            c.scope()?;
            c.number()?
        },
        recipient_until_ms: c.number()?,
    };
    c.finish()?;
    interval(e.issued_ms, e.deadline_ms)?;
    interval(e.recipient_from_ms, e.recipient_until_ms)?;
    if e.root_generation != 1
        || e.deadline_ms - e.issued_ms > 60_000
        || e.successor_version
            != e.predecessor_version
                .checked_add(1)
                .ok_or("evidence successor")?
        || e.successor_digest == e.predecessor_digest
        || e.reader_point == e.auth_point
        || e.issued_ms > e.recipient_from_ms
    {
        return Err("evidence enrollment bounds");
    }
    keyed(&e.reader_point, &e.reader_key_id, [0, 0x10])?;
    keyed(&e.auth_point, &e.auth_key_id, [1, 1])?;
    Ok(e)
}

pub fn decode_attestation(bytes: &[u8]) -> Result<Attestation, Error> {
    let mut c = Cursor::new(bytes, b"ZMCP\x01\x01", 442..=442)?;
    let i = Attestation {
        enrollment: c.id()?,
        account: c.id()?,
        root_generation: c.number()?,
        root_fingerprint: c.id()?,
        predecessor_version: c.number()?,
        predecessor_digest: c.id()?,
        reader: c.id()?,
        reader_generation: c.number()?,
        reader_key_id: c.id()?,
        reader_point: c.point()?,
        workload: c.id()?,
        auth_key_id: c.id()?,
        issuer: c.id()?,
        policy: c.id()?,
        policy_version: c.number()?,
        policy_digest: c.id()?,
        runtime: c.id()?,
        raw_evidence_digest: c.id()?,
        assurance: c.byte()?,
        issued_ms: c.number()?,
        expires_ms: c.number()?,
        recipient_from_ms: {
            c.scope()?;
            c.number()?
        },
        recipient_until_ms: c.number()?,
    };
    c.finish()?;
    interval(i.issued_ms, i.expires_ms)?;
    interval(i.recipient_from_ms, i.recipient_until_ms)?;
    if i.root_generation != 1
        || i.assurance > 2
        || i.issued_ms > i.recipient_from_ms
        || i.expires_ms < i.recipient_until_ms
    {
        return Err("evidence attestation bounds");
    }
    keyed(&i.reader_point, &i.reader_key_id, [0, 0x10])?;
    Ok(i)
}

fn append_origin(bytes: &mut Vec<u8>, origin: &str) -> Result<(), Error> {
    if !(9..=512).contains(&origin.len()) {
        return Err("evidence origin");
    }
    bytes.extend_from_slice(&(origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(origin.as_bytes());
    Ok(())
}
macro_rules! fields {
    ($bytes:ident; $($field:expr),+ $(,)?) => {$( $bytes.extend_from_slice(&$field); )+};
}
macro_rules! numbers {
    ($bytes:ident; $($field:expr),+ $(,)?) => {$( $bytes.extend_from_slice(&$field.to_be_bytes()); )+};
}
/// Encode unsigned public fields only; no signing or configuration authority.
pub fn encode_policy(p: &Policy) -> Result<Vec<u8>, Error> {
    if !(1..=16).contains(&p.runtimes.len()) {
        return Err("evidence policy bounds");
    }
    let mut b = b"ZMPC\x01\x01".to_vec();
    fields!(b;p.account);
    append_origin(&mut b, &p.origin)?;
    fields!(b;p.issuer,p.issuer_key_id,p.issuer_point,p.id);
    numbers!(b;p.version);
    b.extend_from_slice(&[3, 0, 8, 0, 16, 0, 1, 0, 1]);
    numbers!(b;p.max_lifetime_ms);
    fields!(b;p.retention_contract);
    numbers!(b;p.from_ms,p.until_ms);
    b.extend_from_slice(&[p.minimum_assurance, p.runtimes.len() as u8]);
    for r in &p.runtimes {
        fields!(b;r.id,r.evidence_contract);
        b.push(r.assurance);
    }
    decode_policy(&b)?;
    Ok(b)
}
pub fn encode_enrollment(e: &Enrollment) -> Result<Vec<u8>, Error> {
    let mut b = b"ZMRE\x01\x01".to_vec();
    fields!(b;e.id,e.account,e.owner_user,e.owner_session,e.approval);
    append_origin(&mut b, &e.origin)?;
    numbers!(b;e.issued_ms,e.deadline_ms,e.root_generation);
    fields!(b;e.root_fingerprint);
    numbers!(b;e.predecessor_version);
    fields!(b;e.predecessor_digest);
    numbers!(b;e.successor_version);
    fields!(b;e.successor_digest,e.reader);
    numbers!(b;e.reader_generation);
    fields!(b;e.reader_key_id,e.reader_point,e.workload,e.auth_point,e.auth_key_id,e.issuer,e.policy);
    numbers!(b;e.policy_version);
    fields!(b;e.policy_digest,e.runtime,e.evidence_digest);
    b.extend_from_slice(&[0, 8]);
    numbers!(b;e.recipient_from_ms,e.recipient_until_ms);
    decode_enrollment(&b)?;
    Ok(b)
}
pub fn encode_attestation(i: &Attestation) -> Result<Vec<u8>, Error> {
    let mut b = b"ZMCP\x01\x01".to_vec();
    fields!(b;i.enrollment,i.account);
    numbers!(b;i.root_generation);
    fields!(b;i.root_fingerprint);
    numbers!(b;i.predecessor_version);
    fields!(b;i.predecessor_digest,i.reader);
    numbers!(b;i.reader_generation);
    fields!(b;i.reader_key_id,i.reader_point,i.workload,i.auth_key_id,i.issuer,i.policy);
    numbers!(b;i.policy_version);
    fields!(b;i.policy_digest,i.runtime,i.raw_evidence_digest);
    b.push(i.assurance);
    numbers!(b;i.issued_ms,i.expires_ms);
    b.extend_from_slice(&[0, 8]);
    numbers!(b;i.recipient_from_ms,i.recipient_until_ms);
    decode_attestation(&b)?;
    Ok(b)
}

fn transcript(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    [domain, &(bytes.len() as u32).to_be_bytes(), bytes].concat()
}
pub fn policy_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    decode_policy(bytes)?;
    Ok(Sha256::digest(transcript(POLICY, bytes)).into())
}
pub fn enrollment_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    decode_enrollment(bytes)?;
    Ok(Sha256::digest(transcript(ENROLLMENT, bytes)).into())
}
pub fn attestation_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    decode_attestation(bytes)?;
    Ok(Sha256::digest(transcript(ATTESTATION, bytes)).into())
}

/// Independent operator trust input. Parsing a request cannot establish its provenance.
pub struct ExpectedPolicy<'a> {
    pub account: &'a [u8; 16],
    pub origin: &'a str,
    pub id: &'a [u8; 16],
    pub version: u64,
    pub digest: &'a [u8; 32],
}
/// Actual privately verified history; no installed/current authority is implied.
pub struct AcceptedHistory<'a> {
    pub manifest: &'a VerifiedManifest,
    pub pin: &'a [u8],
    pub account: &'a [u8; 16],
    pub compared_fingerprint: &'a [u8; 32],
    pub archive_key_id: &'a [u8; 32],
    /// Externally trusted comparison time, never copied from received bytes.
    pub trusted_now_ms: u64,
}
/// Independently intended bindings; contains no editable root point or expiry.
pub struct ExpectedEnrollment {
    pub id: [u8; 16],
    pub owner_user: [u8; 16],
    pub owner_session: [u8; 16],
    pub approval: [u8; 16],
    pub reader: [u8; 16],
    pub reader_generation: u64,
    pub reader_point: [u8; 65],
    pub workload: [u8; 16],
    pub auth_point: [u8; 65],
    pub runtime: [u8; 16],
    pub recipient_from_ms: u64,
    pub recipient_until_ms: u64,
}
pub struct Evidence<'a> {
    pub policy: &'a [u8],
    pub enrollment: &'a [u8],
    pub enrollment_signature: &'a [u8],
    pub attestation: &'a [u8],
    pub attestation_signature: &'a [u8],
}
#[derive(Clone)]
pub struct EvidenceIdentity {
    pub policy_digest: [u8; 32],
    pub enrollment_digest: [u8; 32],
    pub attestation_digest: [u8; 32],
    pub enrollment: Enrollment,
    pub attestation: Attestation,
}
pub struct VerifiedSignedEvidence {
    identity: EvidenceIdentity,
}
redacted!(ExpectedEnrollment, EvidenceIdentity, VerifiedSignedEvidence);
impl VerifiedSignedEvidence {
    pub fn kind(&self) -> &'static str {
        "cryptographic_signed_evidence"
    }
    pub fn identity(&self) -> EvidenceIdentity {
        self.identity.clone()
    }
}
fn signature(point: &[u8; 65], signature: &[u8], domain: &[u8], bytes: &[u8]) -> Result<(), Error> {
    let s = Signature::from_slice(signature).map_err(|_| "evidence signature")?;
    if s.normalize_s().to_bytes().as_slice() != signature {
        return Err("evidence high-s");
    }
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| "evidence point")?
        .verify(&transcript(domain, bytes), &s)
        .map_err(|_| "evidence signature")
}

/// Pure authenticity/binding/interval comparison only. No issuer is configured.
pub fn verify_signed_evidence(
    evidence: &Evidence<'_>,
    policy: &ExpectedPolicy<'_>,
    history: &AcceptedHistory<'_>,
    expected: &ExpectedEnrollment,
) -> Result<VerifiedSignedEvidence, Error> {
    let p = decode_policy(evidence.policy)?;
    let e = decode_enrollment(evidence.enrollment)?;
    let i = decode_attestation(evidence.attestation)?;
    let pd = policy_digest(evidence.policy)?;
    let ed = enrollment_digest(evidence.enrollment)?;
    let id = attestation_digest(evidence.attestation)?;
    let now = history.trusted_now_ms;
    if now == 0
        || now > i64::MAX as u64
        || p.account != *policy.account
        || p.origin != policy.origin
        || p.id != *policy.id
        || p.version != policy.version
        || pd != *policy.digest
        || p.account != *history.account
    {
        return Err("evidence independent policy");
    }
    let m = history
        .manifest
        .account_archive_statement_records(history.archive_key_id, now)?;
    let fp = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
        history.pin,
        history.account,
    )?;
    if fp != *history.compared_fingerprint
        || history.pin.get(29..94) != Some(m.root_point.as_slice())
        || m.account != *history.account
        || m.generation != 1
        || purpose_key_id([1, 1], &m.root_point) != m.root_id
    {
        return Err("evidence compared root");
    }
    if e.account != p.account
        || e.origin != p.origin
        || e.root_fingerprint != fp
        || e.predecessor_version != m.version
        || e.predecessor_digest != m.digest
        || e.issuer != p.issuer
        || e.policy != p.id
        || e.policy_version != p.version
        || e.policy_digest != pd
        || e.evidence_digest != id
    {
        return Err("evidence enrollment binding");
    }
    if e.id != expected.id
        || e.owner_user != expected.owner_user
        || e.owner_session != expected.owner_session
        || e.approval != expected.approval
        || e.reader != expected.reader
        || e.reader_generation != expected.reader_generation
        || e.reader_point != expected.reader_point
        || e.workload != expected.workload
        || e.auth_point != expected.auth_point
        || e.runtime != expected.runtime
        || e.recipient_from_ms != expected.recipient_from_ms
        || e.recipient_until_ms != expected.recipient_until_ms
    {
        return Err("evidence independent enrollment");
    }
    if i.enrollment != e.id
        || i.account != e.account
        || i.root_generation != e.root_generation
        || i.root_fingerprint != e.root_fingerprint
        || i.predecessor_version != e.predecessor_version
        || i.predecessor_digest != e.predecessor_digest
        || i.reader != e.reader
        || i.reader_generation != e.reader_generation
        || i.reader_key_id != e.reader_key_id
        || i.reader_point != e.reader_point
        || i.workload != e.workload
        || i.auth_key_id != e.auth_key_id
        || i.issuer != e.issuer
        || i.policy != e.policy
        || i.policy_version != e.policy_version
        || i.policy_digest != e.policy_digest
        || i.runtime != e.runtime
        || i.recipient_from_ms != e.recipient_from_ms
        || i.recipient_until_ms != e.recipient_until_ms
    {
        return Err("evidence attestation binding");
    }
    let r = p
        .runtimes
        .iter()
        .find(|r| r.id == i.runtime)
        .ok_or("evidence policy runtime")?;
    if r.assurance != i.assurance
        || i.assurance < p.minimum_assurance
        || i.expires_ms - i.issued_ms > p.max_lifetime_ms
        || i.issued_ms > e.issued_ms
        || e.issued_ms > now
        || now >= e.deadline_ms
        || now < i.issued_ms
        || now >= i.expires_ms
        || now < p.from_ms
        || now >= p.until_ms
        || i.issued_ms < p.from_ms
        || i.expires_ms > p.until_ms
        || i.issued_ms < m.issued
        || i.issued_ms < m.root_from
        || i.expires_ms > m.expires
        || i.expires_ms > m.root_until
        || e.deadline_ms > i.expires_ms
        || e.recipient_until_ms > i.expires_ms
        || e.recipient_from_ms < m.root_from
    {
        return Err("evidence interval comparison");
    }
    let points = [
        &p.issuer_point,
        &e.auth_point,
        &e.reader_point,
        &m.root_point,
        &m.reader_point,
    ];
    for (at, point) in points.iter().enumerate() {
        if points[..at].contains(point) {
            return Err("evidence distinct key purpose");
        }
    }
    signature(
        &p.issuer_point,
        evidence.attestation_signature,
        ATTESTATION,
        evidence.attestation,
    )?;
    signature(
        &m.root_point,
        evidence.enrollment_signature,
        ENROLLMENT,
        evidence.enrollment,
    )?;
    Ok(VerifiedSignedEvidence {
        identity: EvidenceIdentity {
            policy_digest: pd,
            enrollment_digest: ed,
            attestation_digest: id,
            enrollment: e,
            attestation: i,
        },
    })
}

#[cfg(test)]
mod tests;
