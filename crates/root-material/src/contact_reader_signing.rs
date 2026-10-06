// SPDX-License-Identifier: AGPL-3.0-only
//! One offline, owner-reviewed contact statement signature using an existing root.
//! Historical public consistency only: no accepted history, current permission,
//! issuer, custody, I/O, enrollment, highwater or generic signing interface.
use crate::{root_backup::RootSecret, sealed_root_enrollment};
use p256::{
    SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const DOMAIN: &[u8] = b"ZT/contact-reader/authorization/v1\0";
const DAY: u64 = 86_400_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("offline contact reader signing refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Canonical bounded public transport bytes only, not authenticated provenance.
pub fn decode_public_base64(value: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    if max > 20_480 || min > max || value.len() > max.div_ceil(3) * 4 {
        return Err(Error);
    }
    let bytes = data_encoding::BASE64
        .decode(value.as_bytes())
        .map_err(|_| Error)?;
    if !(min..=max).contains(&bytes.len()) || data_encoding::BASE64.encode(&bytes) != value {
        return Err(Error);
    }
    Ok(bytes)
}

/// Independently intended public values, not copied authority from a proposal.
pub struct Expected {
    pub account: [u8; 16],
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub reader_id: [u8; 32],
    pub reader_point: [u8; 65],
    pub requested_until_ms: u64,
}
/// Untrusted public wire values. These never establish a current/accepted brand.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceRecord {
    pub key_id: [u8; 32],
    pub point: [u8; 65],
    pub from_ms: u64,
    pub until_ms: u64,
}
pub struct Source<'a> {
    pub account: [u8; 16],
    pub pin: &'a [u8],
    pub fingerprint: [u8; 32],
    pub generation: u64,
    pub version: u64,
    pub digest: [u8; 32],
    pub manifest: &'a [u8],
    pub observed_ms: u64,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub signed_until_ms: u64,
    pub reader: SourceRecord,
    pub root_writer: SourceRecord,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewFacts {
    pub authorization: [u8; 16],
    pub account: [u8; 16],
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub manifest_version: u64,
    pub manifest_digest: [u8; 32],
    pub reader_generation: u64,
    pub reader: SourceRecord,
    pub root_writer: SourceRecord,
    pub observed_ms: u64,
    pub issued_ms: u64,
    pub until_ms: u64,
    pub unsigned_digest: [u8; 32],
}
/// Private copied review state; consumed by signing. No Clone/serde/constructor.
pub struct ReviewedContactReader {
    facts: ReviewFacts,
    unsigned: Vec<u8>,
    inspected_ms: u64,
}
pub struct SignedStatement {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn number(bytes: &[u8], zero: bool) -> Result<u64> {
    let value = u64::from_be_bytes(bytes.try_into().map_err(|_| Error)?);
    if value > i64::MAX as u64 || (!zero && value == 0) {
        return Err(Error);
    }
    Ok(value)
}
fn point(bytes: &[u8]) -> Result<[u8; 65]> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(Error);
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error)?;
    bytes.try_into().map_err(|_| Error)
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
fn transcript(domain: &[u8], unsigned: &[u8]) -> Vec<u8> {
    [domain, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat()
}
fn signature_check(root: &[u8], signature: &[u8], domain: &[u8], unsigned: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(signature).map_err(|_| Error)?;
    if signature.normalize_s() != signature {
        return Err(Error);
    }
    VerifyingKey::from_sec1_bytes(root)
        .map_err(|_| Error)?
        .verify(&transcript(domain, unsigned), &signature)
        .map_err(|_| Error)
}
struct Record {
    role: u8,
    value: SourceRecord,
    state: u8,
}
fn active(record: &Record, now: u64) -> bool {
    record.state == 1 && record.value.from_ms <= now && now < record.value.until_ms
}
fn historical_source(source: &Source<'_>, expected: &Expected, issued: u64) -> Result<()> {
    if source.account != expected.account
        || source.generation != 1
        || source.fingerprint != expected.fingerprint
        || source.version == 0
        || source.version > i64::MAX as u64
        || source.observed_ms == 0
        || source.observed_ms > i64::MAX as u64
        || issued < source.observed_ms
    {
        return Err(Error);
    }
    let pin = source.pin;
    if pin.len() != 94
        || &pin[..5] != b"ZTRP\x02"
        || pin[5..21] != expected.account
        || number(&pin[21..29], false)? != 1
        || sealed_root_enrollment::root_fingerprint(pin, &expected.account).map_err(|_| Error)?
            != expected.fingerprint
    {
        return Err(Error);
    }
    let root_point = point(&pin[29..])?;
    let bytes = source.manifest;
    if !(364..=9751).contains(&bytes.len()) || &bytes[..5] != b"ZTMA\x02" {
        return Err(Error);
    }
    let count = usize::from(bytes[150]);
    if !(1..=64).contains(&count) || bytes.len() != 215 + 149 * count {
        return Err(Error);
    }
    let manifest_issued = number(&bytes[37..45], false)?;
    let expires = number(&bytes[45..53], false)?;
    if bytes[5..21] != expected.account
        || number(&bytes[21..29], false)? != 1
        || number(&bytes[29..37], false)? != source.version
        || bytes[85..150] != root_point
        || manifest_issued != source.issued_ms
        || expires != source.expires_ms
        || expires <= manifest_issued
        || expires - manifest_issued > DAY
        || manifest_issued > source.observed_ms.saturating_add(300_000)
        || source.observed_ms >= expires
        || issued < manifest_issued
        || issued >= expires
    {
        return Err(Error);
    }
    let unsigned = &bytes[..bytes.len() - 64];
    if hash(unsigned) != source.digest {
        return Err(Error);
    }
    signature_check(
        &root_point,
        &bytes[unsigned.len()..],
        b"ZTSE/manifest/v2\0",
        unsigned,
    )?;
    let mut records: Vec<Record> = Vec::with_capacity(count);
    let mut points = HashSet::new();
    let mut roots = 0;
    let mut archives = 0;
    for index in 0..count {
        let at = 151 + 149 * index;
        let role = bytes[at];
        let id: [u8; 32] = bytes[at + 1..at + 33].try_into().map_err(|_| Error)?;
        let public = point(&bytes[at + 33..at + 98])?;
        let device = &bytes[at + 98..at + 114];
        let line = &bytes[at + 114..at + 130];
        let scope = u16::from_be_bytes(bytes[at + 130..at + 132].try_into().map_err(|_| Error)?);
        let from = number(&bytes[at + 132..at + 140], true)?;
        let until = number(&bytes[at + 140..at + 148], true)?;
        let state = bytes[at + 148];
        let subject = match role {
            1 => scope == 4 && device != [0; 16] && line != [0; 16],
            2 => scope == 12 && device == [0; 16] && line == [0; 16],
            3 => [4, 8, 12].contains(&scope) && device == [0; 16] && line == [0; 16],
            4 => scope == 2 && device != [0; 16] && line != [0; 16],
            5 => scope == 1 && device == [0; 16] && line != [0; 16],
            6 => scope == 0 && device == [0; 16] && line == [0; 16],
            _ => false,
        };
        if !subject
            || from > until
            || ![1, 2].contains(&state)
            || id != key_id(role, &public)
            || !points.insert(public)
            || records
                .last()
                .is_some_and(|p| (role, id) <= (p.role, p.value.key_id))
        {
            return Err(Error);
        }
        if role == 6 {
            roots += 1;
            if public != root_point || state != 1 || from > manifest_issued || until < expires {
                return Err(Error);
            }
        }
        if role == 2 && state == 1 {
            archives += 1;
        }
        records.push(Record {
            role,
            value: SourceRecord {
                key_id: id,
                point: public,
                from_ms: from,
                until_ms: until,
            },
            state,
        });
    }
    if roots != 1 || archives != 1 {
        return Err(Error);
    }
    let reader = records
        .iter()
        .find(|r| r.role == 2 && r.value.key_id == expected.reader_id)
        .ok_or(Error)?;
    let root = records.iter().find(|r| r.role == 6).ok_or(Error)?;
    if !active(reader, source.observed_ms)
        || !active(root, source.observed_ms)
        || !active(reader, issued)
        || !active(root, issued)
        || reader.value.point != expected.reader_point
        || reader.value != source.reader
        || root.value != source.root_writer
        || source.signed_until_ms != expires.min(reader.value.until_ms).min(root.value.until_ms)
    {
        return Err(Error);
    }
    Ok(())
}
/// Inspect exact copied unsigned bytes and historical public facts; no current authority.
pub fn inspect(
    unsigned: &[u8],
    source: &Source<'_>,
    expected: &Expected,
    now_ms: u64,
) -> Result<ReviewedContactReader> {
    if !(250..=753).contains(&unsigned.len()) || &unsigned[..6] != b"ZTKA\x01\x03" {
        return Err(Error);
    }
    let n = usize::from(u16::from_be_bytes(
        unsigned[38..40].try_into().map_err(|_| Error)?,
    ));
    if !(9..=512).contains(&n) || unsigned.len() != 241 + n {
        return Err(Error);
    }
    let origin = std::str::from_utf8(&unsigned[40..40 + n]).map_err(|_| Error)?;
    if !origin.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || !sealed_root_enrollment::canonical_origin(origin)
        || origin != expected.origin
        || expected.account == [0; 16]
        || expected.fingerprint == [0; 32]
        || expected.reader_id == [0; 32]
        || expected.requested_until_ms == 0
        || expected.requested_until_ms > i64::MAX as u64
    {
        return Err(Error);
    }
    let at = 40 + n;
    let authorization = unsigned[6..22].try_into().map_err(|_| Error)?;
    let generation = number(&unsigned[at..at + 8], false)?;
    let version = number(&unsigned[at + 8..at + 16], false)?;
    let reader_generation = number(&unsigned[at + 16..at + 24], false)?;
    let issued = number(&unsigned[at + 185..at + 193], false)?;
    let until = number(&unsigned[at + 193..at + 201], false)?;
    if authorization == [0; 16]
        || unsigned[22..38] != expected.account
        || generation != 1
        || version != source.version
        || unsigned[at + 24..at + 56] != expected.fingerprint
        || unsigned[at + 56..at + 88] != source.digest
        || unsigned[at + 88..at + 120] != expected.reader_id
        || point(&unsigned[at + 120..at + 185])? != expected.reader_point
        || key_id(2, &expected.reader_point) != expected.reader_id
        || until <= issued
        || until - issued > DAY
        || until > expected.requested_until_ms
        || until > source.signed_until_ms
    {
        return Err(Error);
    }
    historical_source(source, expected, issued)?;
    let facts = ReviewFacts {
        authorization,
        account: expected.account,
        origin: origin.to_owned(),
        fingerprint: expected.fingerprint,
        manifest_version: version,
        manifest_digest: source.digest,
        reader_generation,
        reader: source.reader.clone(),
        root_writer: source.root_writer.clone(),
        observed_ms: source.observed_ms,
        issued_ms: issued,
        until_ms: until,
        unsigned_digest: hash(unsigned),
    };
    let reviewed = ReviewedContactReader {
        facts,
        unsigned: unsigned.to_vec(),
        inspected_ms: now_ms,
    };
    reviewed.check_time(now_ms)?;
    Ok(reviewed)
}
impl ReviewedContactReader {
    pub fn facts(&self) -> ReviewFacts {
        self.facts.clone()
    }
    pub fn check_time(&self, now_ms: u64) -> Result<()> {
        if now_ms == 0
            || now_ms > i64::MAX as u64
            || now_ms < self.inspected_ms
            || now_ms < self.facts.issued_ms
            || now_ms >= self.facts.until_ms
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn sign(self, root: &RootSecret, now_ms: u64) -> Result<SignedStatement> {
        self.check_time(now_ms)?;
        let secret = SecretKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if secret.public_key().to_sec1_point(false).as_bytes() != self.facts.root_writer.point {
            return Err(Error);
        }
        drop(secret);
        let signing = SigningKey::from_bytes(root.as_bytes().into()).map_err(|_| Error)?;
        let signature: Signature = signing.sign(&transcript(DOMAIN, &self.unsigned));
        let signature = signature.normalize_s();
        signature_check(
            &self.facts.root_writer.point,
            signature.to_bytes().as_slice(),
            DOMAIN,
            &self.unsigned,
        )?;
        drop(signing);
        let mut bytes = self.unsigned;
        bytes.extend_from_slice(signature.to_bytes().as_slice());
        Ok(SignedStatement {
            digest: hash(&bytes),
            bytes,
        })
    }
}

#[cfg(test)]
mod tests;
