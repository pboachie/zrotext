// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant ZTKA01 historical integrity. No installed contact permission, custody,
//! trusted write timestamp, network, storage, signing or decryption operation.

use crate::sealed_manifest::VerifiedManifest;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ZT/contact-reader/authorization/v1\0";
pub type Error = &'static str;

#[derive(Clone, PartialEq, Eq)]
pub struct UnsignedStatement {
    pub authorization_id: [u8; 16],
    pub account_id: [u8; 16],
    pub origin: String,
    pub trust_generation: u64,
    pub manifest_version: u64,
    pub reader_generation: u64,
    pub root_fingerprint: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub reader_id: [u8; 32],
    pub reader_point: [u8; 65],
    pub issued_ms: u64,
    pub until_ms: u64,
    pub capability: u8,
}

fn origin(value: &str) -> Result<(), Error> {
    if !(9..=512).contains(&value.len()) || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("statement origin");
    }
    let url = url::Url::parse(value).map_err(|_| "statement origin")?;
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != value
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("statement origin");
    }
    Ok(())
}

fn positive(n: u64) -> Result<(), Error> {
    if n == 0 || n > i64::MAX as u64 {
        return Err("statement integer");
    }
    Ok(())
}

/// Public unsigned framing only; does not establish curve membership or trust.
pub fn encode_unsigned(s: &UnsignedStatement) -> Result<Vec<u8>, Error> {
    origin(&s.origin)?;
    for n in [
        s.trust_generation,
        s.manifest_version,
        s.reader_generation,
        s.issued_ms,
        s.until_ms,
    ] {
        positive(n)?;
    }
    if s.authorization_id == [0; 16]
        || s.account_id == [0; 16]
        || s.root_fingerprint == [0; 32]
        || s.manifest_digest == [0; 32]
        || s.reader_id == [0; 32]
        || s.reader_point[0] != 4
        || s.trust_generation != 1
        || s.capability != 3
        || s.until_ms <= s.issued_ms
        || s.until_ms - s.issued_ms > 86_400_000
    {
        return Err("statement framing");
    }
    let mut bytes = Vec::with_capacity(241 + s.origin.len());
    bytes.extend_from_slice(b"ZTKA\x01\x03");
    bytes.extend_from_slice(&s.authorization_id);
    bytes.extend_from_slice(&s.account_id);
    bytes.extend_from_slice(&(s.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(s.origin.as_bytes());
    for n in [s.trust_generation, s.manifest_version, s.reader_generation] {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    for field in [&s.root_fingerprint, &s.manifest_digest, &s.reader_id] {
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&s.reader_point);
    bytes.extend_from_slice(&s.issued_ms.to_be_bytes());
    bytes.extend_from_slice(&s.until_ms.to_be_bytes());
    Ok(bytes)
}

#[derive(Clone)]
pub struct ParsedStatement {
    statement: UnsignedStatement,
    bytes: Vec<u8>,
    unsigned: Vec<u8>,
    signature: [u8; 64],
}
impl ParsedStatement {
    pub fn statement(&self) -> UnsignedStatement {
        self.statement.clone()
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    pub fn unsigned(&self) -> Vec<u8> {
        self.unsigned.clone()
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
}
impl std::fmt::Debug for ParsedStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedStatement").finish_non_exhaustive()
    }
}

/// Strict bounded framing, actual P256 membership and canonical low-S scalars.
/// Parsing alone does not verify the root signature or accepted history.
pub fn parse(bytes: &[u8]) -> Result<ParsedStatement, Error> {
    if !(314..=817).contains(&bytes.len()) || &bytes[..6] != b"ZTKA\x01\x03" {
        return Err("statement shape");
    }
    let n = u16::from_be_bytes(bytes[38..40].try_into().unwrap()) as usize;
    if !(9..=512).contains(&n) || bytes.len() != 305 + n {
        return Err("statement length");
    }
    let at = 40 + n;
    let number =
        |offset| u64::from_be_bytes(bytes[at + offset..at + offset + 8].try_into().unwrap());
    let s = UnsignedStatement {
        authorization_id: bytes[6..22].try_into().unwrap(),
        account_id: bytes[22..38].try_into().unwrap(),
        origin: std::str::from_utf8(&bytes[40..at])
            .map_err(|_| "statement origin")?
            .to_owned(),
        trust_generation: number(0),
        manifest_version: number(8),
        reader_generation: number(16),
        root_fingerprint: bytes[at + 24..at + 56].try_into().unwrap(),
        manifest_digest: bytes[at + 56..at + 88].try_into().unwrap(),
        reader_id: bytes[at + 88..at + 120].try_into().unwrap(),
        reader_point: bytes[at + 120..at + 185].try_into().unwrap(),
        issued_ms: number(185),
        until_ms: number(193),
        capability: 3,
    };
    let unsigned = encode_unsigned(&s)?;
    let signature: [u8; 64] = bytes[241 + n..].try_into().unwrap();
    let scalars = Signature::from_slice(&signature).map_err(|_| "statement scalar")?;
    if scalars.normalize_s().to_bytes().as_slice() != signature {
        return Err("statement high-s");
    }
    VerifyingKey::from_sec1_bytes(&s.reader_point).map_err(|_| "statement point")?;
    let id: [u8; 32] =
        Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &s.reader_point].concat()).into();
    if id != s.reader_id || unsigned != bytes[..241 + n] {
        return Err("statement reader identity");
    }
    Ok(ParsedStatement {
        statement: s,
        bytes: bytes.to_vec(),
        unsigned,
        signature,
    })
}

pub struct ExpectedIdentity<'a> {
    pub account_id: &'a [u8; 16],
    pub origin: &'a str,
    /// Already independently compared, not inferred from the statement/directory.
    pub root_fingerprint: &'a [u8; 32],
}
#[derive(Clone, Copy)]
pub enum Comparison {
    DeclaredIssuedMs,
}

#[derive(Clone)]
pub struct StatementIdentity {
    pub parsed: ParsedStatement,
    pub digest: [u8; 32],
    pub root_writer_id: [u8; 32],
    pub root_point: [u8; 65],
    pub root_from_ms: u64,
    pub root_until_ms: u64,
    pub reader_from_ms: u64,
    pub reader_until_ms: u64,
}

pub struct VerifiedContactReaderStatement {
    identity: StatementIdentity,
}
impl VerifiedContactReaderStatement {
    pub fn kind(&self) -> &'static str {
        "historical_integrity"
    }
    pub fn identity(&self) -> StatementIdentity {
        self.identity.clone()
    }
}
impl std::fmt::Debug for VerifiedContactReaderStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedContactReaderStatement")
            .finish_non_exhaustive()
    }
}

/// One-time historical consistency at signed declared issuance. No current time,
/// grant installation, trusted write timestamp or contact access is implied.
pub fn verify(
    bytes: &[u8],
    manifest: &VerifiedManifest,
    expected: &ExpectedIdentity<'_>,
    comparison: Comparison,
) -> Result<VerifiedContactReaderStatement, Error> {
    let Comparison::DeclaredIssuedMs = comparison;
    origin(expected.origin)?;
    let parsed = parse(bytes)?;
    let s = &parsed.statement;
    let m = manifest.account_archive_statement_records(&s.reader_id, s.issued_ms)?;
    if s.account_id != *expected.account_id
        || m.account != *expected.account_id
        || s.origin != expected.origin
        || s.trust_generation != m.generation
        || s.manifest_version != m.version
        || s.manifest_digest != m.digest
        || s.reader_point != m.reader_point
        || s.issued_ms < m.issued
        || s.until_ms > m.expires
        || s.until_ms > m.reader_until
        || s.until_ms > m.root_until
    {
        return Err("statement accepted history");
    }
    let mut pin = b"ZTRP\x02".to_vec();
    pin.extend_from_slice(expected.account_id);
    pin.extend_from_slice(&1_u64.to_be_bytes());
    pin.extend_from_slice(&m.root_point);
    let fingerprint =
        zrotext_root_material::sealed_root_enrollment::root_fingerprint(&pin, expected.account_id)?;
    if fingerprint != *expected.root_fingerprint || s.root_fingerprint != fingerprint {
        return Err("statement compared pin");
    }
    let key = VerifyingKey::from_sec1_bytes(&m.root_point).map_err(|_| "statement root")?;
    let signature = Signature::from_slice(&parsed.signature).map_err(|_| "statement scalar")?;
    key.verify(
        &[
            DOMAIN,
            &(parsed.unsigned.len() as u32).to_be_bytes(),
            &parsed.unsigned,
        ]
        .concat(),
        &signature,
    )
    .map_err(|_| "statement signature")?;
    let digest = Sha256::digest(&parsed.bytes).into();
    Ok(VerifiedContactReaderStatement {
        identity: StatementIdentity {
            parsed,
            digest,
            root_writer_id: m.root_id,
            root_point: m.root_point,
            root_from_ms: m.root_from,
            root_until_ms: m.root_until,
            reader_from_ms: m.reader_from,
            reader_until_ms: m.reader_until,
        },
    })
}

#[cfg(test)]
mod tests;
