// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated first-activation line approval-key transcript. Parsing and signature
//! verification establish no database authority, lease, session or phone consent.
//! Root signing exists only in the explicitly enabled offline unlock build.
use crate::{root_backup::ExpectedIdentity, sealed_root_enrollment};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
#[cfg(feature = "unlock")]
use {
    crate::root_backup::RootSecret,
    p256::ecdsa::{SigningKey, signature::Signer},
};

pub const DOMAIN: &[u8] = b"ZTSE/line/owner-key/register/v1\0";
pub const MAX_TRANSCRIPT: usize = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("line approval-key registration refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 16],
    pub user: [u8; 16],
    pub owner_session: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub next_generation: u64,
    pub challenge: [u8; 16],
    pub nonce: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub approval_fingerprint: [u8; 32],
    pub paired_signing_fingerprint: [u8; 32],
    pub connection_epoch: u64,
    pub deployment_epoch: u64,
    pub site_id: String,
    pub instance_id: String,
    pub origin: String,
}
/// Every scope value and root identity must come from independent selection,
/// not merely from the downloaded transcript. A matching UUID is not provenance.
#[derive(Clone)]
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub scope: Scope,
    pub root_pin: [u8; 94],
}
#[derive(Clone)]
pub struct Statement {
    scope: Scope,
    root_pin: [u8; 94],
    root_fingerprint: [u8; 32],
    approval_point: [u8; 65],
}
pub struct ReviewedRegistration {
    statement: Statement,
    transcript: Vec<u8>,
}

fn positive(n: u64) -> bool {
    n > 0 && n <= i64::MAX as u64
}
fn ascii_id(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn validate_scope(s: &Scope) -> Result<()> {
    if [
        s.account,
        s.user,
        s.owner_session,
        s.device,
        s.line,
        s.challenge,
    ]
    .contains(&[0; 16])
        || [
            s.nonce,
            s.approval_fingerprint,
            s.paired_signing_fingerprint,
        ]
        .contains(&[0; 32])
        || [
            s.next_generation,
            s.issued_ms,
            s.expires_ms,
            s.connection_epoch,
            s.deployment_epoch,
        ]
        .iter()
        .any(|n| !positive(*n))
        || s.approval_fingerprint == s.paired_signing_fingerprint
        || s.expires_ms <= s.issued_ms
        || s.expires_ms - s.issued_ms > 300_000
        || !ascii_id(&s.site_id)
        || !ascii_id(&s.instance_id)
        || s.origin.len() > 255
        || !sealed_root_enrollment::canonical_origin(&s.origin)
    {
        return Err(Error);
    }
    Ok(())
}
fn current(s: &Scope, now: u64) -> Result<()> {
    validate_scope(s)?;
    if !positive(now) || now < s.issued_ms || now >= s.expires_ms {
        return Err(Error);
    }
    Ok(())
}
impl Statement {
    pub fn new(
        scope: Scope,
        root_pin: [u8; 94],
        root_fingerprint: [u8; 32],
        approval_point: [u8; 65],
    ) -> Result<Self> {
        let statement = Self {
            scope,
            root_pin,
            root_fingerprint,
            approval_point,
        };
        statement.validate()?;
        Ok(statement)
    }
    fn validate(&self) -> Result<()> {
        validate_scope(&self.scope)?;
        if sealed_root_enrollment::root_fingerprint(&self.root_pin, &self.scope.account)
            .map_err(|_| Error)?
            != self.root_fingerprint
            || self.approval_point[0] != 4
            || self.approval_point.as_slice() == &self.root_pin[29..]
            || <[u8; 32]>::from(Sha256::digest(self.approval_point))
                != self.scope.approval_fingerprint
        {
            return Err(Error);
        }
        let key = VerifyingKey::from_sec1_bytes(&self.approval_point).map_err(|_| Error)?;
        if key.to_sec1_point(false).as_bytes() != self.approval_point {
            return Err(Error);
        }
        Ok(())
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn root_pin(&self) -> &[u8; 94] {
        &self.root_pin
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.root_fingerprint
    }
    pub fn approval_point(&self) -> &[u8; 65] {
        &self.approval_point
    }
    /// Mathematical possession only; caller must inspect independent expectations,
    /// fresh time and database authority/replay state before relying on this.
    pub fn verify_root(&self, signature: &[u8]) -> Result<()> {
        verify(&self.root_pin[29..], &encode(self)?, signature)
    }
    pub fn verify_approval(&self, signature: &[u8]) -> Result<()> {
        verify(&self.approval_point, &encode(self)?, signature)
    }
}
fn verify(point: &[u8], bytes: &[u8], raw: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(raw).map_err(|_| Error)?;
    if signature.normalize_s().to_bytes() != signature.to_bytes() {
        return Err(Error);
    }
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| Error)?
        .verify(bytes, &signature)
        .map_err(|_| Error)
}
/// Exact transcript, including the dedicated domain; no wrapper or length tag.
pub fn encode(s: &Statement) -> Result<Vec<u8>> {
    s.validate()?;
    let v = &s.scope;
    let mut bytes = Vec::with_capacity(MAX_TRANSCRIPT);
    bytes.extend_from_slice(DOMAIN);
    for id in [v.account, v.user, v.owner_session, v.device, v.line] {
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&v.next_generation.to_be_bytes());
    bytes.extend_from_slice(&v.challenge);
    bytes.extend_from_slice(&v.nonce);
    bytes.extend_from_slice(&v.issued_ms.to_be_bytes());
    bytes.extend_from_slice(&v.expires_ms.to_be_bytes());
    bytes.extend_from_slice(&s.root_pin);
    bytes.extend_from_slice(&s.root_fingerprint);
    bytes.extend_from_slice(&s.approval_point);
    bytes.extend_from_slice(&v.approval_fingerprint);
    bytes.extend_from_slice(&v.paired_signing_fingerprint);
    bytes.extend_from_slice(&v.connection_epoch.to_be_bytes());
    bytes.extend_from_slice(&v.deployment_epoch.to_be_bytes());
    for text in [&v.site_id, &v.instance_id, &v.origin] {
        bytes.extend_from_slice(&(text.len() as u16).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    if bytes.len() > MAX_TRANSCRIPT {
        return Err(Error);
    }
    Ok(bytes)
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
    fn text(&mut self, max: usize) -> Result<String> {
        let n = u16::from_be_bytes(self.array()?) as usize;
        if n == 0 || n > max {
            return Err(Error);
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error)
    }
}
pub fn decode(bytes: &[u8]) -> Result<Statement> {
    if bytes.len() > MAX_TRANSCRIPT {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(DOMAIN.len())? != DOMAIN {
        return Err(Error);
    }
    let account = c.array()?;
    let user = c.array()?;
    let owner_session = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let next_generation = c.num()?;
    let challenge = c.array()?;
    let nonce = c.array()?;
    let issued_ms = c.num()?;
    let expires_ms = c.num()?;
    let root_pin = c.array()?;
    let root_fingerprint = c.array()?;
    let approval_point = c.array()?;
    let approval_fingerprint = c.array()?;
    let paired_signing_fingerprint = c.array()?;
    let connection_epoch = c.num()?;
    let deployment_epoch = c.num()?;
    let site_id = c.text(128)?;
    let instance_id = c.text(128)?;
    let origin = c.text(255)?;
    if c.at != bytes.len() {
        return Err(Error);
    }
    Statement::new(
        Scope {
            account,
            user,
            owner_session,
            device,
            line,
            next_generation,
            challenge,
            nonce,
            issued_ms,
            expires_ms,
            approval_fingerprint,
            paired_signing_fingerprint,
            connection_epoch,
            deployment_epoch,
            site_id,
            instance_id,
            origin,
        },
        root_pin,
        root_fingerprint,
        approval_point,
    )
}
pub fn inspect(
    statement: &Statement,
    expected: &Expected,
    now: u64,
) -> Result<ReviewedRegistration> {
    current(&expected.scope, now)?;
    statement.validate()?;
    if statement.scope != expected.scope
        || statement.root_pin != expected.root_pin
        || expected.identity.account_id != expected.scope.account
        || expected.identity.origin != expected.scope.origin
        || statement.root_fingerprint != expected.identity.root_fingerprint
    {
        return Err(Error);
    }
    Ok(ReviewedRegistration {
        statement: statement.clone(),
        transcript: encode(statement)?,
    })
}
impl ReviewedRegistration {
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    #[cfg(feature = "unlock")]
    pub fn sign(self, root: &RootSecret, now: u64) -> Result<[u8; 64]> {
        current(&self.statement.scope, now)?;
        let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if key.verifying_key().to_sec1_point(false).as_bytes() != &self.statement.root_pin[29..] {
            return Err(Error);
        }
        let signature: Signature = key.sign(&self.transcript);
        Ok(signature.normalize_s().to_bytes().into())
    }
}
#[cfg(test)]
mod tests;
