// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate enrolled-root possession for one isolated workspace continuation.
//! No runtime caller, authentication, database lookup, replay store or session issuance.
//! A retained root kit and authenticated broker context are separate trust inputs.

use crate::{root_backup::ExpectedIdentity, sealed_root_enrollment};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
#[cfg(feature = "unlock")]
use {
    crate::root_backup::RootSecret,
    p256::ecdsa::{SigningKey, signature::Signer},
};

pub const DOMAIN: &[u8] = b"ZTSE/review-workspace/resume/v1\0";
pub const MAX_UNSIGNED: usize = 845;
const FIXED: usize = 333;
const MAX_WINDOW_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("review workspace root continuation refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Public statement claims, never authority by themselves. Broker/session/event
/// identify an authenticated review broker context, not an owner session.
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub realm: [u8; 16],
    pub broker: [u8; 16],
    pub broker_session: [u8; 16],
    pub authentication_event: [u8; 16],
    pub credential_revision: u64,
    pub account: [u8; 16],
    pub owner: [u8; 16],
    pub challenge: [u8; 16],
    pub nonce: [u8; 32],
    /// Commitment to the exact private browser continuation; not a bearer token.
    pub browser_binding: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub origin: String,
}

#[derive(Clone)]
pub struct Statement {
    scope: Scope,
    root_pin: [u8; 94],
    fingerprint: [u8; 32],
}

/// Identity/pin come from the reviewer's independently retained root kit. Scope
/// comes from an authenticated broker challenge/context response, never by
/// copying imported proposal bytes. Caller authentication is not established here.
pub struct Expected {
    pub identity: ExpectedIdentity,
    pub root_pin: [u8; 94],
    pub scope: Scope,
    pub captured_ms: u64,
}

/// An owned immutable inspection snapshot. It is neither a durable consumed
/// challenge nor proof that the server enrolled or still accepts this root.
pub struct ReviewedResume {
    statement: Statement,
    transcript: Vec<u8>,
    inspected_ms: u64,
}

fn positive(n: u64) -> bool {
    n > 0 && n <= i64::MAX as u64
}
fn validate_scope(s: &Scope) -> Result<()> {
    if [
        s.realm,
        s.broker,
        s.broker_session,
        s.authentication_event,
        s.account,
        s.owner,
        s.challenge,
    ]
    .contains(&[0; 16])
        || [s.nonce, s.browser_binding].contains(&[0; 32])
        || ![s.credential_revision, s.issued_ms, s.expires_ms]
            .into_iter()
            .all(positive)
        || s.expires_ms <= s.issued_ms
        || s.expires_ms - s.issued_ms > MAX_WINDOW_MS
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
    pub fn new(scope: Scope, root_pin: [u8; 94], fingerprint: [u8; 32]) -> Result<Self> {
        let value = Self {
            scope,
            root_pin,
            fingerprint,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        validate_scope(&self.scope)?;
        if sealed_root_enrollment::root_fingerprint(&self.root_pin, &self.scope.account)
            .map_err(|_| Error)?
            != self.fingerprint
        {
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
        &self.fingerprint
    }
}

/// Strict fixed-order big-endian public framing. No normalization or trailing data.
pub fn encode(s: &Statement) -> Result<Vec<u8>> {
    s.validate()?;
    let v = &s.scope;
    let mut bytes = Vec::with_capacity(FIXED + v.origin.len());
    bytes.extend_from_slice(b"ZTRW\x01");
    for id in [v.realm, v.broker, v.broker_session, v.authentication_event] {
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&v.credential_revision.to_be_bytes());
    for id in [v.account, v.owner, v.challenge] {
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&v.nonce);
    bytes.extend_from_slice(&v.browser_binding);
    bytes.extend_from_slice(&v.issued_ms.to_be_bytes());
    bytes.extend_from_slice(&v.expires_ms.to_be_bytes());
    bytes.extend_from_slice(&s.root_pin);
    bytes.extend_from_slice(&s.fingerprint);
    bytes.extend_from_slice(&(v.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(v.origin.as_bytes());
    Ok(bytes)
}

/// Decode claims only. Length is checked before any fixed-offset access.
pub fn decode(bytes: &[u8]) -> Result<Statement> {
    if !(FIXED + 1..=MAX_UNSIGNED).contains(&bytes.len()) || &bytes[..5] != b"ZTRW\x01" {
        return Err(Error);
    }
    let length = u16::from_be_bytes(bytes[331..333].try_into().map_err(|_| Error)?) as usize;
    if length == 0 || length > 512 || bytes.len() != FIXED + length {
        return Err(Error);
    }
    fn id<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
        bytes[at..at + N].try_into().map_err(|_| Error)
    }
    fn num(bytes: &[u8], at: usize) -> Result<u64> {
        Ok(u64::from_be_bytes(id(bytes, at)?))
    }
    let scope = Scope {
        realm: id(bytes, 5)?,
        broker: id(bytes, 21)?,
        broker_session: id(bytes, 37)?,
        authentication_event: id(bytes, 53)?,
        credential_revision: num(bytes, 69)?,
        account: id(bytes, 77)?,
        owner: id(bytes, 93)?,
        challenge: id(bytes, 109)?,
        nonce: id(bytes, 125)?,
        browser_binding: id(bytes, 157)?,
        issued_ms: num(bytes, 189)?,
        expires_ms: num(bytes, 197)?,
        origin: std::str::from_utf8(&bytes[FIXED..])
            .map_err(|_| Error)?
            .to_owned(),
    };
    Statement::new(scope, id(bytes, 205)?, id(bytes, 299)?)
}

/// Dedicated purpose plus u32 big-endian byte length and exact unsigned bytes.
pub fn transcript(unsigned: &[u8]) -> Result<Vec<u8>> {
    decode(unsigned)?;
    Ok([DOMAIN, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat())
}

pub fn inspect(unsigned: &[u8], expected: &Expected, now: u64) -> Result<ReviewedResume> {
    current(&expected.scope, expected.captured_ms)?;
    current(&expected.scope, now)?;
    let statement = decode(unsigned)?;
    if now < expected.captured_ms
        || statement.scope != expected.scope
        || statement.root_pin != expected.root_pin
        || expected.identity.account_id != statement.scope.account
        || expected.identity.origin != statement.scope.origin
        || expected.identity.root_fingerprint != statement.fingerprint
    {
        return Err(Error);
    }
    Ok(ReviewedResume {
        statement,
        transcript: transcript(unsigned)?,
        inspected_ms: now,
    })
}

/// Verify possession of an independently expected root and exact authenticated
/// challenge. This does not check enrollment/currentness or consume replay state.
pub fn verify(unsigned: &[u8], raw: &[u8], expected: &Expected, now: u64) -> Result<()> {
    let reviewed = inspect(unsigned, expected, now)?;
    let signature = Signature::from_slice(raw).map_err(|_| Error)?;
    if signature.normalize_s().to_bytes() != signature.to_bytes() {
        return Err(Error);
    }
    VerifyingKey::from_sec1_bytes(&reviewed.statement.root_pin[29..])
        .map_err(|_| Error)?
        .verify(&reviewed.transcript, &signature)
        .map_err(|_| Error)
}
impl ReviewedResume {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
    /// One typed offline signature after explicit consent and genuine recovery.
    /// Fresh trusted time must not regress behind the inspection snapshot.
    #[cfg(feature = "unlock")]
    pub fn sign(self, root: &RootSecret, now: u64) -> Result<[u8; 64]> {
        current(&self.statement.scope, now)?;
        if now < self.inspected_ms {
            return Err(Error);
        }
        let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if key.verifying_key().to_sec1_point(false).as_bytes() != &self.statement.root_pin[29..] {
            return Err(Error);
        }
        let signature: Signature = key.sign(&self.transcript);
        Ok(signature.normalize_s().to_bytes().into())
    }
    /// Trusted inspection time, not a server receipt or an authorization lifetime.
    pub fn inspected_ms(&self) -> u64 {
        self.inspected_ms
    }
}

#[cfg(test)]
mod tests;
