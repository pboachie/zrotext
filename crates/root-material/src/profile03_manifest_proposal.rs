// SPDX-License-Identifier: AGPL-3.0-only
//! Purpose-bound offline browser-signer enrollment/renewal/replacement.
//! Public review is not accepted ancestry, owner authentication or permission.
use crate::{
    profile03_manifest::{self as policy, Checkpoint03, Operation03, VerifiedCheckpoint03},
    root_backup::ExpectedIdentity,
    sealed_root_enrollment::canonical_origin,
};
use sha2::{Digest, Sha256};

const MAX_PACKET: usize = 20_480;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("offline profile03 manifest proposal refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Independently compared intent and retained original high-water. Never copy
/// this from the downloaded proposal to manufacture an expected context.
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub operation: Operation03,
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub origin: String,
    pub fingerprint: [u8; 32],
    pub predecessor_version: u64,
    pub predecessor_digest: [u8; 32],
    pub predecessor_accepted_ms: u64,
    pub phone_reader: [u8; 32],
    pub browser_point: [u8; 65],
    pub browser_key: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone)]
pub struct Expected {
    pub identity: ExpectedIdentity,
    /// Existing independently selected public card, not a proposal field.
    pub root_pin: [u8; 94],
    pub scope: Scope,
}
#[derive(Clone)]
pub struct Proposal {
    scope: Scope,
    predecessor: Vec<u8>,
    unsigned: Vec<u8>,
}
impl Proposal {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn predecessor(&self) -> &[u8] {
        &self.predecessor
    }
    pub fn unsigned(&self) -> &[u8] {
        &self.unsigned
    }
}
/// Immutable reviewed intent. No Clone, signing method or approval flag. The
/// unlock-only signing function consumes it and rechecks the actual clock.
pub struct Reviewed {
    proposal: Proposal,
    expected: Expected,
    last_checked_ms: u64,
}
impl Reviewed {
    pub fn scope(&self) -> &Scope {
        self.proposal.scope()
    }
    pub fn unsigned(&self) -> &[u8] {
        self.proposal.unsigned()
    }
    /// Fresh post-consent clock check; never supplies signing permission.
    pub fn recheck(&mut self, now: u64) -> Result<()> {
        if now < self.last_checked_ms {
            return Err(Error);
        }
        verify(&self.proposal, &self.expected, now)?;
        self.last_checked_ms = now;
        Ok(())
    }
}
fn positive(value: u64) -> Result<()> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(Error);
    }
    Ok(())
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn validate(scope: &Scope) -> Result<()> {
    if [scope.account, scope.device, scope.line].contains(&[0; 16])
        || [
            scope.fingerprint,
            scope.predecessor_digest,
            scope.phone_reader,
            scope.browser_key,
        ]
        .contains(&[0; 32])
        || scope.origin.len() > 512
        || !canonical_origin(&scope.origin)
        || scope.browser_point[0] != 4
        || scope.expires_ms <= scope.issued_ms
        || scope.expires_ms - scope.issued_ms > 86_400_000
    {
        return Err(Error);
    }
    for value in [
        scope.predecessor_version,
        scope.predecessor_accepted_ms,
        scope.issued_ms,
        scope.expires_ms,
    ] {
        positive(value)?;
    }
    let key_input = [b"ZTSE/key/v1\0".as_slice(), &[1, 1], &scope.browser_point].concat();
    if hash(&key_input) != scope.browser_key {
        return Err(Error);
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&scope.browser_point).map_err(|_| Error)?;
    Ok(())
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(size).ok_or(Error)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error)?;
        self.at = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error)
    }
    fn number(&mut self) -> Result<u64> {
        let n = u64::from_be_bytes(self.array()?);
        positive(n)?;
        Ok(n)
    }
    fn sized(&mut self, maximum: usize) -> Result<Vec<u8>> {
        let size = usize::from(u16::from_be_bytes(self.array()?));
        if size > maximum {
            return Err(Error);
        }
        Ok(self.take(size)?.to_vec())
    }
}
/// Closed public ZTMU01: magic5, operation1, account/device/line16 each,
/// canonical origin u16+ASCII, root fingerprint32, original version u64,
/// digest32, original accepted_ms u64, phone reader32, browser point65 and
/// keyID32, issue/expiry u64 each, signed predecessor u16+bytes, unsigned
/// successor u16+bytes. No private key, credentials, JSON or trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<Proposal> {
    if bytes.len() > MAX_PACKET {
        return Err(Error);
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(5)? != b"ZTMU\x01" {
        return Err(Error);
    }
    let operation = match c.take(1)?[0] {
        1 => Operation03::Enroll,
        2 => Operation03::Renew,
        3 => Operation03::Replace,
        _ => return Err(Error),
    };
    let account = c.array()?;
    let device = c.array()?;
    let line = c.array()?;
    let origin = String::from_utf8(c.sized(512)?).map_err(|_| Error)?;
    let scope = Scope {
        operation,
        account,
        device,
        line,
        origin,
        fingerprint: c.array()?,
        predecessor_version: c.number()?,
        predecessor_digest: c.array()?,
        predecessor_accepted_ms: c.number()?,
        phone_reader: c.array()?,
        browser_point: c.array()?,
        browser_key: c.array()?,
        issued_ms: c.number()?,
        expires_ms: c.number()?,
    };
    validate(&scope)?;
    let predecessor = c.sized(9753)?;
    let unsigned = c.sized(9689)?;
    if c.at != bytes.len() || predecessor.len() < 366 || unsigned.len() < 302 {
        return Err(Error);
    }
    Ok(Proposal {
        scope,
        predecessor,
        unsigned,
    })
}
fn verify(proposal: &Proposal, expected: &Expected, now: u64) -> Result<VerifiedCheckpoint03> {
    validate(&expected.scope)?;
    positive(now)?;
    let scope = proposal.scope();
    if *scope != expected.scope
        || scope.account != expected.identity.account_id
        || scope.origin != expected.identity.origin
        || scope.fingerprint != expected.identity.root_fingerprint
        || scope.issued_ms > now
        || now >= scope.expires_ms
        || now - scope.issued_ms >= 300_000
    {
        return Err(Error);
    }
    let prior = policy::verify_checkpoint(
        &expected.root_pin,
        proposal.predecessor(),
        &Checkpoint03 {
            account_id: scope.account,
            root_fingerprint: scope.fingerprint,
            version: scope.predecessor_version,
            digest: scope.predecessor_digest,
            accepted_ms: scope.predecessor_accepted_ms,
        },
        now,
    )
    .map_err(|_| Error)?;
    let review = policy::inspect_unsigned_successor(
        &prior,
        proposal.unsigned(),
        &scope.line,
        &scope.browser_point,
        now,
    )
    .map_err(|_| Error)?;
    if review.operation() != scope.operation
        || proposal.unsigned()[39..47] != scope.issued_ms.to_be_bytes()
        || proposal.unsigned()[47..55] != scope.expires_ms.to_be_bytes()
    {
        return Err(Error);
    }
    let selected: Vec<_> = proposal.unsigned()[153..]
        .as_chunks::<149>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .filter(|record| {
            record[0] == 1
                && record[1..33] == scope.phone_reader
                && record[98..114] == scope.device
                && record[114..130] == scope.line
                && record[148] == 1
        })
        .collect();
    // Full record grammar/scope and live selected line reader were checked by
    // shared policy; this binds that reader to the independently selected phone.
    if selected.len() != 1 {
        return Err(Error);
    }
    Ok(prior)
}
/// Inspect before asking for one explicit offline signing decision. No sign,
/// recovery, enrollment or permission follows from successful public review.
pub fn inspect(proposal: &Proposal, expected: &Expected, now: u64) -> Result<Reviewed> {
    verify(proposal, expected, now)?;
    Ok(Reviewed {
        proposal: proposal.clone(),
        expected: expected.clone(),
        last_checked_ms: now,
    })
}
/// Public returned artifact verification against the exact reviewed unsigned
/// bytes and independently selected root/checkpoint. Does not prove acceptance.
pub fn verify_signed(
    proposal: &Proposal,
    expected: &Expected,
    signed: &[u8],
    now: u64,
) -> Result<()> {
    let prior = verify(proposal, expected, now)?;
    if signed.len() != proposal.unsigned().len() + 64
        || &signed[..signed.len() - 64] != proposal.unsigned()
    {
        return Err(Error);
    }
    let checked = policy::verify_successor(
        &prior,
        signed,
        &expected.scope.line,
        &expected.scope.browser_point,
        now,
    )
    .map_err(|_| Error)?;
    if checked.operation() != expected.scope.operation {
        return Err(Error);
    }
    Ok(())
}
/// One typed recovered-root signature, compiled only for offline unlock builds.
/// The caller supplies explicit approval; no general byte-signing API exists.
#[cfg(feature = "unlock")]
pub fn sign(
    root: &crate::root_backup::RootSecret,
    mut reviewed: Reviewed,
    now: u64,
) -> Result<Vec<u8>> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    reviewed.recheck(now)?;
    let key = SigningKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
    if key.verifying_key().to_sec1_point(false).as_bytes() != &reviewed.expected.root_pin[29..94] {
        return Err(Error);
    }
    let unsigned = reviewed.proposal.unsigned();
    let transcript = [
        b"ZTSE/manifest/v3\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        unsigned,
    ]
    .concat();
    let signature: Signature = key.sign(&transcript);
    let mut signed = unsigned.to_vec();
    signed.extend_from_slice(&signature.normalize_s().to_bytes());
    verify_signed(&reviewed.proposal, &reviewed.expected, &signed, now)?;
    Ok(signed)
}
#[cfg(test)]
mod tests;
