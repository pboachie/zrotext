// SPDX-License-Identifier: AGPL-3.0-only
//! Closed pre-account root possession evidence, never staging authority.
//! Expected context, trusted time, recovery/consent and one-use state are caller
//! obligations. Signing is available only in the existing offline unlock build.
use crate::sealed_root_enrollment::{canonical_origin, root_fingerprint};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
#[cfg(feature = "unlock")]
use {
    crate::root_backup::RootSecret,
    p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::sec1::ToSec1Point,
    },
};

const INTENT_DOMAIN: &[u8] = b"ZTSE/preaccount-intent/v1\0";
const ROOT_DOMAIN: &[u8] = b"ZTSE/preaccount-root/v1\0";
pub const INTENT_FIXED: usize = 354;
pub const INTENT_MIN: usize = INTENT_FIXED + 1;
pub const INTENT_MAX: usize = INTENT_FIXED + 512;
pub const CHALLENGE_SIZE: usize = 122;
pub const EVIDENCE_MIN: usize = 2 + INTENT_MIN + CHALLENGE_SIZE + 64;
pub const EVIDENCE_MAX: usize = 2 + INTENT_MAX + CHALLENGE_SIZE + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("pre-account root evidence refused")]
pub struct Error;
type Result<T> = std::result::Result<T, Error>;

/// Public commitments, not accepted policy/custody, account or stage authority.
#[derive(Clone, PartialEq, Eq)]
pub struct Intent {
    pub epoch: [u8; 16],
    pub allocation: u64,
    pub account: [u8; 16],
    pub user: [u8; 16],
    pub approval: [u8; 16],
    pub origin: String,
    pub root_pin: [u8; 94],
    pub root_fingerprint: [u8; 32],
    pub backup: [u8; 16],
    pub backup_digest: [u8; 32],
    pub card_digest: [u8; 32],
    pub managed_plan_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub deadline_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Challenge {
    pub epoch: [u8; 16],
    pub allocation: u64,
    pub intent_digest: [u8; 32],
    pub id: [u8; 16],
    pub nonce: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}

/// Every field must come from independent intended context, not received proof.
#[derive(Clone)]
pub struct ExpectedStageRoot {
    pub intent: Intent,
    pub challenge: Challenge,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceIdentity {
    pub epoch: [u8; 16],
    pub allocation: u64,
    pub account: [u8; 16],
    pub user: [u8; 16],
    pub approval: [u8; 16],
    pub challenge: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub intent_digest: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}

/// Private construction proves signature/binding only; no authority conversion.
pub struct VerifiedStageRootEvidence {
    identity: EvidenceIdentity,
}
impl VerifiedStageRootEvidence {
    pub fn kind(&self) -> &'static str {
        "cryptographic_signed_evidence"
    }
    pub fn identity(&self) -> EvidenceIdentity {
        self.identity.clone()
    }
}

macro_rules! redacted {
    ($($t:ty),+ $(,)?) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($t), "([REDACTED])"))
            }
        }
    )+};
}
redacted!(
    Intent,
    Challenge,
    ExpectedStageRoot,
    EvidenceIdentity,
    VerifiedStageRootEvidence
);

fn positive(n: u64) -> bool {
    n > 0 && n <= i64::MAX as u64
}
fn validate_intent(i: &Intent) -> Result<()> {
    if [i.epoch, i.account, i.user, i.approval, i.backup].contains(&[0; 16])
        || !positive(i.allocation)
        || !positive(i.deadline_ms)
        || !canonical_origin(&i.origin)
        || root_fingerprint(&i.root_pin, &i.account).map_err(|_| Error)? != i.root_fingerprint
    {
        return Err(Error);
    }
    Ok(())
}
fn validate_challenge(c: &Challenge) -> Result<()> {
    if [c.epoch, c.id].contains(&[0; 16])
        || c.nonce == [0; 32]
        || ![c.allocation, c.issued_ms, c.expires_ms]
            .into_iter()
            .all(positive)
        || c.expires_ms <= c.issued_ms
        || c.expires_ms - c.issued_ms > 300_000
    {
        return Err(Error);
    }
    Ok(())
}

pub fn encode_intent(i: &Intent) -> Result<Vec<u8>> {
    validate_intent(i)?;
    let mut b = Vec::with_capacity(INTENT_FIXED + i.origin.len());
    b.extend_from_slice(&[1, 1]);
    b.extend_from_slice(&i.epoch);
    b.extend_from_slice(&i.allocation.to_be_bytes());
    for id in [&i.account, &i.user, &i.approval] {
        b.extend_from_slice(id);
    }
    b.extend_from_slice(&(i.origin.len() as u16).to_be_bytes());
    b.extend_from_slice(i.origin.as_bytes());
    b.extend_from_slice(&i.root_pin);
    b.extend_from_slice(&i.root_fingerprint);
    b.extend_from_slice(&i.backup);
    for digest in [
        &i.backup_digest,
        &i.card_digest,
        &i.managed_plan_digest,
        &i.policy_digest,
    ] {
        b.extend_from_slice(digest);
    }
    b.extend_from_slice(&i.deadline_ms.to_be_bytes());
    Ok(b)
}
fn field<const N: usize>(b: &[u8], offset: usize) -> Result<[u8; N]> {
    b.get(offset..offset.checked_add(N).ok_or(Error)?)
        .ok_or(Error)?
        .try_into()
        .map_err(|_| Error)
}
pub fn decode_intent(b: &[u8]) -> Result<Intent> {
    if !(INTENT_MIN..=INTENT_MAX).contains(&b.len()) || b[..2] != [1, 1] {
        return Err(Error);
    }
    let n = u16::from_be_bytes(field(b, 74)?) as usize;
    if !(1..=512).contains(&n) || b.len() != INTENT_FIXED + n {
        return Err(Error);
    }
    let i = Intent {
        epoch: field(b, 2)?,
        allocation: u64::from_be_bytes(field(b, 18)?),
        account: field(b, 26)?,
        user: field(b, 42)?,
        approval: field(b, 58)?,
        origin: std::str::from_utf8(&b[76..76 + n])
            .map_err(|_| Error)?
            .to_owned(),
        root_pin: field(b, 76 + n)?,
        root_fingerprint: field(b, 170 + n)?,
        backup: field(b, 202 + n)?,
        backup_digest: field(b, 218 + n)?,
        card_digest: field(b, 250 + n)?,
        managed_plan_digest: field(b, 282 + n)?,
        policy_digest: field(b, 314 + n)?,
        deadline_ms: u64::from_be_bytes(field(b, 346 + n)?),
    };
    validate_intent(&i)?;
    Ok(i)
}
pub fn intent_digest(b: &[u8]) -> Result<[u8; 32]> {
    decode_intent(b)?;
    let mut hash = Sha256::new();
    hash.update(INTENT_DOMAIN);
    hash.update((b.len() as u32).to_be_bytes());
    hash.update(b);
    Ok(hash.finalize().into())
}
pub fn encode_challenge(c: &Challenge) -> Result<Vec<u8>> {
    validate_challenge(c)?;
    let mut b = Vec::with_capacity(CHALLENGE_SIZE);
    b.extend_from_slice(&[1, 1]);
    b.extend_from_slice(&c.epoch);
    b.extend_from_slice(&c.allocation.to_be_bytes());
    b.extend_from_slice(&c.intent_digest);
    b.extend_from_slice(&c.id);
    b.extend_from_slice(&c.nonce);
    b.extend_from_slice(&c.issued_ms.to_be_bytes());
    b.extend_from_slice(&c.expires_ms.to_be_bytes());
    Ok(b)
}
pub fn decode_challenge(b: &[u8]) -> Result<Challenge> {
    if b.len() != CHALLENGE_SIZE || b[..2] != [1, 1] {
        return Err(Error);
    }
    let c = Challenge {
        epoch: field(b, 2)?,
        allocation: u64::from_be_bytes(field(b, 18)?),
        intent_digest: field(b, 26)?,
        id: field(b, 58)?,
        nonce: field(b, 74)?,
        issued_ms: u64::from_be_bytes(field(b, 106)?),
        expires_ms: u64::from_be_bytes(field(b, 114)?),
    };
    validate_challenge(&c)?;
    Ok(c)
}
fn bound(i: &Intent, c: &Challenge, ib: &[u8]) -> Result<()> {
    if c.epoch != i.epoch
        || c.allocation != i.allocation
        || c.intent_digest != intent_digest(ib)?
        || c.expires_ms > i.deadline_ms
    {
        return Err(Error);
    }
    Ok(())
}
fn current(c: &Challenge, now: u64) -> Result<()> {
    if !positive(now) || now < c.issued_ms || now >= c.expires_ms {
        return Err(Error);
    }
    Ok(())
}
fn intended(i: &Intent, c: &Challenge, e: &ExpectedStageRoot, ib: &[u8], now: u64) -> Result<()> {
    if i != &e.intent || c != &e.challenge {
        return Err(Error);
    }
    bound(i, c, ib)?;
    current(c, now)
}
fn transcript(ib: &[u8], cb: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(ROOT_DOMAIN.len() + 8 + ib.len() + cb.len());
    b.extend_from_slice(ROOT_DOMAIN);
    b.extend_from_slice(&(ib.len() as u32).to_be_bytes());
    b.extend_from_slice(ib);
    b.extend_from_slice(&(CHALLENGE_SIZE as u32).to_be_bytes());
    b.extend_from_slice(cb);
    b
}
fn canonical_signature(raw: &[u8]) -> Result<Signature> {
    let signature = Signature::from_slice(raw).map_err(|_| Error)?;
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92,
        0xa8,
    ];
    if &raw[32..] > HALF_ORDER.as_slice() {
        return Err(Error);
    }
    Ok(signature)
}
pub fn encode_evidence(i: &Intent, c: &Challenge, signature: &[u8; 64]) -> Result<Vec<u8>> {
    let ib = encode_intent(i)?;
    let cb = encode_challenge(c)?;
    bound(i, c, &ib)?;
    canonical_signature(signature)?;
    let mut b = Vec::with_capacity(2 + ib.len() + CHALLENGE_SIZE + 64);
    b.extend_from_slice(&(ib.len() as u16).to_be_bytes());
    b.extend_from_slice(&ib);
    b.extend_from_slice(&cb);
    b.extend_from_slice(signature);
    Ok(b)
}

/// Verifies exact independent context and signed intervals; consumes no state.
pub fn verify(
    b: &[u8],
    expected: &ExpectedStageRoot,
    trusted_now_ms: u64,
) -> Result<VerifiedStageRootEvidence> {
    if !(EVIDENCE_MIN..=EVIDENCE_MAX).contains(&b.len()) {
        return Err(Error);
    }
    let n = u16::from_be_bytes(field(b, 0)?) as usize;
    if !(INTENT_MIN..=INTENT_MAX).contains(&n) || b.len() != 2 + n + CHALLENGE_SIZE + 64 {
        return Err(Error);
    }
    let ib = &b[2..2 + n];
    let cb = &b[2 + n..2 + n + CHALLENGE_SIZE];
    let i = decode_intent(ib)?;
    let c = decode_challenge(cb)?;
    intended(&i, &c, expected, ib, trusted_now_ms)?;
    let signature = canonical_signature(&b[2 + n + CHALLENGE_SIZE..])?;
    VerifyingKey::from_sec1_bytes(&i.root_pin[29..])
        .map_err(|_| Error)?
        .verify(&transcript(ib, cb), &signature)
        .map_err(|_| Error)?;
    Ok(VerifiedStageRootEvidence {
        identity: EvidenceIdentity {
            epoch: i.epoch,
            allocation: i.allocation,
            account: i.account,
            user: i.user,
            approval: i.approval,
            challenge: c.id,
            root_fingerprint: i.root_fingerprint,
            intent_digest: c.intent_digest,
            issued_ms: c.issued_ms,
            expires_ms: c.expires_ms,
        },
    })
}

/// One owned, reviewed stage snapshot; available only in the offline unlock build.
#[cfg(feature = "unlock")]
pub struct ReviewedStageRoot {
    intent: Intent,
    challenge: Challenge,
    ib: Vec<u8>,
    cb: Vec<u8>,
    inspected_ms: u64,
}
#[cfg(feature = "unlock")]
redacted!(ReviewedStageRoot);
#[cfg(feature = "unlock")]
impl ReviewedStageRoot {
    pub fn inspect(
        ib: &[u8],
        cb: &[u8],
        expected: &ExpectedStageRoot,
        trusted_now_ms: u64,
    ) -> Result<Self> {
        let intent = decode_intent(ib)?;
        let challenge = decode_challenge(cb)?;
        intended(&intent, &challenge, expected, ib, trusted_now_ms)?;
        Ok(Self {
            intent,
            challenge,
            ib: ib.to_vec(),
            cb: cb.to_vec(),
            inspected_ms: trusted_now_ms,
        })
    }
    /// Consumes this review. Caller separately enforces consent, custody, fresh
    /// output time/cancellation and the server's actual one-use challenge state.
    pub fn sign(self, root: &RootSecret, fresh_now_ms: u64) -> Result<Vec<u8>> {
        if fresh_now_ms < self.inspected_ms {
            return Err(Error);
        }
        current(&self.challenge, fresh_now_ms)?;
        bound(&self.intent, &self.challenge, &self.ib)?;
        // Internal ephemeral maintained key copies; no scalar/key return API.
        let secret = p256::SecretKey::from_slice(root.as_bytes()).map_err(|_| Error)?;
        if secret.public_key().to_sec1_point(false).as_bytes() != &self.intent.root_pin[29..] {
            return Err(Error);
        }
        let key = SigningKey::from(secret);
        let signature: Signature = key.sign(&transcript(&self.ib, &self.cb));
        let signature = signature.normalize_s();
        let mut raw = [0; 64];
        raw.copy_from_slice(signature.to_bytes().as_slice());
        encode_evidence(&self.intent, &self.challenge, &raw)
    }
}

#[cfg(test)]
mod tests;
