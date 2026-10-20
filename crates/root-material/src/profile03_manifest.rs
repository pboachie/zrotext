// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only public03 parsing, signature and narrow successor policy. This
//! module has no signing, secret, unlock, network, database or storage API.
//! Verified public bytes do not prove independent root selection, acceptance,
//! cookie/MFA, custody, current mutable permission or effect authority.
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
pub type Result<T> = std::result::Result<T, &'static str>;
const MAX: u64 = i64::MAX as u64;
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn number(bytes: &[u8]) -> Result<u64> {
    let n = u64::from_be_bytes(bytes.try_into().map_err(|_| "integer width")?);
    if n > MAX {
        return Err("signed storage range");
    }
    Ok(n)
}
fn positive(n: u64) -> Result<()> {
    if n == 0 || n > MAX {
        return Err("positive storage range");
    }
    Ok(())
}
fn framed(label: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).map_err(|_| "transcript bound")?;
    Ok([label, &len.to_be_bytes(), body].concat())
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
fn signature(point: &[u8], raw: &[u8], transcript: &[u8]) -> Result<()> {
    if point.len() != 65 || point[0] != 4 {
        return Err("signature point shape");
    }
    let sig = Signature::from_slice(raw).map_err(|_| "signature scalar/width")?;
    if sig.normalize_s().to_bytes().as_slice() != raw {
        return Err("received high-s signature");
    }
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| "signature point curve")?
        .verify(transcript, &sig)
        .map_err(|_| "signature verification")
}

/// Exact owned public candidate. Its getters expose wire data, not a selected
/// root, principal, permission, durable accepted record or possession of a key.
pub struct PossessionStatement03 {
    bytes: [u8; 513],
    ids: [[u8; 16]; 8],
    numbers: [u64; 7],
    digests: [[u8; 32]; 8],
    point: [u8; 65],
}
impl PossessionStatement03 {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 513 || &bytes[..8] != b"ZTMS\x01\x03\x03\0" {
            return Err("possession shape/profile");
        }
        let mut ids = [[0; 16]; 8];
        let mut numbers = [0; 7];
        let mut digests = [[0; 32]; 8];
        let mut at = 8;
        for id in &mut ids {
            id.copy_from_slice(&bytes[at..at + 16]);
            at += 16;
            if *id == [0; 16] {
                return Err("zero possession identity");
            }
        }
        for n in &mut numbers {
            *n = number(&bytes[at..at + 8])?;
            positive(*n)?;
            at += 8;
        }
        for digest in &mut digests {
            digest.copy_from_slice(&bytes[at..at + 32]);
            at += 32;
            if *digest == [0; 32] {
                return Err("zero possession digest");
            }
        }
        let point: [u8; 65] = bytes[at..].try_into().unwrap();
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| "possession curve")?;
        if point[0] != 4
            || key_id(5, &point) != digests[7]
            || numbers[1] != 1
            || numbers[2] != 1
            || numbers[3].checked_add(1) != Some(numbers[4])
            || numbers[6] <= numbers[5]
            || numbers[6] - numbers[5] > 300_000
            || ids[7] == ids[5]
            || ids[7] == ids[6]
        {
            return Err("possession scope/window");
        }
        Ok(Self {
            bytes: bytes.try_into().unwrap(),
            ids,
            numbers,
            digests,
            point,
        })
    }
    pub fn bytes(&self) -> &[u8; 513] {
        &self.bytes
    }
    /// account,user,ownerSession,device,line,binding,electionChallenge,opening.
    pub fn identities(&self) -> [[u8; 16]; 8] {
        self.ids
    }
    /// bindingGeneration,vaultGeneration,epoch,priorVersion,nextVersion,issued,expires.
    pub fn counters_and_window(&self) -> [u64; 7] {
        self.numbers
    }
    /// root,election,bundle,origin,ownerSession,priorSemantic,successorExact,role5ID.
    pub fn commitments(&self) -> [[u8; 32]; 8] {
        self.digests
    }
    pub fn browser_point(&self) -> [u8; 65] {
        self.point
    }
    pub fn transcript(&self) -> Vec<u8> {
        framed(
            b"ZTSE/line/payload-profile/manifest-install03/v1\0",
            &self.bytes,
        )
        .expect("fixed statement")
    }
    pub fn verify_signature(&self, raw: &[u8]) -> Result<()> {
        signature(&self.point, raw, &self.transcript())
    }
}

/// Independently selected retained root/highwater and original accepted time.
/// Copying these fields from an untrusted proposal supplies no such provenance.
pub struct Checkpoint03 {
    pub account_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub accepted_ms: u64,
}
pub struct VerifiedCheckpoint03 {
    pin: [u8; 94],
    signed: Vec<u8>,
    account: [u8; 16],
    root: [u8; 65],
    version: u64,
    digest: [u8; 32],
    accepted: u64,
    comparison: u64,
}
impl VerifiedCheckpoint03 {
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn accepted_ms(&self) -> u64 {
        self.accepted
    }
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account
    }
    pub fn root_pin(&self) -> &[u8; 94] {
        &self.pin
    }
}
struct Parsed03 {
    account: [u8; 16],
    root: [u8; 65],
    version: u64,
    issued: u64,
    expires: u64,
    previous: [u8; 32],
    predecessor_profile: u8,
    digest: [u8; 32],
}
fn records(unsigned: &[u8]) -> Result<Vec<&[u8]>> {
    if !(302..=9689).contains(&unsigned.len())
        || unsigned[..6] != *b"ZTMA\x03\x03"
        || unsigned.len() != 153 + 149 * usize::from(unsigned[152])
        || !(1..=64).contains(&unsigned[152])
    {
        return Err("manifest unsigned framing");
    }
    Ok(unsigned[153..].chunks_exact(149).collect())
}
fn parse_unsigned(bytes: &[u8], now: u64) -> Result<Parsed03> {
    positive(now)?;
    let records = records(bytes)?;
    if ![2, 3].contains(&bytes[6]) {
        return Err("manifest predecessor profile");
    }
    let account: [u8; 16] = bytes[7..23].try_into().unwrap();
    let generation = number(&bytes[23..31])?;
    let version = number(&bytes[31..39])?;
    let issued = number(&bytes[39..47])?;
    let expires = number(&bytes[47..55])?;
    if account == [0; 16]
        || generation != 1
        || version == 0
        || issued == 0
        || expires <= issued
        || expires - issued > 86_400_000
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err("manifest identity/window");
    }
    let root: [u8; 65] = bytes[87..152].try_into().unwrap();
    VerifyingKey::from_sec1_bytes(&root).map_err(|_| "manifest root curve")?;
    if root[0] != 4 {
        return Err("manifest root point");
    }
    let mut seen = HashSet::new();
    let mut prior = None;
    let (mut roots, mut archives) = (0, 0);
    for r in records {
        let role = r[0];
        let id: [u8; 32] = r[1..33].try_into().unwrap();
        let point: [u8; 65] = r[33..98].try_into().unwrap();
        let device: [u8; 16] = r[98..114].try_into().unwrap();
        let line: [u8; 16] = r[114..130].try_into().unwrap();
        let scope = u16::from_be_bytes(r[130..132].try_into().unwrap());
        let from = number(&r[132..140])?;
        let until = number(&r[140..148])?;
        let state = r[148];
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
            || ![1, 2].contains(&state)
            || prior.is_some_and(|p| p >= (role, id))
            || point[0] != 4
            || key_id(role, &point) != id
            || !seen.insert(point)
        {
            return Err("manifest record/scope/order/alias");
        }
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| "manifest key curve")?;
        prior = Some((role, id));
        if role == 6 {
            roots += 1;
            if point != root || state != 1 || from > issued || until < expires {
                return Err("manifest root record");
            }
        }
        if role == 2 && state == 1 {
            archives += 1;
        }
    }
    if roots != 1 || archives != 1 {
        return Err("manifest root/archive cardinality");
    }
    Ok(Parsed03 {
        account,
        root,
        version,
        issued,
        expires,
        previous: bytes[55..87].try_into().unwrap(),
        predecessor_profile: bytes[6],
        digest: hash(bytes),
    })
}
pub fn verify_checkpoint(
    pin: &[u8],
    signed: &[u8],
    selected: &Checkpoint03,
    comparison_ms: u64,
) -> Result<VerifiedCheckpoint03> {
    positive(selected.accepted_ms)?;
    positive(comparison_ms)?;
    if !(366..=9753).contains(&signed.len())
        || comparison_ms < selected.accepted_ms
        || crate::sealed_root_enrollment::root_fingerprint(pin, &selected.account_id)?
            != selected.root_fingerprint
    {
        return Err("manifest selected checkpoint/root");
    }
    let unsigned = &signed[..signed.len() - 64];
    let original = parse_unsigned(unsigned, selected.accepted_ms)?;
    if original.account != selected.account_id
        || original.root != pin[29..94]
        || original.version != selected.version
        || original.digest != selected.digest
    {
        return Err("manifest selected identity");
    }
    signature(
        &original.root,
        &signed[unsigned.len()..],
        &framed(b"ZTSE/manifest/v3\0", unsigned)?,
    )?;
    // This is historical public evidence, not current availability. Retain the
    // independently monotonic comparison, but verify original validity at the
    // actual accepted checkpoint so a cold process may renew expired history.
    Ok(VerifiedCheckpoint03 {
        pin: pin.try_into().map_err(|_| "root pin length")?,
        signed: signed.to_vec(),
        account: original.account,
        root: original.root,
        version: original.version,
        digest: original.digest,
        accepted: selected.accepted_ms,
        comparison: comparison_ms,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation03 {
    Enroll,
    Renew,
    Replace,
}
impl Operation03 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Renew => "renew",
            Self::Replace => "replace",
        }
    }
}

/// Explicitly UNSIGNED public review. It carries no valid successor signature,
/// signing approval, accepted root, durable installation or current permission.
pub struct UnsignedSuccessor03 {
    bytes: Vec<u8>,
    operation: Operation03,
    parsed: Parsed03,
    comparison: u64,
}
impl UnsignedSuccessor03 {
    pub fn unsigned(&self) -> &[u8] {
        &self.bytes
    }
    pub fn operation(&self) -> Operation03 {
        self.operation
    }
    pub fn version(&self) -> u64 {
        self.parsed.version
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.parsed.digest
    }
}
pub fn inspect_unsigned_successor(
    prior: &VerifiedCheckpoint03,
    unsigned: &[u8],
    line: &[u8; 16],
    browser_point: &[u8; 65],
    now: u64,
) -> Result<UnsignedSuccessor03> {
    if now < prior.comparison || line == &[0; 16] {
        return Err("successor selected clock/line");
    }
    VerifyingKey::from_sec1_bytes(browser_point).map_err(|_| "successor browser curve")?;
    let parsed = parse_unsigned(unsigned, now)?;
    if parsed.issued > now
        || parsed.predecessor_profile != 3
        || parsed.account != prior.account
        || parsed.root != prior.root
        || prior.version.checked_add(1) != Some(parsed.version)
        || parsed.previous != prior.digest
    {
        return Err("successor root/chain/window");
    }
    let operation = record_policy(
        &prior.signed[..prior.signed.len() - 64],
        unsigned,
        line,
        browser_point,
        &key_id(5, browser_point),
        now,
        parsed.expires,
    )?;
    let selected: Vec<_> = records(unsigned)?
        .into_iter()
        .filter(|r| r[0] == 1 && r[114..130] == *line && r[148] == 1)
        .collect();
    if selected.len() != 1
        || number(&selected[0][132..140])? > now
        || number(&selected[0][140..148])? <= now
    {
        return Err("successor live selected reader");
    }
    Ok(UnsignedSuccessor03 {
        bytes: unsigned.to_vec(),
        operation,
        parsed,
        comparison: now,
    })
}
pub struct VerifiedSuccessor03 {
    checkpoint: VerifiedCheckpoint03,
    operation: Operation03,
}
impl VerifiedSuccessor03 {
    pub fn checkpoint(&self) -> &VerifiedCheckpoint03 {
        &self.checkpoint
    }
    pub fn into_checkpoint(self) -> VerifiedCheckpoint03 {
        self.checkpoint
    }
    pub fn operation(&self) -> Operation03 {
        self.operation
    }
}
pub fn verify_successor(
    prior: &VerifiedCheckpoint03,
    signed: &[u8],
    line: &[u8; 16],
    browser_point: &[u8; 65],
    now: u64,
) -> Result<VerifiedSuccessor03> {
    if !(366..=9753).contains(&signed.len()) {
        return Err("successor signed bound");
    }
    let review = inspect_unsigned_successor(
        prior,
        &signed[..signed.len() - 64],
        line,
        browser_point,
        now,
    )?;
    signature(
        &prior.root,
        &signed[signed.len() - 64..],
        &framed(b"ZTSE/manifest/v3\0", review.unsigned())?,
    )?;
    Ok(VerifiedSuccessor03 {
        operation: review.operation,
        checkpoint: VerifiedCheckpoint03 {
            pin: prior.pin,
            signed: signed.to_vec(),
            account: review.parsed.account,
            root: review.parsed.root,
            version: review.parsed.version,
            digest: review.parsed.digest,
            accepted: now,
            comparison: review.comparison,
        },
    })
}
#[cfg(test)]
mod tests;

fn record_policy(
    old: &[u8],
    new: &[u8],
    line: &[u8; 16],
    point: &[u8; 65],
    key: &[u8; 32],
    now: u64,
    expires: u64,
) -> Result<Operation03> {
    let prior = records(old)?;
    let next = records(new)?;
    let selected: Vec<_> = prior
        .iter()
        .copied()
        .filter(|r| r[0] == 5 && r[114..130] == *line && r[148] == 1)
        .collect();
    if selected.len() > 1 {
        return Err("manifest browser signer ambiguity");
    }
    let additions: Vec<_> = next
        .iter()
        .copied()
        .filter(|r| !prior.iter().any(|old| old[..33] == r[..33]))
        .collect();
    let operation = match (selected.first(), additions.as_slice()) {
        (None, [_]) => Operation03::Enroll,
        (Some(old), []) if old[1..33] == *key && old[33..98] == *point => Operation03::Renew,
        (Some(old), [_]) if old[1..33] != *key && old[33..98] != *point => Operation03::Replace,
        _ => return Err("manifest browser enrollment shape"),
    };
    if next.len() != prior.len() + usize::from(operation != Operation03::Renew) {
        return Err("manifest removed authority");
    }
    for old in prior {
        let row = next
            .iter()
            .copied()
            .find(|r| r[..33] == old[..33])
            .ok_or("manifest removed original key")?;
        if operation == Operation03::Replace
            && selected.first().is_some_and(|r| r[..33] == old[..33])
        {
            if row[..148] != old[..148] || row[148] != 2 {
                return Err("manifest replacement historical key");
            }
        } else if old[148] != 1 {
            if row != old {
                return Err("manifest inactive key changed");
            }
        } else {
            let before = number(&old[140..148])?;
            let until = number(&row[140..148])?;
            if row[..140] != old[..140] || row[148] != old[148] || until < before || until > expires
            {
                return Err("manifest unrelated authority/window changed");
            }
        }
    }
    let current: Vec<_> = next
        .iter()
        .copied()
        .filter(|r| r[0] == 5 && r[114..130] == *line && r[148] == 1)
        .collect();
    if current.len() != 1 {
        return Err("manifest current browser signer count");
    }
    let signer = current[0];
    let from = number(&signer[132..140])?;
    let until = number(&signer[140..148])?;
    if signer[1..33] != *key
        || signer[33..98] != *point
        || signer[98..114] != [0; 16]
        || signer[130..132] != [0, 1]
        || from > now
        || until <= now
        || until > expires
    {
        return Err("manifest current browser signer scope");
    }
    if let Some(added) = additions.first() {
        let issued = number(&new[39..47])?;
        if *added != signer || from < issued {
            return Err("manifest unrelated new key");
        }
    }
    Ok(operation)
}
