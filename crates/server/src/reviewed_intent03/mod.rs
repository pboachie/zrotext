// SPDX-License-Identifier: AGPL-3.0-only
//! Exact ZTRI01 syntax and cryptography, composed only with separately held
//! current owner/interval/device authority by the admission adapter. A decoded
//! object or valid signature never authenticates its own database provenance.
use crate::sealed_manifest03::{self as crypto, Authorization03, Check, VerifiedManifest03};
use crate::sealed_payload_election03::{self as election, CurrentAuthority03, VerifiedElection03};
use uuid::Uuid;

const HEADER: &[u8; 8] = b"ZTRI\x01\x03\x03\0";
const DOMAIN: &[u8] = b"zrotext/conversation/reviewed-send03/v1\0";

/// Owned structural candidate. Routing getters select records to authenticate;
/// they never establish that those records or received sessions are current.
pub struct Intent03 {
    bytes: Vec<u8>,
    ids: [[u8; 16]; 8],
    numbers: [u64; 8],
    digests: [[u8; 32]; 11],
    peer: Vec<u8>,
    recipients: Vec<(u8, [u8; 32])>,
    ceiling: u8,
}
impl std::fmt::Debug for Intent03 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intent03").finish_non_exhaustive()
    }
}
fn nonzero(bytes: &[u8]) -> Check<()> {
    if bytes.iter().all(|b| *b == 0) {
        return Err("review zero identity/digest");
    }
    Ok(())
}
impl Intent03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        if !(624..=835).contains(&bytes.len()) || &bytes[..8] != HEADER {
            return Err("review shape/profile");
        }
        let mut ids = [[0; 16]; 8];
        let mut numbers = [0; 8];
        let mut digests = [[0; 32]; 11];
        let mut at = 8;
        for id in &mut ids {
            id.copy_from_slice(&bytes[at..at + 16]);
            nonzero(id)?;
            at += 16;
        }
        for n in &mut numbers {
            *n = crypto::number(&bytes[at..at + 8])?;
            crypto::time(*n)?;
            at += 8;
        }
        for d in &mut digests {
            d.copy_from_slice(&bytes[at..at + 32]);
            nonzero(d)?;
            at += 32;
        }
        let peer_len = usize::from(bytes[at]);
        at += 1;
        let peer = bytes.get(at..at + peer_len).ok_or("review peer framing")?;
        if !(3..=16).contains(&peer.len())
            || peer[0] != b'+'
            || !(b'1'..=b'9').contains(&peer[1])
            || !peer[2..].iter().all(u8::is_ascii_digit)
        {
            return Err("review peer");
        }
        at += peer_len;
        let count = usize::from(*bytes.get(at).ok_or("review recipients")?);
        at += 1;
        if !(2..=8).contains(&count) || at + 33 * count + 1 != bytes.len() {
            return Err("review recipients/trailing");
        }
        let mut recipients = Vec::with_capacity(count);
        let (mut devices, mut archives) = (0, 0);
        for _ in 0..count {
            let role = bytes[at];
            let id: [u8; 32] = bytes[at + 1..at + 33].try_into().unwrap();
            nonzero(&id)?;
            if !(1..=3).contains(&role)
                || recipients.last().is_some_and(|prior| *prior >= (role, id))
            {
                return Err("review reader order/role");
            }
            devices += usize::from(role == 1);
            archives += usize::from(role == 2);
            recipients.push((role, id));
            at += 33;
        }
        let ceiling = bytes[at];
        if devices != 1
            || archives != 1
            || !recipients.contains(&(1, digests[0]))
            || !(1..=6).contains(&ceiling)
        {
            return Err("review reader/ceiling policy");
        }
        let [_, _, _, _, observed, expires, issued, review_expires] = numbers;
        if numbers[1] != 1
            || numbers[3] != 1
            || observed > issued
            || issued >= review_expires
            || review_expires > expires
            || review_expires - issued > 30_000
            || expires - observed > 900_000
        {
            return Err("review lifetime");
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            ids,
            numbers,
            digests,
            peer: peer.to_vec(),
            recipients,
            ceiling,
        })
    }
    pub fn account_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[0])
    }
    pub fn line_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[2])
    }
    pub fn interval_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[6])
    }
    pub fn message_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[7])
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sms_ceiling(&self) -> u8 {
        self.ceiling
    }
    pub fn transcript(&self) -> Vec<u8> {
        crypto::framed(DOMAIN, &self.bytes).expect("bounded intent")
    }
}

/// Internal composition inputs must be derived from actual locked readers.
/// This cryptographic verifier cannot prove authentication or storage by type.
pub(crate) struct ExpectedReview03<'a> {
    pub current: &'a CurrentAuthority03,
    pub election: &'a VerifiedElection03,
    pub manifest: &'a VerifiedManifest03,
    pub selection_epoch: u64,
    pub user: Uuid,
    pub session: Uuid,
    pub canonical_origin: &'a str,
    pub interval: Uuid,
    pub interval_starts_ms: u64,
    pub interval_expires_ms: u64,
    pub peer: &'a [u8],
    pub signer: &'a [u8; 32],
    pub recipients: &'a [(u8, [u8; 32])],
}

/// Exact verified candidate bytes only, not a committed admission or radio
/// permit. Keep immutable originals for idempotency and receiver verification.
pub(crate) struct VerifiedReview03 {
    intent: Intent03,
    signature: [u8; 64],
    envelope: crate::sealed_envelope03::VerifiedEnvelope03,
}
impl VerifiedReview03 {
    pub(crate) fn intent(&self) -> &Intent03 {
        &self.intent
    }
    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub(crate) fn envelope(&self) -> &crate::sealed_envelope03::VerifiedEnvelope03 {
        &self.envelope
    }
    pub(crate) fn expires_ms(&self) -> u64 {
        self.intent.numbers[5]
    }
    pub(crate) fn body_digest(&self) -> &[u8; 32] {
        &self.intent.digests[10]
    }
}

pub(crate) fn verify(
    intent: Intent03,
    signature: &[u8],
    envelope: &[u8],
    expected: &ExpectedReview03<'_>,
    now: u64,
) -> Check<VerifiedReview03> {
    let c = election::require_current(expected.election, expected.manifest, expected.current, now)?;
    crypto::time(expected.selection_epoch)?;
    crypto::time(expected.interval_starts_ms)?;
    crypto::time(expected.interval_expires_ms)?;
    if expected.user.is_nil()
        || expected.session.is_nil()
        || expected.interval.is_nil()
        || now < expected.interval_starts_ms
        || now >= expected.interval_expires_ms
    {
        return Err("review approved interval");
    }
    let owner = election::adapter_contract::OwnerSessionIdentity03 {
        account_id: c.account_id,
        user_id: *expected.user.as_bytes(),
        session_id: *expected.session.as_bytes(),
    }
    .digest()?;
    let origin = election::adapter_contract::origin_digest(expected.canonical_origin)?;
    if intent.ids[..7]
        != [
            c.account_id,
            c.device_id,
            c.line_id,
            c.binding_id,
            *expected.user.as_bytes(),
            *expected.session.as_bytes(),
            *expected.interval.as_bytes(),
        ]
        || intent.numbers[..4]
            != [
                c.binding_generation,
                c.vault_generation,
                c.manifest_version,
                expected.selection_epoch,
            ]
        || intent.digests[..8]
            != [
                c.selected_reader_key_id,
                c.root_fingerprint,
                c.manifest_digest,
                c.election_commitment,
                c.election_bundle_sha256,
                owner,
                origin,
                *expected.signer,
            ]
        || intent.peer != expected.peer
        || intent.recipients != expected.recipients
    {
        return Err("review selected context");
    }
    let (point, from, deadline) = expected.manifest.authorize(
        &Authorization03 {
            kind: 1,
            account: &c.account_id,
            device: &c.device_id,
            line: &c.line_id,
            signer_id: expected.signer,
            readers: expected.recipients,
        },
        now,
    )?;
    let [_, _, _, _, observed, expires, issued, review_expires] = intent.numbers;
    if issued > now
        || now >= review_expires
        || observed < from
        || observed < expected.interval_starts_ms
        || expires > deadline
        || expires > c.permission_expires_at_ms
        || expires > expected.interval_expires_ms
    {
        return Err("review current timing");
    }
    let sealed = crate::sealed_envelope03::verify(
        envelope,
        expected.manifest,
        &crate::sealed_envelope03::ExpectedContext03 {
            kind: 1,
            account_id: c.account_id,
            message_id: intent.ids[7],
            device_id: c.device_id,
            line_id: c.line_id,
            peer: expected.peer,
            recipients: expected.recipients,
        },
        now,
    )?;
    if !sealed.matches_review(expected.signer, observed, expires)
        || *sealed.envelope_digest() != intent.digests[8]
        || *sealed.unsigned_digest() != intent.digests[9]
    {
        return Err("review exact envelope");
    }
    crypto::signature(&point, signature, &intent.transcript())?;
    Ok(VerifiedReview03 {
        intent,
        signature: signature.try_into().map_err(|_| "review signature width")?,
        envelope: sealed,
    })
}

pub(crate) mod live;
#[cfg(test)]
pub(crate) mod tests;
