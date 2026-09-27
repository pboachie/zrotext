// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant sealed-candidate envelope verification; no HTTP/WSS route calls it.
//!
//! A verified signature is not permission to store, dispatch or decrypt. Callers
//! must independently verify the pinned manifest chain, signer role/scope and
//! recipient set, then provide that trusted context. Freshness, active line
//! generation, session/grant fencing and replay checks remain transactional
//! admission responsibilities. Neither candidate is enabled for production.

use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use sha2::{Digest, Sha256};

const WRAP_LEN: usize = 146;
const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Interoperability proof only, including the pinned high-s signature.
    Draft01Proof = 1,
    /// Unaccepted candidate, requiring canonical low-s signatures.
    Draft02Candidate = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Outbound = 1,
    Inbound = 2,
}

pub struct Wrap<'a> {
    pub role: u8,
    pub key_id: &'a [u8],
    pub enc: &'a [u8],
    pub ct: &'a [u8],
}

pub struct Envelope<'a> {
    pub profile: Profile,
    pub kind: Kind,
    pub protected: &'a [u8],
    pub account_id: &'a [u8],
    pub message_id: &'a [u8],
    pub device_id: &'a [u8],
    pub line_id: &'a [u8],
    pub keyset_version: u64,
    pub manifest_digest: &'a [u8],
    pub signer_key_id: &'a [u8],
    pub observed_ms: u64,
    pub expires_ms: Option<u64>,
    pub event_id: Option<&'a [u8]>,
    pub local_sequence: Option<u64>,
    pub peer: &'a [u8],
    pub nonce: &'a [u8],
    pub body_ct: &'a [u8],
    pub wraps: Vec<Wrap<'a>>,
    pub unsigned: &'a [u8],
    pub signature: &'a [u8],
}

fn read_u64(bytes: &[u8]) -> Result<u64, &'static str> {
    let value = u64::from_be_bytes(bytes.try_into().map_err(|_| "u64 width")?);
    if value > i64::MAX as u64 {
        return Err("signed storage range");
    }
    Ok(value)
}

fn e164(peer: &[u8]) -> bool {
    (3..=16).contains(&peer.len())
        && peer[0] == b'+'
        && (b'1'..=b'9').contains(&peer[1])
        && peer[2..].iter().all(u8::is_ascii_digit)
}

/// The caller must choose the profile; this reader never downgrades or retries.
// Crate callers may inspect bounded claims to select authority. Nothing returned
// by this parser is authenticated until verify() accepts the exact input bytes.
pub(crate) fn parse(input: &[u8], expected: Profile) -> Result<Envelope<'_>, &'static str> {
    if !(426..=36_864).contains(&input.len()) {
        return Err("envelope size");
    }
    if &input[..4] != b"ZTSE" || input[4] != expected as u8 {
        return Err("magic/profile");
    }
    let kind = match input[5] {
        1 => Kind::Outbound,
        2 => Kind::Inbound,
        _ => return Err("kind"),
    };
    if input[6..8] != [0, 0] {
        return Err("flags");
    }
    let (min_protected, max_protected, peer_len_at, base_len, min_wraps, max_wraps, max_total) =
        match kind {
            Kind::Outbound => (157, 170, 153, 154, 2, 8, 34_213),
            Kind::Inbound => (172, 185, 168, 169, 1, 7, 34_082),
        };
    if input.len() > max_total {
        return Err("kind envelope size");
    }
    let protected_len = usize::from(u16::from_be_bytes([input[8], input[9]]));
    if !(min_protected..=max_protected).contains(&protected_len) {
        return Err("protected length");
    }
    let protected_end = 10usize
        .checked_add(protected_len)
        .ok_or("offset overflow")?;
    let body_len_at = protected_end.checked_add(12).ok_or("offset overflow")?;
    let body_at = body_len_at.checked_add(4).ok_or("offset overflow")?;
    let body_len_bytes = input.get(body_len_at..body_at).ok_or("truncated header")?;
    let protected = input.get(10..protected_end).ok_or("truncated protected")?;
    let peer_len = usize::from(protected[peer_len_at]);
    if !(3..=16).contains(&peer_len) || protected_len != base_len + peer_len {
        return Err("noncanonical protected length");
    }
    let peer = &protected[peer_len_at + 1..];
    if !e164(peer) {
        return Err("peer");
    }
    let keyset_version = read_u64(&protected[64..72])?;
    let observed_ms = read_u64(&protected[136..144])?;
    let (expires_ms, event_id, local_sequence) = match kind {
        Kind::Outbound => {
            let expires = read_u64(&protected[144..152])?;
            if protected[152] != 1 || expires <= observed_ms || expires - observed_ms > 900_000 {
                return Err("intent/expiry");
            }
            (Some(expires), None, None)
        }
        Kind::Inbound => {
            let event_id = &protected[144..160];
            let sequence = read_u64(&protected[160..168])?;
            if protected[16..32] != *event_id || sequence == 0 {
                return Err("inbound identity/sequence");
            }
            (None, Some(event_id), Some(sequence))
        }
    };
    let body_len = usize::try_from(u32::from_be_bytes(body_len_bytes.try_into().unwrap()))
        .map_err(|_| "body length conversion")?;
    if !(17..=32_784).contains(&body_len) {
        return Err("body length");
    }
    let body_end = body_at.checked_add(body_len).ok_or("offset overflow")?;
    let count = usize::from(*input.get(body_end).ok_or("truncated body")?);
    if !(min_wraps..=max_wraps).contains(&count) {
        return Err("wrap count");
    }
    let unsigned_end = body_end
        .checked_add(1)
        .and_then(|end| end.checked_add(count * WRAP_LEN))
        .ok_or("offset overflow")?;
    let expected_end = unsigned_end
        .checked_add(SIGNATURE_LEN)
        .ok_or("offset overflow")?;
    if expected_end != input.len() {
        return Err("truncated/trailing wrap or signature");
    }
    // All offset and EOF checks have passed before allocating the wrap vector.
    let mut wraps = Vec::with_capacity(count);
    let mut device_count = 0;
    let mut archive_count = 0;
    for index in 0..count {
        let start = body_end + 1 + index * WRAP_LEN;
        let role = input[start];
        if !(1..=3).contains(&role) {
            return Err("wrap role");
        }
        let key_id = &input[start + 1..start + 33];
        let enc = &input[start + 33..start + 98];
        let ct = &input[start + 98..start + WRAP_LEN];
        if let Some(previous) = wraps.last() {
            let previous: &Wrap<'_> = previous;
            if (role, key_id) <= (previous.role, previous.key_id) {
                return Err("wrap order/duplicate");
            }
        }
        if PublicKey::from_sec1_bytes(enc).is_err() || enc[0] != 4 {
            return Err("enc point");
        }
        device_count += usize::from(role == 1);
        archive_count += usize::from(role == 2);
        wraps.push(Wrap {
            role,
            key_id,
            enc,
            ct,
        });
    }
    if device_count != usize::from(kind == Kind::Outbound) || archive_count != 1 {
        return Err("recipient roles");
    }
    let signature = &input[unsigned_end..];
    let parsed_signature = Signature::from_slice(signature).map_err(|_| "signature scalar")?;
    if expected == Profile::Draft02Candidate
        && parsed_signature.normalize_s().to_bytes().as_slice() != signature
    {
        return Err("high-s signature");
    }
    Ok(Envelope {
        profile: expected,
        kind,
        protected,
        account_id: &protected[0..16],
        message_id: &protected[16..32],
        device_id: &protected[32..48],
        line_id: &protected[48..64],
        keyset_version,
        manifest_digest: &protected[72..104],
        signer_key_id: &protected[104..136],
        observed_ms,
        expires_ms,
        event_id,
        local_sequence,
        peer,
        nonce: &input[protected_end..body_len_at],
        body_ct: &input[body_at..body_end],
        wraps,
        unsigned: &input[..unsigned_end],
        signature,
    })
}

/// One recipient selected by an independently verified manifest, in wire order.
#[derive(Clone, Copy)]
pub struct ExpectedRecipient {
    pub role: u8,
    pub key_id: [u8; 32],
}

/// Expected routing and authority supplied by the caller. Account/device/line
/// and signer authority must come from authenticated state. Request-selected
/// message, peer and reader claims become trusted only after exact signature
/// verification and manifest authorization. A relay directory is not a trust root.
#[derive(Clone)]
pub struct ExpectedContext<'a> {
    pub profile: Profile,
    pub kind: Kind,
    pub account_id: [u8; 16],
    pub message_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub keyset_version: u64,
    pub manifest_digest: [u8; 32],
    pub peer: &'a [u8],
    pub signer_public_point: &'a [u8],
    pub recipients: &'a [ExpectedRecipient],
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid sealed envelope: {0}")]
    InvalidEnvelope(&'static str),
    #[error("sealed envelope differs from the expected context")]
    ContextMismatch,
    #[error("invalid sealed signer")]
    InvalidSigner,
    #[error("invalid sealed signature")]
    InvalidSignature,
}

/// Only `verify` constructs this result. It proves exact-byte signature and
/// context matching, not freshness, manifest trust, decryption or admission.
pub struct SignatureVerifiedEnvelope<'a> {
    envelope: Envelope<'a>,
    unsigned_digest: [u8; 32],
}

impl<'a> SignatureVerifiedEnvelope<'a> {
    pub fn envelope(&self) -> &Envelope<'a> {
        &self.envelope
    }

    /// Replay identity excludes the signature, as required by Q6.
    pub fn unsigned_digest(&self) -> &[u8; 32] {
        &self.unsigned_digest
    }
}

// Do not accidentally include peer identifiers or envelope bytes in logs.
impl std::fmt::Debug for SignatureVerifiedEnvelope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureVerifiedEnvelope")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("profile", &self.profile)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Bound and parse original bytes, match trusted context and verify P-256 over
/// `profile_label || u32(len(unsigned)) || unsigned`: proof-only draft 01 uses
/// `ZTSE/sign/v1\0`, candidate 02 uses `ZTSE/sign/v2\0`. No reserialization,
/// plaintext fallback, profile negotiation, storage or other effect occurs.
pub fn verify<'a>(
    input: &'a [u8],
    expected: &ExpectedContext<'_>,
) -> Result<SignatureVerifiedEnvelope<'a>, VerifyError> {
    let envelope = parse(input, expected.profile).map_err(VerifyError::InvalidEnvelope)?;
    if envelope.kind != expected.kind
        || envelope.account_id != expected.account_id
        || envelope.message_id != expected.message_id
        || envelope.device_id != expected.device_id
        || envelope.line_id != expected.line_id
        || envelope.keyset_version != expected.keyset_version
        || envelope.manifest_digest != expected.manifest_digest
        || envelope.peer != expected.peer
        || envelope.wraps.len() != expected.recipients.len()
        || envelope
            .wraps
            .iter()
            .zip(expected.recipients)
            .any(|(actual, wanted)| actual.role != wanted.role || actual.key_id != wanted.key_id)
    {
        return Err(VerifyError::ContextMismatch);
    }
    let point = expected.signer_public_point;
    if point.len() != 65 || point[0] != 4 {
        return Err(VerifyError::InvalidSigner);
    }
    let key = VerifyingKey::from_sec1_bytes(point).map_err(|_| VerifyError::InvalidSigner)?;
    let signer_id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], point].concat());
    if envelope.signer_key_id != signer_id.as_slice() {
        return Err(VerifyError::ContextMismatch);
    }
    let signature =
        Signature::from_slice(envelope.signature).map_err(|_| VerifyError::InvalidSignature)?;
    let label = match expected.profile {
        Profile::Draft01Proof => b"ZTSE/sign/v1\0",
        Profile::Draft02Candidate => b"ZTSE/sign/v2\0",
    };
    let transcript = [
        label.as_slice(),
        &(envelope.unsigned.len() as u32).to_be_bytes(),
        envelope.unsigned,
    ]
    .concat();
    key.verify(&transcript, &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;
    let unsigned_digest = Sha256::digest(envelope.unsigned).into();
    Ok(SignatureVerifiedEnvelope {
        envelope,
        unsigned_digest,
    })
}

#[cfg(test)]
mod tests;
