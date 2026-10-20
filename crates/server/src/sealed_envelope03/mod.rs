// SPDX-License-Identifier: AGPL-3.0-only
//! Exact candidate03 ciphertext/signature verification, with no decryption,
//! grant, durable binding/session/replay checks or admission/radio effects.

use crate::sealed_manifest03::{
    Authorization03, Check, VerifiedManifest03, framed, number, sha, signature, time,
};
use p256::PublicKey;

pub struct ExpectedContext03<'a> {
    pub kind: u8,
    pub account_id: [u8; 16],
    pub message_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub peer: &'a [u8],
    pub recipients: &'a [(u8, [u8; 32])],
}
struct Parsed {
    kind: u8,
    prefix_end: usize,
    unsigned_end: usize,
    account: [u8; 16],
    message: [u8; 16],
    device: [u8; 16],
    line: [u8; 16],
    version: u64,
    manifest: [u8; 32],
    signer: [u8; 32],
    observed: u64,
    expires: Option<u64>,
    readers: Vec<(u8, [u8; 32])>,
}
/// Owned exact ciphertext evidence. A valid signature is not permission to
/// store, decrypt, fetch, prepare a journal or submit an SMS.
pub struct VerifiedEnvelope03 {
    bytes: Vec<u8>,
    parsed: Parsed,
    unsigned_digest: [u8; 32],
    envelope_digest: [u8; 32],
}
impl std::fmt::Debug for VerifiedEnvelope03 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedEnvelope03").finish_non_exhaustive()
    }
}
impl VerifiedEnvelope03 {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn unsigned_digest(&self) -> &[u8; 32] {
        &self.unsigned_digest
    }
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }
    pub fn body_aad(&self) -> Vec<u8> {
        [
            b"ZTSE/body/v3\0".as_slice(),
            &self.bytes[..self.parsed.prefix_end],
        ]
        .concat()
    }
    fn wrap_context(&self, index: usize, label: &[u8]) -> Check<Vec<u8>> {
        let (role, id) = self.parsed.readers.get(index).ok_or("wrap index")?;
        Ok([label, &self.bytes[..self.parsed.prefix_end], &[*role], id].concat())
    }
    pub fn wrap_info(&self, index: usize) -> Check<Vec<u8>> {
        self.wrap_context(index, b"ZTSE/wrap/v3\0")
    }
    pub fn wrap_aad(&self, index: usize) -> Check<Vec<u8>> {
        self.wrap_context(index, b"ZTSE/wrap-aad/v3\0")
    }
}
fn parse(bytes: &[u8]) -> Check<Parsed> {
    if !(426..=36864).contains(&bytes.len()) || &bytes[..5] != b"ZTSE\x03" || bytes[6..8] != [0; 2]
    {
        return Err("envelope shape/profile/flags");
    }
    let kind = bytes[5];
    let (min, max, base, peer_at, min_wrap, max_wrap, max_total) = match kind {
        1 => (157, 170, 154, 153, 2, 8, 34213),
        2 => (172, 185, 169, 168, 1, 7, 34082),
        _ => return Err("envelope kind"),
    };
    let protected_len = usize::from(u16::from_be_bytes(bytes[8..10].try_into().unwrap()));
    if bytes.len() > max_total || !(min..=max).contains(&protected_len) {
        return Err("envelope protected/kind size");
    }
    let end = 10 + protected_len; // protected_len is already bounded above.
    let p = bytes.get(10..end).ok_or("truncated protected")?;
    let peer_len = usize::from(p[peer_at]);
    let peer = &p[peer_at + 1..];
    if !(3..=16).contains(&peer_len)
        || protected_len != base + peer_len
        || peer[0] != b'+'
        || !(b'1'..=b'9').contains(&peer[1])
        || !peer[2..].iter().all(u8::is_ascii_digit)
    {
        return Err("peer");
    }
    let account = p[..16].try_into().unwrap();
    let message = p[16..32].try_into().unwrap();
    let device = p[32..48].try_into().unwrap();
    let line = p[48..64].try_into().unwrap();
    if [account, message, device, line].contains(&[0; 16]) {
        return Err("zero routing identity");
    }
    let version = number(&p[64..72])?;
    let observed = number(&p[136..144])?;
    time(version)?;
    time(observed)?;
    let expires = if kind == 1 {
        let e = number(&p[144..152])?;
        if p[152] != 1 || e <= observed || e - observed > 900_000 {
            return Err("intent/expiry");
        }
        Some(e)
    } else {
        if p[144..160] != message || number(&p[160..168])? == 0 {
            return Err("inbound event/sequence");
        }
        None
    };
    let body_len = u32::from_be_bytes(
        bytes
            .get(end + 12..end + 16)
            .ok_or("body header")?
            .try_into()
            .unwrap(),
    );
    if !(17..=32784).contains(&body_len) {
        return Err("body size");
    }
    let body_end = end
        .checked_add(16)
        .and_then(|n| n.checked_add(body_len as usize))
        .ok_or("offset overflow")?;
    let count = usize::from(*bytes.get(body_end).ok_or("body truncation")?);
    if !(min_wrap..=max_wrap).contains(&count) {
        return Err("wrap count");
    }
    let unsigned_end = body_end
        .checked_add(1 + count * 146)
        .ok_or("offset overflow")?;
    if unsigned_end.checked_add(64) != Some(bytes.len()) {
        return Err("truncated/trailing envelope");
    }
    let mut readers = Vec::with_capacity(count);
    let (mut devices, mut archives) = (0, 0);
    for i in 0..count {
        let at = body_end + 1 + i * 146;
        let role = bytes[at];
        let id = bytes[at + 1..at + 33].try_into().unwrap();
        if !(1..=3).contains(&role) || readers.last().is_some_and(|p| *p >= (role, id)) {
            return Err("wrap role/order");
        }
        let enc = &bytes[at + 33..at + 98];
        if enc[0] != 4 || PublicKey::from_sec1_bytes(enc).is_err() {
            return Err("enc point");
        }
        devices += usize::from(role == 1);
        archives += usize::from(role == 2);
        readers.push((role, id));
    }
    if devices != usize::from(kind == 1) || archives != 1 {
        return Err("reader cardinality");
    }
    Ok(Parsed {
        kind,
        prefix_end: end,
        unsigned_end,
        account,
        message,
        device,
        line,
        version,
        manifest: p[72..104].try_into().unwrap(),
        signer: p[104..136].try_into().unwrap(),
        observed,
        expires,
        readers,
    })
}

/// Verify exact03 grammar, signed routing and current manifest roles. Live
/// durable authority and incoming age policy remain independent adapter gates.
pub fn verify(
    bytes: &[u8],
    manifest: &VerifiedManifest03,
    expected: &ExpectedContext03<'_>,
    now: u64,
) -> Check<VerifiedEnvelope03> {
    let p = parse(bytes)?;
    let id = manifest.identity_at(now)?;
    let peer_at = if p.kind == 1 { 164 } else { 179 };
    if p.kind != expected.kind
        || p.account != expected.account_id
        || p.message != expected.message_id
        || p.device != expected.device_id
        || p.line != expected.line_id
        || &bytes[peer_at..p.prefix_end] != expected.peer
        || p.version != id.version
        || p.manifest != id.digest
        || p.readers != expected.recipients
    {
        return Err("envelope context mismatch");
    }
    let (point, not_before, deadline) = manifest.authorize(
        &Authorization03 {
            kind: p.kind,
            account: &p.account,
            device: &p.device,
            line: &p.line,
            signer_id: &p.signer,
            readers: &p.readers,
        },
        now,
    )?;
    if p.observed > now
        || p.kind == 1 && p.observed < not_before
        || p.expires.is_some_and(|e| now >= e || e > deadline)
    {
        return Err("envelope authority deadline");
    }
    signature(
        &point,
        &bytes[p.unsigned_end..],
        &framed(b"ZTSE/sign/v3\0", &bytes[..p.unsigned_end])?,
    )?;
    Ok(VerifiedEnvelope03 {
        bytes: bytes.to_vec(),
        unsigned_digest: sha(&bytes[..p.unsigned_end]),
        envelope_digest: sha(bytes),
        parsed: p,
    })
}

#[cfg(test)]
mod tests;
