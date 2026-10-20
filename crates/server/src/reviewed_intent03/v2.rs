// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit ZTRI02 syntax and its distinct signature domain. This module has
//! no plaintext commitment and does not reinterpret historical ZTRI01 bytes.
//! Signature checks alone provide no database, interval or current authority.
use crate::sealed_manifest03::{self as crypto, Check};
use uuid::Uuid;

const HEADER: &[u8; 8] = b"ZTRI\x02\x03\x03\0";
const DOMAIN: &[u8] = b"zrotext/conversation/reviewed-send03/v2\0";

/// A structurally checked, owned candidate. Its routing fields select records
/// to authenticate independently; none of them establish current permission.
pub struct Intent03V2 {
    bytes: Vec<u8>,
    ids: [[u8; 16]; 8],
    numbers: [u64; 8],
    digests: [[u8; 32]; 10],
    peer: Vec<u8>,
    recipients: Vec<(u8, [u8; 32])>,
    ceiling: u8,
}
impl std::fmt::Debug for Intent03V2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intent03V2").finish_non_exhaustive()
    }
}
impl Intent03V2 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        if !(592..=803).contains(&bytes.len()) || &bytes[..8] != HEADER {
            return Err("review v2 shape/profile");
        }
        let mut ids = [[0; 16]; 8];
        let mut numbers = [0; 8];
        let mut digests = [[0; 32]; 10];
        let mut at = 8;
        for id in &mut ids {
            id.copy_from_slice(&bytes[at..at + 16]);
            super::nonzero(id)?;
            at += 16;
        }
        for n in &mut numbers {
            *n = crypto::number(&bytes[at..at + 8])?;
            crypto::time(*n)?;
            at += 8;
        }
        for digest in &mut digests {
            digest.copy_from_slice(&bytes[at..at + 32]);
            super::nonzero(digest)?;
            at += 32;
        }
        let peer_len = usize::from(bytes[at]);
        at += 1;
        let peer = bytes
            .get(at..at + peer_len)
            .ok_or("review v2 peer framing")?;
        if !(3..=16).contains(&peer.len())
            || peer[0] != b'+'
            || !(b'1'..=b'9').contains(&peer[1])
            || !peer[2..].iter().all(u8::is_ascii_digit)
        {
            return Err("review v2 peer");
        }
        at += peer_len;
        let count = usize::from(*bytes.get(at).ok_or("review v2 recipients")?);
        at += 1;
        if !(2..=8).contains(&count) || at + 33 * count + 1 != bytes.len() {
            return Err("review v2 recipients/trailing");
        }
        let mut recipients = Vec::with_capacity(count);
        let (mut devices, mut archives) = (0, 0);
        for _ in 0..count {
            let role = bytes[at];
            let id: [u8; 32] = bytes[at + 1..at + 33].try_into().unwrap();
            super::nonzero(&id)?;
            if !(1..=3).contains(&role)
                || recipients.last().is_some_and(|prior| *prior >= (role, id))
            {
                return Err("review v2 reader order/role");
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
            return Err("review v2 reader/ceiling policy");
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
            return Err("review v2 lifetime");
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
    pub fn device_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[1])
    }
    pub fn line_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[2])
    }
    pub fn binding_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[3])
    }
    pub fn user_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[4])
    }
    pub fn owner_session_id(&self) -> Uuid {
        Uuid::from_bytes(self.ids[5])
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
    pub fn peer(&self) -> &[u8] {
        &self.peer
    }
    pub fn recipients(&self) -> &[(u8, [u8; 32])] {
        &self.recipients
    }
    pub fn binding_generation(&self) -> u64 {
        self.numbers[0]
    }
    pub fn vault_generation(&self) -> u64 {
        self.numbers[1]
    }
    pub fn manifest_version(&self) -> u64 {
        self.numbers[2]
    }
    pub fn selection_epoch(&self) -> u64 {
        self.numbers[3]
    }
    pub fn observed_ms(&self) -> u64 {
        self.numbers[4]
    }
    pub fn message_expires_ms(&self) -> u64 {
        self.numbers[5]
    }
    pub fn review_issued_ms(&self) -> u64 {
        self.numbers[6]
    }
    pub fn review_expires_ms(&self) -> u64 {
        self.numbers[7]
    }
    pub fn reader_key_id(&self) -> &[u8; 32] {
        &self.digests[0]
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.digests[1]
    }
    pub fn manifest_digest(&self) -> &[u8; 32] {
        &self.digests[2]
    }
    pub fn election_commitment(&self) -> &[u8; 32] {
        &self.digests[3]
    }
    pub fn election_bundle_sha256(&self) -> &[u8; 32] {
        &self.digests[4]
    }
    pub fn owner_session_digest(&self) -> &[u8; 32] {
        &self.digests[5]
    }
    pub fn origin_digest(&self) -> &[u8; 32] {
        &self.digests[6]
    }
    pub fn signer_key_id(&self) -> &[u8; 32] {
        &self.digests[7]
    }
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.digests[8]
    }
    pub fn unsigned_digest(&self) -> &[u8; 32] {
        &self.digests[9]
    }
    pub fn transcript(&self) -> Vec<u8> {
        crypto::framed(DOMAIN, &self.bytes).expect("bounded v2 intent")
    }
}

/// Exact V2 bytes whose signature was checked with the supplied public point.
/// The caller must independently establish the selected role5 key, ciphertext,
/// current owner/interval/physical scope and actual admission provenance.
pub struct SignatureCheckedIntent03V2 {
    intent: Intent03V2,
    signature: [u8; 64],
}
impl std::fmt::Debug for SignatureCheckedIntent03V2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureCheckedIntent03V2")
            .finish_non_exhaustive()
    }
}
impl SignatureCheckedIntent03V2 {
    pub fn intent(&self) -> &Intent03V2 {
        &self.intent
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}
pub fn verify_signature(
    intent: Intent03V2,
    signature: &[u8],
    signing_point: &[u8],
) -> Check<SignatureCheckedIntent03V2> {
    crypto::signature(signing_point, signature, &intent.transcript())?;
    Ok(SignatureCheckedIntent03V2 {
        intent,
        signature: signature
            .try_into()
            .map_err(|_| "review v2 signature width")?,
    })
}

#[cfg(test)]
mod tests;
