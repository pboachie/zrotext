// SPDX-License-Identifier: AGPL-3.0-only
//! Pure candidate commitments for typed03 effects. These bytes and signatures
//! establish no enrolled actor, durable phone phase, server acceptance, current
//! permission or invocation permit. The authenticated adapters remain separate.
use crate::sealed_manifest03::{self as crypto, Check};

pub mod wire;

const SUBMIT: &[u8] = b"ZTSE/conversation/submit-command03/v1\0";
const OUTCOME: &[u8] = b"ZTSE/conversation/outcome-command03/v1\0";
const CLOSURE: &[u8] = b"ZTSE/conversation/no-submit-record03/v1\0";
const PROOF: &[u8] = b"ZTSE/conversation/no-submit-proof03/v1\0";
const HEADER: &[u8; 8] = b"ZTNS\x01\x03\x03\0";

fn nonzero(bytes: &[u8]) -> Check<()> {
    if bytes.iter().all(|b| *b == 0) {
        Err("effect zero identity/digest")
    } else {
        Ok(())
    }
}
fn count(value: u8) -> Check<()> {
    if (1..=6).contains(&value) {
        Ok(())
    } else {
        Err("effect segment count")
    }
}
fn digest(label: &[u8], bytes: &[u8]) -> Check<[u8; 32]> {
    Ok(crypto::sha(&crypto::framed(label, bytes)?))
}
type DecodedFields<const I: usize, const D: usize> = ([[u8; 16]; I], [[u8; 32]; D]);
fn fields<const I: usize, const D: usize>(bytes: &[u8]) -> Check<DecodedFields<I, D>> {
    if bytes.len() < I * 16 + D * 32 {
        return Err("effect field width");
    }
    let mut ids = [[0; 16]; I];
    let mut hashes = [[0; 32]; D];
    let mut at = 0;
    for id in &mut ids {
        id.copy_from_slice(&bytes[at..at + 16]);
        nonzero(id)?;
        at += 16;
    }
    for hash in &mut hashes {
        hash.copy_from_slice(&bytes[at..at + 32]);
        nonzero(hash)?;
        at += 32;
    }
    Ok((ids, hashes))
}

/// Exact original account/device/event/message/attempt, Fetch362 digest,
/// original full-device-session digest, segment count and observed time.
pub struct SubmitCommand03 {
    bytes: [u8; 153],
    ids: [[u8; 16]; 5],
    hashes: [[u8; 32]; 2],
    count: u8,
    observed: u64,
}
impl SubmitCommand03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        let bytes: [u8; 153] = bytes.try_into().map_err(|_| "submit command width")?;
        let (ids, hashes) = fields(&bytes)?;
        count(bytes[144])?;
        let observed = crypto::number(&bytes[145..153])?;
        crypto::time(observed)?;
        Ok(Self {
            bytes,
            ids,
            hashes,
            count: bytes[144],
            observed,
        })
    }
    pub fn bytes(&self) -> &[u8; 153] {
        &self.bytes
    }
    pub fn identities(&self) -> &[[u8; 16]; 5] {
        &self.ids
    }
    pub fn fetch_digest(&self) -> &[u8; 32] {
        &self.hashes[0]
    }
    pub fn device_session_digest(&self) -> &[u8; 32] {
        &self.hashes[1]
    }
    pub fn segment_count(&self) -> u8 {
        self.count
    }
    pub fn observed_ms(&self) -> u64 {
        self.observed
    }
    pub fn digest(&self) -> Check<[u8; 32]> {
        digest(SUBMIT, &self.bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome03 {
    SentOk,
    SentFailed,
    DeliveryOk,
    DeliveryTimeout,
    CrashWithoutCallback,
    CallbackConflict,
}
impl Outcome03 {
    fn decode(value: u8) -> Check<Self> {
        Ok(match value {
            0 => Self::SentOk,
            1 => Self::SentFailed,
            2 => Self::DeliveryOk,
            3 => Self::DeliveryTimeout,
            4 => Self::CrashWithoutCallback,
            5 => Self::CallbackConflict,
            _ => return Err("outcome evidence"),
        })
    }
    fn sent(self) -> bool {
        matches!(self, Self::SentOk | Self::SentFailed)
    }
}
/// A reported fact relative to an original submit tuple. Its outer reporting
/// connection is intentionally absent from this immutable historical identity.
pub struct OutcomeCommand03 {
    bytes: [u8; 211],
    ids: [[u8; 16]; 6],
    hashes: [[u8; 32]; 3],
    submit_observed: u64,
    count: u8,
    evidence: Outcome03,
    observed: u64,
    index: Option<u8>,
}
impl OutcomeCommand03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        let bytes: [u8; 211] = bytes.try_into().map_err(|_| "outcome command width")?;
        let (ids, hashes) = fields(&bytes)?;
        let submit_observed = crypto::number(&bytes[192..200])?;
        let observed = crypto::number(&bytes[202..210])?;
        crypto::time(submit_observed)?;
        crypto::time(observed)?;
        count(bytes[200])?;
        let evidence = Outcome03::decode(bytes[201])?;
        let index = if evidence.sent() {
            if bytes[210] >= bytes[200] {
                return Err("sent segment index");
            }
            Some(bytes[210])
        } else {
            if bytes[210] != 255 {
                return Err("aggregate segment index");
            }
            None
        };
        Ok(Self {
            bytes,
            ids,
            hashes,
            submit_observed,
            count: bytes[200],
            evidence,
            observed,
            index,
        })
    }
    pub fn bytes(&self) -> &[u8; 211] {
        &self.bytes
    }
    pub fn identities(&self) -> &[[u8; 16]; 6] {
        &self.ids
    }
    pub fn digests(&self) -> &[[u8; 32]; 3] {
        &self.hashes
    }
    pub fn submit_observed_ms(&self) -> u64 {
        self.submit_observed
    }
    pub fn segment_count(&self) -> u8 {
        self.count
    }
    pub fn evidence(&self) -> Outcome03 {
        self.evidence
    }
    pub fn observed_ms(&self) -> u64 {
        self.observed
    }
    pub fn segment_index(&self) -> Option<u8> {
        self.index
    }
    pub fn digest(&self) -> Check<[u8; 32]> {
        digest(OUTCOME, &self.bytes)
    }
}

/// Exact durable local assertion. Syntax does not prove its Room transaction
/// happened, exclude platform entry or constitute remote operating-system proof.
pub struct NoSubmitRecord03 {
    bytes: [u8; 210],
}
impl NoSubmitRecord03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        let bytes: [u8; 210] = bytes.try_into().map_err(|_| "closure record width")?;
        fields::<6, 3>(&bytes)?;
        count(bytes[192])?;
        let submitted = crypto::number(&bytes[193..201])?;
        let closed = crypto::number(&bytes[202..210])?;
        crypto::time(submitted)?;
        crypto::time(closed)?;
        if bytes[201] > 1 || closed < submitted {
            return Err("closure phase/time");
        }
        Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8; 210] {
        &self.bytes
    }
    pub fn digest(&self) -> Check<[u8; 32]> {
        digest(CLOSURE, &self.bytes)
    }
}

/// Candidate challenge bytes, including both original and current proof lease
/// commitments. A signature under a supplied point proves only that signature.
pub struct NoSubmitCore03 {
    bytes: [u8; 441],
    ids: [[u8; 16]; 8],
    numbers: [u64; 10],
    hashes: [[u8; 32]; 7],
}
impl NoSubmitCore03 {
    pub fn decode(bytes: &[u8]) -> Check<Self> {
        let bytes: [u8; 441] = bytes.try_into().map_err(|_| "closure core width")?;
        if &bytes[..8] != HEADER {
            return Err("closure core profile");
        }
        let mut ids = [[0; 16]; 8];
        let mut numbers = [0; 10];
        let mut hashes = [[0; 32]; 7];
        let mut at = 8;
        for id in &mut ids {
            id.copy_from_slice(&bytes[at..at + 16]);
            nonzero(id)?;
            at += 16;
        }
        for number in &mut numbers {
            *number = crypto::number(&bytes[at..at + 8])?;
            crypto::time(*number)?;
            at += 8;
        }
        for hash in &mut hashes {
            hash.copy_from_slice(&bytes[at..at + 32]);
            nonzero(hash)?;
            at += 32;
        }
        if numbers[4] != 1
            || !(1..=6).contains(&numbers[5])
            || numbers[7] < numbers[6]
            || numbers[9] <= numbers[8]
            || numbers[9] - numbers[8] > 30_000
            || bytes[440] > 1
        {
            return Err("closure core phase/generation/time");
        }
        Ok(Self {
            bytes,
            ids,
            numbers,
            hashes,
        })
    }
    pub fn bytes(&self) -> &[u8; 441] {
        &self.bytes
    }
    pub fn identities(&self) -> &[[u8; 16]; 8] {
        &self.ids
    }
    pub fn numbers(&self) -> &[u64; 10] {
        &self.numbers
    }
    pub fn digests(&self) -> &[[u8; 32]; 7] {
        &self.hashes
    }
    pub fn matches_record(&self, record: &NoSubmitRecord03) -> Check<()> {
        let mut expected = Vec::with_capacity(210);
        for id in &self.ids[..6] {
            expected.extend(id);
        }
        for hash in &self.hashes[..3] {
            expected.extend(hash);
        }
        expected.push(self.numbers[5] as u8);
        expected.extend(self.numbers[6].to_be_bytes());
        expected.push(self.bytes[440]);
        expected.extend(self.numbers[7].to_be_bytes());
        if expected.as_slice() != record.bytes() || record.digest()? != self.hashes[6] {
            return Err("closure original record binding");
        }
        Ok(())
    }
    pub fn verify_candidate_signature(&self, point: &[u8], raw: &[u8]) -> Check<()> {
        if crate::sealed_manifest::key_id(4, point) != self.hashes[4] {
            return Err("closure candidate key identity");
        }
        crypto::signature(point, raw, &crypto::framed(PROOF, &self.bytes)?)
    }
}

#[cfg(test)]
mod tests;
