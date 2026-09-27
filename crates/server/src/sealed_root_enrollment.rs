// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate-only generation-one root possession proof. No runtime caller.
//!
//! This is NOT enrollment or manifest trust. The caller must independently
//! obtain the expected challenge, enforce owner/MFA/session and one-time state,
//! and arrange out-of-band root comparison. No private key enters this module.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ZTSE/root-enroll/v1\0";
const PIN_DOMAIN: &[u8] = b"ZTSE/root-pin/v2\0";
const FIXED: usize = 151;
const MAX_ORIGIN: usize = 512;
const MAX_UNSIGNED: usize = FIXED + MAX_ORIGIN;

/// Independently supplied expected challenge, never derived from the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub account_id: [u8; 16],
    pub user_id: [u8; 16],
    pub session_id: [u8; 16],
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 32],
    pub root_fingerprint: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub origin: String,
}

/// Only states that a root signed one exact challenge. Cannot grant authority.
#[derive(Debug)]
pub struct PossessionProof {
    fingerprint: [u8; 32],
}
impl PossessionProof {
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// Exact existing HTTPS origin serialization; no input normalization.
pub fn canonical_origin(origin: &str) -> bool {
    if origin.is_empty() || origin.len() > MAX_ORIGIN || !origin.is_ascii() {
        return false;
    }
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.has_host()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.origin().ascii_serialization() == origin
}

fn validate(challenge: &Challenge) -> Result<(), &'static str> {
    for id in [
        challenge.account_id,
        challenge.user_id,
        challenge.session_id,
        challenge.challenge_id,
    ] {
        if id == [0; 16] {
            return Err("zero identity");
        }
    }
    if challenge.issued_ms == 0
        || challenge.expires_ms > i64::MAX as u64
        || challenge.expires_ms <= challenge.issued_ms
        || challenge.expires_ms - challenge.issued_ms > 300_000
    {
        return Err("challenge time window");
    }
    if !canonical_origin(&challenge.origin) {
        return Err("canonical origin");
    }
    Ok(())
}

/// Encode unsigned candidate bytes; this neither creates nor reserves a challenge.
pub fn encode(challenge: &Challenge) -> Result<Vec<u8>, &'static str> {
    validate(challenge)?;
    let mut bytes = Vec::with_capacity(FIXED + challenge.origin.len());
    bytes.extend_from_slice(b"ZTRE\x01");
    for id in [
        challenge.account_id,
        challenge.user_id,
        challenge.session_id,
        challenge.challenge_id,
    ] {
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(&challenge.root_fingerprint);
    bytes.extend_from_slice(&challenge.issued_ms.to_be_bytes());
    bytes.extend_from_slice(&challenge.expires_ms.to_be_bytes());
    bytes.extend_from_slice(&(challenge.origin.len() as u16).to_be_bytes());
    bytes.extend_from_slice(challenge.origin.as_bytes());
    Ok(bytes)
}

/// Parse bounded received bytes without trusting any of their claims.
pub fn parse(bytes: &[u8]) -> Result<Challenge, &'static str> {
    if !(FIXED + 1..=MAX_UNSIGNED).contains(&bytes.len()) || &bytes[..5] != b"ZTRE\x01" {
        return Err("enrollment shape");
    }
    let length = u16::from_be_bytes(bytes[149..151].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_ORIGIN || bytes.len() != FIXED + length {
        return Err("origin length");
    }
    let challenge = Challenge {
        account_id: bytes[5..21].try_into().unwrap(),
        user_id: bytes[21..37].try_into().unwrap(),
        session_id: bytes[37..53].try_into().unwrap(),
        challenge_id: bytes[53..69].try_into().unwrap(),
        nonce: bytes[69..101].try_into().unwrap(),
        root_fingerprint: bytes[101..133].try_into().unwrap(),
        issued_ms: u64::from_be_bytes(bytes[133..141].try_into().unwrap()),
        expires_ms: u64::from_be_bytes(bytes[141..149].try_into().unwrap()),
        origin: std::str::from_utf8(&bytes[151..])
            .map_err(|_| "origin encoding")?
            .to_owned(),
    };
    validate(&challenge)?;
    Ok(challenge)
}

/// Construct the signing transcript from exact bounded bytes, without reserialization.
pub fn transcript(unsigned: &[u8]) -> Result<Vec<u8>, &'static str> {
    parse(unsigned)?;
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 4 + unsigned.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
    bytes.extend_from_slice(unsigned);
    Ok(bytes)
}

/// Compute the candidate fingerprint of a strictly validated genesis RootPin02.
/// The result is not evidence that an independent comparison occurred.
pub fn root_fingerprint(pin: &[u8], account: &[u8; 16]) -> Result<[u8; 32], &'static str> {
    if pin.len() != 94
        || &pin[..5] != b"ZTRP\x02"
        || *account == [0; 16]
        || &pin[5..21] != account
        || pin[21..29] != 1_u64.to_be_bytes()
        || pin[29] != 4
        || VerifyingKey::from_sec1_bytes(&pin[29..]).is_err()
    {
        return Err("genesis root pin");
    }
    Ok(Sha256::digest([PIN_DOMAIN, pin].concat()).into())
}

/// Verify possession only. Time is caller-supplied, and replay prevention,
/// MFA/session checks and independent root comparison remain caller obligations.
pub fn verify(
    pin: &[u8],
    unsigned: &[u8],
    signature: &[u8],
    expected: &Challenge,
    now_ms: u64,
) -> Result<PossessionProof, &'static str> {
    let received = parse(unsigned)?;
    if &received != expected {
        return Err("challenge context");
    }
    if now_ms < received.issued_ms || now_ms >= received.expires_ms {
        return Err("challenge expired or not yet valid");
    }
    let fingerprint = root_fingerprint(pin, &expected.account_id)?;
    if fingerprint != expected.root_fingerprint {
        return Err("root fingerprint");
    }
    // from_slice checks exact 64-byte width and nonzero scalars below the order.
    let raw = signature;
    let signature = Signature::from_slice(raw).map_err(|_| "signature scalar or width")?;
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92,
        0xa8,
    ];
    if &raw[32..] > HALF_ORDER.as_slice() {
        return Err("high-s signature");
    }
    let key = VerifyingKey::from_sec1_bytes(&pin[29..]).map_err(|_| "root point")?;
    key.verify(&transcript(unsigned)?, &signature)
        .map_err(|_| "root possession signature")?;
    Ok(PossessionProof { fingerprint })
}
