// SPDX-License-Identifier: AGPL-3.0-only
//! Closed public-only phase packets for matched registered-account root
//! evidence preparation: preparation, root-custody proof and first manifest.
//!
//! This leaf is a pure grammar and continuity reviewer. It holds no secret,
//! signs nothing, reads no clock and performs no I/O. A packet that passes
//! proves only exact structure and continuity against independently supplied
//! expectations. It does not establish archive custody, installed manifest
//! authority, issuer initialization, restore protection, authenticated time or
//! production readiness. Callers supply `now_ms` from a trusted clock.
use crate::sealed_root_enrollment::{canonical_origin, root_fingerprint};
use data_encoding::HEXLOWER;

pub const MAX_PACKET: usize = 2048;
pub const MAX_INTERVAL_MS: u64 = 86_400_000;
/// Newest accepted final signing time relative to the caller's current time.
pub const MAX_SIGNING_AGE_MS: u64 = 300_000;
const HEADER: &str = "zt-root-evidence-packet=1";
const COMMON: [&str; 9] = [
    "account",
    "origin",
    "root_pin",
    "root_fingerprint",
    "backup_digest",
    "card_digest",
    "archive_id",
    "issued_ms",
    "expires_ms",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("packet size, framing or encoding is not canonical")]
    Framing,
    #[error("packet phase is not the expected phase")]
    Phase,
    #[error("packet repeats a field")]
    Duplicate,
    #[error("packet contains an unknown field")]
    Unknown,
    #[error("packet fields are missing or out of order")]
    Shape,
    #[error("packet field value is not canonical")]
    Value,
    #[error("packet identity does not match the independent expectation")]
    Identity,
    #[error("packet artifacts are missing, zero or reused across phases")]
    Artifact,
    #[error("packet signing times regressed, are stale or fall outside validity")]
    Time,
}
type Result<T> = std::result::Result<T, Refusal>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Prepare,
    Custody,
    Manifest,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Custody => "custody",
            Self::Manifest => "manifest",
        }
    }
    fn tail(self) -> &'static [&'static str] {
        match self {
            Self::Prepare => &["prepared_ms"],
            Self::Custody => &["custody_digest", "signed_ms"],
            Self::Manifest => &["unsigned_digest", "signed_ms"],
        }
    }
}

/// Public fields only. `stamp_ms` is the preparation or signing time and
/// `artifact_digest` is the custody or unsigned-manifest digest (absent for
/// preparation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub phase: Phase,
    pub account: [u8; 16],
    pub origin: String,
    pub root_pin: [u8; 94],
    pub root_fingerprint: [u8; 32],
    pub backup_digest: [u8; 32],
    pub card_digest: [u8; 32],
    pub archive_id: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub stamp_ms: u64,
    pub artifact_digest: Option<[u8; 32]>,
}

/// Independent owner-reviewed context, never taken from a received packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub account: [u8; 16],
    pub origin: String,
    pub root_pin: [u8; 94],
    pub backup_digest: [u8; 32],
    pub card_digest: [u8; 32],
    pub archive_id: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}

fn positive(n: u64) -> bool {
    n > 0 && n <= i64::MAX as u64
}

fn validate(p: &Packet) -> Result<()> {
    if p.account == [0; 16]
        || !canonical_origin(&p.origin)
        || ![p.issued_ms, p.expires_ms, p.stamp_ms]
            .into_iter()
            .all(positive)
        || p.expires_ms <= p.issued_ms
        || p.expires_ms - p.issued_ms > MAX_INTERVAL_MS
        || p.stamp_ms < p.issued_ms
        || p.stamp_ms >= p.expires_ms
        || [p.backup_digest, p.card_digest, p.archive_id].contains(&[0; 32])
    {
        return Err(Refusal::Value);
    }
    if root_fingerprint(&p.root_pin, &p.account).map_err(|_| Refusal::Value)? != p.root_fingerprint
    {
        return Err(Refusal::Value);
    }
    match (p.phase, p.artifact_digest) {
        (Phase::Prepare, None) => Ok(()),
        (Phase::Custody | Phase::Manifest, Some(d)) if d != [0; 32] => Ok(()),
        _ => Err(Refusal::Artifact),
    }
}

/// Canonical bytes for a valid packet; the sole accepted spelling.
pub fn encode(p: &Packet) -> Result<Vec<u8>> {
    validate(p)?;
    let hex = |b: &[u8]| HEXLOWER.encode(b);
    let mut values = vec![
        hex(&p.account),
        p.origin.clone(),
        hex(&p.root_pin),
        hex(&p.root_fingerprint),
        hex(&p.backup_digest),
        hex(&p.card_digest),
        hex(&p.archive_id),
        p.issued_ms.to_string(),
        p.expires_ms.to_string(),
    ];
    if let Some(d) = p.artifact_digest {
        values.push(hex(&d));
    }
    values.push(p.stamp_ms.to_string());
    let mut out = format!("{HEADER}\nphase={}\n", p.phase.name());
    for (key, value) in COMMON.iter().chain(p.phase.tail()).zip(values) {
        out.push_str(&format!("{key}={value}\n"));
    }
    if out.len() > MAX_PACKET {
        return Err(Refusal::Framing);
    }
    Ok(out.into_bytes())
}

fn decimal(s: &str) -> Result<u64> {
    if s.is_empty()
        || s.len() > 19
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(Refusal::Value);
    }
    s.parse().map_err(|_| Refusal::Value)
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    // HEXLOWER rejects uppercase and any non-hex byte.
    HEXLOWER
        .decode(s.as_bytes())
        .map_err(|_| Refusal::Value)?
        .try_into()
        .map_err(|_| Refusal::Value)
}

/// Strictly decode one packet of the expected phase. Never lenient: no
/// whitespace, CR, reordering, defaults, repeated or unknown fields.
pub fn decode(bytes: &[u8], expected: Phase) -> Result<Packet> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET || !bytes.is_ascii() || bytes.contains(&b'\r') {
        return Err(Refusal::Framing);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::Framing)?;
    let body = text.strip_suffix('\n').ok_or(Refusal::Framing)?;
    let mut lines = body.split('\n');
    if lines.next() != Some(HEADER) {
        return Err(Refusal::Framing);
    }
    let phase = match lines.next().and_then(|l| l.strip_prefix("phase=")) {
        Some("prepare") => Phase::Prepare,
        Some("custody") => Phase::Custody,
        Some("manifest") => Phase::Manifest,
        _ => return Err(Refusal::Framing),
    };
    if phase != expected {
        return Err(Refusal::Phase);
    }
    let allowed: Vec<&str> = COMMON.iter().chain(phase.tail()).copied().collect();
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(allowed.len());
    for line in lines {
        let (key, value) = line.split_once('=').ok_or(Refusal::Framing)?;
        if pairs.iter().any(|(k, _)| *k == key) {
            return Err(Refusal::Duplicate);
        }
        if !allowed.contains(&key) {
            return Err(Refusal::Unknown);
        }
        pairs.push((key, value));
    }
    if pairs.len() != allowed.len() || pairs.iter().map(|p| p.0).ne(allowed.iter().copied()) {
        return Err(Refusal::Shape);
    }
    let v = |i: usize| pairs[i].1;
    let packet = Packet {
        phase,
        account: fixed(v(0))?,
        origin: v(1).to_owned(),
        root_pin: fixed(v(2))?,
        root_fingerprint: fixed(v(3))?,
        backup_digest: fixed(v(4))?,
        card_digest: fixed(v(5))?,
        archive_id: fixed(v(6))?,
        issued_ms: decimal(v(7))?,
        expires_ms: decimal(v(8))?,
        artifact_digest: if phase == Phase::Prepare {
            None
        } else {
            Some(fixed(v(9))?)
        },
        stamp_ms: decimal(v(pairs.len() - 1))?,
    };
    validate(&packet)?;
    Ok(packet)
}

/// Review the three phase packets of one matched preparation. Every identity
/// and artifact binding is compared exactly against `expected`. The caller
/// supplies fresh trusted `now_ms`; this function authenticates no clock.
pub fn review_sequence(
    prepare: &[u8],
    custody: &[u8],
    manifest: &[u8],
    expected: &Expected,
    now_ms: u64,
) -> Result<[Packet; 3]> {
    let packets = [
        decode(prepare, Phase::Prepare)?,
        decode(custody, Phase::Custody)?,
        decode(manifest, Phase::Manifest)?,
    ];
    for p in &packets {
        if p.account != expected.account
            || p.origin != expected.origin
            || p.root_pin != expected.root_pin
            || p.backup_digest != expected.backup_digest
            || p.card_digest != expected.card_digest
            || p.archive_id != expected.archive_id
            || p.issued_ms != expected.issued_ms
            || p.expires_ms != expected.expires_ms
        {
            return Err(Refusal::Identity);
        }
    }
    if packets[1].artifact_digest == packets[2].artifact_digest {
        return Err(Refusal::Artifact);
    }
    let [a, b, c] = [
        packets[0].stamp_ms,
        packets[1].stamp_ms,
        packets[2].stamp_ms,
    ];
    if a > b
        || b > c
        || now_ms < c
        || now_ms >= expected.expires_ms
        || now_ms - c > MAX_SIGNING_AGE_MS
    {
        return Err(Refusal::Time);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests;
