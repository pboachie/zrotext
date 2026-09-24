// SPDX-License-Identifier: AGPL-3.0-only
//! Test-only structural reader for the unaccepted ZTSE envelope candidates.
//! This module is deliberately outside the server library and all HTTP routes.
//! A successful parse does not verify a signature, manifest, grant, replay state,
//! HPKE wrap, body AEAD, or permission to send an SMS.

use p256::{PublicKey, ecdsa::Signature};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../protocol/v1/vectors/ztse-draft-01.json");
const WRAP_LEN: usize = 146;
const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Draft01 = 1,
    Draft02 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Outbound = 1,
    Inbound = 2,
}

#[derive(Debug)]
struct Wrap<'a> {
    role: u8,
    key_id: &'a [u8],
    enc: &'a [u8],
    ct: &'a [u8],
}

#[derive(Debug)]
struct Envelope<'a> {
    profile: Profile,
    kind: Kind,
    protected: &'a [u8],
    account_id: &'a [u8],
    message_id: &'a [u8],
    device_id: &'a [u8],
    line_id: &'a [u8],
    keyset_version: u64,
    manifest_digest: &'a [u8],
    signer_key_id: &'a [u8],
    observed_ms: u64,
    expires_ms: Option<u64>,
    event_id: Option<&'a [u8]>,
    local_sequence: Option<u64>,
    peer: &'a [u8],
    nonce: &'a [u8],
    body_ct: &'a [u8],
    wraps: Vec<Wrap<'a>>,
    unsigned: &'a [u8],
    signature: &'a [u8],
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
fn parse(input: &[u8], expected: Profile) -> Result<Envelope<'_>, &'static str> {
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
    if expected == Profile::Draft02
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

fn fixture(which: &str) -> Vec<u8> {
    let json: Value = serde_json::from_str(FIXTURE).unwrap();
    let hex = json[which]["envelopeHex"].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn draft02_shape(mut bytes: Vec<u8>) -> Vec<u8> {
    // Syntax-only derivative of the unchanged draft-01 fixture. This is not a
    // valid signed profile-02 vector and must never be used as an open test.
    bytes[4] = 2;
    let at = bytes.len() - SIGNATURE_LEN;
    let signature = Signature::from_slice(&bytes[at..]).unwrap();
    bytes[at..].copy_from_slice(&signature.normalize_s().to_bytes());
    bytes
}

fn change(source: &[u8], at: usize, value: u8) -> Vec<u8> {
    let mut bytes = source.to_vec();
    bytes[at] = value;
    bytes
}

fn resized_shape(
    source: &[u8],
    profile: Profile,
    peer: &[u8],
    body_len: usize,
    readers: u8,
) -> Vec<u8> {
    // Syntactic sizes only: modified ciphertext/wrap bytes are not signed or decryptable.
    let parsed = parse(source, profile).unwrap();
    let peer_len_at = if parsed.kind == Kind::Outbound {
        153
    } else {
        168
    };
    let mut protected = parsed.protected[..peer_len_at].to_vec();
    protected.push(peer.len() as u8);
    protected.extend_from_slice(peer);
    let mut bytes = source[..8].to_vec();
    bytes.extend_from_slice(&(protected.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&protected);
    bytes.extend_from_slice(parsed.nonce);
    bytes.extend_from_slice(&(body_len as u32).to_be_bytes());
    bytes.resize(bytes.len() + body_len, 0);
    bytes.push(parsed.wraps.len() as u8 + readers);
    for wrap in &parsed.wraps {
        bytes.push(wrap.role);
        bytes.extend_from_slice(wrap.key_id);
        bytes.extend_from_slice(wrap.enc);
        bytes.extend_from_slice(wrap.ct);
    }
    let archive = parsed.wraps.iter().find(|wrap| wrap.role == 2).unwrap();
    for number in 1..=readers {
        let mut key_id = [0u8; 32];
        key_id[31] = number;
        bytes.push(3);
        bytes.extend_from_slice(&key_id);
        bytes.extend_from_slice(archive.enc);
        bytes.extend_from_slice(archive.ct);
    }
    bytes.extend_from_slice(parsed.signature);
    bytes
}

fn assert_rejected(bytes: &[u8], expected: Profile) {
    assert!(
        parse(bytes, expected).is_err(),
        "accepted malformed {}-byte envelope",
        bytes.len()
    );
}

#[test]
fn exact_draft01_fixtures_and_explicit_profile_selection() {
    for (which, kind) in [("outbound", Kind::Outbound), ("inbound", Kind::Inbound)] {
        let bytes = fixture(which);
        let parsed = parse(&bytes, Profile::Draft01).unwrap();
        assert_eq!(parsed.profile, Profile::Draft01);
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.account_id.len(), 16);
        assert_eq!(parsed.message_id.len(), 16);
        assert_eq!(parsed.device_id.len(), 16);
        assert_eq!(parsed.line_id.len(), 16);
        assert_eq!(parsed.keyset_version, 3);
        assert_eq!(parsed.manifest_digest.len(), 32);
        assert_eq!(parsed.signer_key_id.len(), 32);
        assert!(parsed.observed_ms > 0);
        assert_eq!(parsed.peer, b"+12");
        assert_eq!(parsed.nonce.len(), 12);
        assert!(parsed.body_ct.len() >= 17);
        assert_eq!(parsed.unsigned.len() + parsed.signature.len(), bytes.len());
        assert_eq!(
            parsed.protected.len(),
            if kind == Kind::Outbound { 157 } else { 172 }
        );
        assert_eq!(
            parsed.wraps.len(),
            if kind == Kind::Outbound { 2 } else { 1 }
        );
        for wrap in &parsed.wraps {
            assert_eq!(wrap.key_id.len(), 32);
            assert_eq!(wrap.enc.len(), 65);
            assert_eq!(wrap.ct.len(), 48);
        }
        if kind == Kind::Outbound {
            assert_eq!(parsed.expires_ms.unwrap() - parsed.observed_ms, 100_000);
            assert!(parsed.event_id.is_none());
        } else {
            assert_eq!(parsed.event_id.unwrap(), parsed.message_id);
            assert_eq!(parsed.local_sequence, Some(7));
            assert!(parsed.expires_ms.is_none());
        }
        assert_rejected(&bytes, Profile::Draft02);
        let candidate = draft02_shape(bytes);
        assert_eq!(parse(&candidate, Profile::Draft02).unwrap().kind, kind);
        assert_rejected(&candidate, Profile::Draft01);
    }
}

#[test]
fn exact_kind_minimum_and_maximum_syntactic_sizes() {
    for (which, minimum, maximum) in [("outbound", 557, 34_213), ("inbound", 426, 34_082)] {
        for profile in [Profile::Draft01, Profile::Draft02] {
            let fixture = fixture(which);
            let original = if profile == Profile::Draft02 {
                draft02_shape(fixture)
            } else {
                fixture
            };
            let smallest = resized_shape(&original, profile, b"+12", 17, 0);
            assert_eq!(smallest.len(), minimum);
            parse(&smallest, profile).unwrap();
            let largest = resized_shape(&original, profile, b"+123456789012345", 32_784, 6);
            assert_eq!(largest.len(), maximum);
            parse(&largest, profile).unwrap();
            assert_rejected(&largest[..largest.len() - 1], profile);
            let mut trailing = largest;
            trailing.push(0);
            assert_rejected(&trailing, profile);
        }
    }
}

#[test]
fn malformed_header_lengths_offsets_and_eof() {
    let good = fixture("outbound");
    for end in 0..good.len() {
        assert_rejected(&good[..end], Profile::Draft01);
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_rejected(&trailing, Profile::Draft01);
    assert_rejected(&vec![0; 36_865], Profile::Draft01);
    for (at, value) in [
        (0, 0),
        (4, 0),
        (4, 3),
        (5, 0),
        (5, 3),
        (6, 1),
        (7, 1),
        (8, 0xff),
        (9, 0),
        (9, 158),
    ] {
        assert_rejected(&change(&good, at, value), Profile::Draft01);
    }
    let parsed = parse(&good, Profile::Draft01).unwrap();
    let body_len_at = 10 + parsed.protected.len() + 12;
    for length in [0u32, 16, 32_785, u32::MAX] {
        let mut bytes = good.clone();
        bytes[body_len_at..body_len_at + 4].copy_from_slice(&length.to_be_bytes());
        assert_rejected(&bytes, Profile::Draft01);
    }
    let count_at = parsed.unsigned.len() - 1 - parsed.wraps.len() * WRAP_LEN;
    for count in [0, 1, 9, 255] {
        assert_rejected(&change(&good, count_at, count), Profile::Draft01);
    }
    let mut bytes = good.clone();
    bytes[body_len_at + 3] += 1;
    assert_rejected(&bytes, Profile::Draft01);
}

#[test]
fn malformed_protected_fields_and_kind_separation() {
    let outbound = fixture("outbound");
    for (at, value) in [
        (10 + 64, 0x80),
        (10 + 136, 0x80),
        (10 + 144, 0x80),
        (10 + 152, 0),
        (10 + 152, 2),
        (10 + 153, 2),
        (10 + 154, b'1'),
        (10 + 155, b'0'),
        (10 + 156, b'a'),
    ] {
        assert_rejected(&change(&outbound, at, value), Profile::Draft01);
    }
    let mut expired = outbound.clone();
    expired[10 + 144..10 + 152].copy_from_slice(&1_700_000_000_000u64.to_be_bytes());
    assert_rejected(&expired, Profile::Draft01);
    let mut too_late = outbound.clone();
    let observed = parse(&outbound, Profile::Draft01).unwrap().observed_ms;
    too_late[10 + 144..10 + 152].copy_from_slice(&(observed + 900_001).to_be_bytes());
    assert_rejected(&too_late, Profile::Draft01);

    let inbound = fixture("inbound");
    for (at, value) in [
        (10 + 144, 0),
        (10 + 160, 0x80),
        (10 + 168, 2),
        (10 + 169, b'1'),
        (10 + 170, b'0'),
        (10 + 171, b'a'),
    ] {
        assert_rejected(&change(&inbound, at, value), Profile::Draft01);
    }
    let mut zero_sequence = inbound.clone();
    zero_sequence[10 + 160..10 + 168].fill(0);
    assert_rejected(&zero_sequence, Profile::Draft01);
    assert_rejected(&change(&outbound, 5, 2), Profile::Draft01);
    assert_rejected(&change(&inbound, 5, 1), Profile::Draft01);
}

#[test]
fn malformed_wrap_roles_order_points_and_signature_scalars() {
    let outbound = fixture("outbound");
    let parsed = parse(&outbound, Profile::Draft01).unwrap();
    let first = parsed.unsigned.len() - parsed.wraps.len() * WRAP_LEN;
    let second = first + WRAP_LEN;
    for (at, value) in [
        (first, 0),
        (first, 3),
        (first, 4),
        (first + 33, 2),
        (first + 34, 0xff),
        (second, 1),
        (second + 33, 0),
    ] {
        assert_rejected(&change(&outbound, at, value), Profile::Draft01);
    }
    let mut duplicate = outbound.clone();
    duplicate[second..second + 33].copy_from_slice(&outbound[first..first + 33]);
    assert_rejected(&duplicate, Profile::Draft01);
    let mut no_archive = outbound.clone();
    no_archive[second] = 3;
    assert_rejected(&no_archive, Profile::Draft01);
    let inbound = fixture("inbound");
    let parsed_inbound = parse(&inbound, Profile::Draft01).unwrap();
    let inbound_wrap = parsed_inbound.unsigned.len() - WRAP_LEN;
    assert_rejected(&change(&inbound, inbound_wrap, 1), Profile::Draft01);
    assert_rejected(&change(&inbound, inbound_wrap, 3), Profile::Draft01);

    let mut zero_signature = outbound.clone();
    zero_signature[parsed.unsigned.len()..].fill(0);
    assert_rejected(&zero_signature, Profile::Draft01);
    let mut overflow_r = outbound.clone();
    overflow_r[parsed.unsigned.len()..parsed.unsigned.len() + 32].fill(0xff);
    assert_rejected(&overflow_r, Profile::Draft01);
    let candidate = draft02_shape(outbound);
    let at = candidate.len() - SIGNATURE_LEN;
    let mut high_s = candidate.clone();
    high_s[at + 32..].fill(0xff);
    assert_rejected(&high_s, Profile::Draft02);
    // Draft 01 did not decide a low-s rule; draft 02 explicitly does.
    let mut high_s_valid = candidate.clone();
    let original = fixture("outbound");
    let high = Signature::from_slice(&original[at..]).unwrap();
    assert_ne!(high.normalize_s().to_bytes(), high.to_bytes());
    high_s_valid[at..].copy_from_slice(&high.to_bytes());
    assert_rejected(&high_s_valid, Profile::Draft02);
}
