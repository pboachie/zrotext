// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../protocol/v1/vectors/ztse-draft-01.json");

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
        let parsed = parse(&bytes, Profile::Draft01Proof).unwrap();
        assert_eq!(parsed.profile, Profile::Draft01Proof);
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
        assert_rejected(&bytes, Profile::Draft02Candidate);
        let candidate = draft02_shape(bytes);
        assert_eq!(
            parse(&candidate, Profile::Draft02Candidate).unwrap().kind,
            kind
        );
        assert_rejected(&candidate, Profile::Draft01Proof);
    }
}

#[test]
fn exact_kind_minimum_and_maximum_syntactic_sizes() {
    for (which, minimum, maximum) in [("outbound", 557, 34_213), ("inbound", 426, 34_082)] {
        for profile in [Profile::Draft01Proof, Profile::Draft02Candidate] {
            let fixture = fixture(which);
            let original = if profile == Profile::Draft02Candidate {
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
        assert_rejected(&good[..end], Profile::Draft01Proof);
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_rejected(&trailing, Profile::Draft01Proof);
    assert_rejected(&vec![0; 36_865], Profile::Draft01Proof);
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
        assert_rejected(&change(&good, at, value), Profile::Draft01Proof);
    }
    let parsed = parse(&good, Profile::Draft01Proof).unwrap();
    let body_len_at = 10 + parsed.protected.len() + 12;
    for length in [0u32, 16, 32_785, u32::MAX] {
        let mut bytes = good.clone();
        bytes[body_len_at..body_len_at + 4].copy_from_slice(&length.to_be_bytes());
        assert_rejected(&bytes, Profile::Draft01Proof);
    }
    let count_at = parsed.unsigned.len() - 1 - parsed.wraps.len() * WRAP_LEN;
    for count in [0, 1, 9, 255] {
        assert_rejected(&change(&good, count_at, count), Profile::Draft01Proof);
    }
    let mut bytes = good.clone();
    bytes[body_len_at + 3] += 1;
    assert_rejected(&bytes, Profile::Draft01Proof);
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
        assert_rejected(&change(&outbound, at, value), Profile::Draft01Proof);
    }
    let mut expired = outbound.clone();
    expired[10 + 144..10 + 152].copy_from_slice(&1_700_000_000_000u64.to_be_bytes());
    assert_rejected(&expired, Profile::Draft01Proof);
    let mut too_late = outbound.clone();
    let observed = parse(&outbound, Profile::Draft01Proof).unwrap().observed_ms;
    too_late[10 + 144..10 + 152].copy_from_slice(&(observed + 900_001).to_be_bytes());
    assert_rejected(&too_late, Profile::Draft01Proof);

    let inbound = fixture("inbound");
    for (at, value) in [
        (10 + 144, 0),
        (10 + 160, 0x80),
        (10 + 168, 2),
        (10 + 169, b'1'),
        (10 + 170, b'0'),
        (10 + 171, b'a'),
    ] {
        assert_rejected(&change(&inbound, at, value), Profile::Draft01Proof);
    }
    let mut zero_sequence = inbound.clone();
    zero_sequence[10 + 160..10 + 168].fill(0);
    assert_rejected(&zero_sequence, Profile::Draft01Proof);
    assert_rejected(&change(&outbound, 5, 2), Profile::Draft01Proof);
    assert_rejected(&change(&inbound, 5, 1), Profile::Draft01Proof);
}

#[test]
fn malformed_wrap_roles_order_points_and_signature_scalars() {
    let outbound = fixture("outbound");
    let parsed = parse(&outbound, Profile::Draft01Proof).unwrap();
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
        assert_rejected(&change(&outbound, at, value), Profile::Draft01Proof);
    }
    let mut duplicate = outbound.clone();
    duplicate[second..second + 33].copy_from_slice(&outbound[first..first + 33]);
    assert_rejected(&duplicate, Profile::Draft01Proof);
    let mut no_archive = outbound.clone();
    no_archive[second] = 3;
    assert_rejected(&no_archive, Profile::Draft01Proof);
    let inbound = fixture("inbound");
    let parsed_inbound = parse(&inbound, Profile::Draft01Proof).unwrap();
    let inbound_wrap = parsed_inbound.unsigned.len() - WRAP_LEN;
    assert_rejected(&change(&inbound, inbound_wrap, 1), Profile::Draft01Proof);
    assert_rejected(&change(&inbound, inbound_wrap, 3), Profile::Draft01Proof);

    let mut zero_signature = outbound.clone();
    zero_signature[parsed.unsigned.len()..].fill(0);
    assert_rejected(&zero_signature, Profile::Draft01Proof);
    let mut overflow_r = outbound.clone();
    overflow_r[parsed.unsigned.len()..parsed.unsigned.len() + 32].fill(0xff);
    assert_rejected(&overflow_r, Profile::Draft01Proof);
    let candidate = draft02_shape(outbound);
    let at = candidate.len() - SIGNATURE_LEN;
    let mut high_s = candidate.clone();
    high_s[at + 32..].fill(0xff);
    assert_rejected(&high_s, Profile::Draft02Candidate);
    // Draft 01 did not decide a low-s rule; draft 02 explicitly does.
    let mut high_s_valid = candidate.clone();
    let original = fixture("outbound");
    let high = Signature::from_slice(&original[at..]).unwrap();
    assert_ne!(high.normalize_s().to_bytes(), high.to_bytes());
    high_s_valid[at..].copy_from_slice(&high.to_bytes());
    assert_rejected(&high_s_valid, Profile::Draft02Candidate);
}

fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

fn signer_point() -> Vec<u8> {
    let vector: Value = serde_json::from_str(FIXTURE).unwrap();
    decode_hex(vector["signerPublicPointHex"].as_str().unwrap())
}

fn recipients(parsed: &Envelope<'_>) -> Vec<ExpectedRecipient> {
    parsed
        .wraps
        .iter()
        .map(|wrap| ExpectedRecipient {
            role: wrap.role,
            key_id: wrap.key_id.try_into().unwrap(),
        })
        .collect()
}

fn context<'a>(
    parsed: &Envelope<'a>,
    point: &'a [u8],
    recipients: &'a [ExpectedRecipient],
) -> ExpectedContext<'a> {
    ExpectedContext {
        profile: parsed.profile,
        kind: parsed.kind,
        account_id: parsed.account_id.try_into().unwrap(),
        message_id: parsed.message_id.try_into().unwrap(),
        device_id: parsed.device_id.try_into().unwrap(),
        line_id: parsed.line_id.try_into().unwrap(),
        keyset_version: parsed.keyset_version,
        manifest_digest: parsed.manifest_digest.try_into().unwrap(),
        peer: parsed.peer,
        signer_public_point: point,
        recipients,
    }
}

#[test]
fn pinned_cross_client_signatures_verify_and_return_exact_unsigned_identity() {
    let vector: Value = serde_json::from_str(FIXTURE).unwrap();
    let point = signer_point();
    for which in ["outbound", "inbound"] {
        let bytes = fixture(which);
        let parsed = parse(&bytes, Profile::Draft01Proof).unwrap();
        let recipients = recipients(&parsed);
        let expected = context(&parsed, &point, &recipients);
        let verified = verify(&bytes, &expected).unwrap();
        assert_eq!(verified.envelope().unsigned, parsed.unsigned);
        assert_eq!(
            verified.unsigned_digest().as_slice(),
            decode_hex(vector[which]["unsignedSha256"].as_str().unwrap())
        );
        assert_eq!(format!("{verified:?}"), "SignatureVerifiedEnvelope { .. }");
        assert!(!format!("{:?}", verified.envelope()).contains("+12"));
    }
}

#[test]
fn a_valid_signature_cannot_override_any_trusted_routing_or_recipient_field() {
    let bytes = fixture("outbound");
    let parsed = parse(&bytes, Profile::Draft01Proof).unwrap();
    let point = signer_point();
    let mut recipients = recipients(&parsed);
    let expected = context(&parsed, &point, &recipients);
    let mut changed = Vec::new();
    let mut wrong = expected.clone();
    wrong.account_id[0] ^= 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.message_id[0] ^= 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.device_id[0] ^= 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.line_id[0] ^= 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.manifest_digest[0] ^= 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.keyset_version += 1;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.peer = b"+34";
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.kind = Kind::Inbound;
    changed.push(wrong);
    let mut wrong = expected.clone();
    wrong.recipients = &recipients[..1];
    changed.push(wrong);
    for wrong in changed {
        assert_eq!(
            verify(&bytes, &wrong).unwrap_err(),
            VerifyError::ContextMismatch
        );
    }
    recipients[0].key_id[0] ^= 1;
    assert_eq!(
        verify(&bytes, &context(&parsed, &point, &recipients)).unwrap_err(),
        VerifyError::ContextMismatch
    );
    recipients[0].key_id[0] ^= 1;
    recipients[0].role = 3;
    assert_eq!(
        verify(&bytes, &context(&parsed, &point, &recipients)).unwrap_err(),
        VerifyError::ContextMismatch
    );
}

#[test]
fn exact_transcript_tampering_fails_even_when_routing_and_shape_match() {
    let bytes = fixture("outbound");
    let parsed = parse(&bytes, Profile::Draft01Proof).unwrap();
    let point = signer_point();
    let recipients = recipients(&parsed);
    let expected = context(&parsed, &point, &recipients);
    let protected_end = 10 + parsed.protected.len();
    let first_wrap = parsed.unsigned.len() - parsed.wraps.len() * WRAP_LEN;
    for at in [
        10 + 143,
        protected_end,
        protected_end + 16,
        first_wrap + 98,
        bytes.len() - 1,
    ] {
        let changed = change(&bytes, at, bytes[at] ^ 1);
        assert_eq!(
            verify(&changed, &expected).unwrap_err(),
            VerifyError::InvalidSignature,
            "tampered offset {at}"
        );
    }
    let mut wrong_point = point.clone();
    wrong_point[0] = 2;
    let mut wrong = expected.clone();
    wrong.signer_public_point = &wrong_point;
    assert_eq!(
        verify(&bytes, &wrong).unwrap_err(),
        VerifyError::InvalidSigner
    );
    use p256::elliptic_curve::Generate;
    let other = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
    let other_point = other.verifying_key().to_sec1_point(false);
    let mut wrong = expected;
    wrong.signer_public_point = other_point.as_bytes();
    assert_eq!(
        verify(&bytes, &wrong).unwrap_err(),
        VerifyError::ContextMismatch
    );
}

#[test]
fn draft01_signature_alias_preserves_unsigned_identity_without_authorizing_candidate02() {
    let bytes = fixture("outbound");
    let parsed = parse(&bytes, Profile::Draft01Proof).unwrap();
    let point = signer_point();
    let recipients = recipients(&parsed);
    let expected = context(&parsed, &point, &recipients);
    let before = verify(&bytes, &expected).unwrap();
    let mut canonical = bytes.clone();
    canonical[parsed.unsigned.len()..].copy_from_slice(
        &Signature::from_slice(parsed.signature)
            .unwrap()
            .normalize_s()
            .to_bytes(),
    );
    assert_eq!(
        verify(&canonical, &expected).unwrap().unsigned_digest(),
        before.unsigned_digest()
    );
    let mut candidate_context = expected.clone();
    candidate_context.profile = Profile::Draft02Candidate;
    assert!(verify(&bytes, &candidate_context).is_err());
    // Merely changing the profile byte cannot make a valid signed candidate.
    canonical[4] = 2;
    assert_eq!(
        verify(&canonical, &candidate_context).unwrap_err(),
        VerifyError::InvalidSignature
    );
}

#[test]
fn signed_candidate02_requires_canonical_signature_and_explicit_profile() {
    use p256::{
        ecdsa::{SigningKey, signature::Signer},
        elliptic_curve::Generate,
    };
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let point = key.verifying_key().to_sec1_point(false);
    let mut bytes = fixture("outbound");
    bytes[4] = 2;
    bytes[10 + 104..10 + 136].copy_from_slice(&Sha256::digest(
        [b"ZTSE/key/v1\0".as_slice(), &[1, 1], point.as_bytes()].concat(),
    ));
    let unsigned_end = bytes.len() - SIGNATURE_LEN;
    let transcript = [
        b"ZTSE/sign/v1\0".as_slice(),
        &(unsigned_end as u32).to_be_bytes(),
        &bytes[..unsigned_end],
    ]
    .concat();
    let signature: Signature = key.sign(&transcript);
    let signature = signature.normalize_s();
    bytes[unsigned_end..].copy_from_slice(&signature.to_bytes());
    let parsed = parse(&bytes, Profile::Draft02Candidate).unwrap();
    let recipients = recipients(&parsed);
    let expected = context(&parsed, point.as_bytes(), &recipients);
    verify(&bytes, &expected).unwrap();
    let mut proof_context = expected.clone();
    proof_context.profile = Profile::Draft01Proof;
    assert!(verify(&bytes, &proof_context).is_err());
    // The mathematically equivalent high-s signature is forbidden in candidate02.
    let order = decode_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut high = bytes.clone();
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference =
            i16::from(order[index]) - i16::from(bytes[unsigned_end + 32 + index]) - borrow;
        high[unsigned_end + 32 + index] = difference.rem_euclid(256) as u8;
        borrow = i16::from(difference < 0);
    }
    assert_eq!(
        verify(&high, &expected).unwrap_err(),
        VerifyError::InvalidEnvelope("high-s signature")
    );
}
