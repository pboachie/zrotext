// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest03::tests::{Fixture, hex, sign};

#[test]
fn shared_independent_component_vectors_keep_exact_bytes_and_real_v2_signatures() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/reviewed-intent03-v2.json"
    ))
    .unwrap();
    let mut lengths = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let bytes = hex(&case["intent_hex"]);
        let signature = hex(&case["signature_hex"]);
        let point = hex(&case["signer_point_hex"]);
        let parsed = Intent03V2::decode(&bytes).unwrap();
        assert_eq!(crypto::sha(&bytes).as_slice(), hex(&case["intent_sha256"]));
        assert_eq!(
            crypto::sha(&parsed.transcript()).as_slice(),
            hex(&case["transcript_sha256"])
        );
        assert_eq!(
            parsed.sms_ceiling(),
            case["fields"]["smsCeiling"].as_u64().unwrap() as u8
        );
        assert_eq!(parsed.selection_epoch(), 1);
        assert_eq!(parsed.vault_generation(), 1);
        assert_eq!(
            parsed.envelope_digest().as_slice(),
            hex(&case["fields"]["envelopeDigest"])
        );
        assert_eq!(
            parsed.unsigned_digest().as_slice(),
            hex(&case["fields"]["unsignedDigest"])
        );
        assert!(case["fields"].get("bodyDigest").is_none());
        let checked = verify_signature(parsed, &signature, &point).unwrap();
        assert_eq!(checked.intent().bytes(), bytes);
        assert_eq!(checked.signature().as_slice(), signature);
        lengths.push(bytes.len());
    }
    assert_eq!(lengths, [592, 803, 592]);
}

// A local syntax producer, not the shared protocol vector. Its public fields
// and real signature test prove no database admission or current authority.
fn structural(peer_len: usize, count: u8, ceiling: u8) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    for n in 1..=8 {
        bytes.extend([n; 16]);
    }
    for n in [1u64, 1, 2, 1, 1_000_000, 1_900_000, 1_000_000, 1_030_000] {
        bytes.extend(n.to_be_bytes());
    }
    for n in 1..=10 {
        bytes.extend([n; 32]);
    }
    assert_eq!(bytes.len(), 520);
    bytes.push(peer_len as u8);
    bytes.push(b'+');
    bytes.push(b'1');
    bytes.extend(std::iter::repeat_n(b'2', peer_len - 2));
    bytes.push(count);
    for (role, id) in [(1, [1; 32]), (2, [11; 32])]
        .into_iter()
        .chain((0..count.saturating_sub(2)).map(|n| (3, [12 + n; 32])))
    {
        bytes.push(role);
        bytes.extend(id);
    }
    bytes.push(ceiling);
    bytes
}

#[test]
fn exact_minimum_and_maximum_have_ten_digest_ranges_and_no_extra_field() {
    for (peer_len, readers, ceiling, length) in [(3, 2, 1, 592), (16, 8, 6, 803)] {
        let bytes = structural(peer_len, readers, ceiling);
        assert_eq!(bytes.len(), length);
        let parsed = Intent03V2::decode(&bytes).unwrap();
        assert_eq!(parsed.bytes(), bytes);
        assert_eq!(parsed.account_id(), Uuid::from_bytes([1; 16]));
        assert_eq!(parsed.device_id(), Uuid::from_bytes([2; 16]));
        assert_eq!(parsed.line_id(), Uuid::from_bytes([3; 16]));
        assert_eq!(parsed.binding_id(), Uuid::from_bytes([4; 16]));
        assert_eq!(parsed.user_id(), Uuid::from_bytes([5; 16]));
        assert_eq!(parsed.owner_session_id(), Uuid::from_bytes([6; 16]));
        assert_eq!(parsed.interval_id(), Uuid::from_bytes([7; 16]));
        assert_eq!(parsed.message_id(), Uuid::from_bytes([8; 16]));
        assert_eq!(parsed.binding_generation(), 1);
        assert_eq!(parsed.vault_generation(), 1);
        assert_eq!(parsed.manifest_version(), 2);
        assert_eq!(parsed.selection_epoch(), 1);
        assert_eq!(parsed.observed_ms(), 1_000_000);
        assert_eq!(parsed.message_expires_ms(), 1_900_000);
        assert_eq!(parsed.review_issued_ms(), 1_000_000);
        assert_eq!(parsed.review_expires_ms(), 1_030_000);
        for (index, digest) in [
            parsed.reader_key_id(),
            parsed.root_fingerprint(),
            parsed.manifest_digest(),
            parsed.election_commitment(),
            parsed.election_bundle_sha256(),
            parsed.owner_session_digest(),
            parsed.origin_digest(),
            parsed.signer_key_id(),
            parsed.envelope_digest(),
            parsed.unsigned_digest(),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(*digest, [index as u8 + 1; 32]);
            assert_eq!(
                digest.as_slice(),
                &bytes[200 + index * 32..232 + index * 32]
            );
        }
        assert_eq!(bytes[520], peer_len as u8);
        assert_eq!(parsed.peer().len(), peer_len);
        assert_eq!(parsed.recipients().len(), usize::from(readers));
        assert_eq!(parsed.sms_ceiling(), ceiling);
        let mut inserted = bytes.clone();
        inserted.splice(520..520, [42; 32]);
        assert!(Intent03V2::decode(&inserted).is_err());
    }
}

#[test]
fn explicit_header_framing_identity_reader_and_ceiling_refusals() {
    let bytes = structural(3, 2, 1);
    for at in 0..8 {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(Intent03V2::decode(&bad).is_err());
    }
    for (start, width) in (8..136)
        .step_by(16)
        .map(|at| (at, 16))
        .chain((200..520).step_by(32).map(|at| (at, 32)))
    {
        let mut bad = bytes.clone();
        bad[start..start + width].fill(0);
        assert!(Intent03V2::decode(&bad).is_err());
    }
    for value in [0, 2] {
        let mut bad = bytes.clone();
        bad[144..152].copy_from_slice(&u64::from(value as u8).to_be_bytes());
        assert!(Intent03V2::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[160..168].copy_from_slice(&u64::from(value as u8).to_be_bytes());
        assert!(Intent03V2::decode(&bad).is_err());
    }
    for at in (136..200).step_by(8) {
        for value in [0, i64::MAX as u64 + 1] {
            let mut bad = bytes.clone();
            bad[at..at + 8].copy_from_slice(&value.to_be_bytes());
            assert!(Intent03V2::decode(&bad).is_err());
        }
    }
    for (at, value) in [
        (520, 2),
        (521, b'-'),
        (522, b'0'),
        (523, b'x'),
        (524, 1),
        (525, 2),
        (558, 1),
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert!(Intent03V2::decode(&bad).is_err(), "offset {at}");
    }
    for ceiling in [0, 7, 255] {
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() = ceiling;
        assert!(Intent03V2::decode(&bad).is_err());
    }
    for end in 0..bytes.len() {
        assert!(Intent03V2::decode(&bytes[..end]).is_err());
    }
    assert!(Intent03V2::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    let mut v1 = bytes.clone();
    v1[4] = 1;
    v1.splice(520..520, [42; 32]);
    assert!(super::super::Intent03::decode(&v1).is_ok());
    assert!(Intent03V2::decode(&v1).is_err());
    assert!(super::super::Intent03::decode(&bytes).is_err());
}

#[test]
fn original_review_and_message_time_bounds_are_not_renewed() {
    let bytes = structural(3, 2, 1);
    for (at, value) in [
        (168, 1_000_001u64),
        (176, 1_900_001),
        (184, 1_030_000),
        (192, 1_000_000),
        (192, 1_030_001),
        (192, 1_900_001),
    ] {
        let mut bad = bytes.clone();
        bad[at..at + 8].copy_from_slice(&value.to_be_bytes());
        assert!(Intent03V2::decode(&bad).is_err());
    }
}

#[test]
fn actual_signature_uses_only_explicit_v2_domain_and_owned_exact_bytes() {
    let f = Fixture::new();
    let point = f.keys[4].verifying_key().to_sec1_point(false);
    let mut bytes = structural(3, 2, 6);
    let signature = sign(&f.keys[4], DOMAIN, &bytes);
    let original = bytes.clone();
    let parsed = Intent03V2::decode(&bytes).unwrap();
    bytes[8] ^= 1;
    let checked = verify_signature(parsed, &signature, point.as_bytes()).unwrap();
    assert_eq!(checked.intent().bytes(), original);
    assert_eq!(checked.signature().as_slice(), signature);
    let transcript = checked.intent().transcript();
    assert_eq!(&transcript[..DOMAIN.len()], DOMAIN);
    assert_eq!(
        &transcript[DOMAIN.len()..DOMAIN.len() + 4],
        &(original.len() as u32).to_be_bytes()
    );
    assert_eq!(&transcript[DOMAIN.len() + 4..], original);
    for bad in [
        sign(&f.keys[3], DOMAIN, &original),
        sign(&f.keys[4], super::super::DOMAIN, &original),
        sign(&f.keys[4], b"ZTSE/sign/v3\0", &original),
    ] {
        assert!(
            verify_signature(
                Intent03V2::decode(&original).unwrap(),
                &bad,
                point.as_bytes()
            )
            .is_err()
        );
    }
    let parsed = p256::ecdsa::Signature::from_slice(&signature).unwrap();
    let (r, s) = parsed.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes())
        .unwrap()
        .to_bytes();
    assert!(
        verify_signature(
            Intent03V2::decode(&original).unwrap(),
            &high,
            point.as_bytes()
        )
        .is_err()
    );
    assert!(
        verify_signature(
            Intent03V2::decode(&bytes).unwrap(),
            &signature,
            point.as_bytes()
        )
        .is_err()
    );
    for bad in [&signature[..63], &[signature.as_slice(), &[0]].concat()] {
        assert!(
            verify_signature(
                Intent03V2::decode(&original).unwrap(),
                bad,
                point.as_bytes()
            )
            .is_err()
        );
    }
}
