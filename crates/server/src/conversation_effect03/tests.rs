// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use sha2::{Digest, Sha256};

// Independently framed synthetic tuples. They represent no accepted server
// command, original grant, device custody or actual platform invocation.
fn prefix(ids: u8, hashes: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in 1..=ids {
        bytes.extend([value; 16]);
    }
    for value in 1..=hashes {
        bytes.extend([value + 20; 32]);
    }
    bytes
}
fn manual_hash(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update([0]);
    h.update(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

#[test]
fn independent_public_vectors_match_all_commands_and_real_enrolled_proofs() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/conversation-effects03-v1.json"
    ))
    .unwrap();
    let bytes = |value: &serde_json::Value| B.decode(value.as_str().unwrap()).unwrap();
    let point = bytes(&vector["enrolled_point"]);
    for case in vector["cases"].as_array().unwrap() {
        let submit = SubmitCommand03::decode(&bytes(&case["submit"])).unwrap();
        assert_eq!(
            submit.digest().unwrap().as_slice(),
            bytes(&case["submit_commitment"])
        );
        let record = NoSubmitRecord03::decode(&bytes(&case["closure_record"])).unwrap();
        assert_eq!(
            record.digest().unwrap().as_slice(),
            bytes(&case["closure_commitment"])
        );
        let core = NoSubmitCore03::decode(&bytes(&case["core"])).unwrap();
        core.matches_record(&record).unwrap();
        let signature = bytes(&case["signature"]);
        core.verify_candidate_signature(&point, &signature).unwrap();
        assert!(core.verify_candidate_signature(&point, &[0; 64]).is_err());
        assert!(
            core.verify_candidate_signature(&[0; 65], &signature)
                .is_err()
        );
        for outcome in case["outcomes"].as_array().unwrap() {
            let command = OutcomeCommand03::decode(&bytes(&outcome["command"])).unwrap();
            assert_eq!(
                command.digest().unwrap().as_slice(),
                bytes(&outcome["commitment"])
            );
            assert_eq!(command.segment_count(), submit.segment_count());
            assert_eq!(command.submit_observed_ms(), submit.observed_ms());
        }
    }
}
fn submit() -> Vec<u8> {
    let mut bytes = prefix(5, 2);
    bytes.push(6);
    bytes.extend(5_000_u64.to_be_bytes());
    assert_eq!(bytes.len(), 153);
    bytes
}
fn outcome(code: u8, index: u8) -> Vec<u8> {
    let mut bytes = prefix(6, 3);
    bytes.extend(5_000_u64.to_be_bytes());
    bytes.extend([6, code]);
    bytes.extend(6_000_u64.to_be_bytes());
    bytes.push(index);
    assert_eq!(bytes.len(), 211);
    bytes
}
fn closure(phase: u8) -> Vec<u8> {
    let mut bytes = prefix(6, 3);
    bytes.push(6);
    bytes.extend(5_000_u64.to_be_bytes());
    bytes.push(phase);
    bytes.extend(6_000_u64.to_be_bytes());
    assert_eq!(bytes.len(), 210);
    bytes
}
pub(super) fn core(key: &SigningKey) -> Vec<u8> {
    let mut bytes = b"ZTNS\x01\x03\x03\0".to_vec();
    bytes.extend(prefix(8, 0));
    for n in [1_u64, 2, 3, 4, 1, 6, 5_000, 6_000, 7_000, 37_000] {
        bytes.extend(n.to_be_bytes());
    }
    for value in 1..=7 {
        if value == 5 {
            // Established enrollment/socket ID is algorithm-framed, not
            // selected from a role4 manifest or supplied as actor authority.
            let mut id = Sha256::new();
            id.update(b"ZTSE/key/v1\0");
            id.update([1, 1]);
            id.update(key.verifying_key().to_sec1_point(false).as_bytes());
            bytes.extend(id.finalize());
        } else if value == 7 {
            bytes.extend(manual_hash(
                b"ZTSE/conversation/no-submit-record03/v1",
                &closure(1),
            ));
        } else {
            bytes.extend([value + 20; 32]);
        }
    }
    bytes.push(1);
    assert_eq!(bytes.len(), 441);
    bytes
}

#[test]
fn exact_submit_tuple_and_framing_bind_every_original_field() {
    let bytes = submit();
    let parsed = SubmitCommand03::decode(&bytes).unwrap();
    assert_eq!(parsed.identities()[4], [5; 16]);
    assert_eq!(parsed.fetch_digest(), &[21; 32]);
    assert_eq!(parsed.device_session_digest(), &[22; 32]);
    assert_eq!(parsed.segment_count(), 6);
    assert_eq!(parsed.observed_ms(), 5_000);
    assert_eq!(parsed.bytes().as_slice(), bytes);
    let expected = manual_hash(b"ZTSE/conversation/submit-command03/v1", &bytes);
    assert_eq!(parsed.digest().unwrap(), expected);
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(value) = SubmitCommand03::decode(&changed) {
            assert_ne!(value.digest().unwrap(), expected, "offset {at}");
        }
    }
    for at in [144, 145] {
        let mut bad = bytes.clone();
        if at == 144 {
            bad[at] = 0;
        } else {
            bad[at..].fill(0);
        }
        assert!(SubmitCommand03::decode(&bad).is_err());
    }
    assert!(SubmitCommand03::decode(&bytes[..152]).is_err());
}

#[test]
fn outcome_sent_indices_and_aggregate_sentinel_are_disjoint() {
    for code in 0..=5 {
        let index = if code <= 1 { 5 } else { 255 };
        let bytes = outcome(code, index);
        let value = OutcomeCommand03::decode(&bytes).unwrap();
        assert_eq!(value.identities()[5], [6; 16]);
        assert_eq!(value.digests()[2], [23; 32]);
        assert_eq!(value.submit_observed_ms(), 5_000);
        assert_eq!(value.observed_ms(), 6_000);
        assert_eq!(value.segment_count(), 6);
        assert_eq!(value.segment_index(), (code <= 1).then_some(5));
        assert_eq!(value.bytes().as_slice(), bytes);
        assert_eq!(
            value.digest().unwrap(),
            manual_hash(b"ZTSE/conversation/outcome-command03/v1", &bytes)
        );
        assert!(OutcomeCommand03::decode(&outcome(code, if code <= 1 { 255 } else { 0 })).is_err());
    }
    assert_eq!(
        OutcomeCommand03::decode(&outcome(2, 255))
            .unwrap()
            .evidence(),
        Outcome03::DeliveryOk
    );
    assert!(OutcomeCommand03::decode(&outcome(6, 255)).is_err());
    assert!(OutcomeCommand03::decode(&outcome(0, 6)).is_err());
}

#[test]
fn durable_closure_record_excludes_platform_entry_phase() {
    let mut bytes = closure(0);
    for phase in [0, 1] {
        bytes[201] = phase;
        let value = NoSubmitRecord03::decode(&bytes).unwrap();
        assert_eq!(value.bytes().as_slice(), bytes);
        assert_eq!(
            value.digest().unwrap(),
            manual_hash(b"ZTSE/conversation/no-submit-record03/v1", &bytes)
        );
    }
    bytes[201] = 2;
    assert!(NoSubmitRecord03::decode(&bytes).is_err());
    bytes[201] = 0;
    bytes[202..210].copy_from_slice(&4_999_u64.to_be_bytes());
    assert!(NoSubmitRecord03::decode(&bytes).is_err());
}

#[test]
fn closure_signature_binds_genuine_point_all_scope_bytes_and_its_domain() {
    let key = SigningKey::generate();
    let bytes = core(&key);
    let mut transcript = b"ZTSE/conversation/no-submit-proof03/v1\0".to_vec();
    transcript.extend(441_u32.to_be_bytes());
    transcript.extend(&bytes);
    let sig: Signature = key.sign(&transcript);
    let raw = sig.normalize_s().to_bytes();
    let point = key.verifying_key().to_sec1_point(false);
    let parsed = NoSubmitCore03::decode(&bytes).unwrap();
    assert_eq!(parsed.identities()[7], [8; 16]);
    assert_eq!(parsed.numbers()[9], 37_000);
    let record = NoSubmitRecord03::decode(&closure(1)).unwrap();
    assert_eq!(&parsed.digests()[6], &record.digest().unwrap());
    parsed.matches_record(&record).unwrap();
    assert!(
        parsed
            .matches_record(&NoSubmitRecord03::decode(&closure(0)).unwrap())
            .is_err()
    );
    assert_eq!(parsed.bytes().as_slice(), bytes);
    parsed
        .verify_candidate_signature(point.as_bytes(), &raw)
        .unwrap();
    let canonical = Signature::from_slice(&raw).unwrap();
    let (r, s) = canonical.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-s).to_bytes())
        .unwrap()
        .to_bytes();
    assert!(
        parsed
            .verify_candidate_signature(point.as_bytes(), &high)
            .is_err()
    );
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        if let Ok(candidate) = NoSubmitCore03::decode(&changed) {
            assert!(
                candidate
                    .verify_candidate_signature(point.as_bytes(), &raw)
                    .is_err(),
                "offset {at}"
            );
        }
    }
    let wrong = SigningKey::generate();
    assert!(
        parsed
            .verify_candidate_signature(wrong.verifying_key().to_sec1_point(false).as_bytes(), &raw)
            .is_err()
    );
    let wrong_sig: Signature = key.sign(b"different synthetic purpose");
    assert!(
        parsed
            .verify_candidate_signature(point.as_bytes(), &wrong_sig.normalize_s().to_bytes())
            .is_err()
    );
    assert!(
        parsed
            .verify_candidate_signature(point.as_bytes(), &[0; 64])
            .is_err()
    );
}

#[test]
fn closure_core_has_no_alternate_generation_phase_or_extended_window() {
    let key = SigningKey::generate();
    let bytes = core(&key);
    for (index, replacement) in [(4, 2_u64), (5, 7), (7, 4_999), (9, 37_001)] {
        let mut bad = bytes.clone();
        let at = 136 + index * 8;
        bad[at..at + 8].copy_from_slice(&replacement.to_be_bytes());
        assert!(NoSubmitCore03::decode(&bad).is_err());
    }
    let mut bad = bytes.clone();
    bad[440] = 2;
    assert!(NoSubmitCore03::decode(&bad).is_err());
    bad = bytes.clone();
    bad[8..24].fill(0);
    assert!(NoSubmitCore03::decode(&bad).is_err());
    assert!(NoSubmitCore03::decode(&bytes[..440]).is_err());
}
