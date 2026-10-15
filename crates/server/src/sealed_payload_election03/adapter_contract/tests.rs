// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn owner() -> OwnerSessionIdentity03 {
    OwnerSessionIdentity03 {
        account_id: [1; 16],
        user_id: [2; 16],
        session_id: [3; 16],
    }
}

fn device() -> DeviceSessionIdentity03<'static> {
    DeviceSessionIdentity03 {
        account_id: [1; 16],
        device_id: [4; 16],
        site_id: "site-A",
        instance_id: "instance-01",
        connection_epoch: 7,
        deployment_epoch: 11,
        line_activation_version: 2,
        enrollment_signing_key_id: [5; 32],
    }
}

fn registration() -> RegistrationEvidence03<'static> {
    RegistrationEvidence03 {
        // Deliberately opaque synthetic bytes: this fixture is NOT a valid
        // registration transcript/signature or an authenticated receipt.
        transcript: b"synthetic-registration-bytes",
        root_signature: &[6; 64],
        approval_signature: &[7; 64],
        approval_point: &[8; 65],
        approval_fingerprint: &[9; 32],
        paired_fingerprint: &[10; 32],
        issued_ms: 1000,
        expires_ms: 2000,
        completed_ms: 1500,
    }
}

fn binding() -> OldBindingIdentity03 {
    OldBindingIdentity03 {
        binding_id: [11; 16],
        account_id: [1; 16],
        device_id: [4; 16],
        line_id: [12; 16],
        generation: 13,
        activation_challenge_id: [14; 16],
        registration_id: [15; 16],
        registration_evidence_sha256: registration().digest().unwrap(),
        owner_approval_digest: [16; 32],
        device_confirmation_digest: [17; 32],
        selected_reader_key_id: [18; 32],
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn independent_canonical_vectors_pin_exact_bytes_domains_and_fence_integer() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/profile03-authority-adapter-canonical.json"
    ))
    .unwrap();
    for (name, canonical) in [
        ("owner_session", owner().canonical().unwrap()),
        ("device_session", device().canonical().unwrap()),
        ("registration_evidence", registration().canonical().unwrap()),
        ("old_binding", binding().canonical().unwrap()),
    ] {
        assert_eq!(hex(&canonical), vector[name]["canonical_hex"], "{name}");
        assert_eq!(hex(&sha(&canonical)), vector[name]["sha256"], "{name}");
    }
    assert_eq!(
        account_fence_key(&[1; 16]).unwrap().to_string(),
        vector["account_fence"]["signed_key_decimal"]
    );
    assert_eq!(
        hex(&origin_digest("https://gateway.example.test").unwrap()),
        vector["origin"]["sha256"]
    );
}

#[test]
fn session_identity_changes_are_bound_but_no_claimed_role_or_permission_is_encoded() {
    let expected = owner().digest().unwrap();
    for field in 0..3 {
        let mut changed = owner();
        match field {
            0 => changed.account_id[0] ^= 1,
            1 => changed.user_id[0] ^= 1,
            _ => changed.session_id[0] ^= 1,
        }
        assert_ne!(changed.digest().unwrap(), expected);
    }
    let expected = device().digest().unwrap();
    for field in 0..7 {
        let mut changed = device();
        match field {
            0 => changed.account_id[0] ^= 1,
            1 => changed.device_id[0] ^= 1,
            2 => changed.site_id = "site-B",
            3 => changed.instance_id = "instance-02",
            4 => changed.connection_epoch += 1,
            5 => changed.deployment_epoch += 1,
            _ => changed.enrollment_signing_key_id[0] ^= 1,
        }
        assert_ne!(changed.digest().unwrap(), expected);
    }
}

#[test]
fn variable_session_identifiers_are_byte_framed_without_normalization() {
    let mut first = device();
    first.site_id = "ab";
    first.instance_id = "c";
    let mut second = device();
    second.site_id = "a";
    second.instance_id = "bc";
    assert_ne!(first.canonical().unwrap(), second.canonical().unwrap());
    first.site_id = "é";
    second.site_id = "e\u{301}";
    assert_ne!(first.digest().unwrap(), second.digest().unwrap());
    let maximum = "é".repeat(128);
    first.site_id = &maximum;
    assert!(first.canonical().is_ok());
    let excessive = "é".repeat(129);
    first.site_id = &excessive;
    assert!(first.canonical().is_err());
    for value in ["", "a\0b", "a\nb", "a\u{7f}b"] {
        first.site_id = value;
        assert!(first.canonical().is_err());
        first.site_id = "site-A";
        first.instance_id = value;
        assert!(first.canonical().is_err());
    }
}

#[test]
fn unsupported_origin_versions_and_zero_or_overflowed_session_fields_refuse() {
    for version in [0, 1, 3, u16::MAX] {
        let mut changed = device();
        changed.line_activation_version = version;
        assert!(changed.canonical().is_err());
    }
    for value in [0, i64::MAX as u64 + 1] {
        let mut changed = device();
        changed.connection_epoch = value;
        assert!(changed.canonical().is_err());
        changed = device();
        changed.deployment_epoch = value;
        assert!(changed.canonical().is_err());
    }
    let mut changed = device();
    changed.enrollment_signing_key_id = [0; 32];
    assert!(changed.canonical().is_err());
    for field in 0..3 {
        let mut changed = owner();
        match field {
            0 => changed.account_id = [0; 16],
            1 => changed.user_id = [0; 16],
            _ => changed.session_id = [0; 16],
        }
        assert!(changed.canonical().is_err());
    }
    assert!(account_fence_key(&[0; 16]).is_err());
}

#[test]
fn persisted_binding_identity_and_exact_registration_proofs_change_the_commitment() {
    let expected = binding().digest().unwrap();
    for field in 0..11 {
        let mut changed = binding();
        match field {
            0 => changed.binding_id[0] ^= 1,
            1 => changed.account_id[0] ^= 1,
            2 => changed.device_id[0] ^= 1,
            3 => changed.line_id[0] ^= 1,
            4 => changed.generation += 1,
            5 => changed.activation_challenge_id[0] ^= 1,
            6 => changed.registration_id[0] ^= 1,
            7 => changed.registration_evidence_sha256[0] ^= 1,
            8 => changed.owner_approval_digest[0] ^= 1,
            9 => changed.device_confirmation_digest[0] ^= 1,
            _ => changed.selected_reader_key_id[0] ^= 1,
        }
        assert_ne!(changed.digest().unwrap(), expected);
    }
    let original = registration().digest().unwrap();
    let mut changed = registration();
    changed.root_signature = &[19; 64];
    assert_ne!(changed.digest().unwrap(), original);
    changed = registration();
    changed.approval_signature = &[20; 64];
    assert_ne!(changed.digest().unwrap(), original);
    changed = registration();
    changed.transcript = b"different-synthetic-registration-bytes";
    assert_ne!(changed.digest().unwrap(), original);
}

#[test]
fn receipt_bounds_and_binding_zero_or_overflow_refuse() {
    for (issued, expires, completed) in [
        (0, 2000, 1500),
        (1000, 1000, 1000),
        (1000, 301001, 1500),
        (1000, 2000, 999),
        (1000, 2000, 2000),
        (1000, i64::MAX as u64 + 1, 1500),
    ] {
        let mut receipt = registration();
        receipt.issued_ms = issued;
        receipt.expires_ms = expires;
        receipt.completed_ms = completed;
        assert!(receipt.canonical().is_err());
    }
    for transcript in [Vec::new(), vec![1; 1025]] {
        let mut receipt = registration();
        receipt.transcript = &transcript;
        assert!(receipt.canonical().is_err());
    }
    let mut changed = binding();
    changed.binding_id = [0; 16];
    assert!(changed.canonical().is_err());
    for generation in [0, i64::MAX as u64 + 1] {
        changed = binding();
        changed.generation = generation;
        assert!(changed.canonical().is_err());
    }
}

#[test]
fn only_the_existing_canonical_https_origin_serialization_is_accepted() {
    for origin in [
        "http://gateway.example.test",
        "https://GATEWAY.example.test",
        "https://gateway.example.test/",
        "https://gateway.example.test:443",
        "https://gateway.example.test/path",
        "https://user@gateway.example.test",
        "https://gateway.example.test?q=1",
        "https://gateway.example.test#fragment",
    ] {
        assert!(origin_digest(origin).is_err(), "{origin}");
    }
}

#[test]
fn enrollment_fingerprint_cannot_substitute_for_the_protocol_signing_key_id() {
    use crate::sealed_manifest03::tests::{corpus, hex as decode};
    let point = decode(&corpus()["publicPointsHex"]["deviceEnrollment"]);
    let fingerprint = sha(&point);
    let key = enrollment_signing_key_id(&point, &fingerprint).unwrap();
    assert_eq!(key, crate::sealed_manifest::key_id(4, &point));
    assert_ne!(key, fingerprint);
    assert!(enrollment_signing_key_id(&point, &key).is_err());
    assert!(enrollment_signing_key_id(&point[..33], &fingerprint).is_err());
    let mut different = point.clone();
    different[10] ^= 1;
    assert!(enrollment_signing_key_id(&different, &fingerprint).is_err());
    let mut off_curve = [0u8; 65];
    off_curve[0] = 4;
    assert!(enrollment_signing_key_id(&off_curve, &sha(&off_curve)).is_err());
}
