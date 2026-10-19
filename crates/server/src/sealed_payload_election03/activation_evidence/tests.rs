// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_inbound::line_activation::LineChallenge;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use uuid::Uuid;
use zrotext_root_material::sealed_root_enrollment;

struct Fixture {
    evidence: ActivationEvidence03,
    registration: Vec<u8>,
    expected: ExpectedActivation03<'static>,
    device: SigningKey,
    owner: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let owner = SigningKey::generate_from_rng(&mut rand::rng());
        let device = SigningKey::generate_from_rng(&mut rand::rng());
        let device_point: [u8; 65] = device
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let owner_point: [u8; 65] = owner
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let identity = super::super::registration_reader::OriginalIdentity {
            account: Uuid::new_v4(),
            registration: Uuid::new_v4(),
            user: Uuid::new_v4(),
            owner_session: Uuid::new_v4(),
            device: Uuid::new_v4(),
            line: Uuid::new_v4(),
            generation: 1,
        };
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(identity.account.as_bytes());
        pin.extend_from_slice(&1u64.to_be_bytes());
        pin.extend_from_slice(root.verifying_key().to_sec1_point(false).as_bytes());
        let pin: [u8; 94] = pin.try_into().unwrap();
        let root_fingerprint =
            sealed_root_enrollment::root_fingerprint(&pin, identity.account.as_bytes()).unwrap();
        let approval_fingerprint = sha(&owner_point);
        let paired_fingerprint = sha(&device_point);
        let statement = registration::Statement::new(
            registration::Scope {
                account: *identity.account.as_bytes(),
                user: *identity.user.as_bytes(),
                owner_session: *identity.owner_session.as_bytes(),
                device: *identity.device.as_bytes(),
                line: *identity.line.as_bytes(),
                next_generation: 1,
                challenge: *identity.registration.as_bytes(),
                nonce: [5; 32],
                issued_ms: 1000,
                expires_ms: 301000,
                approval_fingerprint,
                paired_signing_fingerprint: paired_fingerprint,
                connection_epoch: 1,
                deployment_epoch: 1,
                site_id: "synthetic-site".into(),
                instance_id: "synthetic-instance".into(),
                origin: "https://gateway.example.test".into(),
            },
            pin,
            root_fingerprint,
            owner_point,
        )
        .unwrap();
        let transcript = registration::encode(&statement).unwrap();
        let root_signature: Signature = root.sign(&transcript);
        let root_signature: [u8; 64] = root_signature.normalize_s().to_bytes().into();
        let approval_signature: Signature = owner.sign(&transcript);
        let approval_signature: [u8; 64] = approval_signature.normalize_s().to_bytes().into();
        let original = RegistrationEvidence03 {
            transcript: &transcript,
            root_signature: &root_signature,
            approval_signature: &approval_signature,
            approval_point: &owner_point,
            approval_fingerprint: &approval_fingerprint,
            paired_fingerprint: &paired_fingerprint,
            issued_ms: 1000,
            expires_ms: 301000,
            completed_ms: 2000,
        }
        .canonical()
        .unwrap();
        let mut observation = [0; 121];
        observation[0..2].copy_from_slice(&34u16.to_be_bytes());
        observation[2..4].copy_from_slice(&2u16.to_be_bytes());
        observation[4..8].copy_from_slice(&7i32.to_be_bytes());
        observation[8] = 2;
        for (at, id) in [(9, 10), (25, 11), (49, 12), (73, 13)] {
            observation[at..at + 16].copy_from_slice(&[id; 16]);
        }
        observation[45..49].copy_from_slice(&1i32.to_be_bytes());
        observation[65..73].copy_from_slice(&1i64.to_be_bytes());
        observation[89..121].copy_from_slice(&[14; 32]);
        let observation = v2::ObservationV2::decode(&observation).unwrap();
        let challenge = LineChallenge {
            id: Uuid::new_v4(),
            account_id: identity.account,
            line_id: identity.line,
            device_id: identity.device,
            generation: 1,
            nonce: [6; 32],
        };
        let device_statement =
            v2::device_statement(PurposeV2::Sealed, &challenge, &observation).unwrap();
        let device_signature: Signature = device.sign(&device_statement.bytes());
        let device_signature_der = device_signature.to_der().as_bytes().to_vec();
        let owner_statement =
            v2::owner_statement(&device_statement, &device_signature_der).unwrap();
        let owner_signature: Signature = owner.sign(&owner_statement.bytes());
        let old_binding_id = *Uuid::new_v4().as_bytes();
        Self {
            evidence: ActivationEvidence03 {
                registration_id: *identity.registration.as_bytes(),
                old_binding_id,
                device_point,
                owner_point,
                device_statement: device_statement.bytes().try_into().unwrap(),
                device_signature_der,
                owner_statement: owner_statement.bytes().try_into().unwrap(),
                owner_signature_der: owner_signature.to_der().as_bytes().to_vec(),
                accepted_ms: 3000,
            },
            registration: original,
            expected: ExpectedActivation03 {
                identity,
                old_binding_id,
                root_fingerprint,
                paired_signing_key_id: crate::sealed_manifest::key_id(4, &device_point),
                selected_reader_key_id: [15; 32],
                canonical_origin: "https://gateway.example.test",
            },
            device,
            owner,
        }
    }
}

#[test]
fn exact_originals_reverify_and_round_trip_without_current_permission() {
    let f = Fixture::new();
    let encoded = f.evidence.canonical().unwrap();
    let decoded = ActivationEvidence03::decode(&encoded).unwrap();
    assert_eq!(decoded.canonical().unwrap(), encoded);
    let proof = decoded
        .verify_original(&f.registration, &f.expected)
        .unwrap();
    assert_eq!(proof.canonical_evidence(), encoded);
    let identity = OldBindingIdentity03 {
        binding_id: f.expected.old_binding_id,
        account_id: *f.expected.identity.account.as_bytes(),
        device_id: *f.expected.identity.device.as_bytes(),
        line_id: *f.expected.identity.line.as_bytes(),
        generation: 1,
        activation_challenge_id: f.evidence.device_statement[86..102].try_into().unwrap(),
        registration_id: *f.expected.identity.registration.as_bytes(),
        registration_evidence_sha256: sha(&f.registration),
        owner_approval_digest: sha(&[
            f.evidence.owner_statement.as_slice(),
            &f.evidence.owner_signature_der,
        ]
        .concat()),
        device_confirmation_digest: sha(&[
            f.evidence.device_statement.as_slice(),
            &f.evidence.device_signature_der,
        ]
        .concat()),
        selected_reader_key_id: [15; 32],
    };
    assert_eq!(
        proof.old_binding_proof_digest(),
        &identity.digest().unwrap()
    );
}

#[test]
fn noncanonical_truncated_extended_and_cross_purpose_frames_refuse() {
    let f = Fixture::new();
    let encoded = f.evidence.canonical().unwrap();
    for n in 0..encoded.len() {
        assert!(ActivationEvidence03::decode(&encoded[..n]).is_err());
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert!(ActivationEvidence03::decode(&extended).is_err());
    let mut changed = f.evidence.clone();
    changed.device_statement[29] = 1;
    assert!(changed.canonical().is_err());
    let mut changed = f.evidence.clone();
    changed.device_signature_der.push(0);
    assert!(changed.canonical().is_err());
    let mut changed = encoded;
    changed[LABEL.len() + 3] ^= 1;
    assert!(ActivationEvidence03::decode(&changed).is_err());
}

#[test]
fn original_binding_registration_root_keys_and_historical_interval_are_independent_expectations() {
    let mut f = Fixture::new();
    f.expected.old_binding_id = *Uuid::new_v4().as_bytes();
    assert!(
        f.evidence
            .verify_original(&f.registration, &f.expected)
            .is_err()
    );
    f.expected.old_binding_id = f.evidence.old_binding_id;
    for which in 0..5 {
        let mut changed = f.evidence.clone();
        match which {
            0 => changed.registration_id[0] ^= 1,
            1 => changed.accepted_ms = 1999,
            2 => changed.accepted_ms = 301000,
            3 => {
                changed.device_point = f
                    .owner
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            }
            _ => {
                changed.owner_point = f
                    .device
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            }
        }
        assert!(
            changed
                .verify_original(&f.registration, &f.expected)
                .is_err()
        );
    }
    let mut original = f.registration.clone();
    original[REGISTRATION_LABEL.len() + 4 + 4 + 10] ^= 1;
    assert!(f.evidence.verify_original(&original, &f.expected).is_err());
    f.expected.root_fingerprint[0] ^= 1;
    assert!(
        f.evidence
            .verify_original(&f.registration, &f.expected)
            .is_err()
    );
}

#[test]
fn changing_a_received_signature_or_owner_commitment_does_not_replace_original_evidence() {
    let f = Fixture::new();
    let mut changed = f.evidence.clone();
    let replacement: Signature = f.owner.sign(b"another statement");
    changed.owner_signature_der = replacement.to_der().as_bytes().to_vec();
    assert!(
        changed
            .verify_original(&f.registration, &f.expected)
            .is_err()
    );
    let replacement: Signature = f.device.sign(b"another statement");
    changed = f.evidence.clone();
    changed.device_signature_der = replacement.to_der().as_bytes().to_vec();
    assert!(changed.canonical().is_err());
}

#[test]
fn original_canonical_high_s_v2_proof_is_preserved_without_normalization() {
    let mut f = Fixture::new();
    let low = Signature::from_der(&f.evidence.device_signature_der)
        .unwrap()
        .normalize_s();
    let mut raw: [u8; 64] = low.to_bytes().into();
    let order: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let n = i16::from(order[i]) - i16::from(raw[i + 32]) - borrow;
        raw[i + 32] = n.rem_euclid(256) as u8;
        borrow = i16::from(n < 0);
    }
    let high = Signature::from_slice(&raw).unwrap();
    assert_ne!(high.normalize_s(), high);
    f.evidence.device_signature_der = high.to_der().as_bytes().to_vec();
    let device =
        v2::DeviceStatementBytesV2::decode(PurposeV2::Sealed, &f.evidence.device_statement)
            .unwrap();
    let owner = v2::owner_statement(&device, &f.evidence.device_signature_der).unwrap();
    f.evidence.owner_statement = owner.bytes().try_into().unwrap();
    let signature: Signature = f.owner.sign(&owner.bytes());
    f.evidence.owner_signature_der = signature.to_der().as_bytes().to_vec();
    let encoded = f.evidence.canonical().unwrap();
    let proof = f
        .evidence
        .verify_original(&f.registration, &f.expected)
        .unwrap();
    assert_eq!(proof.canonical_evidence(), encoded);
    assert_eq!(
        ActivationEvidence03::decode(&encoded)
            .unwrap()
            .device_signature_der,
        high.to_der().as_bytes()
    );
}

#[test]
fn independently_framed_shared_vector_preserves_the_original_high_s_signature() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/sealed-profile03-activation-evidence-01.json"
    ))
    .unwrap();
    let bytes = |name: &str| -> Vec<u8> {
        v[name]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let id = |name: &str| Uuid::from_bytes(bytes(name).try_into().unwrap());
    let evidence_bytes = bytes("activation_evidence");
    let evidence = ActivationEvidence03::decode(&evidence_bytes).unwrap();
    let expected = ExpectedActivation03 {
        identity: super::super::registration_reader::OriginalIdentity {
            account: id("account_id"),
            registration: id("registration_id"),
            user: id("user_id"),
            owner_session: id("owner_session_id"),
            device: id("device_id"),
            line: id("line_id"),
            generation: 1,
        },
        old_binding_id: bytes("old_binding_id").try_into().unwrap(),
        root_fingerprint: bytes("root_fingerprint").try_into().unwrap(),
        paired_signing_key_id: bytes("paired_signing_key_id").try_into().unwrap(),
        selected_reader_key_id: bytes("selected_reader_key_id").try_into().unwrap(),
        canonical_origin: v["origin"].as_str().unwrap(),
    };
    let signature = Signature::from_der(&evidence.device_signature_der).unwrap();
    assert_ne!(signature.normalize_s(), signature);
    let proof = evidence
        .verify_original(&bytes("registration_evidence"), &expected)
        .unwrap();
    assert_eq!(proof.canonical_evidence(), evidence_bytes);
    assert_eq!(
        proof.old_binding_proof_digest().as_slice(),
        bytes("old_binding_proof_digest")
    );
}
