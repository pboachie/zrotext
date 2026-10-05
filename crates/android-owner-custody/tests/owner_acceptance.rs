// SPDX-License-Identifier: AGPL-3.0-only
//! Independent acceptance checks using only published synthetic codec vectors.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zrotext_android_owner_custody::custody::{self, ExpectedIdentity};
use zrotext_android_owner_custody::signing::{
    Authority, OperationHandle, SigningError, SigningService, TimeAnchor,
};
use zrotext_android_owner_custody::typed::{self, OperationKind, TypedOutput, TypedService};
use zrotext_root_material::sealed_root_enrollment;
use zrotext_root_material::{recovery_kit, root_backup};

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn line_typed_fixture() -> (RetainedKit, Vec<u8>, Value) {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../crates/root-material/src/line_key_registration/vector.json"
    ))
    .unwrap();
    let pin = hex(&vector, "rootPin");
    let expected = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://owner.invalid".into(),
        root_fingerprint: hex(&vector, "rootFingerprint").try_into().unwrap(),
    };
    // Scalar one is the published vector's synthetic root, never production material.
    let mut scalar = Zeroizing::new([0; 32]);
    scalar[31] = 1;
    let root = root_backup::RootSecret::new(scalar).unwrap();
    let recovery = root_backup::RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"synthetic typed owner acceptance recovery").into(),
    ));
    let backup = root_backup::seal(&root, &recovery, &expected).unwrap();
    drop(root);
    let bundle_id = root_backup::validate_public_header(&backup, &expected).unwrap();
    let card =
        recovery_kit::encode_public_card(&pin, &expected, &Sha256::digest(&backup).into()).unwrap();
    let context = recovery_kit::KitContext::new(expected.clone(), &pin, bundle_id).unwrap();
    let token = recovery_kit::encode_token(&recovery, &context);
    let expectation = serde_json::json!({
        "root_pin": lower_hex(&pin),
        "scope": {
            "account": lower_hex(&[1; 16]), "user": lower_hex(&[2; 16]),
            "owner_session": lower_hex(&[3; 16]), "device": lower_hex(&[4; 16]),
            "line": lower_hex(&[5; 16]), "next_generation": 1,
            "challenge": lower_hex(&[6; 16]), "nonce": lower_hex(&[7; 32]),
            "issued_ms": 2000, "expires_ms": 62000,
            "approval_fingerprint": vector["approvalFingerprint"],
            "paired_signing_fingerprint": vector["pairedSigningFingerprint"],
            "connection_epoch": 8, "deployment_epoch": 9,
            "site_id": "site-fixture", "instance_id": "instance-fixture",
            "origin": "https://owner.invalid"
        }
    });
    (
        RetainedKit {
            expected,
            backup,
            card,
            pin,
            token: Zeroizing::new(token.expose_ascii().to_vec()),
        },
        hex(&vector, "transcript"),
        expectation,
    )
}

fn typed_anchor() -> TimeAnchor {
    TimeAnchor {
        authenticated_server_ms: 2000,
        authenticated_elapsed_ms: 100,
        uncertainty_ms: 0,
    }
}

fn open_line(
    service: &TypedService,
    kit: &RetainedKit,
    proposal: &[u8],
    expectation: &Value,
) -> Result<OperationHandle, SigningError> {
    service.open(
        OperationKind::LineRegistration,
        proposal,
        &serde_json::to_vec(expectation).unwrap(),
        &kit.backup,
        &kit.card,
        &kit.expected,
        authority(),
        typed_anchor(),
        100,
    )
}

#[test]
fn typed_line_signature_verifies_exact_published_transcript_and_cannot_reopen() {
    let (kit, proposal, expected) = line_typed_fixture();
    let service = TypedService::default();
    let handle = open_line(&service, &kit, &proposal, &expected).unwrap();
    let reviewed = service.review(handle).unwrap();
    assert_eq!(reviewed[0], proposal);
    assert_eq!(reviewed[1], serde_json::to_vec(&expected).unwrap());
    let TypedOutput::Public(signatures) = service
        .execute(handle, &kit.token, &[], &[], &authority(), || Ok(100))
        .unwrap()
    else {
        panic!("Line registration must return only a public signature");
    };
    assert_eq!(signatures.len(), 1);
    let signature = Signature::from_slice(&signatures[0]).unwrap();
    assert_eq!(signature.to_bytes(), signature.normalize_s().to_bytes());
    let verifying = VerifyingKey::from_sec1_bytes(&kit.pin[29..]).unwrap();
    verifying.verify(&proposal, &signature).unwrap();
    let mut substituted = proposal.clone();
    substituted[40] ^= 1;
    assert!(verifying.verify(&substituted, &signature).is_err());
    assert!(
        verifying
            .verify(
                &[b"ZTSE/root-custody/v1\0".as_slice(), &proposal].concat(),
                &signature
            )
            .is_err()
    );
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &authority(), || Ok(100))
            .is_err()
    );
    service.close_all();
    assert!(open_line(&service, &kit, &proposal, &expected).is_err());
}

#[test]
fn typed_line_independent_expectations_session_and_json_bounds_fail_closed() {
    let (kit, proposal, expected) = line_typed_fixture();
    for field in [
        "device",
        "line",
        "owner_session",
        "approval_fingerprint",
        "paired_signing_fingerprint",
        "nonce",
    ] {
        let mut changed = expected.clone();
        changed["scope"][field] = Value::String(lower_hex(
            if field.contains("fingerprint") || field == "nonce" {
                &[9; 32]
            } else {
                &[9; 16]
            },
        ));
        assert!(
            open_line(&TypedService::default(), &kit, &proposal, &changed).is_err(),
            "{field}"
        );
    }
    let mut changed = expected.clone();
    changed["untrusted_extra"] = Value::Bool(true);
    assert!(open_line(&TypedService::default(), &kit, &proposal, &changed).is_err());
    let mut changed = expected.clone();
    changed["scope"]["next_generation"] = Value::String("1".into());
    assert!(open_line(&TypedService::default(), &kit, &proposal, &changed).is_err());
    for malformed in [
        vec![],
        vec![b' '; typed::MAX_EXPECTED + 1],
        b"{\"root_pin\":null}".to_vec(),
    ] {
        assert!(
            TypedService::default()
                .open(
                    OperationKind::LineRegistration,
                    &proposal,
                    &malformed,
                    &kit.backup,
                    &kit.card,
                    &kit.expected,
                    authority(),
                    typed_anchor(),
                    100
                )
                .is_err()
        );
    }
    let oversized = vec![0; typed::MAX_PROPOSAL + 1];
    assert!(open_line(&TypedService::default(), &kit, &oversized, &expected).is_err());
    let service = TypedService::default();
    let handle = open_line(&service, &kit, &proposal, &expected).unwrap();
    let wrong = Authority {
        session_id: [9; 16],
        ..authority()
    };
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &wrong, || Ok(100))
            .is_err()
    );
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &authority(), || Ok(100))
            .is_err()
    );
}

#[test]
fn typed_archive_returns_recoverable_ciphertext_and_separate_recovery_with_no_scalar_output() {
    let kit = synthetic_kit();
    let expected = serde_json::to_vec(&serde_json::json!({ "root_pin": lower_hex(&kit.pin),
        "operation_id": lower_hex(&[7; 16]), "issued_ms": 1_000_000, "expires_ms": 1_060_000 }))
    .unwrap();
    let service = TypedService::default();
    let handle = service
        .open(
            OperationKind::ArchiveCreation,
            &[],
            &expected,
            &kit.backup,
            &kit.card,
            &kit.expected,
            authority(),
            anchor(),
            500,
        )
        .unwrap();
    let TypedOutput::Archive(archive) = service
        .execute(handle, &kit.token, &[], &[], &authority(), || Ok(500))
        .unwrap()
    else {
        panic!("Archive creation must return an encrypted archive kit");
    };
    assert!(archive.encrypted_backup.len() <= 845);
    assert_eq!(archive.recovery.len(), 32);
    assert_eq!(archive.archive_point[0], 4);
    assert_eq!(
        archive.archive_id,
        <[u8; 32]>::from(Sha256::digest(
            [
                b"ZTSE/key/v1\0".as_slice(),
                &[0, 16],
                &archive.archive_point
            ]
            .concat()
        ))
    );
    typed::check_archive_recovery(
        &archive.encrypted_backup,
        archive.recovery.as_slice(),
        &kit.expected,
        &archive.archive_id,
        &archive.archive_point,
    )
    .unwrap();
    let mut corrupt = archive.encrypted_backup.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        typed::check_archive_recovery(
            &corrupt,
            archive.recovery.as_slice(),
            &kit.expected,
            &archive.archive_id,
            &archive.archive_point
        )
        .is_err()
    );
    assert!(
        typed::check_archive_recovery(
            &archive.encrypted_backup,
            &[0; 32],
            &kit.expected,
            &archive.archive_id,
            &archive.archive_point
        )
        .is_err()
    );
    let mut wrong_identity = kit.expected.clone();
    wrong_identity.origin = "https://other.example.test".into();
    assert!(
        typed::check_archive_recovery(
            &archive.encrypted_backup,
            archive.recovery.as_slice(),
            &wrong_identity,
            &archive.archive_id,
            &archive.archive_point
        )
        .is_err()
    );
    let mut wrong_id = archive.archive_id;
    wrong_id[0] ^= 1;
    assert!(
        typed::check_archive_recovery(
            &archive.encrypted_backup,
            archive.recovery.as_slice(),
            &kit.expected,
            &wrong_id,
            &archive.archive_point
        )
        .is_err()
    );
    assert!(
        !archive
            .public_receipt
            .windows(archive.recovery.len())
            .any(|v| v == archive.recovery.as_slice())
    );
    service.close_all();
    assert!(
        service
            .open(
                OperationKind::ArchiveCreation,
                &[],
                &expected,
                &kit.backup,
                &kit.card,
                &kit.expected,
                authority(),
                anchor(),
                500
            )
            .is_err()
    );
}

#[test]
fn typed_expiry_after_crypto_and_cancellation_consume_approval_without_output() {
    let (kit, proposal, expected) = line_typed_fixture();
    let service = TypedService::default();
    let handle = open_line(&service, &kit, &proposal, &expected).unwrap();
    let mut sample = 0;
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &authority(), || {
                sample += 1;
                Ok(if sample == 1 { 100 } else { 60_100 })
            })
            .is_err()
    );
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &authority(), || Ok(100))
            .is_err()
    );
    let service = TypedService::default();
    let handle = open_line(&service, &kit, &proposal, &expected).unwrap();
    service.close_all();
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &authority(), || Ok(100))
            .is_err()
    );
    assert!(open_line(&service, &kit, &proposal, &expected).is_err());
}

fn custody_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-custody-01.json"
    ))
    .unwrap()
}

fn authority() -> Authority {
    Authority {
        account_id: [1; 16],
        user_id: [2; 16],
        session_id: [3; 16],
    }
}

fn anchor() -> TimeAnchor {
    TimeAnchor {
        authenticated_server_ms: 1_000_000,
        authenticated_elapsed_ms: 500,
        uncertainty_ms: 0,
    }
}

fn open(service: &SigningService, kit: &RetainedKit) -> OperationHandle {
    service
        .open_custody(
            &hex(&custody_vector(), "unsignedHex"),
            &kit.backup,
            &kit.card,
            &kit.expected,
            &root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap(),
            authority(),
            anchor(),
            500,
        )
        .unwrap()
}

struct RetainedKit {
    expected: ExpectedIdentity,
    backup: Vec<u8>,
    card: Vec<u8>,
    pin: Vec<u8>,
    token: Zeroizing<Vec<u8>>,
}

fn hex(value: &Value, field: &str) -> Vec<u8> {
    let input = value[field].as_str().unwrap();
    (0..input.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).unwrap())
        .collect()
}

fn synthetic_kit() -> RetainedKit {
    let backup: Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    let kit: Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap();
    let expected = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: hex(&kit, "fingerprintHex").try_into().unwrap(),
    };
    let pin = hex(&kit, "rootPinHex");
    let context = recovery_kit::KitContext::new(
        expected.clone(),
        &pin,
        hex(&kit, "backupIdHex").try_into().unwrap(),
    )
    .unwrap();
    let secret = root_backup::RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic root-backup test recovery").into(),
    ));
    let token = recovery_kit::encode_token(&secret, &context);
    assert_eq!(
        Sha256::digest(token.expose_ascii()).as_slice(),
        hex(&kit, "tokenSha256Hex")
    );
    RetainedKit {
        expected,
        backup: hex(&backup, "ciphertextHex"),
        card: hex(&kit, "cardHex"),
        pin,
        token: Zeroizing::new(token.expose_ascii().to_vec()),
    }
}

#[test]
fn independently_retained_fixture_recovers_without_application_storage_or_wrapping_key() {
    // This entry point has no store, keystore key, creation handle or previous
    // process state. The vectors stand in for a separately retained recovery kit.
    let kit = synthetic_kit();
    for _fresh_invocation in 0..2 {
        let restored = custody::recover(&kit.backup, &kit.card, &kit.token, &kit.expected).unwrap();
        assert_eq!(
            restored.as_bytes().as_slice(),
            Sha256::digest(b"ZROtext synthetic root-backup test root").as_slice()
        );
    }
}

#[test]
fn independently_expected_account_origin_and_fingerprint_are_each_required() {
    let kit = synthetic_kit();
    for field in 0..3 {
        let mut expected = kit.expected.clone();
        match field {
            0 => expected.account_id = [2; 16],
            1 => expected.origin = "https://other.example.test".into(),
            _ => expected.root_fingerprint[0] ^= 1,
        }
        assert!(custody::recover(&kit.backup, &kit.card, &kit.token, &expected).is_err());
    }
}

#[test]
fn valid_transcription_checksum_with_wrong_recovery_material_does_not_unlock_root() {
    let kit = synthetic_kit();
    let bundle = root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap();
    let context = recovery_kit::KitContext::new(kit.expected.clone(), &kit.pin, bundle).unwrap();
    let wrong = root_backup::RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic incorrect Android acceptance recovery").into(),
    ));
    let token = recovery_kit::encode_token(&wrong, &context);
    // Grammar, identity-bound typo checksum and the ciphertext's public header
    // all pass; full AEAD decryption must still fail closed.
    assert!(recovery_kit::decode_token(token.expose_ascii(), &context).is_ok());
    assert!(custody::recover(&kit.backup, &kit.card, token.expose_ascii(), &kit.expected).is_err());
}

#[test]
fn authenticated_ciphertext_corruption_fails_even_with_a_matching_public_card_digest() {
    let kit = synthetic_kit();
    let header_len = 80 + kit.expected.origin.len();
    for offset in [header_len, header_len + 44, kit.backup.len() - 1] {
        let mut damaged = kit.backup.clone();
        damaged[offset] ^= 1;
        let matching_card = recovery_kit::encode_public_card(
            &kit.pin,
            &kit.expected,
            &Sha256::digest(&damaged).into(),
        )
        .unwrap();
        assert!(root_backup::validate_public_header(&damaged, &kit.expected).is_ok());
        assert!(
            custody::recover(&damaged, &matching_card, &kit.token, &kit.expected).is_err(),
            "authenticated ciphertext byte {offset}"
        );
    }
}

#[test]
fn incomplete_or_unbounded_recovery_kit_returns_no_root() {
    let kit = synthetic_kit();
    for (backup, card, token) in [
        (&[][..], kit.card.as_slice(), kit.token.as_slice()),
        (kit.backup.as_slice(), &[][..], kit.token.as_slice()),
        (kit.backup.as_slice(), kit.card.as_slice(), &[][..]),
    ] {
        assert!(custody::recover(backup, card, token, &kit.expected).is_err());
    }
    let oversized_backup = vec![0; 749];
    let oversized_card = vec![0; 646];
    let oversized_token = vec![0; 80];
    assert!(custody::recover(&oversized_backup, &kit.card, &kit.token, &kit.expected).is_err());
    assert!(custody::recover(&kit.backup, &oversized_card, &kit.token, &kit.expected).is_err());
    assert!(custody::recover(&kit.backup, &kit.card, &oversized_token, &kit.expected).is_err());
}

#[test]
fn native_creation_uses_existing_wire_codecs_and_needs_the_separate_retained_token() {
    let created = custody::create([1; 16], "https://example.test").unwrap();
    assert!(created.encrypted_backup.starts_with(b"ZTRB\x01\x01"));
    assert!(created.public_card.starts_with(b"ZTRC\x01"));
    assert!(created.recovery_token.starts_with(b"ZTRK1-"));
    let expected = created.identity.clone();
    let retained_backup = created.encrypted_backup.clone();
    let retained_card = created.public_card.clone();
    let retained_token = Zeroizing::new(created.recovery_token.to_vec());
    let bundle = root_backup::validate_public_header(&retained_backup, &expected).unwrap();
    let context =
        recovery_kit::KitContext::new(expected.clone(), &created.root_pin, bundle).unwrap();
    let recovery = recovery_kit::decode_token(&retained_token, &context).unwrap();
    let independently_opened = root_backup::open(&retained_backup, &recovery, &expected).unwrap();
    let intended_scalar = Zeroizing::new(*independently_opened.as_bytes());
    drop(independently_opened);
    drop(recovery);
    drop(created);
    let restored =
        custody::recover(&retained_backup, &retained_card, &retained_token, &expected).unwrap();
    assert_eq!(restored.as_bytes(), intended_scalar.as_ref());
    assert!(
        !retained_backup
            .windows(32)
            .any(|part| part == restored.as_bytes())
    );
    assert!(custody::recover(&retained_backup, &retained_card, &[], &expected).is_err());
}

#[test]
fn one_shot_signatures_match_existing_custody_vector_and_enrollment_verifier() {
    let kit = synthetic_kit();
    let service = SigningService::default();
    let handle = open(&service, &kit);
    let unsigned = hex(&custody_vector(), "unsignedHex");
    assert_eq!(service.review(handle).unwrap(), unsigned);
    let signatures = service
        .sign(handle, &kit.token, &authority(), || Ok(500))
        .unwrap();
    // ECDSA nonce choice is not a wire-format invariant. Verify against the
    // independent fixture's exact server transcript and require canonical low-s.
    let message = hex(&custody_vector(), "transcriptHex");
    let key = VerifyingKey::from_sec1_bytes(&kit.pin[29..]).unwrap();
    let custody = Signature::from_slice(&signatures.custody).unwrap();
    assert_eq!(
        custody.normalize_s().to_bytes().as_slice(),
        signatures.custody
    );
    key.verify(&message, &custody).unwrap();
    key.verify(
        &message,
        &Signature::from_slice(&hex(&custody_vector(), "signatureHex")).unwrap(),
    )
    .unwrap();
    assert!(
        key.verify(
            &message,
            &Signature::from_slice(&signatures.enrollment).unwrap()
        )
        .is_err()
    );
    for offset in [
        0,
        24,
        message.len() - 96,
        message.len() - 64,
        message.len() - 32,
    ] {
        let mut changed = message.clone();
        changed[offset] ^= 1;
        assert!(key.verify(&changed, &custody).is_err());
    }
    let challenge = sealed_root_enrollment::parse(&unsigned).unwrap();
    sealed_root_enrollment::verify(
        &kit.pin,
        &unsigned,
        &signatures.enrollment,
        &challenge,
        1_000_000,
    )
    .unwrap();
    assert!(service.review(handle).is_err());
    assert!(
        service
            .sign(handle, &kit.token, &authority(), || Ok(500))
            .is_err()
    );
    assert!(
        service
            .open_custody(
                &unsigned,
                &kit.backup,
                &kit.card,
                &kit.expected,
                &root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap(),
                authority(),
                anchor(),
                500,
            )
            .is_err()
    );
}

#[test]
fn cancelling_or_lifecycle_loss_closes_pending_approval_and_remembers_replay() {
    let kit = synthetic_kit();
    for close_all in [false, true] {
        let service = SigningService::default();
        let handle = open(&service, &kit);
        if close_all {
            service.close_all();
        } else {
            service.close(handle);
        }
        assert!(service.review(handle).is_err());
        assert!(
            service
                .sign(handle, &kit.token, &authority(), || Ok(500))
                .is_err()
        );
        assert!(
            service
                .open_custody(
                    &hex(&custody_vector(), "unsignedHex"),
                    &kit.backup,
                    &kit.card,
                    &kit.expected,
                    &root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap(),
                    authority(),
                    anchor(),
                    500,
                )
                .is_err()
        );
    }
}

#[test]
fn session_switch_wrong_recovery_and_clock_failure_consume_approval() {
    let kit = synthetic_kit();
    for failure in 0..3 {
        let service = SigningService::default();
        let handle = open(&service, &kit);
        let mut current = authority();
        if failure == 0 {
            current.session_id = [9; 16];
        }
        let token = if failure == 1 {
            &[][..]
        } else {
            kit.token.as_slice()
        };
        assert!(
            service
                .sign(handle, token, &current, || {
                    if failure == 2 {
                        Err(SigningError::TimeRejected)
                    } else {
                        Ok(500)
                    }
                })
                .is_err()
        );
        assert!(
            service
                .sign(handle, &kit.token, &authority(), || Ok(500))
                .is_err()
        );
    }
}

#[test]
fn late_expiry_and_pre_recovery_cancellation_prevent_public_signature_output() {
    let kit = synthetic_kit();
    for cancel in [false, true] {
        let service = SigningService::default();
        let handle = open(&service, &kit);
        let mut samples = 0;
        let result = service.sign(handle, &kit.token, &authority(), || {
            samples += 1;
            if samples == 1 {
                if cancel {
                    // Cancellation wins the registry before recovery starts.
                    // Final clock callbacks cannot reenter its publication lock.
                    service.close_all();
                }
                return Ok(500);
            }
            Ok(300_500)
        });
        assert_eq!(samples, if cancel { 1 } else { 2 });
        assert!(result.is_err());
        assert!(service.review(handle).is_err());
    }
}

#[test]
fn authenticated_time_uncertainty_suspend_and_regression_fail_closed() {
    let kit = synthetic_kit();
    let unsigned = hex(&custody_vector(), "unsignedHex");
    let bundle = root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap();
    for (time, elapsed) in [
        (
            TimeAnchor {
                uncertainty_ms: 1,
                ..anchor()
            },
            500,
        ),
        (anchor(), 499),
        (anchor(), 300_500),
        (anchor(), 300_501),
        (
            TimeAnchor {
                uncertainty_ms: 5_001,
                ..anchor()
            },
            501,
        ),
        (
            TimeAnchor {
                authenticated_server_ms: u64::MAX,
                ..anchor()
            },
            500,
        ),
    ] {
        let service = SigningService::default();
        assert!(
            service
                .open_custody(
                    &unsigned,
                    &kit.backup,
                    &kit.card,
                    &kit.expected,
                    &bundle,
                    authority(),
                    time,
                    elapsed,
                )
                .is_err()
        );
    }
    let service = SigningService::default();
    let handle = open(&service, &kit);
    let mut samples = 0;
    assert!(
        service
            .sign(handle, &kit.token, &authority(), || {
                samples += 1;
                Ok(if samples == 1 { 501 } else { 500 })
            })
            .is_err()
    );
}

#[test]
fn downloaded_context_and_non_enrollment_transcripts_cannot_replace_authority() {
    let kit = synthetic_kit();
    let bundle = root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap();
    let original = hex(&custody_vector(), "unsignedHex");
    for offset in [5, 21, 37, 101] {
        let mut substituted = original.clone();
        substituted[offset] ^= 1;
        assert!(
            SigningService::default()
                .open_custody(
                    &substituted,
                    &kit.backup,
                    &kit.card,
                    &kit.expected,
                    &bundle,
                    authority(),
                    anchor(),
                    500,
                )
                .is_err()
        );
    }
    for unsigned in [
        &b"arbitrary signing bytes"[..],
        &b"ZTCG\x01"[..],
        &vec![0; 664][..],
    ] {
        assert!(
            SigningService::default()
                .open_custody(
                    unsigned,
                    &kit.backup,
                    &kit.card,
                    &kit.expected,
                    &bundle,
                    authority(),
                    anchor(),
                    500,
                )
                .is_err()
        );
    }
}

#[test]
fn process_restart_does_not_restore_a_previous_operation_handle() {
    let kit = synthetic_kit();
    let previous = SigningService::default();
    let handle = open(&previous, &kit);
    drop(previous);
    let fresh = SigningService::default();
    assert!(fresh.review(handle).is_err());
    assert!(
        fresh
            .sign(handle, &kit.token, &authority(), || Ok(500))
            .is_err()
    );
    // A new explicit ceremony is possible; durable server challenge consumption
    // remains necessary to prevent already published challenges across processes.
    let fresh_handle = open(&fresh, &kit);
    fresh.close(fresh_handle);
}

#[test]
fn pending_approvals_are_bounded_and_closed_capacity_can_be_reused() {
    let kit = synthetic_kit();
    let service = SigningService::default();
    let bundle = root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap();
    let original = sealed_root_enrollment::parse(&hex(&custody_vector(), "unsignedHex")).unwrap();
    let mut handles = Vec::new();
    for index in 1..=9 {
        let mut challenge = original.clone();
        challenge.challenge_id = [index; 16];
        let result = service.open_custody(
            &sealed_root_enrollment::encode(&challenge).unwrap(),
            &kit.backup,
            &kit.card,
            &kit.expected,
            &bundle,
            authority(),
            anchor(),
            500,
        );
        if index <= 8 {
            handles.push(result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
    service.close(handles.remove(0));
    let mut challenge = original;
    challenge.challenge_id = [9; 16];
    let reused = service
        .open_custody(
            &sealed_root_enrollment::encode(&challenge).unwrap(),
            &kit.backup,
            &kit.card,
            &kit.expected,
            &bundle,
            authority(),
            anchor(),
            500,
        )
        .unwrap();
    service.close(reused);
}

#[test]
fn a_full_replay_ledger_fails_closed_without_evicting_cancelled_challenges() {
    let kit = synthetic_kit();
    let service = SigningService::default();
    let bundle = root_backup::validate_public_header(&kit.backup, &kit.expected).unwrap();
    let original = sealed_root_enrollment::parse(&hex(&custody_vector(), "unsignedHex")).unwrap();
    for index in 1_u32..=257 {
        let mut challenge = original.clone();
        challenge.challenge_id = [0; 16];
        challenge.challenge_id[12..].copy_from_slice(&index.to_be_bytes());
        let result = service.open_custody(
            &sealed_root_enrollment::encode(&challenge).unwrap(),
            &kit.backup,
            &kit.card,
            &kit.expected,
            &bundle,
            authority(),
            anchor(),
            500,
        );
        if index <= 256 {
            service.close(result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
    service.close_all();
    assert!(
        service
            .open_custody(
                &sealed_root_enrollment::encode(&original).unwrap(),
                &kit.backup,
                &kit.card,
                &kit.expected,
                &bundle,
                authority(),
                anchor(),
                500,
            )
            .is_err()
    );
}
