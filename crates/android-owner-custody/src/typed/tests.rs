// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde_json::{Value, json};
use zrotext_root_material::root_backup::RecoverySecret;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn scalar(n: u8) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0; 32]);
    out[31] = n;
    out
}
fn point(n: u8) -> [u8; 65] {
    SigningKey::from_slice(scalar(n).as_slice())
        .unwrap()
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn key_id(role: u8, point: &[u8; 65]) -> [u8; 32] {
    Sha256::digest(
        [
            b"ZTSE/key/v1\0".as_slice(),
            if role <= 3 { &[0, 16] } else { &[1, 1] },
            point,
        ]
        .concat(),
    )
    .into()
}
struct Kit {
    identity: ExpectedIdentity,
    pin: [u8; 94],
    backup: Vec<u8>,
    card: Vec<u8>,
    token: Zeroizing<Vec<u8>>,
}
fn kit() -> Kit {
    let root = RootSecret::new(scalar(1)).unwrap();
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &point(1),
    ]
    .concat()
    .try_into()
    .unwrap();
    let identity = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://owner.invalid".into(),
        root_fingerprint: sealed_root_enrollment::root_fingerprint(&pin, &[1; 16]).unwrap(),
    };
    let recovery = RecoverySecret::new(Zeroizing::new([7; 32]));
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let card =
        recovery_kit::encode_public_card(&pin, &identity, &Sha256::digest(&backup).into()).unwrap();
    let context = recovery_kit::KitContext::new(
        identity.clone(),
        &pin,
        root_backup::validate_public_header(&backup, &identity).unwrap(),
    )
    .unwrap();
    let token = Zeroizing::new(
        recovery_kit::encode_token(&recovery, &context)
            .expose_ascii()
            .to_vec(),
    );
    Kit {
        identity,
        pin,
        backup,
        card,
        token,
    }
}
fn auth(session: u8) -> Authority {
    Authority {
        account_id: [1; 16],
        user_id: [2; 16],
        session_id: [session; 16],
    }
}
fn anchor() -> TimeAnchor {
    TimeAnchor {
        authenticated_server_ms: 2100,
        authenticated_elapsed_ms: 500,
        uncertainty_ms: 0,
    }
}
fn open(
    service: &TypedService,
    kit: &Kit,
    kind: OperationKind,
    proposal: &[u8],
    expected: &Value,
    session: u8,
) -> OperationHandle {
    service
        .open(
            kind,
            proposal,
            &serde_json::to_vec(expected).unwrap(),
            &kit.backup,
            &kit.card,
            &kit.identity,
            auth(session),
            anchor(),
            500,
        )
        .unwrap()
}
fn public(output: TypedOutput) -> Vec<u8> {
    match output {
        TypedOutput::Public(mut v) => {
            assert_eq!(v.len(), 1);
            v.remove(0)
        }
        _ => panic!("expected public result"),
    }
}
fn verify_manifest(signed: &[u8], pin: &[u8; 94]) {
    let n = signed.len() - 64;
    let transcript = [
        b"ZTSE/manifest/v2\0".as_slice(),
        &(n as u32).to_be_bytes(),
        &signed[..n],
    ]
    .concat();
    let sig = Signature::from_slice(&signed[n..]).unwrap();
    assert_eq!(sig.to_bytes(), sig.normalize_s().to_bytes());
    VerifyingKey::from_sec1_bytes(&pin[29..])
        .unwrap()
        .verify(&transcript, &sig)
        .unwrap();
}
fn line_fixture() -> (Vec<u8>, Value) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../root-material/src/line_key_registration/vector.json"
    ))
    .unwrap();
    let s = &v["selection"];
    (
        unhex(v["transcript"].as_str().unwrap()),
        json!({"root_pin":v["rootPin"],"scope":{
            "account":s["account"],"user":s["user"],"owner_session":s["ownerSession"],"device":s["device"],"line":s["line"],
            "next_generation":1,"challenge":s["challenge"],"nonce":s["nonce"],"issued_ms":2000,"expires_ms":62000,
            "approval_fingerprint":v["approvalFingerprint"],"paired_signing_fingerprint":v["pairedSigningFingerprint"],
            "connection_epoch":8,"deployment_epoch":9,"site_id":"site-fixture","instance_id":"instance-fixture","origin":"https://owner.invalid"
        }}),
    )
}
fn retained_archive(kit: &Kit) -> archive_init::PreparedArchive {
    archive_init::prepare(
        ArchiveSecret::new(scalar(3)).unwrap(),
        ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
        &kit.identity,
        &kit.pin,
    )
    .unwrap()
}
fn genesis_fixture(archive: &archive_init::PreparedArchive) -> (Vec<u8>, Value, Vec<u8>) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/conversation-genesis-01.json"
    ))
    .unwrap();
    let s = &v["selection"];
    let expected = json!({"scope":{"account":s["account"],"session":s["session"],"device":s["device"],"line":s["line"],
        "device_signing_fingerprint":s["phoneSigningFingerprint"],"generation":1,"peer":"+12","origin":v["origin"],
        "fingerprint":v["comparedRootFingerprint"],"issued_ms":2000,"expires_ms":62000},
        "root_pin":v["rootPin"],"phone_reader":v["phoneReaderPoint"],"archive_reader":v["archiveReaderPoint"],
        "phone_signer":v["phoneSignerPoint"],"archive_backup_sha256":hex(&Sha256::digest(archive.encrypted_backup()))});
    (
        unhex(v["proposal"].as_str().unwrap()),
        expected,
        unhex(v["unsignedManifest"].as_str().unwrap()),
    )
}
#[test]
fn native_typed_line_signature_verifies_unchanged_registration_vector() {
    let kit = kit();
    let service = TypedService::default();
    let (proposal, expected) = line_fixture();
    let handle = open(
        &service,
        &kit,
        OperationKind::LineRegistration,
        &proposal,
        &expected,
        3,
    );
    let signed = public(
        service
            .execute(handle, &kit.token, &[], &[], &auth(3), || Ok(500))
            .unwrap(),
    );
    line::decode(&proposal)
        .unwrap()
        .verify_root(&signed)
        .unwrap();
    assert!(
        service
            .execute(handle, &kit.token, &[], &[], &auth(3), || Ok(500))
            .is_err()
    );
}
#[test]
fn genesis_requires_fresh_separate_archive_recovery_and_matches_sdk_manifest_bytes() {
    let kit = kit();
    let archive = retained_archive(&kit);
    let (proposal, expected, unsigned) = genesis_fixture(&archive);
    let service = TypedService::default();
    let handle = open(
        &service,
        &kit,
        OperationKind::Genesis,
        &proposal,
        &expected,
        2,
    );
    let signed = public(
        service
            .execute(
                handle,
                &kit.token,
                archive.encrypted_backup(),
                archive.recovery_bytes(),
                &auth(2),
                || Ok(500),
            )
            .unwrap(),
    );
    assert_eq!(&signed[..signed.len() - 64], unsigned);
    verify_manifest(&signed, &kit.pin);
    for recovery in [&kit.token[..], &[9; 32][..], &[]] {
        let service = TypedService::default();
        let handle = open(
            &service,
            &kit,
            OperationKind::Genesis,
            &proposal,
            &expected,
            2,
        );
        assert!(
            service
                .execute(
                    handle,
                    &kit.token,
                    archive.encrypted_backup(),
                    recovery,
                    &auth(2),
                    || Ok(500)
                )
                .is_err()
        );
    }
    let service = TypedService::default();
    let handle = open(
        &service,
        &kit,
        OperationKind::Genesis,
        &proposal,
        &expected,
        2,
    );
    let mut changed = archive.encrypted_backup().to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        service
            .execute(
                handle,
                &kit.token,
                &changed,
                archive.recovery_bytes(),
                &auth(2),
                || Ok(500)
            )
            .is_err()
    );
}
fn archive_expected(kit: &Kit) -> Value {
    json!({"root_pin":hex(&kit.pin),"operation_id":hex(&[9;16]),"issued_ms":2000,"expires_ms":62000})
}
#[test]
fn archive_creation_uses_separate_entropy_and_retained_aead_recovery() {
    let kit = kit();
    let service = TypedService::default();
    let expected = archive_expected(&kit);
    let handle = open(
        &service,
        &kit,
        OperationKind::ArchiveCreation,
        &[],
        &expected,
        2,
    );
    let TypedOutput::Archive(created) = service
        .execute(handle, &kit.token, &[], &[], &auth(2), || Ok(500))
        .unwrap()
    else {
        panic!("archive expected")
    };
    assert_ne!(created.archive_point, &kit.pin[29..]);
    assert_ne!(*created.recovery, [7; 32]);
    assert!(
        created
            .public_receipt
            .starts_with(b"ZROtext archive receipt v1\n")
    );
    check_archive_recovery(
        &created.encrypted_backup,
        created.recovery.as_slice(),
        &kit.identity,
        &created.archive_id,
        &created.archive_point,
    )
    .unwrap();
    assert!(
        check_archive_recovery(
            &created.encrypted_backup,
            &kit.token,
            &kit.identity,
            &created.archive_id,
            &created.archive_point
        )
        .is_err()
    );
    let mut wrong = kit.identity.clone();
    wrong.root_fingerprint[0] ^= 1;
    assert!(
        check_archive_recovery(
            &created.encrypted_backup,
            created.recovery.as_slice(),
            &wrong,
            &created.archive_id,
            &created.archive_point
        )
        .is_err()
    );
    let restarted = TypedService::default();
    assert!(restarted.review(handle).is_err());
}
fn predecessor(kit: &Kit) -> Vec<u8> {
    let archive = retained_archive(kit);
    let (_, _, unsigned) = genesis_fixture(&archive);
    let signature: Signature = SigningKey::from_slice(scalar(1).as_slice()).unwrap().sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned.len() as u32).to_be_bytes(),
            &unsigned,
        ]
        .concat(),
    );
    [unsigned, signature.normalize_s().to_bytes().to_vec()].concat()
}
fn sized(bytes: &[u8]) -> Vec<u8> {
    [&(bytes.len() as u16).to_be_bytes(), bytes].concat()
}
fn successors(kit: &Kit, kind: OperationKind) -> (Vec<u8>, Value, Vec<u8>) {
    let before = predecessor(kit);
    let digest: [u8; 32] = Sha256::digest(&before[..before.len() - 64]).into();
    let mut unsigned = before[..before.len() - 64].to_vec();
    unsigned[29..37].copy_from_slice(&2u64.to_be_bytes());
    unsigned[37..45].copy_from_slice(&2100u64.to_be_bytes());
    unsigned[53..85].copy_from_slice(&digest);
    let mut bytes = if kind == OperationKind::Activation {
        b"ZTCA\x01".to_vec()
    } else {
        b"ZTCF\x01".to_vec()
    };
    bytes.extend([1; 16]);
    bytes.extend([2; 16]);
    if kind == OperationKind::Refresh {
        bytes.extend([3; 16]);
    }
    bytes.extend([4; 16]);
    bytes.extend([5; 16]);
    bytes.extend(1u64.to_be_bytes());
    bytes.push(3);
    bytes.extend(b"+12");
    bytes.extend(sized(kit.identity.origin.as_bytes()));
    bytes.extend(kit.identity.root_fingerprint);
    bytes.extend(1u64.to_be_bytes());
    bytes.extend(digest);
    let reader = key_id(1, &point(2));
    let archive = key_id(2, &point(3));
    bytes.extend(reader);
    bytes.extend(archive);
    let mut scope = json!({"account":hex(&[1;16]),"session":hex(&[2;16]),"device":hex(&[4;16]),"line":hex(&[5;16]),
        "line_generation":1,"peer":"+12","origin":kit.identity.origin,"fingerprint":hex(&kit.identity.root_fingerprint),
        "predecessor_version":1,"predecessor_digest":hex(&digest),"phone_reader":hex(&reader),"archive_reader":hex(&archive)});
    if kind == OperationKind::Activation {
        let signer = key_id(4, &point(4));
        bytes.extend(signer);
        bytes.extend(2100u64.to_be_bytes());
        scope["phone_signer"] = json!(hex(&signer));
        scope["issued_ms"] = json!(2100);
    } else {
        let signer = key_id(5, &point(5));
        bytes.extend(signer);
        bytes.extend(point(5));
        bytes.extend(60000u64.to_be_bytes());
        scope["interval"] = json!(hex(&[3; 16]));
        scope["signer"] = json!(hex(&signer));
        scope["point"] = json!(hex(&point(5)));
        scope["until_ms"] = json!(60000);
        let new_record = [
            &[5][..],
            &signer,
            &point(5),
            &[0; 16],
            &[5; 16],
            &1u16.to_be_bytes(),
            &2100u64.to_be_bytes(),
            &60000u64.to_be_bytes(),
            &[1],
        ]
        .concat();
        let mut records = unsigned[151..]
            .chunks_exact(149)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        records.push(new_record);
        records.sort_by(|a, b| a[..33].cmp(&b[..33]));
        unsigned.truncate(151);
        unsigned[150] = 5;
        for record in records {
            unsigned.extend(record);
        }
    }
    bytes.extend(sized(&before));
    bytes.extend(sized(&unsigned));
    (bytes, json!({"scope":scope}), unsigned)
}
#[test]
fn activation_and_role5_refresh_preserve_current_manifest_records() {
    let kit = kit();
    for kind in [OperationKind::Activation, OperationKind::Refresh] {
        let (proposal, expected, unsigned) = successors(&kit, kind);
        let service = TypedService::default();
        let handle = open(&service, &kit, kind, &proposal, &expected, 2);
        let signed = public(
            service
                .execute(handle, &kit.token, &[], &[], &auth(2), || Ok(500))
                .unwrap(),
        );
        assert_eq!(&signed[..signed.len() - 64], unsigned);
        verify_manifest(&signed, &kit.pin);
        let old = predecessor(&kit);
        for record in old[151..old.len() - 64].chunks_exact(149) {
            assert!(
                signed[151..signed.len() - 64]
                    .chunks_exact(149)
                    .any(|r| r == record)
            );
        }
        let mut wrong = expected.clone();
        wrong["scope"]["predecessor_digest"] = json!(hex(&[8; 32]));
        let service = TypedService::default();
        assert!(
            service
                .open(
                    kind,
                    &proposal,
                    &serde_json::to_vec(&wrong).unwrap(),
                    &kit.backup,
                    &kit.card,
                    &kit.identity,
                    auth(2),
                    anchor(),
                    500
                )
                .is_err()
        );
    }
}
#[test]
fn expected_scope_point_checkpoint_and_wrong_transcript_type_cannot_be_substituted() {
    let kit = kit();
    let archive = retained_archive(&kit);
    let (proposal, expected, _) = genesis_fixture(&archive);
    for field in ["phone_reader", "archive_reader", "phone_signer"] {
        let mut wrong = expected.clone();
        wrong[field] = json!(hex(&point(5)));
        assert!(
            TypedService::default()
                .open(
                    OperationKind::Genesis,
                    &proposal,
                    &serde_json::to_vec(&wrong).unwrap(),
                    &kit.backup,
                    &kit.card,
                    &kit.identity,
                    auth(2),
                    anchor(),
                    500
                )
                .is_err()
        );
    }
    for field in [
        "account",
        "session",
        "device",
        "line",
        "fingerprint",
        "device_signing_fingerprint",
    ] {
        let mut wrong = expected.clone();
        let width = if field.contains("fingerprint") {
            32
        } else {
            16
        };
        wrong["scope"][field] = json!(hex(&vec![9; width]));
        assert!(
            TypedService::default()
                .open(
                    OperationKind::Genesis,
                    &proposal,
                    &serde_json::to_vec(&wrong).unwrap(),
                    &kit.backup,
                    &kit.card,
                    &kit.identity,
                    auth(2),
                    anchor(),
                    500
                )
                .is_err()
        );
    }
    for kind in [
        OperationKind::LineRegistration,
        OperationKind::ArchiveCreation,
        OperationKind::Activation,
        OperationKind::Refresh,
    ] {
        assert!(
            TypedService::default()
                .open(
                    kind,
                    &proposal,
                    &serde_json::to_vec(&expected).unwrap(),
                    &kit.backup,
                    &kit.card,
                    &kit.identity,
                    auth(2),
                    anchor(),
                    500
                )
                .is_err()
        );
    }
}
#[test]
fn duplicate_unknown_trailing_and_unbounded_expected_json_are_rejected() {
    let kit = kit();
    let expected = serde_json::to_vec(&archive_expected(&kit)).unwrap();
    let extra = [&expected[..expected.len() - 1], b",\"unknown\":0}"].concat();
    let duplicate = [&expected[..expected.len() - 1], b",\"issued_ms\":2000}"].concat();
    for invalid in [
        extra,
        duplicate,
        [expected.clone(), vec![0]].concat(),
        vec![b' '; MAX_EXPECTED + 1],
    ] {
        assert!(
            TypedService::default()
                .open(
                    OperationKind::ArchiveCreation,
                    &[],
                    &invalid,
                    &kit.backup,
                    &kit.card,
                    &kit.identity,
                    auth(2),
                    anchor(),
                    500
                )
                .is_err()
        );
    }
}
#[test]
fn replay_is_not_reopened_by_expected_json_whitespace_or_hex_case() {
    let kit = kit();
    let service = TypedService::default();
    let (proposal, mut expected) = line_fixture();
    let handle = open(
        &service,
        &kit,
        OperationKind::LineRegistration,
        &proposal,
        &expected,
        3,
    );
    service.close(handle);
    let whitespace = serde_json::to_vec_pretty(&expected).unwrap();
    assert!(
        service
            .open(
                OperationKind::LineRegistration,
                &proposal,
                &whitespace,
                &kit.backup,
                &kit.card,
                &kit.identity,
                auth(3),
                anchor(),
                500
            )
            .is_err()
    );
    expected["root_pin"] = json!(expected["root_pin"].as_str().unwrap().to_uppercase());
    assert!(
        service
            .open(
                OperationKind::LineRegistration,
                &proposal,
                &serde_json::to_vec(&expected).unwrap(),
                &kit.backup,
                &kit.card,
                &kit.identity,
                auth(3),
                anchor(),
                500
            )
            .is_err()
    );
    service.close_all();
    assert!(service.review(handle).is_err());
}
#[test]
fn wrong_root_recovery_session_switch_expiry_and_cancel_consume_typed_approval() {
    let kit = kit();
    let (proposal, expected) = line_fixture();
    for failure in 0..4 {
        let service = TypedService::default();
        let handle = open(
            &service,
            &kit,
            OperationKind::LineRegistration,
            &proposal,
            &expected,
            3,
        );
        let mut user = auth(3);
        if failure == 1 {
            user.session_id = [8; 16];
        }
        if failure == 3 {
            service.close_all();
        }
        assert!(
            service
                .execute(
                    handle,
                    if failure == 0 { b"bad" } else { &kit.token },
                    &[],
                    &[],
                    &user,
                    || Ok(if failure == 2 { 60400 } else { 500 })
                )
                .is_err()
        );
        assert!(
            service
                .execute(handle, &kit.token, &[], &[], &auth(3), || Ok(500))
                .is_err()
        );
    }
}
#[test]
fn archive_secret_publication_is_discarded_on_late_expiry_and_cancellation() {
    let kit = kit();
    for failure in 0..3 {
        let service = TypedService::default();
        let handle = open(
            &service,
            &kit,
            OperationKind::ArchiveCreation,
            &[],
            &archive_expected(&kit),
            2,
        );
        let mut clock = 500;
        let discarded = AtomicBool::new(false);
        let managed_copy = Arc::new(Mutex::new(Vec::<u8>::new()));
        let result = service.execute_with_output(
            handle,
            &kit.token,
            &[],
            &[],
            &auth(2),
            &mut clock,
            |clock| {
                if failure == 2 && *clock == 501 {
                    panic!("synthetic publication failure");
                }
                Ok(*clock)
            },
            |clock, output| {
                let TypedOutput::Archive(created) = output else {
                    panic!("archive output expected")
                };
                assert_eq!(created.recovery.len(), 32);
                *managed_copy.lock().unwrap() = created.recovery.to_vec();
                if failure == 1 {
                    service.close_all();
                } else if failure == 2 {
                    *clock = 501;
                } else {
                    *clock = 60400;
                }
                Ok(managed_copy.clone())
            },
            |_, output| {
                output.lock().unwrap().fill(0);
                discarded.store(true, Ordering::SeqCst);
            },
        );
        assert!(result.is_err());
        assert!(discarded.load(Ordering::SeqCst));
        assert_eq!(*managed_copy.lock().unwrap(), vec![0; 32]);
    }
}

struct EntropyFault {
    calls: usize,
    fail_at: Option<usize>,
    zero_recovery: bool,
}
impl TryRng for EntropyFault {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        bytes.fill(0);
        if !bytes.is_empty() {
            *bytes.last_mut().unwrap() = 3;
        }
        let call = self.calls;
        self.calls += 1;
        if self.zero_recovery && call == 1 {
            bytes.fill(0);
        }
        if self.fail_at == Some(call) {
            return Err(std::io::Error::other("synthetic entropy failure"));
        }
        Ok(())
    }
}
impl TryCryptoRng for EntropyFault {}
#[test]
fn archive_scalar_and_recovery_entropy_failure_produce_no_partial_kit() {
    let kit = kit();
    for (fail_at, zero_recovery) in [(Some(0), false), (Some(1), false), (None, true)] {
        let mut rng = EntropyFault {
            calls: 0,
            fail_at,
            zero_recovery,
        };
        assert!(create_archive_with_rng(&kit.identity, &kit.pin, &mut rng).is_err());
    }
    let mut invalid = kit.identity.clone();
    invalid.root_fingerprint[0] ^= 1;
    let mut rng = EntropyFault {
        calls: 0,
        fail_at: None,
        zero_recovery: false,
    };
    assert!(create_archive_with_rng(&invalid, &kit.pin, &mut rng).is_err());
    assert_eq!(rng.calls, 0);
}

#[test]
fn oversized_archive_recovery_input_consumes_approval_before_hash_or_recovery() {
    let kit = kit();
    let archive = retained_archive(&kit);
    let (proposal, expected, _) = genesis_fixture(&archive);
    for (backup, recovery) in [
        (vec![0; 846], vec![8; 32]),
        (archive.encrypted_backup().to_vec(), vec![8; 33]),
    ] {
        let service = TypedService::default();
        let handle = open(
            &service,
            &kit,
            OperationKind::Genesis,
            &proposal,
            &expected,
            2,
        );
        let clock_called = AtomicBool::new(false);
        assert!(
            service
                .execute(handle, &kit.token, &backup, &recovery, &auth(2), || {
                    clock_called.store(true, Ordering::SeqCst);
                    Ok(500)
                })
                .is_err()
        );
        assert!(!clock_called.load(Ordering::SeqCst));
        assert!(
            service
                .execute(
                    handle,
                    &kit.token,
                    archive.encrypted_backup(),
                    archive.recovery_bytes(),
                    &auth(2),
                    || Ok(500)
                )
                .is_err()
        );
    }
}

#[test]
fn final_registry_wait_crossing_expiry_discards_archive_output() {
    use std::sync::{atomic::AtomicU64, mpsc};
    use std::time::Duration;
    let kit = kit();
    let service = TypedService::default();
    let handle = open(
        &service,
        &kit,
        OperationKind::ArchiveCreation,
        &[],
        &archive_expected(&kit),
        2,
    );
    let clock = AtomicU64::new(500);
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (sample_tx, sample_rx) = mpsc::channel();
    let discarded = AtomicBool::new(false);
    let managed_copy = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (result, pre_release_sample, published_while_locked) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut samples = 0;
            service
                .execute_with_output(
                    handle,
                    &kit.token,
                    &[],
                    &[],
                    &auth(2),
                    &mut (),
                    |_| {
                        samples += 1;
                        let elapsed = clock.load(Ordering::SeqCst);
                        if samples == 2 {
                            sample_tx.send(elapsed).unwrap();
                        }
                        Ok(elapsed)
                    },
                    |_, output| {
                        let TypedOutput::Archive(created) = output else {
                            panic!("archive output expected")
                        };
                        *managed_copy.lock().unwrap() = created.recovery.to_vec();
                        ready_tx.send(()).unwrap();
                        // A setup timeout cannot leave a scoped worker parked forever.
                        release_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(|_| SigningError::Unavailable)?;
                        Ok(managed_copy.clone())
                    },
                    |_, output| {
                        output.lock().unwrap().fill(0);
                        discarded.store(true, Ordering::SeqCst);
                    },
                )
                .map(|_| ())
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let registry = service.registry.lock().unwrap();
        release_tx.send(()).unwrap();
        let sample = sample_rx.recv_timeout(Duration::from_millis(500)).ok();
        let finished = worker.is_finished();
        clock.store(60_400, Ordering::SeqCst);
        drop(registry);
        (worker.join().unwrap(), sample, finished)
    });
    assert!(!published_while_locked);
    assert_eq!(result, Err(SigningError::TimeRejected));
    assert!(
        pre_release_sample.is_none(),
        "final time must be sampled after acquiring the mutex"
    );
    assert!(discarded.load(Ordering::SeqCst));
    assert_eq!(*managed_copy.lock().unwrap(), vec![0; 32]);
    assert!(service.review(handle).is_err());
    assert!(matches!(
        service.execute(handle, &kit.token, &[], &[], &auth(2), || Ok(500)),
        Err(SigningError::Unavailable)
    ));
}
