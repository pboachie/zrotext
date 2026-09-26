// SPDX-License-Identifier: AGPL-3.0-only
//! Keep the public server paths interoperable with the extracted crate and fixed vectors.

use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zrotext_root_material::{
    root_backup as shared_backup, sealed_root_enrollment as shared_enroll,
};
use zrotext_server::{root_backup as server_backup, sealed_root_enrollment as server_enroll};

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    let hex = value[field].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn server_enrollment_path_preserves_shared_types_and_exact_vector_bytes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-enrollment-01.json"
    ))
    .unwrap();
    let unsigned = bytes(&fixture, "unsignedHex");
    let challenge: shared_enroll::Challenge = server_enroll::parse(&unsigned).unwrap();
    assert_eq!(server_enroll::encode(&challenge).unwrap(), unsigned);
    assert_eq!(
        server_enroll::transcript(&unsigned).unwrap(),
        bytes(&fixture, "transcriptHex")
    );
    let proof: shared_enroll::PossessionProof = server_enroll::verify(
        &bytes(&fixture, "rootPinHex"),
        &unsigned,
        &bytes(&fixture, "signatureHex"),
        &challenge,
        fixture["nowMs"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        proof.root_fingerprint(),
        bytes(&fixture, "fingerprintHex").as_slice()
    );
}

#[test]
fn server_backup_path_opens_fixed_ciphertext_using_shared_secret_types() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    let recovery = shared_backup::RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic root-backup test recovery").into(),
    ));
    let expected = shared_backup::ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: bytes(&fixture, "fingerprintHex").try_into().unwrap(),
    };
    let ciphertext = bytes(&fixture, "ciphertextHex");
    let restored: shared_backup::RootSecret =
        server_backup::open(&ciphertext, &recovery, &expected).unwrap();
    assert_eq!(
        restored.as_bytes().as_slice(),
        Sha256::digest(b"ZROtext synthetic root-backup test root").as_slice()
    );
    let mut wrong_identity = expected;
    wrong_identity.account_id = [2; 16];
    let error: shared_backup::BackupError =
        server_backup::open(&ciphertext, &recovery, &wrong_identity).unwrap_err();
    assert_eq!(error, shared_backup::BackupError::Rejected);
}
