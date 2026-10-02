// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::root_unlock::tests::{challenge, material, pin_of};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

fn bundle(
    root: &RootSecret,
    recovery: &crate::root_backup::RecoverySecret,
    expected: &ExpectedIdentity,
) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
    let backup = root_backup::seal(root, recovery, expected).unwrap();
    let id = root_backup::validate_public_header(&backup, expected).unwrap();
    let card = recovery_kit::encode_public_card(
        &pin_of(root, expected.account_id),
        expected,
        &Sha256::digest(&backup).into(),
    )
    .unwrap();
    (backup, card, id)
}

#[test]
fn exact_server_transcript_verifies_and_mutations_do_not() {
    let (root, recovery, expected) = material("synthetic custody transcript");
    let (backup, card, id) = bundle(&root, &recovery, &expected);
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    let reviewed =
        ReviewedCustody::inspect(&unsigned, &backup, &card, &expected, &id, 1_000_000).unwrap();
    // Independent encoding matching the existing server custody verifier.
    let mut message = b"ZTSE/root-custody/v1\0".to_vec();
    message.extend_from_slice(&u32::try_from(unsigned.len()).unwrap().to_be_bytes());
    message.extend_from_slice(&unsigned);
    message.extend_from_slice(&Sha256::digest(&backup));
    message.extend_from_slice(&Sha256::digest(&card));
    message.extend_from_slice(&expected.root_fingerprint);
    assert_eq!(reviewed.statement, message);
    let signatures = reviewed.sign(&root, 1_000_000).unwrap();
    let pin = pin_of(&root, expected.account_id);
    let key = VerifyingKey::from_sec1_bytes(&pin[29..]).unwrap();
    let custody = Signature::from_slice(&signatures.custody).unwrap();
    assert_eq!(
        custody.normalize_s().to_bytes().as_slice(),
        signatures.custody
    );
    key.verify(&message, &custody).unwrap();
    crate::sealed_root_enrollment::verify(
        &pin,
        &unsigned,
        &signatures.enrollment,
        &crate::sealed_root_enrollment::parse(&unsigned).unwrap(),
        1_000_000,
    )
    .unwrap();
    assert_ne!(signatures.enrollment, signatures.custody);
    assert!(
        key.verify(
            &message,
            &Signature::from_slice(&signatures.enrollment).unwrap()
        )
        .is_err()
    );
    for offset in [
        0,
        20,
        24,
        message.len() - 96,
        message.len() - 64,
        message.len() - 32,
    ] {
        let mut changed = message.clone();
        changed[offset] ^= 1;
        assert!(key.verify(&changed, &custody).is_err());
    }
}

#[test]
fn custody_rejects_bundle_card_identity_bounds_wrong_root_and_expiry() {
    let (root, recovery, expected) = material("synthetic custody rejection");
    let (backup, card, id) = bundle(&root, &recovery, &expected);
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    let inspect = |u: &[u8], b: &[u8], c: &[u8], e: &ExpectedIdentity, i: &[u8; 16]| {
        ReviewedCustody::inspect(u, b, c, e, i, 1_000_000)
    };
    assert!(inspect(&unsigned, &backup, &card, &expected, &[0; 16]).is_err());
    assert!(inspect(&unsigned, &backup, &card, &expected, &[9; 16]).is_err());
    assert!(inspect(&unsigned, &vec![0; 749], &card, &expected, &id).is_err());
    assert!(inspect(&unsigned, &backup, &vec![0; 646], &expected, &id).is_err());
    assert!(inspect(&[], &backup, &card, &expected, &id).is_err());
    let mut changed = backup.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(inspect(&unsigned, &changed, &card, &expected, &id).is_err());
    let mut changed = card.clone();
    changed[0] ^= 1;
    assert!(inspect(&unsigned, &backup, &changed, &expected, &id).is_err());
    for wrong in [
        ExpectedIdentity {
            account_id: [9; 16],
            ..expected.clone()
        },
        ExpectedIdentity {
            origin: "https://other.invalid".into(),
            ..expected.clone()
        },
        ExpectedIdentity {
            root_fingerprint: [9; 32],
            ..expected.clone()
        },
    ] {
        assert!(inspect(&unsigned, &backup, &card, &wrong, &id).is_err());
    }
    let (wrong_root, _, _) = material("synthetic other custody root");
    assert!(matches!(
        inspect(&unsigned, &backup, &card, &expected, &id)
            .unwrap()
            .sign(&wrong_root, 1_000_000),
        Err(UnlockError::ContextRejected)
    ));
    assert!(matches!(
        inspect(&unsigned, &backup, &card, &expected, &id)
            .unwrap()
            .sign(&root, 1_300_000),
        Err(UnlockError::TimeRejected)
    ));
    assert!(matches!(
        inspect(&unsigned, &backup, &card, &expected, &id)
            .unwrap()
            .sign(&root, 999_999),
        Err(UnlockError::TimeRejected)
    ));
}

#[test]
fn review_snapshots_are_unchanged_by_later_caller_mutations() {
    let (root, recovery, expected) = material("synthetic custody snapshots");
    let (mut backup, mut card, id) = bundle(&root, &recovery, &expected);
    let mut unsigned = challenge(&expected, 1_000_000, 1_300_000);
    let reviewed =
        ReviewedCustody::inspect(&unsigned, &backup, &card, &expected, &id, 1_000_000).unwrap();
    let original = reviewed.statement.clone();
    unsigned.fill(0);
    backup.fill(0);
    card.fill(0);
    let signatures = reviewed.sign(&root, 1_000_000).unwrap();
    VerifyingKey::from_sec1_bytes(&pin_of(&root, expected.account_id)[29..])
        .unwrap()
        .verify(
            &original,
            &Signature::from_slice(&signatures.custody).unwrap(),
        )
        .unwrap();
}
