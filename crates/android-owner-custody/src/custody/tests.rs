// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use rand::TryRng;

struct SyntheticRng {
    call: u32,
    fail_at: Option<u32>,
    zero_at: Option<u32>,
}

impl TryRng for SyntheticRng {
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

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let call = self.call;
        self.call += 1;
        let block = Zeroizing::new(
            Sha256::digest(
                [
                    b"ZROtext synthetic Android owner entropy".as_slice(),
                    &call.to_be_bytes(),
                ]
                .concat(),
            )
            .to_vec(),
        );
        output.copy_from_slice(&block[..output.len()]);
        if self.zero_at == Some(call) {
            output.fill(0);
        }
        // Fail after partially writing to exercise cleanup on entropy errors.
        if self.fail_at == Some(call) {
            return Err(std::io::Error::other("synthetic entropy failure"));
        }
        Ok(())
    }
}

impl TryCryptoRng for SyntheticRng {}

fn rng() -> SyntheticRng {
    SyntheticRng {
        call: 0,
        fail_at: None,
        zero_at: None,
    }
}

fn kit() -> CreatedKit {
    create_with_sources(
        [1; 16],
        "https://example.test",
        &mut rng(),
        root_backup::seal,
    )
    .unwrap()
}

fn restore(kit: &CreatedKit) -> Result<RootSecret, CustodyError> {
    recover(
        &kit.encrypted_backup,
        &kit.public_card,
        &kit.recovery_token,
        &kit.identity,
    )
}

#[test]
fn independently_retained_kit_restores_without_creation_state_or_local_wrapper() {
    let created = kit();
    let expected = created.identity.clone();
    let retained_backup = created.encrypted_backup.clone();
    let retained_card = created.public_card.clone();
    let separate_token = Zeroizing::new(created.recovery_token.to_vec());
    let retained_pin = created.root_pin;
    drop(created);
    let root = recover(&retained_backup, &retained_card, &separate_token, &expected).unwrap();
    assert_eq!(root_pin(&root, expected.account_id).unwrap(), retained_pin);
    assert_eq!(format!("{root:?}"), "RootSecret([REDACTED])");
    assert!(
        !retained_backup
            .windows(32)
            .any(|window| window == root.as_bytes())
    );
}

#[test]
fn independent_account_origin_and_full_fingerprint_are_required() {
    let created = kit();
    for field in 0..3 {
        let mut wrong = created.identity.clone();
        match field {
            0 => wrong.account_id = [2; 16],
            1 => wrong.origin = "https://other.example.test".into(),
            _ => wrong.root_fingerprint[31] ^= 1,
        }
        assert_eq!(
            recover(
                &created.encrypted_backup,
                &created.public_card,
                &created.recovery_token,
                &wrong,
            )
            .unwrap_err(),
            CustodyError::Rejected
        );
    }
    assert!(restore(&created).is_ok());
}

#[test]
fn valid_token_checksum_with_wrong_secret_still_requires_backup_authentication() {
    let created = kit();
    let backup_id =
        root_backup::validate_public_header(&created.encrypted_backup, &created.identity).unwrap();
    let context = KitContext::new(created.identity.clone(), &created.root_pin, backup_id).unwrap();
    let wrong_secret = RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic wrong Android recovery key").into(),
    ));
    let wrong_token = recovery_kit::encode_token(&wrong_secret, &context);
    assert!(recovery_kit::decode_token(wrong_token.expose_ascii(), &context).is_ok());
    assert_eq!(
        recover(
            &created.encrypted_backup,
            &created.public_card,
            wrong_token.expose_ascii(),
            &created.identity,
        )
        .unwrap_err(),
        CustodyError::Rejected
    );
}

#[test]
fn corrupted_ciphertext_is_rejected_even_with_a_matching_public_card_digest() {
    let created = kit();
    for offset in 0..created.encrypted_backup.len() {
        let mut changed = created.encrypted_backup.clone();
        changed[offset] ^= 1;
        let digest = Sha256::digest(&changed).into();
        let matching_card =
            recovery_kit::encode_public_card(&created.root_pin, &created.identity, &digest)
                .unwrap();
        assert!(
            recover(
                &changed,
                &matching_card,
                &created.recovery_token,
                &created.identity,
            )
            .is_err(),
            "changed backup offset {offset}"
        );
    }
}

#[test]
fn malformed_missing_and_oversized_retained_material_never_releases_a_root() {
    let created = kit();
    for offset in 0..created.public_card.len() {
        let mut changed = created.public_card.clone();
        changed[offset] ^= 1;
        assert!(
            recover(
                &created.encrypted_backup,
                &changed,
                &created.recovery_token,
                &created.identity,
            )
            .is_err()
        );
    }
    for offset in 0..created.recovery_token.len() {
        let mut changed = Zeroizing::new(created.recovery_token.to_vec());
        changed[offset] ^= 1;
        assert!(
            recover(
                &created.encrypted_backup,
                &created.public_card,
                &changed,
                &created.identity,
            )
            .is_err()
        );
    }
    let oversized_backup = vec![0; 749];
    let oversized_card = vec![0; 646];
    let oversized_token = Zeroizing::new(vec![0; 80]);
    for (backup, card, token) in [
        (
            &[][..],
            created.public_card.as_slice(),
            created.recovery_token.as_slice(),
        ),
        (
            created.encrypted_backup.as_slice(),
            &[][..],
            created.recovery_token.as_slice(),
        ),
        (
            created.encrypted_backup.as_slice(),
            created.public_card.as_slice(),
            &[][..],
        ),
        (
            oversized_backup.as_slice(),
            created.public_card.as_slice(),
            created.recovery_token.as_slice(),
        ),
        (
            created.encrypted_backup.as_slice(),
            oversized_card.as_slice(),
            created.recovery_token.as_slice(),
        ),
        (
            created.encrypted_backup.as_slice(),
            created.public_card.as_slice(),
            oversized_token.as_slice(),
        ),
    ] {
        assert!(recover(backup, card, token, &created.identity).is_err());
    }
}

#[test]
fn entropy_failures_and_unusable_recovery_entropy_return_no_created_kit() {
    for fail_at in [0, 1] {
        let mut source = SyntheticRng {
            fail_at: Some(fail_at),
            ..rng()
        };
        assert_eq!(
            create_with_sources(
                [1; 16],
                "https://example.test",
                &mut source,
                root_backup::seal
            )
            .unwrap_err(),
            CustodyError::Randomness
        );
        assert_eq!(source.call, fail_at + 1);
    }
    let mut source = SyntheticRng {
        zero_at: Some(1),
        ..rng()
    };
    assert_eq!(
        create_with_sources(
            [1; 16],
            "https://example.test",
            &mut source,
            root_backup::seal
        )
        .unwrap_err(),
        CustodyError::Randomness
    );
    let mut source = SyntheticRng {
        zero_at: Some(0),
        fail_at: Some(1),
        ..rng()
    };
    assert_eq!(
        create_with_sources(
            [1; 16],
            "https://example.test",
            &mut source,
            root_backup::seal
        )
        .unwrap_err(),
        CustodyError::Randomness
    );
}

#[test]
fn backup_entropy_failure_and_failed_readback_return_no_partial_kit() {
    assert_eq!(
        create_with_sources([1; 16], "https://example.test", &mut rng(), |_, _, _| {
            Err(BackupError::Randomness)
        })
        .unwrap_err(),
        CustodyError::Randomness
    );
    assert_eq!(
        create_with_sources(
            [1; 16],
            "https://example.test",
            &mut rng(),
            |root, secret, identity| {
                let mut backup = root_backup::seal(root, secret, identity)?;
                *backup.last_mut().unwrap() ^= 1;
                Ok(backup)
            }
        )
        .unwrap_err(),
        CustodyError::Rejected
    );
}

#[test]
fn invalid_creation_context_never_requests_entropy_and_errors_are_redacted() {
    for (account, origin) in [
        ([0; 16], "https://example.test"),
        ([1; 16], "http://example.test"),
        ([1; 16], "https://example.test/"),
        ([1; 16], "https://EXAMPLE.test"),
        ([1; 16], "https://example.test:443"),
    ] {
        let mut source = rng();
        assert_eq!(
            create_with_sources(account, origin, &mut source, root_backup::seal).unwrap_err(),
            CustodyError::InvalidInput
        );
        assert_eq!(source.call, 0);
    }
    let created = kit();
    let debug = format!("{created:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("ZTRK1"));
    for error in [
        CustodyError::InvalidInput,
        CustodyError::Rejected,
        CustodyError::Randomness,
        CustodyError::Crypto,
    ] {
        assert!(!format!("{error:?} {error}").contains("synthetic"));
    }
}

#[test]
fn existing_root_backup_and_recovery_kit_vectors_restore_unchanged() {
    let backup_vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    let kit_vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap();
    let hex = |value: &serde_json::Value, field: &str| -> Vec<u8> {
        let input = value[field].as_str().unwrap();
        (0..input.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&input[offset..offset + 2], 16).unwrap())
            .collect()
    };
    let expected = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: hex(&kit_vector, "fingerprintHex").try_into().unwrap(),
    };
    let backup = hex(&backup_vector, "ciphertextHex");
    let pin = hex(&kit_vector, "rootPinHex");
    let backup_id = root_backup::validate_public_header(&backup, &expected).unwrap();
    let context = KitContext::new(expected.clone(), &pin, backup_id).unwrap();
    let secret = RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic root-backup test recovery").into(),
    ));
    let token = recovery_kit::encode_token(&secret, &context);
    assert_eq!(
        Sha256::digest(token.expose_ascii()).as_slice(),
        hex(&kit_vector, "tokenSha256Hex")
    );
    let root = recover(
        &backup,
        &hex(&kit_vector, "cardHex"),
        token.expose_ascii(),
        &expected,
    )
    .unwrap();
    assert!(
        root.as_bytes().as_slice()
            == Sha256::digest(b"ZROtext synthetic root-backup test root").as_slice()
    );
    assert_eq!(
        root_pin(&root, expected.account_id).unwrap().as_slice(),
        pin
    );
}
