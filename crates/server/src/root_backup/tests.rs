use super::*;
use rand::TryRng;
use sha2::Digest;

// Derivable synthetic test material only, never usable owner credentials.
fn synthetic(label: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(label).into())
}
fn material() -> (RootSecret, RecoverySecret, ExpectedIdentity) {
    let root = RootSecret::new(synthetic(b"ZROtext synthetic root-backup test root")).unwrap();
    let recovery = RecoverySecret::new(synthetic(b"ZROtext synthetic root-backup test recovery"));
    let key = SecretKey::from_slice(root.as_bytes()).unwrap();
    let pin = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1_u64.to_be_bytes(),
        key.public_key().to_sec1_point(false).as_bytes(),
    ]
    .concat();
    let expected = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: root_fingerprint(&pin, &[1; 16]).unwrap(),
    };
    (root, recovery, expected)
}

struct TestRng {
    call: u32,
    fail_at: Option<u32>,
}
impl TryRng for TestRng {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let input = [
            b"ZROtext synthetic root-backup randomness".as_slice(),
            &self.call.to_be_bytes(),
        ]
        .concat();
        let block = synthetic(&input);
        output.copy_from_slice(&block[..output.len()]);
        let call = self.call;
        self.call += 1;
        if self.fail_at == Some(call) {
            return Err(std::io::Error::other("synthetic entropy failure"));
        }
        Ok(())
    }
}
impl TryCryptoRng for TestRng {}
fn rng() -> TestRng {
    TestRng {
        call: 0,
        fail_at: None,
    }
}

#[test]
fn synthetic_round_trip_returns_only_the_bound_scalar() {
    let (root, recovery, expected) = material();
    let bytes = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    assert_eq!(bytes.len(), 236 + expected.origin.len());
    let opened = open(&bytes, &recovery, &expected).unwrap();
    assert!(opened.as_bytes() == root.as_bytes());
    assert_eq!(format!("{root:?}"), "RootSecret([REDACTED])");
    assert_eq!(format!("{recovery:?}"), "RecoverySecret([REDACTED])");
    assert!(
        !bytes
            .windows(32)
            .any(|window| window == root.as_bytes() || window == recovery.0.as_slice())
    );
}

#[test]
fn every_entropy_failure_returns_no_backup_even_after_partial_fill() {
    let (root, recovery, expected) = material();
    for fail_at in 0..5 {
        let mut rng = TestRng {
            call: 0,
            fail_at: Some(fail_at),
        };
        assert_eq!(
            seal_with_rng(&root, &recovery, &expected, &mut rng).unwrap_err(),
            BackupError::Randomness
        );
        assert_eq!(rng.call, fail_at + 1);
    }
}

#[test]
fn separate_seals_request_fresh_entropy_for_every_random_field() {
    let (root, recovery, expected) = material();
    let mut rng = rng();
    let a = seal_with_rng(&root, &recovery, &expected, &mut rng).unwrap();
    let b = seal_with_rng(&root, &recovery, &expected, &mut rng).unwrap();
    assert_eq!(rng.call, 10);
    let h = HEADER_FIXED + expected.origin.len();
    for (start, end) in [
        (6, 22),
        (h, h + 32),
        (h + 32, h + 44),
        (h + 44, h + 92),
        (h + 92, h + 104),
        (h + 108, h + 156),
    ] {
        assert_ne!(&a[start..end], &b[start..end]);
    }
    assert!(open(&a, &recovery, &expected).is_ok());
    assert!(open(&b, &recovery, &expected).is_ok());
}

#[test]
fn every_changed_byte_and_all_truncations_fail_without_plaintext() {
    let (root, recovery, expected) = material();
    let bytes = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(open(&changed, &recovery, &expected).is_err(), "offset {at}");
        assert!(
            open(&bytes[..at], &recovery, &expected).is_err(),
            "length {at}"
        );
    }
    assert!(open(&[bytes, vec![0]].concat(), &recovery, &expected).is_err());
    assert!(open(&vec![0; 749], &recovery, &expected).is_err());
}

#[test]
fn independent_identity_and_recovery_secret_are_required() {
    let (root, recovery, expected) = material();
    let bytes = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    let wrong = RecoverySecret::new(synthetic(b"ZROtext synthetic wrong recovery"));
    assert!(open(&bytes, &wrong, &expected).is_err());
    for at in 0..3 {
        let mut changed = expected.clone();
        match at {
            0 => changed.account_id = [2; 16],
            1 => changed.origin = "https://other.example.test".into(),
            _ => changed.root_fingerprint[0] ^= 1,
        }
        assert!(open(&bytes, &recovery, &changed).is_err());
        assert_eq!(
            seal_with_rng(&root, &recovery, &changed, &mut rng()).is_ok(),
            at == 1
        );
    }
}

#[test]
fn canonical_origin_and_scalar_bounds_are_enforced() {
    let (root, recovery, mut expected) = material();
    assert!(RootSecret::new(Zeroizing::new([0; 32])).is_err());
    assert!(RootSecret::new(Zeroizing::new([255; 32])).is_err());
    for origin in [
        "https://example.test/",
        "http://example.test",
        "https://EXAMPLE.test",
        "https://example.test:443",
    ] {
        expected.origin = origin.into();
        assert_eq!(
            seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap_err(),
            BackupError::InvalidInput
        );
    }
    expected.origin = format!("https://{}.test", "a".repeat(499));
    let bytes = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    assert_eq!(bytes.len(), MAX_FILE);
    assert!(open(&bytes, &recovery, &expected).is_ok());
    expected.origin.insert(8, 'a');
    assert!(seal_with_rng(&root, &recovery, &expected, &mut rng()).is_err());
}

#[test]
fn authenticated_non_scalar_or_wrong_root_is_not_released() {
    let (root, recovery, expected) = material();
    let original = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    let h = HEADER_FIXED + expected.origin.len();
    let key = wrapping_key(&recovery, &original[h..h + 32], &expected).unwrap();
    let vault = decrypt(
        key.as_slice(),
        &original[h + 32..h + 44],
        &[WRAP_AAD, &original[..h + 44]].concat(),
        &original[h + 44..h + 92],
    )
    .unwrap();
    for scalar in [
        Zeroizing::new([0; 32]),
        synthetic(b"ZROtext synthetic different root"),
    ] {
        let mut changed = original[..h + 108].to_vec();
        // Synthetic forgery only: replace the body with a valid AEAD tag to
        // isolate post-authentication scalar/fingerprint checks.
        let body = encrypt(
            vault.as_slice(),
            &original[h + 92..h + 104],
            &[ROOT_AAD, &changed].concat(),
            &scalar,
        )
        .unwrap();
        changed.extend(body);
        assert!(open(&changed, &recovery, &expected).is_err());
    }
}

#[test]
fn independent_node_known_answer_matches_complete_backup() {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    assert_eq!(value["status"], "PROPOSED_ROOT_BACKUP_01");
    let hex = value["ciphertextHex"].as_str().unwrap();
    let vector: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    let (root, recovery, expected) = material();
    let actual = seal_with_rng(&root, &recovery, &expected, &mut rng()).unwrap();
    assert_eq!(actual, vector);
    assert!(open(&vector, &recovery, &expected).unwrap().as_bytes() == root.as_bytes());
}

#[test]
fn invalid_identity_never_requests_entropy_and_errors_are_redacted() {
    let (root, recovery, mut expected) = material();
    expected.account_id = [0; 16];
    let mut source = rng();
    assert_eq!(
        seal_with_rng(&root, &recovery, &expected, &mut source).unwrap_err(),
        BackupError::InvalidInput
    );
    assert_eq!(source.call, 0);
    for error in [
        BackupError::InvalidInput,
        BackupError::Rejected,
        BackupError::Randomness,
        BackupError::Crypto,
    ] {
        assert!(!format!("{error:?} {error}").contains("synthetic"));
    }
}
