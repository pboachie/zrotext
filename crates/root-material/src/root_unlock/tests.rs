use super::*;
use crate::root_backup::{self, RecoverySecret};
use zeroize::Zeroizing;

// Derivable synthetic test material only, never usable owner credentials.
fn synthetic(label: &[u8]) -> Zeroizing<[u8; 32]> {
    use sha2::Digest;
    Zeroizing::new(sha2::Sha256::digest(label).into())
}

fn pin_of(root: &RootSecret, account: [u8; 16]) -> [u8; 94] {
    let secret = p256::SecretKey::from_slice(root.as_bytes()).unwrap();
    let mut pin = [0_u8; 94];
    pin[..5].copy_from_slice(b"ZTRP\x02");
    pin[5..21].copy_from_slice(&account);
    pin[21..29].copy_from_slice(&1_u64.to_be_bytes());
    pin[29..].copy_from_slice(secret.public_key().to_sec1_point(false).as_bytes());
    pin
}

fn material(label: &str) -> (RootSecret, RecoverySecret, ExpectedIdentity) {
    let account = [0xaa; 16];
    let root = RootSecret::new(synthetic(label.as_bytes())).unwrap();
    let recovery = RecoverySecret::new(synthetic(b"ZROtext synthetic root-unlock recovery"));
    let pin = pin_of(&root, account);
    let expected = ExpectedIdentity {
        account_id: account,
        origin: "https://example.invalid".into(),
        root_fingerprint: sealed_root_enrollment::root_fingerprint(&pin, &account).unwrap(),
    };
    (root, recovery, expected)
}

fn challenge(expected: &ExpectedIdentity, issued: u64, expires: u64) -> Vec<u8> {
    sealed_root_enrollment::encode(&Challenge {
        account_id: expected.account_id,
        user_id: [2; 16],
        session_id: [3; 16],
        challenge_id: [4; 16],
        nonce: [5; 32],
        root_fingerprint: expected.root_fingerprint,
        issued_ms: issued,
        expires_ms: expires,
        origin: expected.origin.clone(),
    })
    .unwrap()
}

const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde,
    0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

#[test]
fn recovered_root_signs_one_bound_challenge_that_verifies() {
    let (root, recovery, expected) = material("ZROtext synthetic root-unlock root");
    // Full candidate recovery chain: seal, authenticated open, then unlock-sign.
    let backup = root_backup::seal(&root, &recovery, &expected).unwrap();
    let recovered = root_backup::open(&backup, &recovery, &expected).unwrap();
    drop(recovery);
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    let signature = sign_enrollment(&recovered, &unsigned, &expected, 1_000_000).unwrap();
    let pin = pin_of(&recovered, expected.account_id);
    let parsed = sealed_root_enrollment::parse(&unsigned).unwrap();
    let proof = sealed_root_enrollment::verify(&pin, &unsigned, &signature, &parsed, 1_000_000)
        .expect("the produced signature verifies against the public codec");
    assert_eq!(proof.root_fingerprint(), &expected.root_fingerprint);
    // Canonical low-s output: the verifier rejects high-s signatures outright.
    assert!(&signature[32..] <= HALF_ORDER.as_slice());
    // A distinct transcript produces a distinct signature.
    let other = challenge(&expected, 1_000_000, 1_299_999);
    let other_signature = sign_enrollment(&recovered, &other, &expected, 1_000_000).unwrap();
    assert_ne!(signature, other_signature);
}

#[test]
fn challenges_for_any_other_identity_are_refused_before_signing() {
    let (root, _recovery, expected) = material("ZROtext synthetic root-unlock other identity");
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    for mutated in [
        Challenge {
            account_id: [0xbb; 16],
            ..sealed_root_enrollment::parse(&unsigned).unwrap()
        },
        Challenge {
            origin: "https://other.invalid".into(),
            ..sealed_root_enrollment::parse(&unsigned).unwrap()
        },
        Challenge {
            root_fingerprint: [9; 32],
            ..sealed_root_enrollment::parse(&unsigned).unwrap()
        },
    ] {
        let attacker = sealed_root_enrollment::encode(&mutated).unwrap();
        assert_eq!(
            inspect_challenge(&attacker, &expected, 1_000_000).unwrap_err(),
            UnlockError::ContextRejected
        );
        assert_eq!(
            sign_enrollment(&root, &attacker, &expected, 1_000_000).unwrap_err(),
            UnlockError::ContextRejected
        );
    }
}

#[test]
fn a_mismatched_expected_identity_never_signs() {
    let (root, _recovery, expected) = material("ZROtext synthetic root-unlock mismatch");
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    for wrong in [
        ExpectedIdentity {
            account_id: [0xbb; 16],
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
        assert_eq!(
            inspect_challenge(&unsigned, &wrong, 1_000_000).unwrap_err(),
            UnlockError::ContextRejected
        );
        assert_eq!(
            sign_enrollment(&root, &unsigned, &wrong, 1_000_000).unwrap_err(),
            UnlockError::ContextRejected
        );
    }
}

#[test]
fn a_root_that_does_not_own_the_expected_fingerprint_never_signs() {
    let (owner, _recovery, expected) = material("ZROtext synthetic root-unlock owner");
    let other = RootSecret::new(synthetic(b"ZROtext synthetic root-unlock wrong root")).unwrap();
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    assert_eq!(
        sign_enrollment(&other, &unsigned, &expected, 1_000_000).unwrap_err(),
        UnlockError::ContextRejected
    );
    // The owning root signs the same bytes without error.
    assert!(sign_enrollment(&owner, &unsigned, &expected, 1_000_000).is_ok());
}

#[test]
fn only_the_exact_time_window_unlocks() {
    let (root, _recovery, expected) = material("ZROtext synthetic root-unlock window");
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    for (now, accepted) in [
        (999_999, false),
        (1_000_000, true),
        (1_299_999, true),
        (1_300_000, false),
        (u64::MAX, false),
    ] {
        assert_eq!(
            inspect_challenge(&unsigned, &expected, now).is_ok(),
            accepted,
            "now={now}"
        );
        assert_eq!(
            sign_enrollment(&root, &unsigned, &expected, now).is_ok(),
            accepted,
            "now={now}"
        );
    }
}

#[test]
fn malformed_challenge_bytes_fail_closed() {
    let (root, _recovery, expected) = material("ZROtext synthetic root-unlock malformed");
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    for length in 0..unsigned.len() {
        assert_eq!(
            inspect_challenge(&unsigned[..length], &expected, 1_000_000).unwrap_err(),
            UnlockError::InvalidInput
        );
        assert_eq!(
            sign_enrollment(&root, &unsigned[..length], &expected, 1_000_000).unwrap_err(),
            UnlockError::InvalidInput
        );
    }
    for malformed in [[unsigned.as_slice(), &[0]].concat(), vec![0; 664], {
        let mut changed = unsigned.clone();
        changed[0] ^= 1;
        changed
    }] {
        assert_eq!(
            inspect_challenge(&malformed, &expected, 1_000_000).unwrap_err(),
            UnlockError::InvalidInput
        );
        assert_eq!(
            sign_enrollment(&root, &malformed, &expected, 1_000_000).unwrap_err(),
            UnlockError::InvalidInput
        );
    }
}

#[test]
fn inspect_returns_public_challenge_fields_for_display() {
    let (_root, _recovery, expected) = material("ZROtext synthetic root-unlock inspect");
    let unsigned = challenge(&expected, 1_000_000, 1_300_000);
    let inspected = inspect_challenge(&unsigned, &expected, 1_000_000).unwrap();
    assert_eq!(inspected, sealed_root_enrollment::parse(&unsigned).unwrap());
    assert_eq!(inspected.challenge_id, [4; 16]);
    assert_eq!(inspected.expires_ms, 1_300_000);
    assert_eq!(inspected.origin, "https://example.invalid");
}
