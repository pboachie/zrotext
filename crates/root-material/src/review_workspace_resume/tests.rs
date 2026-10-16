// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/review-workspace-resume-01.json"
    ))
    .unwrap()
}
fn bytes(v: &Value, key: &str) -> Vec<u8> {
    let hex = v[key].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> (Vec<u8>, Expected) {
    let v = vector();
    let unsigned = bytes(&v, "unsignedHex");
    let s = decode(&unsigned).unwrap();
    let expected = Expected {
        identity: ExpectedIdentity {
            account_id: s.scope.account,
            origin: s.scope.origin.clone(),
            root_fingerprint: s.fingerprint,
        },
        root_pin: s.root_pin,
        scope: s.scope,
        captured_ms: 1_000_000,
    };
    // Fixture construction only. Production expected context must come from the
    // independent kit and authenticated broker response, not this decoding pattern.
    (unsigned, expected)
}
fn key() -> SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    SigningKey::from_slice(&scalar).unwrap()
}
fn sign(unsigned: &[u8]) -> [u8; 64] {
    let signature: Signature = key().sign(&transcript(unsigned).unwrap());
    signature.normalize_s().to_bytes().into()
}

#[test]
fn independent_vector_has_exact_bytes_hashes_and_valid_low_s_possession() {
    let v = vector();
    let (u, expected) = fixture();
    let s = decode(&u).unwrap();
    assert_eq!(u.len(), 353);
    assert_eq!(encode(&s).unwrap(), u);
    assert_eq!(transcript(&u).unwrap(), bytes(&v, "transcriptHex"));
    assert_eq!(s.root_pin.as_slice(), bytes(&v, "rootPinHex"));
    assert_eq!(s.fingerprint.as_slice(), bytes(&v, "rootFingerprintHex"));
    assert_eq!(Sha256::digest(&u).as_slice(), bytes(&v, "unsignedSha256"));
    assert_eq!(
        Sha256::digest(transcript(&u).unwrap()).as_slice(),
        bytes(&v, "transcriptSha256")
    );
    verify(&u, &bytes(&v, "signatureHex"), &expected, 1_000_000).unwrap();
}

#[test]
fn validly_resigned_changes_do_not_replace_the_independent_expected_context() {
    let (u, expected) = fixture();
    let original = decode(&u).unwrap();
    let changes: [fn(&mut Scope); 13] = [
        |s| s.realm[0] ^= 1,
        |s| s.broker[0] ^= 1,
        |s| s.broker_session[0] ^= 1,
        |s| s.authentication_event[0] ^= 1,
        |s| s.credential_revision += 1,
        |s| s.owner[0] ^= 1,
        |s| s.challenge[0] ^= 1,
        |s| s.nonce[0] ^= 1,
        |s| s.browser_binding[0] ^= 1,
        |s| {
            s.issued_ms -= 1;
            s.expires_ms -= 1;
        },
        |s| s.expires_ms -= 1,
        |s| s.origin = "https://other.example.test".into(),
        |s| {
            s.issued_ms += 1;
            s.expires_ms += 1;
        },
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed.scope);
        let altered = encode(&changed).unwrap();
        let signature = sign(&altered);
        // Prove this is a cryptographically valid signature, not random corruption.
        key()
            .verifying_key()
            .verify(
                &transcript(&altered).unwrap(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        assert!(verify(&altered, &signature, &expected, 1_000_010).is_err());
    }
}

#[test]
fn another_account_with_the_same_public_point_cannot_replace_the_retained_kit() {
    let (u, expected) = fixture();
    let mut s = decode(&u).unwrap();
    s.scope.account = [12; 16];
    s.root_pin[5..21].copy_from_slice(&s.scope.account);
    s.fingerprint =
        sealed_root_enrollment::root_fingerprint(&s.root_pin, &s.scope.account).unwrap();
    let altered = encode(&s).unwrap();
    assert!(verify(&altered, &sign(&altered), &expected, 1_000_010).is_err());
}

#[test]
fn independently_expected_identity_pin_and_fingerprint_must_all_agree() {
    for field in 0..4 {
        let (u, mut expected) = fixture();
        match field {
            0 => expected.identity.account_id[0] ^= 1,
            1 => expected.identity.origin = "https://other.example.test".into(),
            2 => expected.identity.root_fingerprint[0] ^= 1,
            _ => expected.root_pin[30] ^= 1,
        }
        assert!(inspect(&u, &expected, 1_000_010).is_err());
    }
}

#[test]
fn zero_scope_values_and_nonpositive_or_overflowing_integers_refuse() {
    for at in [5, 21, 37, 53, 77, 93, 109] {
        let (mut u, _) = fixture();
        u[at..at + 16].fill(0);
        assert!(decode(&u).is_err());
    }
    for at in [125, 157] {
        let (mut u, _) = fixture();
        u[at..at + 32].fill(0);
        assert!(decode(&u).is_err());
    }
    for at in [69, 189, 197] {
        for n in [0_u64, i64::MAX as u64 + 1, u64::MAX] {
            let (mut u, _) = fixture();
            u[at..at + 8].copy_from_slice(&n.to_be_bytes());
            assert!(decode(&u).is_err());
        }
    }
}

#[test]
fn bounded_exact_framing_refuses_truncation_trailing_data_and_alternate_versions() {
    let (u, _) = fixture();
    for n in 0..u.len() {
        assert!(decode(&u[..n]).is_err(), "prefix {n}");
    }
    let mut changed = u.clone();
    changed.push(0);
    assert!(decode(&changed).is_err());
    for at in [0, 4, 205, 209, 227] {
        let mut changed = u.clone();
        changed[at] ^= 1;
        assert!(decode(&changed).is_err());
    }
    for length in [0_u16, 19, 21, 513, u16::MAX] {
        let mut changed = u.clone();
        changed[331..333].copy_from_slice(&length.to_be_bytes());
        assert!(decode(&changed).is_err());
    }
    assert!(decode(&vec![0; MAX_UNSIGNED + 1]).is_err());
}

#[test]
fn origin_aliases_credentials_paths_and_invalid_utf8_refuse_without_normalization() {
    for origin in [
        "https://EXAMPLE.test",
        "https://example.test/",
        "https://example.test:443",
        "http://example.test",
        "https://user@example.test",
        "https://example.test/a",
        "https://example.test?x",
        "https://example.test#x",
    ] {
        let (u, _) = fixture();
        let mut s = decode(&u).unwrap();
        s.scope.origin = origin.into();
        assert!(encode(&s).is_err());
    }
    let (mut u, _) = fixture();
    u[FIXED] = 0xff;
    assert!(decode(&u).is_err());
}

#[test]
fn trusted_time_refuses_future_expired_regressing_and_unbounded_windows() {
    let (u, mut expected) = fixture();
    for now in [0, 999_999, 1_300_000, i64::MAX as u64 + 1] {
        assert!(inspect(&u, &expected, now).is_err());
    }
    expected.captured_ms += 10;
    assert!(inspect(&u, &expected, 1_000_009).is_err());
    inspect(&u, &expected, 1_000_010).unwrap();
    let mut s = decode(&u).unwrap();
    s.scope.expires_ms += 1;
    assert!(encode(&s).is_err());
    s.scope.expires_ms = s.scope.issued_ms;
    assert!(encode(&s).is_err());
    expected.captured_ms = 999_999;
    assert!(inspect(&u, &expected, 1_000_010).is_err());
}

#[test]
fn malformed_width_zero_scalars_and_valid_high_s_malleation_refuse() {
    let (u, expected) = fixture();
    for raw in [vec![], vec![0; 63], vec![0; 64], vec![0; 65], vec![255; 64]] {
        assert!(verify(&u, &raw, &expected, 1_000_010).is_err());
    }
    let mut high = sign(&u);
    let order = [
        255_u8, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250,
        173, 167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
    ];
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let d = i16::from(order[i]) - i16::from(high[32 + i]) - borrow;
        high[32 + i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    let signature = Signature::from_slice(&high).unwrap();
    assert_ne!(signature.normalize_s().to_bytes(), signature.to_bytes());
    // This mathematically valid twin must be refused, never normalized by receiver.
    key()
        .verifying_key()
        .verify(&transcript(&u).unwrap(), &signature)
        .unwrap();
    assert!(verify(&u, &high, &expected, 1_000_010).is_err());
}

#[test]
fn enrollment_custody_and_unframed_signatures_do_not_authorize_resume() {
    let (u, expected) = fixture();
    for wrong in [
        u.clone(),
        [
            b"ZTSE/root-enroll/v1\0".as_slice(),
            &(u.len() as u32).to_be_bytes(),
            &u,
        ]
        .concat(),
        [b"ZTSE/root-custody/v1\0".as_slice(), &u].concat(),
    ] {
        let signature: Signature = key().sign(&wrong);
        assert!(
            verify(
                &u,
                &signature.normalize_s().to_bytes(),
                &expected,
                1_000_010
            )
            .is_err()
        );
    }
}

#[cfg(feature = "unlock")]
#[test]
fn signing_owns_the_reviewed_snapshot_and_matches_the_expected_recovered_root() {
    let (u, mut expected) = fixture();
    let reviewed = inspect(&u, &expected, 1_000_020).unwrap();
    expected.scope.broker_session[0] ^= 1;
    expected.identity.account_id[0] ^= 1;
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(zeroize::Zeroizing::new(scalar)).unwrap();
    let signature = reviewed.sign(&root, 1_000_021).unwrap();
    let (_, fresh) = fixture();
    verify(&u, &signature, &fresh, 1_000_021).unwrap();
    scalar[31] = 2;
    let other = RootSecret::new(zeroize::Zeroizing::new(scalar)).unwrap();
    assert!(
        inspect(&u, &fresh, 1_000_020)
            .unwrap()
            .sign(&other, 1_000_021)
            .is_err()
    );
}

#[cfg(feature = "unlock")]
#[test]
fn signing_rechecks_fresh_time_after_secret_entry_and_refuses_regression() {
    let (u, expected) = fixture();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(zeroize::Zeroizing::new(scalar)).unwrap();
    for now in [1_000_019, 1_300_000] {
        assert!(
            inspect(&u, &expected, 1_000_020)
                .unwrap()
                .sign(&root, now)
                .is_err()
        );
    }
}
