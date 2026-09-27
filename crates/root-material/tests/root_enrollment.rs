// SPDX-License-Identifier: AGPL-3.0-only
use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};
use p256::elliptic_curve::Generate;
use serde_json::Value;
use zrotext_root_material::sealed_root_enrollment::*;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-enrollment-01.json"
    ))
    .unwrap()
}
fn bytes(v: &Value, name: &str) -> Vec<u8> {
    let hex = v[name].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn ephemeral_root(account: [u8; 16]) -> (SigningKey, Vec<u8>) {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let pin = [
        b"ZTRP\x02".as_slice(),
        &account,
        &1_u64.to_be_bytes(),
        key.verifying_key().to_sec1_point(false).as_bytes(),
    ]
    .concat();
    (key, pin)
}

fn sign_candidate(key: &SigningKey, unsigned: &[u8]) -> Vec<u8> {
    let statement = transcript(unsigned).unwrap();
    let signature: Signature = key.sign(&statement);
    let signature = signature.normalize_s();
    // Prove the signature is valid before testing a separate trust binding.
    key.verifying_key().verify(&statement, &signature).unwrap();
    signature.to_bytes().to_vec()
}

#[test]
fn attacker_root_cannot_claim_the_independently_expected_fingerprint() {
    let v = fixture();
    let unsigned = bytes(&v, "unsignedHex");
    let expected = parse(&unsigned).unwrap();
    let (attacker, pin) = ephemeral_root(expected.account_id);
    assert_ne!(
        root_fingerprint(&pin, &expected.account_id).unwrap(),
        expected.root_fingerprint
    );
    // Exact legitimate U/context/time, but a valid signature from the attacker's
    // distinct on-curve root for the same account. Only the pin/fingerprint
    // comparison prevents possession of that other root from claiming this pin.
    let signature = sign_candidate(&attacker, &unsigned);
    assert_eq!(
        verify(&pin, &unsigned, &signature, &expected, expected.issued_ms).unwrap_err(),
        "root fingerprint"
    );
}

#[test]
fn validly_resigned_context_change_cannot_replace_trusted_expectation() {
    let v = fixture();
    let mut expected = parse(&bytes(&v, "unsignedHex")).unwrap();
    let (owner, pin) = ephemeral_root(expected.account_id);
    expected.root_fingerprint = root_fingerprint(&pin, &expected.account_id).unwrap();
    let mut changed = expected.clone();
    changed.session_id = [9; 16];
    let unsigned = encode(&changed).unwrap();
    let signature = sign_candidate(&owner, &unsigned);
    assert!(verify(&pin, &unsigned, &signature, &changed, expected.issued_ms).is_ok());
    assert_eq!(
        verify(&pin, &unsigned, &signature, &expected, expected.issued_ms).unwrap_err(),
        "challenge context"
    );
}

#[test]
fn independent_public_vector_matches_exact_transcript_and_possession() {
    let v = fixture();
    let unsigned = bytes(&v, "unsignedHex");
    let expected = parse(&unsigned).unwrap();
    assert_eq!(expected.account_id, [1; 16]);
    assert_eq!(expected.user_id, [2; 16]);
    assert_eq!(expected.session_id, [3; 16]);
    assert_eq!(expected.challenge_id, [4; 16]);
    assert_eq!(expected.origin, "https://example.test");
    assert_eq!(expected.issued_ms, 1_000_000);
    assert_eq!(expected.expires_ms, 1_300_000);
    assert_eq!(encode(&expected).unwrap(), unsigned);
    assert_eq!(transcript(&unsigned).unwrap(), bytes(&v, "transcriptHex"));
    let pin = bytes(&v, "rootPinHex");
    let signature = bytes(&v, "signatureHex");
    let proof = verify(&pin, &unsigned, &signature, &expected, 1_000_000).unwrap();
    assert_eq!(
        proof.root_fingerprint().as_slice(),
        bytes(&v, "fingerprintHex")
    );
    // Possession verification has deliberately no replay ledger: repeated verification
    // succeeds and must never be confused with permission to enroll twice.
    assert!(verify(&pin, &unsigned, &signature, &expected, 1_000_000).is_ok());
}

#[test]
fn every_received_field_is_bound_to_independent_expected_context() {
    let v = fixture();
    let unsigned = bytes(&v, "unsignedHex");
    let expected = parse(&unsigned).unwrap();
    for offset in [5, 21, 37, 53, 69, 101, 140, 148, 160] {
        let mut changed = unsigned.clone();
        changed[offset] ^= 1;
        assert!(
            verify(
                &bytes(&v, "rootPinHex"),
                &changed,
                &bytes(&v, "signatureHex"),
                &expected,
                1_000_000
            )
            .is_err()
        );
        // Even trusting mutated claims cannot make the old signature cover them.
        if let Ok(context) = parse(&changed) {
            assert!(
                verify(
                    &bytes(&v, "rootPinHex"),
                    &changed,
                    &bytes(&v, "signatureHex"),
                    &context,
                    1_000_001
                )
                .is_err()
            );
        }
    }
    let mut wrong = expected.clone();
    wrong.session_id = [9; 16];
    assert!(
        verify(
            &bytes(&v, "rootPinHex"),
            &unsigned,
            &bytes(&v, "signatureHex"),
            &wrong,
            1_000_000
        )
        .is_err()
    );
}

#[test]
fn exact_window_includes_issue_and_excludes_expiry() {
    let v = fixture();
    let unsigned = bytes(&v, "unsignedHex");
    let expected = parse(&unsigned).unwrap();
    for (now, accepted) in [
        (999_999, false),
        (1_000_000, true),
        (1_299_999, true),
        (1_300_000, false),
        (u64::MAX, false),
    ] {
        assert_eq!(
            verify(
                &bytes(&v, "rootPinHex"),
                &unsigned,
                &bytes(&v, "signatureHex"),
                &expected,
                now
            )
            .is_ok(),
            accepted
        );
    }
    for (issued, expires) in [
        (0, 1),
        (1, 1),
        (2, 1),
        (1, 300_002),
        (1, u64::MAX),
        (i64::MAX as u64, i64::MAX as u64 + 1),
    ] {
        let mut changed = expected.clone();
        changed.issued_ms = issued;
        changed.expires_ms = expires;
        assert!(encode(&changed).is_err());
        let mut wire = unsigned.clone();
        wire[133..141].copy_from_slice(&issued.to_be_bytes());
        wire[141..149].copy_from_slice(&expires.to_be_bytes());
        assert!(parse(&wire).is_err());
    }
}

#[test]
fn origin_is_exact_existing_https_serialization_without_alias_normalization() {
    for origin in [
        "https://example.test",
        "https://example.test:8443",
        "https://example.test.",
        "https://xn--bcher-kva.example",
    ] {
        assert!(canonical_origin(origin), "{origin}");
    }
    for origin in [
        "http://example.test",
        "HTTPS://example.test",
        "https://EXAMPLE.test",
        "https://example.test/",
        "https://example.test:443",
        "https://example.test:08443",
        "https://user@example.test",
        "https://example.test/path",
        "https://example.test?",
        "https://example.test#",
        " https://example.test",
        "https://example.test\n",
        "https://bücher.example",
        "https://example.test\\",
        "",
    ] {
        assert!(!canonical_origin(origin), "{origin:?}");
    }
    let v = fixture();
    let mut c = parse(&bytes(&v, "unsignedHex")).unwrap();
    // The origin contract bounds bytes, not DNS reachability or connection policy.
    c.origin = format!("https://{}.test", "a".repeat(499));
    assert_eq!(c.origin.len(), 512);
    let wire = encode(&c).unwrap();
    assert_eq!(wire.len(), 663);
    assert_eq!(transcript(&wire).unwrap().len(), 687);
    c.origin.insert(8, 'a');
    assert!(encode(&c).is_err());
}

#[test]
fn malformed_frames_and_zero_ids_never_parse() {
    let v = fixture();
    let wire = bytes(&v, "unsignedHex");
    for length in 0..wire.len() {
        assert!(parse(&wire[..length]).is_err());
    }
    let mut changed = wire.clone();
    changed.push(0);
    assert!(parse(&changed).is_err());
    assert!(parse(&vec![0; 664]).is_err());
    for offset in [0, 4, 149, 150] {
        let mut changed = wire.clone();
        changed[offset] ^= 1;
        assert!(parse(&changed).is_err());
    }
    for offset in [5, 21, 37, 53] {
        let mut changed = wire.clone();
        changed[offset..offset + 16].fill(0);
        assert!(parse(&changed).is_err());
    }
    let mut changed = wire.clone();
    changed[151] = 0xff;
    assert!(parse(&changed).is_err());
}

#[test]
fn pin_generation_account_point_and_signature_encodings_fail_closed() {
    let v = fixture();
    let unsigned = bytes(&v, "unsignedHex");
    let expected = parse(&unsigned).unwrap();
    let pin = bytes(&v, "rootPinHex");
    let signature = bytes(&v, "signatureHex");
    for offset in [0, 4, 5, 28, 29, 30] {
        let mut changed = pin.clone();
        changed[offset] ^= 1;
        assert!(verify(&changed, &unsigned, &signature, &expected, 1_000_000).is_err());
    }
    for malformed in [pin[..93].to_vec(), [pin.clone(), vec![0]].concat()] {
        assert!(root_fingerprint(&malformed, &expected.account_id).is_err());
    }
    assert!(root_fingerprint(&pin, &[0; 16]).is_err());
    let mut zero_r = signature.clone();
    zero_r[..32].fill(0);
    let mut zero_s = signature.clone();
    zero_s[32..].fill(0);
    let mut big_r = signature.clone();
    big_r[..32].fill(255);
    let mut big_s = signature.clone();
    big_s[32..].fill(255);
    let der = p256::ecdsa::Signature::from_slice(&signature)
        .unwrap()
        .to_der();
    for invalid in [
        bytes(&v, "highSignatureHex"),
        zero_r,
        zero_s,
        big_r,
        big_s,
        signature[..63].to_vec(),
        [signature, vec![0]].concat(),
        der.as_bytes().to_vec(),
    ] {
        assert!(verify(&pin, &unsigned, &invalid, &expected, 1_000_000).is_err());
    }
}
