// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};

#[test]
fn binding_transcript_matches_shared_network_order_vector() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../protocol/v1/vectors/pairing-binding-01.json"
    ))
    .unwrap();
    let c = BindingChallenge {
        account_id: v["account_id"].as_str().unwrap().parse().unwrap(),
        pairing_id: v["pairing_id"].as_str().unwrap().parse().unwrap(),
        challenge_id: v["challenge_id"].as_str().unwrap().parse().unwrap(),
        fingerprint: parse_fingerprint(v["key_fingerprint"].as_str().unwrap()).unwrap(),
        nonce: parse_fingerprint(&v["nonce_hex"].as_str().unwrap().to_ascii_uppercase()).unwrap(),
    };
    let encoded: String = challenge_bytes(&c)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(encoded, v["transcript_hex"].as_str().unwrap());
}

#[test]
fn binding_proof_cannot_be_replayed_as_enrollment_or_other_scope() {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let fp: [u8; 32] = Sha256::digest(key.verifying_key().to_sec1_point(false).as_bytes()).into();
    let hasher = EnrollmentHasher::new(crate::test_keys::key(182)).unwrap();
    let mut c = BindingChallenge {
        account_id: Uuid::from_bytes([1; 16]),
        pairing_id: Uuid::from_bytes([2; 16]),
        challenge_id: timestamped_challenge_id(1_800_000_000_000),
        fingerprint: fp,
        nonce: [0; 32],
    };
    c.nonce = nonce(&hasher, &c);
    let bytes = challenge_bytes(&c);
    let signature: Signature = key.sign(&bytes);
    assert_eq!(bytes.len(), 139);
    assert!(verify_signature(
        key.verifying_key().to_sec1_point(false).as_bytes(),
        &bytes,
        signature.to_der().as_bytes()
    ));
    assert!(!verify_signature(
        key.verifying_key().to_sec1_point(false).as_bytes(),
        &enrollment_challenge_bytes(c.account_id, c.pairing_id, &fp, &c.nonce),
        signature.to_der().as_bytes()
    ));
    assert!(challenge_is_current(&hasher, &c, 1_800_000_060_000));
    assert!(!challenge_is_current(&hasher, &c, 1_800_000_070_001));
    assert!(!challenge_is_current(&hasher, &c, 1_799_999_989_999));
    for field in 0..5 {
        let mut changed = c.clone();
        match field {
            0 => changed.account_id = Uuid::new_v4(),
            1 => changed.pairing_id = Uuid::new_v4(),
            2 => changed.challenge_id = Uuid::new_v4(),
            3 => changed.fingerprint[0] ^= 1,
            _ => changed.nonce[0] ^= 1,
        };
        assert!(!challenge_is_current(&hasher, &changed, 1_800_000_000_000));
        assert!(!verify_signature(
            key.verifying_key().to_sec1_point(false).as_bytes(),
            &challenge_bytes(&changed),
            signature.to_der().as_bytes()
        ));
    }
}

#[test]
fn fingerprints_are_exact_current_uppercase_hex() {
    assert_eq!(parse_fingerprint(&"AF".repeat(32)).unwrap(), [175; 32]);
    for bad in [
        "af".repeat(32),
        "A".repeat(63),
        "A".repeat(65),
        "AG".repeat(32),
    ] {
        assert!(parse_fingerprint(&bad).is_err());
    }
}
