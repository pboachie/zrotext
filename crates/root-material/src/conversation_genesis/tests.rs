// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_root_enrollment::root_fingerprint;
use p256::ecdsa::signature::Verifier;
#[path = "fixture.rs"]
mod fixture;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn independently_encoded_first_manifest_signs_exact_canonical_transcript() {
    let (root, expected, bytes, unsigned) = fixture::fixture(2000, 62000);
    // Independently generated SDK vector's canonical unsigned manifest digest.
    assert_eq!(
        hex(&Sha256::digest(&unsigned)),
        "086040e10201f9c8804a68a42fa604d245241a0c95fdbce7fc83f03466b66bde"
    );
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        "29f0a64d951ccfa13dd0f42c00bc6f8c9e8bee208f96cd5e397eef314a55e814"
    );
    let proposal = decode(&bytes).unwrap();
    let reviewed = inspect(&proposal, &expected, 2000).unwrap();
    let signed = reviewed.sign(&root, 2000).unwrap();
    assert_eq!(&signed[..747], unsigned);
    let signature = Signature::from_slice(&signed[747..]).unwrap();
    assert_eq!(signature.to_bytes(), signature.normalize_s().to_bytes());
    let transcript = [
        b"ZTSE/manifest/v2\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        &unsigned,
    ]
    .concat();
    VerifyingKey::from_sec1_bytes(&expected.root_pin[29..])
        .unwrap()
        .verify(&transcript, &signature)
        .unwrap();
    let enrollment = [b"ZTSE/root-custody/v1\0".as_slice(), &unsigned].concat();
    assert!(
        VerifyingKey::from_sec1_bytes(&expected.root_pin[29..])
            .unwrap()
            .verify(&enrollment, &signature)
            .is_err()
    );
}

#[test]
fn every_proposal_byte_is_bound_and_truncation_extra_bytes_are_refused() {
    let (_, expected, bytes, _) = fixture::fixture(2000, 62000);
    for n in 0..bytes.len() {
        assert!(decode(&bytes[..n]).is_err());
        let mut changed = bytes.clone();
        changed[n] ^= 1;
        assert!(
            decode(&changed)
                .and_then(|p| inspect(&p, &expected, 2000))
                .is_err(),
            "offset {n}"
        );
    }
    assert!(decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    assert!(decode(&vec![0; MAX_PROPOSAL + 1]).is_err());
}

#[test]
fn independent_scope_point_pairing_fingerprint_and_root_mismatches_are_refused() {
    let (_, expected, bytes, _) = fixture::fixture(2000, 62000);
    let p = decode(&bytes).unwrap();
    for field in 0..12 {
        let mut wrong = expected.clone();
        match field {
            0 => wrong.scope.account[0] ^= 1,
            1 => wrong.scope.session[0] ^= 1,
            2 => wrong.scope.device[0] ^= 1,
            3 => wrong.scope.line[0] ^= 1,
            4 => wrong.scope.generation += 1,
            5 => wrong.scope.peer = "+13".into(),
            6 => wrong.scope.origin = "https://other.invalid".into(),
            7 => wrong.scope.device_signing_fingerprint[0] ^= 1,
            8 => wrong.scope.fingerprint[0] ^= 1,
            9 => wrong.scope.issued_ms += 1,
            10 => wrong.scope.expires_ms += 1,
            _ => wrong.root_pin[29] ^= 1,
        }
        assert!(inspect(&p, &wrong, 3000).is_err());
    }
    for field in 0..3 {
        let mut wrong = expected.clone();
        match field {
            0 => wrong.phone_reader = expected.archive_reader,
            1 => wrong.archive_reader = expected.phone_reader,
            _ => wrong.phone_signer = expected.phone_reader,
        };
        assert!(inspect(&p, &wrong, 2000).is_err());
    }
    // A matching API identifier/fingerprint-shaped field cannot replace the
    // independently expected signing point, including a newly introduced point.
    let mut wrong = expected.clone();
    wrong.phone_signer = [0; 65];
    assert!(inspect(&p, &wrong, 2000).is_err());
}

#[test]
fn secret_entry_expiry_wrong_recovered_root_and_review_mutation_fail_closed() {
    let (root, expected, mut bytes, _) = fixture::fixture(2000, 62000);
    let p = decode(&bytes).unwrap();
    for now in [1999, 62000, u64::MAX] {
        assert!(
            inspect(&p, &expected, 2000)
                .unwrap()
                .sign(&root, now)
                .is_err()
        );
    }
    let mut scalar = [0; 32];
    scalar[31] = 9;
    let wrong = RootSecret::new(zeroize::Zeroizing::new(scalar)).unwrap();
    assert!(
        inspect(&p, &expected, 2000)
            .unwrap()
            .sign(&wrong, 2000)
            .is_err()
    );
    let reviewed = inspect(&p, &expected, 2000).unwrap();
    bytes.fill(0);
    assert_eq!(reviewed.sign(&root, 2000).unwrap().len(), 811);
    let (_, e, b, _) = fixture::fixture(2000, 86_402_001);
    assert!(decode(&b).and_then(|p| inspect(&p, &e, 2000)).is_err());
}
