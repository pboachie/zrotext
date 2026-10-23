// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use uuid::Uuid;

#[test]
fn proof_retains_the_exact_key_and_purpose_id_instead_of_a_uuid_projection() {
    let key = SigningKey::generate_from_rng(&mut rand::rng());
    let other = SigningKey::generate_from_rng(&mut rand::rng());
    let challenge = DeviceChallenge {
        id: Uuid::from_u128(1),
        account_id: Uuid::from_u128(2),
        device_id: Uuid::from_u128(3),
        nonce: [4; 32],
    };
    let bytes = super::super::device_challenge_bytes(&challenge);
    let signature: Signature = key.sign(&bytes);
    let point = key.verifying_key().to_sec1_point(false);
    let verified = verify(&challenge, point.as_bytes(), signature.to_der().as_bytes()).unwrap();
    assert_eq!(
        verified.identity(),
        AuthenticatedDevice {
            account_id: challenge.account_id,
            device_id: challenge.device_id
        }
    );
    assert!(verified.matches_point(point.as_bytes()));
    assert!(!verified.matches_point(other.verifying_key().to_sec1_point(false).as_bytes()));
    let mut framed = b"ZTSE/key/v1\0\x01\x01".to_vec();
    framed.extend(point.as_bytes());
    assert_eq!(
        verified.signing_key_id().as_slice(),
        Sha256::digest(framed).as_slice()
    );
    assert!(matches!(
        verify(
            &challenge,
            other.verifying_key().to_sec1_point(false).as_bytes(),
            signature.to_der().as_bytes()
        ),
        Err(EnrollmentError::Unauthorized)
    ));
    let changed = DeviceChallenge {
        device_id: Uuid::from_u128(5),
        ..challenge
    };
    assert!(verify(&changed, point.as_bytes(), signature.to_der().as_bytes()).is_err());
    assert!(verify(&changed, point.as_bytes(), &[0; 64]).is_err());
}
