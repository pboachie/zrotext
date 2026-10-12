// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;

pub(super) fn observation(kind: u8, count: u16) -> ObservationV2 {
    let mut bytes = [0u8; 121];
    bytes[0..2].copy_from_slice(&35u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&count.to_be_bytes());
    bytes[4..8].copy_from_slice(&7i32.to_be_bytes());
    bytes[8] = kind;
    for offset in [9, 25, 49, 73] {
        bytes[offset..offset + 16].copy_from_slice(Uuid::new_v4().as_bytes());
    }
    bytes[41..45].copy_from_slice(&1i32.to_be_bytes());
    bytes[45..49].copy_from_slice(&0i32.to_be_bytes());
    bytes[65..73].copy_from_slice(&3i64.to_be_bytes());
    bytes[89..121].copy_from_slice(&digest(b"synthetic complete enabled set"));
    ObservationV2::decode(&bytes).unwrap()
}

#[test]
fn signatures_bind_physical_and_embedded_complete_sets_to_purpose_and_tuple() {
    let device = SigningKey::generate_from_rng(&mut rand::rng());
    let owner = SigningKey::generate_from_rng(&mut rand::rng());
    let challenge = LineChallenge {
        id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        line_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        generation: 9,
        nonce: [0x39; 32],
    };
    for (kind, count) in [(1, 2), (2, 256)] {
        let o = observation(kind, count);
        let statement = v2::device_statement(PurposeV2::Sms, &challenge, &o).unwrap();
        let signature: Signature = device.sign(&statement.bytes());
        let der = signature.to_der();
        let owner_statement = v2::owner_statement(&statement, der.as_bytes()).unwrap();
        let approval: Signature = owner.sign(&owner_statement.bytes());
        assert!(v2::verify_device_signature(
            device.verifying_key().to_sec1_point(false).as_bytes(),
            &statement,
            der.as_bytes()
        ));
        assert!(v2::verify_owner_signature(
            owner.verifying_key().to_sec1_point(false).as_bytes(),
            &owner_statement,
            approval.to_der().as_bytes()
        ));
        let other = v2::device_statement(PurposeV2::Sealed, &challenge, &o).unwrap();
        assert!(!v2::verify_device_signature(
            device.verifying_key().to_sec1_point(false).as_bytes(),
            &other,
            der.as_bytes()
        ));
        let mut changed = challenge;
        changed.generation += 1;
        let other = v2::device_statement(PurposeV2::Sms, &changed, &o).unwrap();
        assert!(!v2::verify_device_signature(
            device.verifying_key().to_sec1_point(false).as_bytes(),
            &other,
            der.as_bytes()
        ));
        assert!(!v2::verify_device_signature(
            owner.verifying_key().to_sec1_point(false).as_bytes(),
            &statement,
            der.as_bytes()
        ));
        // The existing v1 constructor retains its exact count-one refusal.
        assert!(
            super::super::sms_device_line_statement(
                &challenge,
                SimObservation {
                    android_api_level: 35,
                    active_subscription_count: 2,
                    selected_subscription_id: 7
                }
            )
            .is_err()
        );
    }
}

#[test]
fn installation_correlation_requires_every_tuple_field_and_both_digests() {
    let ack = Ack {
        challenge_id: Uuid::new_v4(),
        account_id: Uuid::new_v4(),
        line_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        generation: 4,
        device_statement_sha256: [1; 32],
        device_signature_sha256: [2; 32],
    };
    assert!(same_ack(ack, ack));
    for field in 0..7 {
        let mut other = ack;
        match field {
            0 => other.challenge_id = Uuid::new_v4(),
            1 => other.account_id = Uuid::new_v4(),
            2 => other.line_id = Uuid::new_v4(),
            3 => other.device_id = Uuid::new_v4(),
            4 => other.generation += 1,
            5 => other.device_statement_sha256[0] ^= 1,
            _ => other.device_signature_sha256[0] ^= 1,
        }
        assert!(!same_ack(ack, other));
    }
}
