// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_payload_election03::adapter_contract::DeviceSessionIdentity03;
use sha2::{Digest, Sha256};

fn identity(version: u16) -> DeviceSessionIdentity03<'static> {
    DeviceSessionIdentity03 {
        account_id: [1; 16],
        device_id: [2; 16],
        site_id: "synthetic-site",
        instance_id: "synthetic-instance",
        connection_epoch: 7,
        deployment_epoch: 9,
        line_activation_version: version,
        enrollment_signing_key_id: [3; 32],
    }
}

#[test]
fn passive_version_two_digest_matches_the_existing_strict_current_identity() {
    assert_eq!(
        passive_session_digest(identity(2)).unwrap(),
        identity(2).digest().unwrap()
    );
    // Current/content canonicalization remains version2-only. Only the
    // explicitly passive path can frame a genuine version1 held lease.
    assert!(identity(1).canonical().is_err());
    assert_ne!(
        passive_session_digest(identity(1)).unwrap(),
        passive_session_digest(identity(2)).unwrap()
    );
}

#[test]
fn passive_version_one_uses_the_same_exact_established_domain_and_integer_widths() {
    let mut payload = Vec::new();
    payload.extend([1; 16]);
    payload.extend([2; 16]);
    payload.extend(14_u32.to_be_bytes());
    payload.extend(b"synthetic-site");
    payload.extend(18_u32.to_be_bytes());
    payload.extend(b"synthetic-instance");
    payload.extend(7_u64.to_be_bytes());
    payload.extend(9_u64.to_be_bytes());
    payload.extend(1_u16.to_be_bytes());
    payload.extend([3; 32]);
    let mut hash = Sha256::new();
    hash.update(b"ZTSE/line/payload-profile/device-session/v1\0");
    hash.update((payload.len() as u32).to_be_bytes());
    hash.update(payload);
    let expected: [u8; 32] = hash.finalize().into();
    assert_eq!(passive_session_digest(identity(1)).unwrap(), expected);
    for version in [0, 3, u16::MAX] {
        assert!(passive_session_digest(identity(version)).is_err());
    }
    let mut invalid = identity(1);
    invalid.site_id = "";
    assert!(passive_session_digest(invalid).is_err());
}
