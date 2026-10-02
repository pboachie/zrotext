// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn fixture() -> (ExpectedIdentity, [u8; 94]) {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let point = SecretKey::from_slice(&scalar)
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    let pin: [u8; 94] = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        point.as_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap();
    (
        ExpectedIdentity {
            account_id: [1; 16],
            origin: "https://owner.invalid".into(),
            root_fingerprint: root_fingerprint(&pin, &[1; 16]).unwrap(),
        },
        pin,
    )
}
fn prepared() -> PreparedArchive {
    let (identity, pin) = fixture();
    let mut scalar = [0; 32];
    scalar[31] = 3;
    prepare(
        ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
        ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
        &identity,
        &pin,
    )
    .unwrap()
}
#[test]
fn exact_backup_and_independent_recovery_are_authenticated() {
    let p = prepared();
    assert_eq!(&p.encrypted_backup()[..4], b"ZTAB");
    let restored = open(
        p.encrypted_backup(),
        &ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
        p.identity(),
    )
    .unwrap();
    assert_eq!(restored.as_bytes()[31], 3);
    p.verify_recovery(
        p.encrypted_backup(),
        ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
    )
    .unwrap();
    assert!(
        p.verify_recovery(
            p.encrypted_backup(),
            ArchiveRecoverySecret::new(Zeroizing::new([9; 32]))
        )
        .is_err()
    );
    let mut changed = p.encrypted_backup().to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(
        p.verify_recovery(
            &changed,
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32]))
        )
        .is_err()
    );
}
#[test]
fn independent_root_binding_is_required_before_seal() {
    let (mut identity, pin) = fixture();
    identity.root_fingerprint[0] ^= 1;
    let mut scalar = [0; 32];
    scalar[31] = 3;
    assert!(
        prepare(
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
            &identity,
            &pin
        )
        .is_err()
    );
    let (mut identity, pin) = fixture();
    identity.account_id = [2; 16];
    assert!(
        prepare(
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
            &identity,
            &pin
        )
        .is_err()
    );
    let (mut identity, pin) = fixture();
    identity.origin = "https://owner.invalid/".into();
    assert!(
        prepare(
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
            &identity,
            &pin
        )
        .is_err()
    );
}
#[test]
fn receipt_is_bounded_public_comparison_material() {
    let p = prepared();
    let receipt = String::from_utf8(p.public_receipt()).unwrap();
    assert!(receipt.len() <= MAX_RECEIPT);
    assert!(receipt.contains(&hex(&p.identity().archive_id)));
    assert!(receipt.contains(&hex(&p.identity().archive_point)));
    assert!(!receipt.contains(&hex(p.recovery_bytes())));
    assert!(receipt.contains("Encrypted archive SHA256:"));
}

#[test]
fn root_scalar_reuse_and_zero_recovery_are_rejected() {
    let (identity, pin) = fixture();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    assert!(
        prepare(
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
            &identity,
            &pin
        )
        .is_err()
    );
    scalar[31] = 3;
    assert!(
        prepare(
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([0; 32])),
            &identity,
            &pin
        )
        .is_err()
    );
}
