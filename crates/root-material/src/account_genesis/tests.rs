// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    archive_backup::{self, ArchiveRecoverySecret, ArchiveSecret},
    archive_init,
    root_backup::{self, RecoverySecret},
};
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

fn scalar(label: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(label).into())
}

// Independent fixed-layout fixture encoding, not the production reconstruction
// function or a substitute for the maintained server admission verifier.
fn unsigned(e: &Expected) -> Vec<u8> {
    let mut out = vec![0; 449];
    out[..5].copy_from_slice(b"ZTMA\x02");
    out[5..21].copy_from_slice(&e.identity.account_id);
    out[21..29].copy_from_slice(&1u64.to_be_bytes());
    out[29..37].copy_from_slice(&1u64.to_be_bytes());
    out[37..45].copy_from_slice(&e.issued_ms.to_be_bytes());
    out[45..53].copy_from_slice(&e.expires_ms.to_be_bytes());
    out[85..150].copy_from_slice(&e.root_pin[29..]);
    out[150] = 2;
    for (at, role, scope, point, algorithm) in [
        (151, 2, 12u16, e.archive.archive_point, [0, 16]),
        (300, 6, 0u16, e.root_pin[29..].try_into().unwrap(), [1, 1]),
    ] {
        let id: [u8; 32] =
            Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, &point].concat()).into();
        out[at] = role;
        out[at + 1..at + 33].copy_from_slice(&id);
        out[at + 33..at + 98].copy_from_slice(&point);
        out[at + 130..at + 132].copy_from_slice(&scope.to_be_bytes());
        out[at + 132..at + 140].copy_from_slice(&e.issued_ms.to_be_bytes());
        out[at + 140..at + 148].copy_from_slice(&e.expires_ms.to_be_bytes());
        out[at + 148] = 1;
    }
    out
}

fn recovered_root(label: &[u8], account: [u8; 16]) -> (RootSecret, ExpectedIdentity, [u8; 94]) {
    let root = RootSecret::new(scalar(label)).unwrap();
    let key = SigningKey::from_slice(root.as_bytes()).unwrap();
    let mut pin = [0; 94];
    pin[..5].copy_from_slice(b"ZTRP\x02");
    pin[5..21].copy_from_slice(&account);
    pin[21..29].copy_from_slice(&1u64.to_be_bytes());
    pin[29..].copy_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
    drop(key);
    let identity = ExpectedIdentity {
        account_id: account,
        origin: "https://account.invalid".into(),
        root_fingerprint: root_fingerprint(&pin, &account).unwrap(),
    };
    let recovery = RecoverySecret::new(scalar(b"synthetic account root recovery"));
    let encrypted = root_backup::seal(&root, &recovery, &identity).unwrap();
    drop(root);
    let restored = root_backup::open(&encrypted, &recovery, &identity).unwrap();
    (restored, identity, pin)
}

fn fixture() -> (RootSecret, Expected, Vec<u8>) {
    let (root, identity, pin) = recovered_root(b"synthetic account owner root", [0x31; 16]);
    let prepared = archive_init::prepare(
        ArchiveSecret::new(scalar(b"synthetic account archive reader")).unwrap(),
        ArchiveRecoverySecret::new(scalar(b"synthetic separate archive recovery")),
        &identity,
        &pin,
    )
    .unwrap();
    let archive = prepared.identity().clone();
    prepared
        .verify_recovery(
            prepared.encrypted_backup(),
            ArchiveRecoverySecret::new(scalar(b"synthetic separate archive recovery")),
        )
        .unwrap();
    let restored_archive = archive_backup::open(
        prepared.encrypted_backup(),
        &ArchiveRecoverySecret::new(scalar(b"synthetic separate archive recovery")),
        &archive,
    )
    .unwrap();
    let archive_key = p256::SecretKey::from_slice(restored_archive.as_bytes()).unwrap();
    assert_eq!(
        archive_key.public_key().to_sec1_point(false).as_bytes(),
        archive.archive_point
    );
    drop(archive_key);
    drop(restored_archive);
    drop(prepared);
    let e = Expected {
        identity,
        root_pin: pin,
        archive,
        issued_ms: 2000,
        expires_ms: 62000,
    };
    let bytes = unsigned(&e);
    (root, e, bytes)
}

#[test]
fn recovered_root_and_archive_sign_exact_two_role_low_s_manifest() {
    let (root, e, bytes) = fixture();
    let signed = inspect(&bytes, &e, 3000)
        .unwrap()
        .sign(&root, 4000)
        .unwrap();
    assert_eq!(signed.len(), 513);
    assert_eq!(&signed[..449], &bytes);
    let sig = Signature::from_slice(&signed[449..]).unwrap();
    assert_eq!(sig.to_bytes(), sig.normalize_s().to_bytes());
    let transcript = [
        b"ZTSE/manifest/v2\0".as_slice(),
        &449u32.to_be_bytes(),
        &bytes,
    ]
    .concat();
    let verifier = VerifyingKey::from_sec1_bytes(&e.root_pin[29..]).unwrap();
    verifier.verify(&transcript, &sig).unwrap();
    for wrong in [
        [b"ZTSE/root-custody/v1\0".as_slice(), &bytes].concat(),
        [
            b"ZTSE/manifest/v2\0".as_slice(),
            &513u32.to_be_bytes(),
            &bytes,
        ]
        .concat(),
        bytes.clone(),
    ] {
        assert!(verifier.verify(&wrong, &sig).is_err());
    }
}

#[test]
fn every_unsigned_byte_and_every_wrong_width_is_refused() {
    let (_, e, bytes) = fixture();
    for offset in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(inspect(&changed, &e, 3000).is_err(), "offset {offset}");
        assert!(inspect(&bytes[..offset], &e, 3000).is_err());
    }
    assert!(inspect(&[bytes.as_slice(), &[0]].concat(), &e, 3000).is_err());
    assert!(inspect(&vec![0; 2048], &e, 3000).is_err());
}

#[test]
fn all_independently_intended_identity_fields_are_required() {
    let (_, e, bytes) = fixture();
    for field in 0..13 {
        let mut changed = e.clone();
        match field {
            0 => changed.identity.account_id[0] ^= 1,
            1 => changed.identity.origin = "https://other.invalid".into(),
            2 => changed.identity.root_fingerprint[0] ^= 1,
            3 => changed.root_pin[0] ^= 1,
            4 => changed.archive.account_id[0] ^= 1,
            5 => changed.archive.origin = "https://other.invalid".into(),
            6 => changed.archive.root_fingerprint[0] ^= 1,
            7 => changed.archive.generation = 2,
            8 => changed.archive.archive_id[0] ^= 1,
            9 => changed.archive.archive_point[10] ^= 1,
            10 => changed.issued_ms += 1,
            11 => changed.expires_ms += 1,
            _ => changed.root_pin[5] ^= 1,
        }
        assert!(inspect(&bytes, &changed, 3000).is_err());
    }
}

#[test]
fn coherent_replacement_root_and_archive_do_not_match_original_proposal() {
    let (_, e, bytes) = fixture();
    let (_, other_identity, other_pin) =
        recovered_root(b"synthetic other account owner root", e.identity.account_id);
    let mut replacement = e.clone();
    replacement.root_pin = other_pin;
    replacement.identity = other_identity.clone();
    replacement.archive.root_fingerprint = other_identity.root_fingerprint;
    assert!(inspect(&bytes, &replacement, 3000).is_err());
    let other = p256::SecretKey::from_slice(scalar(b"synthetic other archive").as_slice()).unwrap();
    let point: [u8; 65] = other
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    replacement = e.clone();
    replacement.archive.archive_point = point;
    replacement.archive.archive_id =
        Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &point].concat()).into();
    assert!(inspect(&bytes, &replacement, 3000).is_err());
}

#[test]
fn duplicate_offcurve_noncanonical_points_and_purpose_swaps_are_refused() {
    let (_, e, _) = fixture();
    for point in [
        e.root_pin[29..].try_into().unwrap(),
        [0; 65],
        [4; 65],
        [2; 65],
    ] {
        let mut wrong = e.clone();
        wrong.archive.archive_point = point;
        wrong.archive.archive_id =
            Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &point].concat()).into();
        assert!(inspect(&unsigned(&wrong), &wrong, 3000).is_err());
    }
    let mut wrong = e.clone();
    wrong.archive.archive_id = Sha256::digest(
        [
            b"ZTSE/key/v1\0".as_slice(),
            &[1, 1],
            &e.archive.archive_point,
        ]
        .concat(),
    )
    .into();
    assert!(inspect(&unsigned(&wrong), &wrong, 3000).is_err());
    for index in [0, 4, 21, 28, 29, 40, 93] {
        let mut wrong = e.clone();
        wrong.root_pin[index] ^= 1;
        assert!(inspect(&unsigned(&wrong), &wrong, 3000).is_err());
    }
}

#[test]
fn roles_scopes_subjects_order_state_and_successor_headers_are_not_admitted() {
    let (_, e, bytes) = fixture();
    for (at, replacement) in [
        (21, 1),
        (36, 2),
        (53, 1),
        (150, 4),
        (151, 3),
        (300, 5),
        (282, 8),
        (431, 1),
        (249, 1),
        (265, 1),
        (398, 1),
        (414, 1),
        (299, 2),
        (448, 0),
    ] {
        let mut wrong = bytes.clone();
        wrong[at] = replacement;
        assert!(inspect(&wrong, &e, 3000).is_err());
    }
    let mut reversed = bytes.clone();
    reversed[151..300].copy_from_slice(&bytes[300..449]);
    reversed[300..449].copy_from_slice(&bytes[151..300]);
    assert!(inspect(&reversed, &e, 3000).is_err());
}

#[test]
fn canonical_origin_nonzero_identity_and_one_day_interval_are_enforced() {
    let (_, e, _) = fixture();
    for origin in [
        "http://account.invalid",
        "https://account.invalid/",
        "https://ACCOUNT.invalid",
        "https://é.invalid",
    ] {
        let mut wrong = e.clone();
        wrong.identity.origin = origin.into();
        wrong.archive.origin = origin.into();
        assert!(inspect(&unsigned(&wrong), &wrong, 3000).is_err());
    }
    for (issued, expires, now) in [
        (0, 62000, 3000),
        (3000, 3000, 3000),
        (3000, 2999, 3000),
        (2000, 86_402_001, 3000),
        (i64::MAX as u64, i64::MAX as u64 + 1, i64::MAX as u64),
    ] {
        let mut wrong = e.clone();
        wrong.issued_ms = issued;
        wrong.expires_ms = expires;
        assert!(inspect(&unsigned(&wrong), &wrong, now).is_err());
    }
    let mut day = e.clone();
    day.expires_ms = day.issued_ms + 86_400_000;
    assert!(inspect(&unsigned(&day), &day, day.issued_ms).is_ok());
    let mut zero = e.clone();
    zero.identity.account_id = [0; 16];
    zero.archive.account_id = [0; 16];
    assert!(inspect(&unsigned(&zero), &zero, 3000).is_err());
    zero = e.clone();
    zero.identity.root_fingerprint = [0; 32];
    zero.archive.root_fingerprint = [0; 32];
    assert!(inspect(&unsigned(&zero), &zero, 3000).is_err());
}

#[test]
fn inspection_and_signing_boundaries_require_fresh_nonregressed_final_time() {
    let (root, e, bytes) = fixture();
    for now in [0, 1999, 62000, i64::MAX as u64 + 1, u64::MAX] {
        assert!(inspect(&bytes, &e, now).is_err());
    }
    for now in [0, 1999, 2999, 62000, i64::MAX as u64 + 1, u64::MAX] {
        assert!(inspect(&bytes, &e, 3000).unwrap().sign(&root, now).is_err());
    }
    for now in [3000, 61999] {
        assert!(inspect(&bytes, &e, 3000).unwrap().sign(&root, now).is_ok());
    }
    assert!(inspect(&bytes, &e, 2000).unwrap().sign(&root, 2000).is_ok());
}

#[test]
fn a_different_genuinely_recovered_root_cannot_sign_reviewed_bytes() {
    let (_, e, bytes) = fixture();
    let (other, _, _) = recovered_root(b"synthetic wrong recovered owner", e.identity.account_id);
    assert!(
        inspect(&bytes, &e, 3000)
            .unwrap()
            .sign(&other, 3000)
            .is_err()
    );
}

#[test]
fn review_retains_exact_snapshot_after_caller_mutation() {
    let (root, mut e, mut bytes) = fixture();
    let original = bytes.clone();
    let reviewed = inspect(&bytes, &e, 3000).unwrap();
    bytes.fill(0);
    e.archive.archive_point.fill(0);
    e.root_pin.fill(0);
    e.expires_ms = 3000;
    let signed = reviewed.sign(&root, 4000).unwrap();
    assert_eq!(&signed[..449], original);
}
