// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};

struct Fixture {
    account: Uuid,
    device: Uuid,
    line: Uuid,
    pin: [u8; 94],
    fp: [u8; 32],
    signer: [u8; 65],
    signer_fp: [u8; 32],
    phone: Vec<u8>,
    archive: Vec<u8>,
}
const ORIGIN: &str = "https://owner.example.test";
fn key() -> [u8; 65] {
    SigningKey::generate_from_rng(&mut rand::rng())
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
impl Fixture {
    fn new() -> Self {
        let account = Uuid::new_v4();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        let mut pin = [0u8; 94];
        pin[..5].copy_from_slice(b"ZTRP\x02");
        pin[5..21].copy_from_slice(account.as_bytes());
        pin[21..29].copy_from_slice(&1u64.to_be_bytes());
        pin[29..].copy_from_slice(&key());
        let fp = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &pin,
            account.as_bytes(),
        )
        .unwrap();
        let signer = key();
        let signer_fp = hash(&signer);
        let reader = key();
        let archive_reader = key();
        let mut phone = b"ZTPK\x01".to_vec();
        phone.extend(account.as_bytes());
        phone.extend(device.as_bytes());
        phone.extend(line.as_bytes());
        phone.extend(signer_fp);
        phone.extend(1u64.to_be_bytes());
        phone.extend(reader);
        phone.extend(signer);
        let mut archive = b"ZTAB\x01\x01".to_vec();
        archive.extend(Uuid::new_v4().as_bytes());
        archive.extend(account.as_bytes());
        archive.extend(1u64.to_be_bytes());
        archive.extend(fp);
        archive.extend(hash(
            &[b"ZTSE/key/v1\0".as_slice(), &[0, 16], &archive_reader].concat(),
        ));
        archive.extend(archive_reader);
        archive.extend((ORIGIN.len() as u16).to_be_bytes());
        archive.extend(ORIGIN.as_bytes());
        // Framing-only ciphertext fixture; this does not claim decryption/recovery.
        let at = archive.len();
        archive.resize(at + 156, 0);
        archive[at + 104..at + 108].copy_from_slice(&48u32.to_be_bytes());
        Self {
            account,
            device,
            line,
            pin,
            fp,
            signer,
            signer_fp,
            phone,
            archive,
        }
    }
    fn binding(&self) -> Binding<'_> {
        Binding {
            account: self.account,
            device: self.device,
            line: self.line,
            generation: 1,
            origin: ORIGIN,
            root_pin: &self.pin,
            root_fingerprint: &self.fp,
            paired_signing_point: &self.signer,
            paired_signing_fingerprint: &self.signer_fp,
        }
    }
}
#[test]
fn genesis_public_inputs_preserve_exact_ciphertext_digest_and_current_phone_points() {
    let f = Fixture::new();
    let got = inspect_genesis_inputs(f.binding(), &f.phone, &f.archive).unwrap();
    assert_eq!(got.phone_signer, f.signer);
    assert_eq!(got.phone_reader, f.phone[93..158]);
    assert_eq!(got.archive_reader, f.archive[110..175]);
    assert_eq!(got.archive_backup_sha256, hash(&f.archive));
    assert_eq!(got.phone_export_sha256, hash(&f.phone));
}
#[test]
fn genesis_public_inputs_refuse_identity_point_header_and_framing_substitution() {
    let f = Fixture::new();
    for offset in [0, 5, 21, 37, 53, 85, 93, 158] {
        let mut p = f.phone.clone();
        p[offset] ^= 1;
        assert!(
            inspect_genesis_inputs(f.binding(), &p, &f.archive).is_err(),
            "phone offset{offset}"
        );
    }
    for offset in [0, 22, 38, 46, 78, 110, 175, 177, f.archive.len() - 52] {
        let mut a = f.archive.clone();
        a[offset] ^= 1;
        assert!(
            inspect_genesis_inputs(f.binding(), &f.phone, &a).is_err(),
            "archive offset{offset}"
        );
    }
    for len in [0, 5, 93, 222] {
        assert!(inspect_genesis_inputs(f.binding(), &f.phone[..len], &f.archive).is_err());
    }
    let mut a = f.archive.clone();
    a.push(0);
    assert!(inspect_genesis_inputs(f.binding(), &f.phone, &a).is_err());
    let mut b = f.binding();
    b.generation = 2;
    assert!(inspect_genesis_inputs(b, &f.phone, &f.archive).is_err());
    let mut b = f.binding();
    b.device = Uuid::new_v4();
    assert!(inspect_genesis_inputs(b, &f.phone, &f.archive).is_err());
}
#[test]
fn genesis_public_inputs_refuse_reader_alias_without_promoting_ciphertext_authenticity() {
    let f = Fixture::new();
    let mut p = f.phone.clone();
    p[93..158].copy_from_slice(&f.signer);
    assert!(inspect_genesis_inputs(f.binding(), &p, &f.archive).is_err());
    // Body authentication belongs exclusively to the independent native custodian.
    let mut a = f.archive.clone();
    let last = a.len() - 1;
    a[last] ^= 1;
    let before = inspect_genesis_inputs(f.binding(), &f.phone, &f.archive).unwrap();
    let after = inspect_genesis_inputs(f.binding(), &f.phone, &a).unwrap();
    assert_ne!(before.archive_backup_sha256, after.archive_backup_sha256);
}
