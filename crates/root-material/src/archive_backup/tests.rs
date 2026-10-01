// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sha2::Digest;
fn fixture() -> (ArchiveSecret, ArchiveRecoverySecret, ArchiveIdentity) {
    let mut d = [0; 32];
    d[31] = 3;
    let archive = ArchiveSecret::new(Zeroizing::new(d)).unwrap();
    let point: [u8; 65] = SecretKey::from_slice(&d)
        .unwrap()
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut r = [0; 32];
    r[31] = 1;
    let root = SecretKey::from_slice(&r)
        .unwrap()
        .public_key()
        .to_sec1_point(false);
    let pin = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        root.as_bytes(),
    ]
    .concat();
    let identity = ArchiveIdentity {
        account_id: [1; 16],
        generation: 1,
        root_fingerprint: Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat()).into(),
        origin: "https://owner.invalid".into(),
        archive_id: Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], &point].concat()).into(),
        archive_point: point,
    };
    (
        archive,
        ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
        identity,
    )
}
#[test]
fn existing_archive_roundtrip_and_fresh_immutable_objects() {
    let (a, r, e) = fixture();
    let b = seal(&a, &r, &e).unwrap();
    assert_eq!(b.len(), 333 + e.origin.len());
    assert_eq!(open(&b, &r, &e).unwrap().as_bytes(), a.as_bytes());
    assert_ne!(b, seal(&a, &r, &e).unwrap());
    assert_eq!(format!("{a:?}"), "ArchiveSecret([REDACTED])");
}
#[test]
fn wrong_independent_identity_and_recovery_are_refused() {
    let (a, r, e) = fixture();
    let b = seal(&a, &r, &e).unwrap();
    for field in 0..7 {
        let mut changed = e.clone();
        match field {
            0 => changed.account_id[0] ^= 1,
            1 => changed.generation += 1,
            2 => changed.root_fingerprint[0] ^= 1,
            3 => changed.archive_id[0] ^= 1,
            4 => changed.archive_point[2] ^= 1,
            5 => changed.origin = "https://other.invalid".into(),
            _ => changed.origin.push('/'),
        };
        assert!(open(&b, &r, &changed).is_err());
    }
    assert!(open(&b, &ArchiveRecoverySecret::new(Zeroizing::new([9; 32])), &e).is_err());
}
#[test]
fn every_corruption_truncation_and_trailing_byte_refused() {
    let (a, r, e) = fixture();
    let b = seal(&a, &r, &e).unwrap();
    for i in 0..b.len() {
        let mut bad = b.clone();
        bad[i] ^= 1;
        assert!(open(&bad, &r, &e).is_err());
        assert!(open(&b[..i], &r, &e).is_err());
    }
    let mut bad = b;
    bad.push(0);
    assert!(open(&bad, &r, &e).is_err());
}
#[test]
fn same_shape_wrong_scalar_cannot_echo_advertised_point() {
    let (a, r, e) = fixture();
    let mut d = [0; 32];
    d[31] = 2;
    let wrong = ArchiveSecret::new(Zeroizing::new(d)).unwrap();
    assert!(seal(&wrong, &r, &e).is_err());
    let mut b = seal(&a, &r, &e).unwrap();
    let h = HEADER_FIXED + e.origin.len();
    let w = wrapping_key(&r, &b[h..h + 32], &e).unwrap();
    let v = decrypt(
        w.as_slice(),
        &b[h + 32..h + 44],
        &[WRAP_AAD, &b[..h + 44]].concat(),
        &b[h + 44..h + 92],
    )
    .unwrap();
    let ct = encrypt(
        v.as_slice(),
        &b[h + 92..h + 104],
        &[ARCHIVE_AAD, &b[..h + 108]].concat(),
        wrong.as_bytes(),
    )
    .unwrap();
    b[h + 108..].copy_from_slice(&ct);
    assert!(open(&b, &r, &e).is_err());
}
struct FailingFixtureRng {
    call: usize,
    fail: usize,
}
impl rand::TryRng for FailingFixtureRng {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        bytes.fill(7);
        let current = self.call;
        self.call += 1;
        if current == self.fail {
            Err(std::io::Error::other("synthetic partial entropy failure"))
        } else {
            Ok(())
        }
    }
}
impl TryCryptoRng for FailingFixtureRng {}
#[test]
fn invalid_scalar_and_identity_never_seal() {
    assert!(ArchiveSecret::new(Zeroizing::new([0; 32])).is_err());
    assert!(ArchiveSecret::new(Zeroizing::new([255; 32])).is_err());
    let (a, r, mut e) = fixture();
    e.generation = 0;
    assert!(seal(&a, &r, &e).is_err());
    e.generation = 1;
    for fail in 0..5 {
        let mut rng = FailingFixtureRng { call: 0, fail };
        assert_eq!(
            seal_with_rng(&a, &r, &e, &mut rng).unwrap_err(),
            ArchiveBackupError::Randomness
        );
        assert_eq!(rng.call, fail + 1);
    }
}
#[test]
fn sdk_interop_existing_archive_producer() {
    let (a, r, e) = fixture();
    let b = seal(&a, &r, &e).unwrap();
    assert_eq!(open(&b, &r, &e).unwrap().as_bytes(), a.as_bytes());
    if std::env::var_os("ZT_ARCHIVE_INTEROP").is_some() {
        println!(
            "ZT_ARCHIVE_INTEROP_CIPHERTEXT={}",
            data_encoding::HEXLOWER.encode(&b)
        );
    }
}
