// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
#[path = "fixture.rs"]
mod fixture;
fn signature(n: u8, bytes: &[u8]) -> [u8; 64] {
    let mut scalar = [0; 32];
    scalar[31] = n;
    let s: Signature = SigningKey::from_slice(&scalar).unwrap().sign(bytes);
    s.normalize_s().to_bytes().into()
}
#[test]
fn pure_codec_and_both_possession_signatures_use_only_the_exact_domain() {
    let (expected, statement, bytes) = fixture::fixture(2000, 62000);
    assert_eq!(encode(&statement).unwrap(), bytes);
    let vector: serde_json::Value = serde_json::from_str(include_str!("vector.json")).unwrap();
    let fixture_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(fixture_hex, vector["transcript"].as_str().unwrap());
    let parsed = decode(&bytes).unwrap();
    assert_eq!(
        inspect(&parsed, &expected, 2000).unwrap().transcript(),
        bytes
    );
    let root = signature(1, &bytes);
    let approval = signature(2, &bytes);
    parsed.verify_root(&root).unwrap();
    parsed.verify_approval(&approval).unwrap();
    assert!(parsed.verify_root(&approval).is_err());
    assert!(parsed.verify_approval(&root).is_err());
    // The mathematically equivalent high-s twin must be refused explicitly.
    let order: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut high = root;
    let mut borrow = 0i16;
    for n in (0..32).rev() {
        let value = order[n] as i16 - root[n + 32] as i16 - borrow;
        high[n + 32] = value.rem_euclid(256) as u8;
        borrow = i16::from(value < 0);
    }
    assert!(parsed.verify_root(&high).is_err());
    for domain in [
        b"ZTSE/root-custody/v1\0".as_slice(),
        b"ZTSE/root-enroll/v1\0",
        b"ZTSE/manifest/v2\0",
    ] {
        assert!(
            parsed
                .verify_root(&signature(1, &[domain, &bytes].concat()))
                .is_err()
        );
    }
    assert!(parsed.verify_root(&root[..63]).is_err());
    assert!(parsed.verify_root(&[0; 64]).is_err());
}
#[test]
fn every_changed_byte_truncation_extra_byte_and_oversize_is_refused() {
    let (expected, _, bytes) = fixture::fixture(2000, 62000);
    for n in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[n] ^= 1;
        if let Ok(parsed) = decode(&changed) {
            assert!(inspect(&parsed, &expected, 3000).is_err(), "byte {n}");
        }
    }
    for n in 0..bytes.len() {
        assert!(decode(&bytes[..n]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode(&extra).is_err());
    assert!(decode(&vec![0; MAX_TRANSCRIPT + 1]).is_err());
}
#[test]
fn independent_root_scope_fingerprints_and_live_time_are_required() {
    let (expected, statement, _) = fixture::fixture(2000, 62000);
    for now in [0, 1999, 62000, i64::MAX as u64 + 1] {
        assert!(inspect(&statement, &expected, now).is_err());
    }
    let mut variants = Vec::new();
    macro_rules! changed {
        ($field:ident,$value:expr) => {{
            let mut e = expected.clone();
            e.scope.$field = $value;
            variants.push(e);
        }};
    }
    changed!(user, [9; 16]);
    changed!(owner_session, [9; 16]);
    changed!(device, [9; 16]);
    changed!(line, [9; 16]);
    changed!(next_generation, 2);
    changed!(challenge, [9; 16]);
    changed!(nonce, [9; 32]);
    changed!(approval_fingerprint, [9; 32]);
    changed!(paired_signing_fingerprint, [9; 32]);
    changed!(connection_epoch, 9);
    changed!(deployment_epoch, 10);
    changed!(site_id, "other".into());
    changed!(instance_id, "other".into());
    changed!(origin, "https://other.invalid".into());
    changed!(issued_ms, 2001);
    changed!(expires_ms, 62001);
    for e in variants {
        assert!(inspect(&statement, &e, 3000).is_err());
    }
    let mut e = expected.clone();
    e.identity.root_fingerprint[0] ^= 1;
    assert!(inspect(&statement, &e, 3000).is_err());
    let mut e = expected.clone();
    e.root_pin[93] ^= 1;
    assert!(inspect(&statement, &e, 3000).is_err());
}
#[test]
fn malformed_scope_point_alias_and_noncanonical_origins_cannot_encode() {
    let (_, statement, _) = fixture::fixture(2000, 62000);
    let mut variants = Vec::new();
    macro_rules! bad {
        ($field:ident,$value:expr) => {{
            let mut s = statement.clone();
            s.scope.$field = $value;
            variants.push(s);
        }};
    }
    bad!(account, [0; 16]);
    bad!(user, [0; 16]);
    bad!(owner_session, [0; 16]);
    bad!(device, [0; 16]);
    bad!(line, [0; 16]);
    bad!(challenge, [0; 16]);
    bad!(nonce, [0; 32]);
    bad!(next_generation, 0);
    bad!(next_generation, i64::MAX as u64 + 1);
    bad!(connection_epoch, 0);
    bad!(deployment_epoch, 0);
    bad!(issued_ms, 0);
    bad!(expires_ms, 2000);
    bad!(expires_ms, 302001);
    bad!(site_id, "bad id".into());
    bad!(instance_id, "x".repeat(129));
    bad!(origin, "https://owner.invalid/".into());
    bad!(
        approval_fingerprint,
        statement.scope.paired_signing_fingerprint
    );
    for s in variants {
        assert!(encode(&s).is_err());
    }
    let mut s = statement.clone();
    s.approval_point = s.root_pin[29..].try_into().unwrap();
    s.scope.approval_fingerprint = Sha256::digest(s.approval_point).into();
    assert!(encode(&s).is_err());
    let mut s = statement.clone();
    s.approval_point[0] = 2;
    assert!(encode(&s).is_err());
}
#[cfg(feature = "unlock")]
#[test]
fn consumed_review_rechecks_time_and_root_after_secret_entry_and_snapshots_inputs() {
    use zeroize::Zeroizing;
    let (mut expected, mut statement, bytes) = fixture::fixture(2000, 62000);
    let reviewed = inspect(&statement, &expected, 3000).unwrap();
    expected.scope.line = [9; 16];
    statement.scope.device = [9; 16];
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    let signed = reviewed.sign(&root, 3001).unwrap();
    decode(&bytes).unwrap().verify_root(&signed).unwrap();
    let (expected, statement, _) = fixture::fixture(2000, 62000);
    assert!(
        inspect(&statement, &expected, 3000)
            .unwrap()
            .sign(&root, 62000)
            .is_err()
    );
    scalar[31] = 3;
    let other = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    assert!(
        inspect(&statement, &expected, 3000)
            .unwrap()
            .sign(&other, 3001)
            .is_err()
    );
}
