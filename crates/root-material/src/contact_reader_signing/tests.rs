// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use zeroize::Zeroizing;

struct Fixture {
    pin: Vec<u8>,
    manifest: Vec<u8>,
    unsigned: Vec<u8>,
    expected: Expected,
}
fn public(scalar: u8) -> [u8; 65] {
    SecretKey::from_slice(&[scalar; 32])
        .unwrap()
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn record(role: u8, scalar: u8, scope: u16, state: u8) -> Vec<u8> {
    let point = public(scalar);
    let mut bytes = vec![role];
    bytes.extend_from_slice(&key_id(role, &point));
    bytes.extend_from_slice(&point);
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&scope.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&10_000_u64.to_be_bytes());
    bytes.push(state);
    bytes
}
fn sign_manifest(unsigned: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signature: Signature = signing.sign(&transcript(b"ZTSE/manifest/v2\0", unsigned));
    let mut bytes = unsigned.to_vec();
    bytes.extend_from_slice(signature.normalize_s().to_bytes().as_slice());
    bytes
}
impl Fixture {
    fn new() -> Self {
        let root = public(1);
        let reader = public(2);
        let account = [7; 16];
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend_from_slice(&account);
        pin.extend_from_slice(&1_u64.to_be_bytes());
        pin.extend_from_slice(&root);
        let fingerprint = sealed_root_enrollment::root_fingerprint(&pin, &account).unwrap();
        let mut m = b"ZTMA\x02".to_vec();
        m.extend_from_slice(&account);
        for n in [1_u64, 1, 1_000, 10_000] {
            m.extend_from_slice(&n.to_be_bytes());
        }
        m.extend_from_slice(&[0; 32]);
        m.extend_from_slice(&root);
        m.push(2);
        m.extend_from_slice(&record(2, 2, 12, 1));
        m.extend_from_slice(&record(6, 1, 0, 1));
        let manifest = sign_manifest(&m);
        let origin = "https://contact.invalid".to_owned();
        let expected = Expected {
            account,
            origin: origin.clone(),
            fingerprint,
            reader_id: key_id(2, &reader),
            reader_point: reader,
            requested_until_ms: 9_000,
        };
        let mut unsigned = b"ZTKA\x01\x03".to_vec();
        unsigned.extend_from_slice(&[8; 16]);
        unsigned.extend_from_slice(&account);
        unsigned.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        unsigned.extend_from_slice(origin.as_bytes());
        for n in [1_u64, 1, 1] {
            unsigned.extend_from_slice(&n.to_be_bytes());
        }
        for value in [fingerprint, hash(&m), expected.reader_id] {
            unsigned.extend_from_slice(&value);
        }
        unsigned.extend_from_slice(&reader);
        unsigned.extend_from_slice(&1_100_u64.to_be_bytes());
        unsigned.extend_from_slice(&9_000_u64.to_be_bytes());
        Self {
            pin,
            manifest,
            unsigned,
            expected,
        }
    }
    fn source(&self) -> Source<'_> {
        Source {
            account: self.expected.account,
            pin: &self.pin,
            fingerprint: self.expected.fingerprint,
            generation: 1,
            version: 1,
            digest: hash(&self.manifest[..self.manifest.len() - 64]),
            manifest: &self.manifest,
            observed_ms: 1_050,
            issued_ms: 1_000,
            expires_ms: 10_000,
            signed_until_ms: 10_000,
            reader: SourceRecord {
                key_id: self.expected.reader_id,
                point: self.expected.reader_point,
                from_ms: 0,
                until_ms: 10_000,
            },
            root_writer: SourceRecord {
                key_id: key_id(6, &public(1)),
                point: public(1),
                from_ms: 0,
                until_ms: 10_000,
            },
        }
    }
    fn inspect(&self) -> Result<ReviewedContactReader> {
        inspect(&self.unsigned, &self.source(), &self.expected, 1_200)
    }
    fn mutate_manifest(&mut self, at: usize, value: u8) {
        let mut m = self.manifest[..self.manifest.len() - 64].to_vec();
        m[at] = value;
        self.manifest = sign_manifest(&m);
        let n = self.expected.origin.len();
        self.unsigned[40 + n + 56..40 + n + 88].copy_from_slice(&hash(&m));
    }
}

#[test]
fn genuine_root_signs_exact_existing_contact_transcript() {
    let f = Fixture::new();
    let reviewed = f.inspect().unwrap();
    let root = RootSecret::new(Zeroizing::new([1; 32])).unwrap();
    let signed = reviewed.sign(&root, 1_201).unwrap();
    assert_eq!(signed.bytes.len(), f.unsigned.len() + 64);
    assert_eq!(&signed.bytes[..f.unsigned.len()], f.unsigned);
    assert_eq!(signed.digest, hash(&signed.bytes));
    signature_check(
        &public(1),
        &signed.bytes[f.unsigned.len()..],
        DOMAIN,
        &f.unsigned,
    )
    .unwrap();
    assert!(
        signature_check(
            &public(1),
            &signed.bytes[f.unsigned.len()..],
            b"ZTSE/manifest/v2\0",
            &f.unsigned
        )
        .is_err()
    );
}
#[test]
fn reviewed_inputs_and_display_facts_are_owned_copies() {
    let mut f = Fixture::new();
    let reviewed = f.inspect().unwrap();
    let facts = reviewed.facts();
    f.unsigned.fill(0);
    f.manifest.fill(0);
    f.pin.fill(0);
    let mut changed = reviewed.facts();
    changed.origin.clear();
    assert_eq!(reviewed.facts().origin, facts.origin);
    let root = RootSecret::new(Zeroizing::new([1; 32])).unwrap();
    assert!(reviewed.sign(&root, 1_201).is_ok());
}
#[test]
fn unrelated_recovered_root_cannot_sign_review() {
    let f = Fixture::new();
    let root = RootSecret::new(Zeroizing::new([3; 32])).unwrap();
    assert!(f.inspect().unwrap().sign(&root, 1_201).is_err());
}
#[test]
fn signing_refuses_expired_future_and_regressed_time() {
    let f = Fixture::new();
    for now in [0, 1_099, 9_000, u64::MAX] {
        assert!(inspect(&f.unsigned, &f.source(), &f.expected, now).is_err());
    }
    let root = RootSecret::new(Zeroizing::new([1; 32])).unwrap();
    assert!(f.inspect().unwrap().sign(&root, 1_199).is_err());
    assert!(f.inspect().unwrap().sign(&root, 9_000).is_err());
}
#[test]
fn frozen_historical_source_cannot_be_replaced_by_lookup_time() {
    let f = Fixture::new();
    let mut source = f.source();
    source.observed_ms = 1_101;
    assert!(inspect(&f.unsigned, &source, &f.expected, 1_200).is_err());
    source = f.source();
    source.reader.from_ms = 1;
    assert!(inspect(&f.unsigned, &source, &f.expected, 1_200).is_err());
    source = f.source();
    source.signed_until_ms = 9_999;
    assert!(inspect(&f.unsigned, &source, &f.expected, 1_200).is_err());
}
#[test]
fn independent_account_origin_fingerprint_and_reader_must_match() {
    for which in 0..5 {
        let mut f = Fixture::new();
        match which {
            0 => f.expected.account[0] ^= 1,
            1 => f.expected.origin = "https://other.invalid".into(),
            2 => f.expected.fingerprint[0] ^= 1,
            3 => f.expected.reader_id[0] ^= 1,
            _ => f.expected.reader_point = public(3),
        };
        assert!(f.inspect().is_err());
    }
}
#[test]
fn unsigned_canonical_framing_and_signed_range_are_closed() {
    for at in [0, 5, 22, 38, 40] {
        let mut f = Fixture::new();
        f.unsigned[at] ^= 1;
        assert!(f.inspect().is_err());
    }
    let mut f = Fixture::new();
    f.unsigned[6..22].fill(0);
    assert!(f.inspect().is_err());
    let mut f = Fixture::new();
    f.unsigned.push(0);
    assert!(f.inspect().is_err());
    for n in [0_u64, u64::MAX] {
        let mut f = Fixture::new();
        let at = 40 + f.expected.origin.len();
        f.unsigned[at + 16..at + 24].copy_from_slice(&n.to_be_bytes());
        assert!(f.inspect().is_err());
    }
}
#[test]
fn historical_manifest_signature_and_semantic_digest_are_required() {
    let mut f = Fixture::new();
    let last = f.manifest.len() - 1;
    f.manifest[last] ^= 1;
    assert!(f.inspect().is_err());
    let f = Fixture::new();
    let mut source = f.source();
    source.digest[0] ^= 1;
    assert!(inspect(&f.unsigned, &source, &f.expected, 1_200).is_err());
}
#[test]
fn revoked_reader_and_wrong_scope_are_refused_even_if_root_signed() {
    for (at, value) in [(151 + 148, 2), (151 + 131, 8)] {
        let mut f = Fixture::new();
        f.mutate_manifest(at, value);
        assert!(f.inspect().is_err());
    }
}
#[test]
fn root_record_must_cover_full_manifest_and_match_pin() {
    let mut f = Fixture::new();
    f.mutate_manifest(151 + 149 + 148, 2);
    assert!(f.inspect().is_err());
    let mut f = Fixture::new();
    f.mutate_manifest(151 + 149 + 147, 0);
    assert!(f.inspect().is_err());
}
#[test]
fn malformed_extra_records_are_not_ignored() {
    let mut f = Fixture::new();
    let m = &f.manifest[..f.manifest.len() - 64];
    let mut extra = m[..151 + 149].to_vec();
    extra.extend_from_slice(&record(3, 3, 0, 1));
    extra.extend_from_slice(&m[151 + 149..]);
    extra[150] = 3;
    f.manifest = sign_manifest(&extra);
    let at = 40 + f.expected.origin.len();
    f.unsigned[at + 56..at + 88].copy_from_slice(&hash(&extra));
    assert!(f.inspect().is_err());
}
#[test]
fn ordering_point_reuse_and_unknown_record_states_refuse() {
    for (at, value) in [(151, 6), (151 + 148, 3), (151 + 149, 2)] {
        let mut f = Fixture::new();
        f.mutate_manifest(at, value);
        assert!(f.inspect().is_err());
    }
    let mut f = Fixture::new();
    let mut m = f.manifest[..f.manifest.len() - 64].to_vec();
    m[151 + 33..151 + 98].copy_from_slice(&public(1));
    m[151 + 1..151 + 33].copy_from_slice(&key_id(2, &public(1)));
    f.manifest = sign_manifest(&m);
    assert!(f.inspect().is_err());
}
#[test]
fn manifest_count_width_and_generation_are_bounded() {
    for (at, value) in [(150, 0), (150, 65), (28, 2)] {
        let mut f = Fixture::new();
        f.mutate_manifest(at, value);
        assert!(f.inspect().is_err());
    }
    let mut f = Fixture::new();
    f.manifest.push(0);
    assert!(f.inspect().is_err());
}
#[test]
fn independent_until_and_full_source_bounds_are_not_extended() {
    let mut f = Fixture::new();
    f.expected.requested_until_ms = 8_999;
    assert!(f.inspect().is_err());
    let mut f = Fixture::new();
    let at = 40 + f.expected.origin.len();
    f.unsigned[at + 193..at + 201].copy_from_slice(&10_001_u64.to_be_bytes());
    assert!(f.inspect().is_err());
}
