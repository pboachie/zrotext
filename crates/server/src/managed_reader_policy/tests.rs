// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic software signatures only; no configured issuer or custody evidence.
use super::*;
use crate::sealed_manifest::{self, ChainPosition, ManifestTrust};
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn field(v: &Value, k: &str) -> Vec<u8> {
    hex(v[k].as_str().unwrap())
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/managed-reader-policy-vectors.json"
    ))
    .unwrap()
}
fn signer(n: u8) -> SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = n;
    SigningKey::from_bytes((&scalar).into()).unwrap()
}
fn sign(n: u8, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let s: Signature = signer(n).sign(&transcript(domain, bytes));
    s.normalize_s().to_bytes().to_vec()
}
struct Fixture {
    policy: Vec<u8>,
    enrollment: Vec<u8>,
    esig: Vec<u8>,
    attestation: Vec<u8>,
    isig: Vec<u8>,
    pin: Vec<u8>,
    fingerprint: [u8; 32],
    account: [u8; 16],
    archive: [u8; 32],
    manifest: VerifiedManifest,
    expected_policy: Policy,
    expected_policy_digest: [u8; 32],
    expected: ExpectedEnrollment,
}
impl Fixture {
    fn new() -> Self {
        let v = vector();
        let account = field(&v, "account_hex").try_into().unwrap();
        let fingerprint = field(&v, "expected_root_fingerprint_hex")
            .try_into()
            .unwrap();
        let pin = field(&v, "root_pin_hex");
        let manifest = sealed_manifest::verify(
            &pin,
            &field(&v, "accepted_manifest_hex"),
            &ManifestTrust {
                account_id: account,
                root_fingerprint: fingerprint,
                generation: 1,
                position: ChainPosition::After {
                    version: v["accepted_previous_version"]
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap(),
                    digest: field(&v, "accepted_previous_digest_hex")
                        .try_into()
                        .unwrap(),
                },
            },
            2000,
        )
        .unwrap();
        let policy = field(&v, "policy_hex");
        let enrollment = field(&v, "enrollment_hex");
        let e = decode_enrollment(&enrollment).unwrap();
        let expected = ExpectedEnrollment {
            id: e.id,
            owner_user: e.owner_user,
            owner_session: e.owner_session,
            approval: e.approval,
            reader: e.reader,
            reader_generation: e.reader_generation,
            reader_point: e.reader_point,
            workload: e.workload,
            auth_point: e.auth_point,
            runtime: e.runtime,
            recipient_from_ms: e.recipient_from_ms,
            recipient_until_ms: e.recipient_until_ms,
        };
        Self {
            expected_policy: decode_policy(&policy).unwrap(),
            expected_policy_digest: policy_digest(&policy).unwrap(),
            policy,
            enrollment,
            esig: field(&v, "enrollment_signature_hex"),
            attestation: field(&v, "attestation_hex"),
            isig: field(&v, "attestation_signature_hex"),
            pin,
            fingerprint,
            account,
            archive: field(&v, "archive_key_id_hex").try_into().unwrap(),
            manifest,
            expected,
        }
    }
    fn check(&self, now: u64) -> Result<VerifiedSignedEvidence, Error> {
        verify_signed_evidence(
            &Evidence {
                policy: &self.policy,
                enrollment: &self.enrollment,
                enrollment_signature: &self.esig,
                attestation: &self.attestation,
                attestation_signature: &self.isig,
            },
            &ExpectedPolicy {
                account: &self.account,
                origin: &self.expected_policy.origin,
                id: &self.expected_policy.id,
                version: self.expected_policy.version,
                digest: &self.expected_policy_digest,
            },
            &AcceptedHistory {
                manifest: &self.manifest,
                pin: &self.pin,
                account: &self.account,
                compared_fingerprint: &self.fingerprint,
                archive_key_id: &self.archive,
                trusted_now_ms: now,
            },
            &self.expected,
        )
    }
    fn replace_attestation(&mut self, i: &Attestation) {
        self.attestation = encode_attestation(i).unwrap();
        self.isig = sign(11, ATTESTATION, &self.attestation);
        let mut e = decode_enrollment(&self.enrollment).unwrap();
        e.evidence_digest = attestation_digest(&self.attestation).unwrap();
        self.replace_enrollment(&e);
    }
    fn replace_enrollment(&mut self, e: &Enrollment) {
        self.enrollment = encode_enrollment(e).unwrap();
        self.esig = sign(1, ENROLLMENT, &self.enrollment);
    }
}

#[test]
fn shared_signed_vector_binds_real_history_and_returns_copied_metadata_only() {
    let f = Fixture::new();
    let v = vector();
    let proof = f.check(2000).unwrap();
    assert_eq!(proof.kind(), "cryptographic_signed_evidence");
    let mut identity = proof.identity();
    for (actual, name) in [
        (identity.policy_digest, "policy_digest_hex"),
        (identity.enrollment_digest, "enrollment_digest_hex"),
        (identity.attestation_digest, "attestation_digest_hex"),
    ] {
        assert_eq!(actual.as_slice(), field(&v, name));
    }
    assert_ne!(
        identity.attestation_digest,
        identity.attestation.raw_evidence_digest
    );
    assert_eq!(
        encode_policy(&decode_policy(&f.policy).unwrap()).unwrap(),
        f.policy
    );
    assert_eq!(
        encode_enrollment(&identity.enrollment).unwrap(),
        f.enrollment
    );
    assert_eq!(
        encode_attestation(&identity.attestation).unwrap(),
        f.attestation
    );
    identity.enrollment.reader_point.fill(0);
    identity.attestation.raw_evidence_digest.fill(0);
    assert_ne!(proof.identity().enrollment.reader_point, [0; 65]);
    assert_eq!(format!("{proof:?}"), "VerifiedSignedEvidence { .. }");
    assert_eq!(format!("{:?}", proof.identity()), "EvidenceIdentity { .. }");
}

#[test]
fn shared_mutations_cannot_reinterpret_any_signed_or_pinned_identity() {
    for mutation in vector()["negative_mutations"].as_array().unwrap() {
        let mut f = Fixture::new();
        let target = match mutation["target"].as_str().unwrap() {
            "policy" => &mut f.policy,
            "enrollment" => &mut f.enrollment,
            "attestation" => &mut f.attestation,
            _ => panic!("fixture target"),
        };
        target[mutation["offset"].as_u64().unwrap() as usize] ^=
            mutation["xor"].as_u64().unwrap() as u8;
        assert!(f.check(2000).is_err());
    }
}

#[test]
fn genuine_signatures_do_not_override_independent_intent_or_attestation_binding() {
    for field in 0..10 {
        let mut f = Fixture::new();
        let mut e = decode_enrollment(&f.enrollment).unwrap();
        match field {
            0 => e.owner_user[0] ^= 1,
            1 => e.owner_session[0] ^= 1,
            2 => e.approval[0] ^= 1,
            3 => e.id[0] ^= 1,
            4 => e.reader[0] ^= 1,
            5 => e.reader_generation += 1,
            6 => e.workload[0] ^= 1,
            7 => e.runtime[0] ^= 1,
            8 => e.predecessor_digest[0] ^= 1,
            _ => e.successor_version += 1,
        }
        // All alterations except successor framing receive a genuine root signature.
        if field == 9 {
            assert!(encode_enrollment(&e).is_err());
            continue;
        }
        f.replace_enrollment(&e);
        assert!(f.check(2000).is_err());
    }
    for field in 0..6 {
        let mut f = Fixture::new();
        let mut i = decode_attestation(&f.attestation).unwrap();
        match field {
            0 => i.account[0] ^= 1,
            1 => i.workload[0] ^= 1,
            2 => i.runtime[0] ^= 1,
            3 => i.policy_version += 1,
            4 => i.assurance = 1,
            _ => i.auth_key_id[0] ^= 1,
        }
        // Genuine issuer and root signatures, including the new semantic evidence hash.
        f.replace_attestation(&i);
        assert!(f.check(2000).is_err());
    }
}

#[test]
fn unrelated_valid_pin_fingerprint_archive_or_clock_cannot_supply_root_intervals() {
    let mut f = Fixture::new();
    f.fingerprint[0] ^= 1;
    assert!(f.check(2000).is_err());
    let mut f = Fixture::new();
    f.pin[29..].copy_from_slice(&f.expected.auth_point);
    assert!(f.check(2000).is_err());
    let mut f = Fixture::new();
    f.archive = f.expected_policy.issuer_key_id;
    assert!(f.check(2000).is_err());
    for now in [0, 999, 1000, 1999, 2100, 3500, 3_602_001, u64::MAX] {
        assert!(Fixture::new().check(now).is_err());
    }
    let mut f = Fixture::new();
    let mut i = decode_attestation(&f.attestation).unwrap();
    i.expires_ms = 4001;
    f.replace_attestation(&i);
    assert!(f.check(2000).is_err());
}

#[test]
fn widths_tags_key_purpose_curves_origins_runtime_order_and_integer_caps_refuse() {
    let f = Fixture::new();
    for original in [&f.policy, &f.enrollment, &f.attestation] {
        for count in [0, 1, 5, original.len() - 1] {
            let candidate = &original[..count];
            assert!(decode_policy(candidate).is_err());
            assert!(decode_enrollment(candidate).is_err());
            assert!(decode_attestation(candidate).is_err());
        }
        let mut extra = original.clone();
        extra.push(0);
        assert!(decode_policy(&extra).is_err());
        assert!(decode_enrollment(&extra).is_err());
        assert!(decode_attestation(&extra).is_err());
    }
    for origin in [
        "https://OWNER.invalid",
        "https://owner.invalid/",
        "https://owner.invalid\n",
        "https://owner.invalid:443",
        "http://owner.invalid",
    ] {
        let mut p = f.expected_policy.clone();
        p.origin = origin.into();
        assert!(encode_policy(&p).is_err());
    }
    let mut p = f.expected_policy.clone();
    p.runtimes.push(p.runtimes[0].clone());
    assert!(encode_policy(&p).is_err());
    for version in [0, u64::MAX] {
        let mut p = f.expected_policy.clone();
        p.version = version;
        assert!(encode_policy(&p).is_err());
    }
    let mut p = f.expected_policy.clone();
    p.issuer_point.fill(0);
    assert!(encode_policy(&p).is_err());
    let mut e = decode_enrollment(&f.enrollment).unwrap();
    e.auth_key_id = e.reader_key_id;
    assert!(encode_enrollment(&e).is_err());
    let mut e = decode_enrollment(&f.enrollment).unwrap();
    e.reader_point = e.auth_point;
    e.reader_key_id = key_id(3, &e.reader_point);
    assert!(encode_enrollment(&e).is_err());
    for size in [0, 17] {
        let mut p = f.expected_policy.clone();
        p.runtimes = vec![p.runtimes[0].clone(); size];
        assert!(encode_policy(&p).is_err());
    }
}

#[test]
fn maximum_runtime_count_and_canonical_origin_are_real_positive_controls() {
    let mut f = Fixture::new();
    let mut p = f.expected_policy.clone();
    p.runtimes = (1..=16)
        .map(|n| Runtime {
            id: [n; 16],
            evidence_contract: [n; 32],
            assurance: 0,
        })
        .collect();
    p.origin = "https://subdomain.owner.invalid".into();
    let bytes = encode_policy(&p).unwrap();
    assert_eq!(bytes.len(), 228 + p.origin.len() + 49 * 16);
    assert_eq!(decode_policy(&bytes).unwrap(), p);
    f.expected_policy.minimum_assurance = 1;
    assert!(encode_policy(&f.expected_policy).is_err());
}

#[test]
fn high_s_foreign_signature_domain_and_extra_signature_bytes_refuse() {
    for enrollment in [false, true] {
        let mut f = Fixture::new();
        let raw = if enrollment { &mut f.esig } else { &mut f.isig };
        let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let mut borrow = 0i16;
        for at in (0..32).rev() {
            let difference = i16::from(order[at]) - i16::from(raw[32 + at]) - borrow;
            raw[32 + at] = difference as u8;
            borrow = i16::from(difference < 0);
        }
        assert!(f.check(2000).is_err());
    }
    let mut f = Fixture::new();
    f.isig = sign(1, ATTESTATION, &f.attestation);
    assert!(f.check(2000).is_err());
    let mut f = Fixture::new();
    f.esig = sign(1, POLICY, &f.enrollment);
    assert!(f.check(2000).is_err());
    let mut f = Fixture::new();
    f.isig.push(0);
    assert!(f.check(2000).is_err());
}
