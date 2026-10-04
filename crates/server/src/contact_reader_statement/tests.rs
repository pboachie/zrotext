// SPDX-License-Identifier: AGPL-3.0-only
// Public synthetic vectors and test-only root scalar; no production custody.
use super::*;
use crate::sealed_manifest::{self, ChainPosition, ManifestTrust};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::Value;

const VECTOR: &str = include_str!("../../../../protocol/v1/contact-reader-statement-vectors.json");
fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn field(v: &Value, name: &str) -> Vec<u8> {
    hex(v[name].as_str().unwrap())
}
fn root() -> SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    SigningKey::from_bytes((&scalar).into()).unwrap()
}
fn signed(unsigned: &[u8], domain: &[u8]) -> Vec<u8> {
    let signature: Signature =
        root().sign(&[domain, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat());
    [unsigned, signature.normalize_s().to_bytes().as_slice()].concat()
}
fn manifest(v: &Value, bytes: &[u8]) -> VerifiedManifest {
    sealed_manifest::verify(
        &field(v, "root_pin_hex"),
        bytes,
        &ManifestTrust {
            account_id: field(v, "account_hex").try_into().unwrap(),
            root_fingerprint: field(v, "expected_root_fingerprint_hex")
                .try_into()
                .unwrap(),
            generation: 1,
            position: ChainPosition::After {
                version: 6,
                digest: [9; 32],
            },
        },
        2000,
    )
    .unwrap()
}
fn expected<'a>(account: &'a [u8; 16], fingerprint: &'a [u8; 32]) -> ExpectedIdentity<'a> {
    ExpectedIdentity {
        account_id: account,
        origin: "https://owner.invalid",
        root_fingerprint: fingerprint,
    }
}
fn check(bytes: &[u8], m: &VerifiedManifest) -> Result<VerifiedContactReaderStatement, Error> {
    let v = vector();
    let account = field(&v, "account_hex").try_into().unwrap();
    let fingerprint = field(&v, "expected_root_fingerprint_hex")
        .try_into()
        .unwrap();
    verify(
        bytes,
        m,
        &expected(&account, &fingerprint),
        Comparison::DeclaredIssuedMs,
    )
}

#[test]
fn shared_ts_vector_exact_signature_digest_and_owned_historical_identity() {
    let v = vector();
    let bytes = field(&v, "statement_hex");
    let m = manifest(&v, &field(&v, "accepted_manifest_hex"));
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.unsigned(), field(&v, "unsigned_hex"));
    assert_eq!(
        encode_unsigned(&parsed.statement()).unwrap(),
        parsed.unsigned()
    );
    let verified = check(&bytes, &m).unwrap();
    assert_eq!(verified.kind(), "historical_integrity");
    assert_eq!(
        verified.identity().digest.as_slice(),
        field(&v, "statement_digest_hex")
    );
    let mut identity = verified.identity();
    identity.parsed.bytes.fill(0);
    identity.root_point.fill(0);
    assert_eq!(verified.identity().parsed.bytes(), bytes);
    assert_eq!(
        format!("{verified:?}"),
        "VerifiedContactReaderStatement { .. }"
    );
    // This result has no clock/installation API: later wall time cannot turn it
    // into permission, and historical consistency deliberately remains intact.
    assert_eq!(verified.identity().parsed.statement().until_ms, 3000);
}

#[test]
fn canonical_lengths_scalars_generation_and_origin_aliases_refuse() {
    let v = vector();
    let bytes = field(&v, "statement_hex");
    for malformed in [&bytes[..bytes.len() - 1], &bytes[1..], &[0; 818]] {
        assert!(parse(malformed).is_err());
    }
    for offset in [0, 4, 5] {
        let mut altered = bytes.clone();
        altered[offset] ^= 1;
        assert!(parse(&altered).is_err());
    }
    let mut zero_sig = bytes.clone();
    let end = zero_sig.len();
    zero_sig[end - 64..].fill(0);
    assert!(parse(&zero_sig).is_err());
    let mut high = bytes.clone();
    let start = high.len() - 32;
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(order[i]) - i16::from(high[start + i]) - borrow;
        high[start + i] = diff as u8;
        borrow = i16::from(diff < 0);
    }
    assert!(parse(&high).is_err());
    let s = parse(&bytes).unwrap().statement();
    for alias in [
        "http://owner.invalid",
        "https://OWNER.invalid",
        "https://owner.invalid:443",
        "https://owner.invalid/",
        "https://owner.invalid?q=1",
        "https://owner.invalid#x",
    ] {
        let mut bad = s.clone();
        bad.origin = alias.to_owned();
        assert!(encode_unsigned(&bad).is_err());
    }
    for n in [0, 2, i64::MAX as u64 + 1] {
        let mut bad = s.clone();
        bad.trust_generation = n;
        assert!(encode_unsigned(&bad).is_err());
    }
    for (issued, until) in [
        (0, 3000),
        (2000, 2000),
        (2000, 86_402_001),
        (2000, i64::MAX as u64 + 1),
    ] {
        let mut bad = s.clone();
        bad.issued_ms = issued;
        bad.until_ms = until;
        assert!(encode_unsigned(&bad).is_err());
    }
}

#[test]
fn off_curve_and_key_alias_refuse_after_framing_only_encode() {
    let v = vector();
    let mut s = parse(&field(&v, "statement_hex")).unwrap().statement();
    s.reader_point = [0; 65];
    s.reader_point[0] = 4;
    assert!(parse(&signed(&encode_unsigned(&s).unwrap(), DOMAIN)).is_err());
    s = parse(&field(&v, "statement_hex")).unwrap().statement();
    s.reader_id = [8; 32];
    assert!(parse(&signed(&encode_unsigned(&s).unwrap(), DOMAIN)).is_err());
}

#[test]
fn genuinely_signed_wrong_identity_domain_bounds_and_signature_refuse() {
    let v = vector();
    let bytes = field(&v, "statement_hex");
    let s = parse(&bytes).unwrap().statement();
    let m = manifest(&v, &field(&v, "accepted_manifest_hex"));
    let mut changes = vec![];
    let mut bad = s.clone();
    bad.account_id = [8; 16];
    changes.push(bad);
    let mut bad = s.clone();
    bad.origin = "https://other.invalid".into();
    changes.push(bad);
    let mut bad = s.clone();
    bad.manifest_version += 1;
    changes.push(bad);
    let mut bad = s.clone();
    bad.manifest_digest = [8; 32];
    changes.push(bad);
    let mut bad = s.clone();
    bad.root_fingerprint = [8; 32];
    changes.push(bad);
    let mut bad = s.clone();
    bad.issued_ms = 999;
    changes.push(bad);
    let mut bad = s.clone();
    bad.until_ms = 3_602_001;
    changes.push(bad);
    for bad in changes {
        assert!(check(&signed(&encode_unsigned(&bad).unwrap(), DOMAIN), &m).is_err());
    }
    assert!(
        check(
            &signed(&encode_unsigned(&s).unwrap(), b"ZTSE/manifest/v2\0"),
            &m
        )
        .is_err()
    );
    let mut altered = bytes;
    let end = altered.len();
    altered[end - 1] ^= 1;
    assert!(check(&altered, &m).is_err());
    assert!(
        verify(
            &field(&v, "statement_hex"),
            &m,
            &expected(&s.account_id, &[8; 32]),
            Comparison::DeclaredIssuedMs
        )
        .is_err()
    );
}

#[test]
fn actual_signed_reader_record_expiry_from_and_retirement_bind_declared_history() {
    let v = vector();
    let mut manifest_bytes = field(&v, "accepted_manifest_hex");
    let original = parse(&field(&v, "statement_hex")).unwrap().statement();
    // Maintained manifest grammar: 151-byte header, 149-byte sorted records.
    let reader = 151 + 149;
    for (from, until) in [(1000u64, 2500u64), (2001, 3_602_000)] {
        manifest_bytes[reader + 132..reader + 140].copy_from_slice(&from.to_be_bytes());
        manifest_bytes[reader + 140..reader + 148].copy_from_slice(&until.to_be_bytes());
        let unsigned_end = manifest_bytes.len() - 64;
        let signed_manifest = signed(&manifest_bytes[..unsigned_end], b"ZTSE/manifest/v2\0");
        let m = manifest(&v, &signed_manifest);
        let mut s = original.clone();
        s.manifest_digest = *m.digest();
        assert!(check(&signed(&encode_unsigned(&s).unwrap(), DOMAIN), &m).is_err());
        if from == 1000 {
            s.until_ms = until;
            assert!(check(&signed(&encode_unsigned(&s).unwrap(), DOMAIN), &m).is_ok());
            s.issued_ms = until;
            s.until_ms = until + 1;
            assert!(check(&signed(&encode_unsigned(&s).unwrap(), DOMAIN), &m).is_err());
        }
    }
    let m = manifest(&v, &field(&v, "accepted_manifest_hex"));
    for ms in [0, i64::MAX as u64 + 1] {
        assert!(
            m.account_archive_statement_records(&original.reader_id, ms)
                .is_err()
        );
    }
}

#[test]
fn genuinely_accepted_replacement_reader_does_not_make_retired_reader_valid() {
    let v = vector();
    let bytes = field(&v, "accepted_manifest_hex");
    let mut records: Vec<Vec<u8>> = bytes[151..bytes.len() - 64]
        .chunks_exact(149)
        .map(<[u8]>::to_vec)
        .collect();
    records[1][148] = 2;
    let mut scalar = [0; 32];
    scalar[31] = 5;
    let alternate = SigningKey::from_bytes((&scalar).into()).unwrap();
    let point = alternate.verifying_key().to_sec1_point(false);
    let mut replacement = records[1].clone();
    replacement[148] = 1;
    let id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[0, 16], point.as_bytes()].concat());
    replacement[1..33].copy_from_slice(&id);
    replacement[33..98].copy_from_slice(point.as_bytes());
    records.push(replacement);
    records.sort_by(|a, b| a[..33].cmp(&b[..33]));
    let mut unsigned = bytes[..151].to_vec();
    unsigned[150] = 5;
    for record in records {
        unsigned.extend_from_slice(&record);
    }
    let m = manifest(&v, &signed(&unsigned, b"ZTSE/manifest/v2\0"));
    let mut s = parse(&field(&v, "statement_hex")).unwrap().statement();
    s.manifest_digest = *m.digest();
    assert!(check(&signed(&encode_unsigned(&s).unwrap(), DOMAIN), &m).is_err());
}

#[test]
fn actual_verified_second_generation_cannot_enter_genesis_only_statement_inspection() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../sdk/typescript/test/vectors/draft02-rotation.json"
    ))
    .unwrap();
    let b64 = |name: &str| STANDARD.decode(v[name].as_str().unwrap()).unwrap();
    let pin = b64("new_root_pin_b64");
    let m = sealed_manifest::verify(
        &pin,
        &b64("new_manifest_b64"),
        &ManifestTrust {
            account_id: pin[5..21].try_into().unwrap(),
            root_fingerprint: b64("new_root_fingerprint_b64").try_into().unwrap(),
            generation: 2,
            position: ChainPosition::Genesis {
                anchor_digest: b64("transition_anchor_digest_b64").try_into().unwrap(),
            },
        },
        v["now_ms"].as_u64().unwrap(),
    )
    .unwrap();
    let reader: [u8; 32] = b64("new_manifest_b64")[151 + 149 + 1..151 + 149 + 33]
        .try_into()
        .unwrap();
    assert!(
        m.account_archive_statement_records(&reader, v["now_ms"].as_u64().unwrap())
            .is_err()
    );
}
