// SPDX-License-Identifier: AGPL-3.0-only
//! Cross-client ZT-009 Q6 vector for the manifest identity correction.
//!
//! Manifest authorization identity is `SHA-256(exact_unsigned_bytes)`, not a
//! digest of the signature. Independently generated canonical low-s P-256
//! signatures over the same unsigned manifest must share one semantic digest,
//! while their complete-byte digests differ. The shared public fixture in
//! `protocol/v1/vectors` is also consumed by the TypeScript suite, which must
//! reach identical digests and accept/reject verdicts. Test-only material.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("../../../protocol/v1/vectors/ztse-manifest-identity-01.json");
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("committed manifest identity vector")
}

fn hex_field(value: &Value, name: &str) -> Vec<u8> {
    let text = value[name].as_str().expect("hex field");
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit"))
        .collect()
}

fn transcript(unsigned: &[u8]) -> Vec<u8> {
    [
        b"ZTSE/manifest/v2\0".as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        unsigned,
    ]
    .concat()
}

/// Scalar-range and low-s policy must pass before any ECDSA verification.
fn strict_raw_ranges(raw: &[u8]) -> Result<[u8; 64], &'static str> {
    let raw: [u8; 64] = raw.try_into().map_err(|_| "signature width")?;
    let r: [u8; 32] = raw[..32].try_into().expect("r half");
    let s: [u8; 32] = raw[32..].try_into().expect("s half");
    if r == [0_u8; 32] || r >= ORDER || s == [0_u8; 32] || s >= ORDER {
        return Err("signature scalar range");
    }
    if s > HALF_ORDER {
        return Err("high-s signature");
    }
    Ok(raw)
}

/// Strict DER-to-raw conversion: rejects nonminimal, negative, zero, overflow,
/// long-form, mismatched and trailing encodings without normalizing anything.
fn der_to_raw(input: &[u8]) -> Result<[u8; 64], &'static str> {
    if input.len() < 8 || input[0] != 0x30 {
        return Err("der sequence tag");
    }
    if input[1] >= 0x80 {
        return Err("der long-form length");
    }
    if input.len() != 2 + usize::from(input[1]) {
        return Err("der sequence length");
    }
    let mut scalars: Vec<[u8; 32]> = Vec::with_capacity(2);
    let mut at = 2_usize;
    for _ in 0..2 {
        if input.len() < at + 2 || input[at] != 0x02 {
            return Err("der integer tag");
        }
        let length = input[at + 1];
        if length >= 0x80 || length == 0 {
            return Err("der integer length");
        }
        let end = at + 2 + usize::from(length);
        if end > input.len() {
            return Err("der integer truncated");
        }
        let mut value = &input[at + 2..end];
        if value[0] & 0x80 != 0 {
            return Err("negative der integer");
        }
        if value[0] == 0 {
            if value.len() == 1 {
                return Err("zero der integer");
            }
            if value[1] & 0x80 == 0 {
                return Err("nonminimal der integer");
            }
            value = &value[1..];
        }
        if value.len() > 32 {
            return Err("der integer width");
        }
        let mut fixed = [0_u8; 32];
        fixed[32 - value.len()..].copy_from_slice(value);
        scalars.push(fixed);
        at = end;
    }
    if at != input.len() {
        return Err("der trailing content");
    }
    let mut raw = [0_u8; 64];
    raw[..32].copy_from_slice(&scalars[0]);
    raw[32..].copy_from_slice(&scalars[1]);
    strict_raw_ranges(&raw)
}

fn strict_accept(root: &VerifyingKey, signed: &[u8], raw: &[u8]) -> Result<(), &'static str> {
    let raw = strict_raw_ranges(raw)?;
    let signature = Signature::from_slice(&raw).map_err(|_| "signature scalar")?;
    root.verify(signed, &signature)
        .map_err(|_| "owner signature")
}

/// Binds the fixture to the Manifest02 grammar without repeating the full
/// profile validator in `draft02_manifest_vector.rs`.
fn structural_identity(unsigned: &[u8], root: &[u8], owner_id: &[u8]) {
    assert_eq!(unsigned.len(), 300, "single-record unsigned manifest");
    assert_eq!(&unsigned[..5], b"ZTMA\x02");
    assert_ne!(&unsigned[5..21], &[0_u8; 16][..], "account id");
    assert_eq!(unsigned[150], 1, "one key record");
    assert_eq!(unsigned[151], 6, "owner-root record");
    assert_eq!(&unsigned[85..150], root, "header root point");
    assert_eq!(&unsigned[184..249], root, "record root point");
    let expected = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], root].concat());
    assert_eq!(&unsigned[152..184], &expected[..], "owner key id");
    assert_eq!(&unsigned[152..184], owner_id, "fixture owner id");
    VerifyingKey::from_sec1_bytes(root).expect("root point on curve");
}

#[test]
fn two_low_s_signatures_share_one_semantic_manifest_identity() {
    let vector = vector();
    let unsigned = hex_field(&vector, "unsignedHex");
    let root = hex_field(&vector, "rootPublicPointHex");
    structural_identity(&unsigned, &root, &hex_field(&vector, "ownerIdHex"));
    let signed = transcript(&unsigned);
    let key = VerifyingKey::from_sec1_bytes(&root).expect("root point");

    let mut complete_digests: Vec<[u8; 32]> = Vec::new();
    let mut raws = Vec::new();
    for entry in vector["signatures"].as_array().expect("two signatures") {
        assert_eq!(entry["canonicalLowS"], true);
        assert_eq!(entry["verifies"], true);
        let raw = hex_field(entry, "rawHex");
        strict_accept(&key, &signed, &raw)
            .unwrap_or_else(|error| panic!("canonical low-s signature rejected: {error}"));
        let complete = Sha256::digest([unsigned.as_slice(), raw.as_slice()].concat());
        assert_eq!(
            &complete[..],
            &hex_field(entry, "completeSignedDigestHex")[..],
            "complete-byte digest must match the fixture"
        );
        complete_digests.push(complete.into());
        raws.push(raw);
    }
    assert_ne!(
        raws[0], raws[1],
        "independently generated signatures differ"
    );
    assert_ne!(
        complete_digests[0], complete_digests[1],
        "complete-byte identity would fork on signature randomness"
    );
    assert_eq!(
        Sha256::digest(&unsigned).as_slice(),
        hex_field(&vector, "semanticDigestHex"),
        "one semantic identity digest for both signatures"
    );
}

#[test]
fn high_s_twin_verifies_only_without_the_strict_low_s_rule() {
    let vector = vector();
    let unsigned = hex_field(&vector, "unsignedHex");
    let root = hex_field(&vector, "rootPublicPointHex");
    let twin = &vector["highSTwinOfA"];
    let high = hex_field(twin, "rawHex");
    assert_eq!(twin["verifiesUnderPlainEcdsa"], true);
    assert_eq!(twin["strictVerdict"], "reject");
    let key = VerifyingKey::from_sec1_bytes(&root).expect("root point");
    key.verify(
        &transcript(&unsigned),
        &Signature::from_slice(&high).unwrap(),
    )
    .expect("plain ECDSA accepts the malleable twin");
    assert_eq!(
        strict_accept(&key, &transcript(&unsigned), &high).unwrap_err(),
        "high-s signature",
        "the strict rule must reject the twin before verification"
    );
}

#[test]
fn strict_der_conversion_rejects_every_malformed_encoding() {
    let vector = vector();
    let unsigned = hex_field(&vector, "unsignedHex");
    let root = hex_field(&vector, "rootPublicPointHex");
    let signed = transcript(&unsigned);
    let key = VerifyingKey::from_sec1_bytes(&root).expect("root point");
    let signature_a = hex_field(&vector["signatures"][0], "rawHex");

    for case in vector["derCases"].as_array().expect("der cases") {
        let name = case["name"].as_str().expect("case name");
        let der = hex_field(case, "derHex");
        match case["expected"].as_str().expect("case verdict") {
            "accept" => {
                let raw = der_to_raw(&der)
                    .unwrap_or_else(|error| panic!("case {name} must convert: {error}"));
                assert_eq!(raw.as_slice(), signature_a, "case {name} round trip");
                key.verify(&signed, &Signature::from_slice(&raw).unwrap())
                    .unwrap_or_else(|error| panic!("case {name} must verify: {error}"));
            }
            "reject" => {
                assert!(der_to_raw(&der).is_err(), "case {name} must be rejected");
            }
            other => panic!("unknown fixture verdict {other}"),
        }
    }
}

#[test]
fn mutated_unsigned_field_changes_identity_and_fails_verification() {
    let vector = vector();
    let unsigned = hex_field(&vector, "unsignedHex");
    let root = hex_field(&vector, "rootPublicPointHex");
    let mutation = &vector["mutatedUnsigned"];
    let mutated = hex_field(mutation, "unsignedHex");
    assert_eq!(mutation["signatureAVerifies"], false);
    assert_eq!(
        mutation["field"],
        "keyset_version u64 at offset 29, byte 36: 1 -> 2"
    );
    assert_ne!(unsigned, mutated);
    assert_eq!(
        Sha256::digest(&mutated).as_slice(),
        hex_field(mutation, "semanticDigestHex")
    );
    assert_ne!(
        hex_field(mutation, "semanticDigestHex"),
        hex_field(&vector, "semanticDigestHex"),
        "a changed unsigned field is a different manifest identity"
    );
    let key = VerifyingKey::from_sec1_bytes(&root).expect("root point");
    let signature_a = hex_field(&vector["signatures"][0], "rawHex");
    key.verify(
        &transcript(&mutated),
        &Signature::from_slice(&signature_a).unwrap(),
    )
    .expect_err("signature over the original bytes must not cover the mutation");
}
