// SPDX-License-Identifier: AGPL-3.0-only
// Real synthetic signatures/HPKE vectors, no production signer or custody.
use super::*;
use crate::{
    contact_reader_statement as reader,
    sealed_manifest::{self, ChainPosition, ManifestTrust},
};
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::Value;
const VECTOR: &str = include_str!("../../../../protocol/v1/contact-content-contract-vectors.json");
fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn data(v: &Value, key: &str) -> Vec<u8> {
    hex(v[key].as_str().unwrap())
}
fn statement(v: &Value, next: bool) -> VerifiedContactReaderStatement {
    let source = &v["reader_statement"];
    let account = data(source, "account_hex").try_into().unwrap();
    let pin = data(source, "expected_root_fingerprint_hex")
        .try_into()
        .unwrap();
    let base = sealed_manifest::verify(
        &data(source, "root_pin_hex"),
        &data(source, "accepted_manifest_hex"),
        &ManifestTrust {
            account_id: account,
            root_fingerprint: pin,
            generation: 1,
            position: ChainPosition::After {
                version: 6,
                digest: [9; 32],
            },
        },
        2000,
    )
    .unwrap();
    let m = if next {
        sealed_manifest::verify(
            &data(source, "root_pin_hex"),
            &data(v, "successor_manifest_hex"),
            &ManifestTrust {
                account_id: account,
                root_fingerprint: pin,
                generation: 1,
                position: ChainPosition::After {
                    version: 7,
                    digest: *base.digest(),
                },
            },
            2002,
        )
        .unwrap()
    } else {
        base
    };
    reader::verify(
        &if next {
            data(v, "successor_statement_hex")
        } else {
            data(source, "statement_hex")
        },
        &m,
        &reader::ExpectedIdentity {
            account_id: &account,
            origin: "https://owner.invalid",
            root_fingerprint: &pin,
        },
        reader::Comparison::DeclaredIssuedMs,
    )
    .unwrap()
}
fn sign(b: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SigningKey::from_bytes((&scalar).into()).unwrap();
    let signature: Signature = key.sign(&[domain, &(b.len() as u32).to_be_bytes(), b].concat());
    [b, signature.normalize_s().to_bytes().as_slice()].concat()
}
struct Fixture {
    v: Value,
    first: VerifiedContactReaderStatement,
    next: VerifiedContactReaderStatement,
    contact: [u8; 16],
    routing: [u8; 32],
}
impl Fixture {
    fn new() -> Self {
        let v = vector();
        Self {
            first: statement(&v, false),
            next: statement(&v, true),
            contact: data(&v, "contact_hex").try_into().unwrap(),
            routing: data(&v, "routing_digest_hex").try_into().unwrap(),
            v,
        }
    }
    fn expected(&self) -> ExpectedContent<'_> {
        ExpectedContent {
            contact: &self.contact,
            routing_digest: &self.routing,
        }
    }
    fn field(&self, key: &str, next: bool) -> VerifiedHistoricalField {
        verify_field(
            &data(&self.v, key),
            if next { &self.next } else { &self.first },
            &self.expected(),
        )
        .unwrap()
    }
    fn mutation(&self, key: &str, next: bool) -> VerifiedHistoricalMutation {
        verify_mutation(
            &data(&self.v, key),
            if next { &self.next } else { &self.first },
            &self.expected(),
            0,
        )
        .unwrap()
    }
    fn changed(&self, m: &UnsignedMutation, next: bool, legacy: u64) -> VerifiedHistoricalMutation {
        verify_mutation(
            &sign(&encode_mutation(m).unwrap(), MUTATION_DOMAIN),
            if next { &self.next } else { &self.first },
            &self.expected(),
            legacy,
        )
        .unwrap()
    }
}
#[test]
fn shared_signed_vectors_hold_exact_hashes_reader_rotation_retention_and_clear() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let replacement = f.field("replacement_notes_hex", true);
    let create = f.mutation("create_hex", false);
    let update = f.mutation("update_hex", true);
    let clear = f.mutation("clear_hex", true);
    assert_eq!(create.digest().as_slice(), data(&f.v, "create_digest_hex"));
    assert_eq!(update.digest().as_slice(), data(&f.v, "update_digest_hex"));
    assert_eq!(clear.digest().as_slice(), data(&f.v, "clear_digest_hex"));
    let first = verify_transition(None, &create, &[&name, &notes]).unwrap();
    let second = verify_transition(Some(&first), &update, &[&replacement]).unwrap();
    let last = verify_transition(Some(&second), &clear, &[]).unwrap();
    assert_eq!(
        second.fields[0]
            .as_ref()
            .unwrap()
            .parsed
            .field
            .reader_generation,
        1
    );
    assert_eq!(
        second.fields[1]
            .as_ref()
            .unwrap()
            .parsed
            .field
            .reader_generation,
        2
    );
    assert!(last.fields[0].is_none());
    assert_eq!(last.fields[1].as_ref().unwrap().digest, replacement.digest);
    assert_eq!(last.kind(), "historical_integrity");
    assert_eq!(format!("{last:?}"), "VerifiedHistoricalTransition { .. }");
    let mut copy = name.parsed();
    copy.bytes.fill(0);
    copy.field.reader.fill(0);
    assert_eq!(name.parsed().bytes(), data(&f.v, "name_hex"));
}
#[test]
fn replacements_are_bounded_distinct_used_and_correct_field_kind() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let replacement = f.field("replacement_notes_hex", true);
    let create = f.mutation("create_hex", false);
    let update = f.mutation("update_hex", true);
    let first = verify_transition(None, &create, &[&name, &notes]).unwrap();
    for replacements in [
        vec![],
        vec![&name],
        vec![&notes],
        vec![&replacement, &replacement],
        vec![&name, &replacement],
        vec![&name, &notes, &replacement],
    ] {
        assert!(verify_transition(Some(&first), &update, &replacements).is_err());
    }
    assert!(verify_transition(None, &update, &[&replacement]).is_err());
    let second = verify_transition(Some(&first), &update, &[&replacement]).unwrap();
    assert!(verify_transition(Some(&second), &f.mutation("clear_hex", true), &[&notes]).is_err());
}
#[test]
fn cleared_or_replaced_old_ciphertext_cannot_reappear_as_retained() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let replacement = f.field("replacement_notes_hex", true);
    let create = f.mutation("create_hex", false);
    let update = f.mutation("update_hex", true);
    let clear = f.mutation("clear_hex", true);
    let first = verify_transition(None, &create, &[&name, &notes]).unwrap();
    let second = verify_transition(Some(&first), &update, &[&replacement]).unwrap();
    let last = verify_transition(Some(&second), &clear, &[]).unwrap();
    let mut resurrect = clear.parsed.mutation.clone();
    resurrect.expected = 3;
    resurrect.revision = 4;
    resurrect.previous_digest = clear.digest;
    resurrect.name = create.parsed.mutation.name.clone();
    assert!(verify_transition(Some(&last), &f.changed(&resurrect, true, 0), &[]).is_err());
    let mut replaced = clear.parsed.mutation.clone();
    replaced.name = update.parsed.mutation.name.clone();
    replaced.notes = create.parsed.mutation.notes.clone();
    assert!(verify_transition(Some(&second), &f.changed(&replaced, true, 0), &[]).is_err());
}
#[test]
fn genuine_signed_wrong_request_successor_and_predecessor_do_not_match_slots() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let create = f.mutation("create_hex", false);
    let update = f.mutation("update_hex", true);
    let first = verify_transition(None, &create, &[&name, &notes]).unwrap();
    let replacement = f.field("replacement_notes_hex", true);
    let mut fork = update.parsed.mutation.clone();
    fork.previous_digest = [7; 32];
    assert!(verify_transition(Some(&first), &f.changed(&fork, true, 0), &[&replacement]).is_err());
    for (revision, request, kind) in [
        (2, [7; 16], 2),
        (1, replacement.parsed.field.request, 2),
        (2, replacement.parsed.field.request, 1),
    ] {
        let mut q = replacement.parsed.field.clone();
        q.revision = revision;
        q.request = request;
        q.kind = kind;
        let verified = verify_field(
            &sign(&encode_field(&q).unwrap(), FIELD_DOMAIN),
            &f.next,
            &f.expected(),
        )
        .unwrap();
        let mut m = update.parsed.mutation.clone();
        m.notes.digest = verified.digest;
        assert!(verify_transition(Some(&first), &f.changed(&m, true, 0), &[&verified]).is_err());
    }
}
#[test]
fn statement_scope_domain_ciphertext_and_lower_history_are_independent_fences() {
    let f = Fixture::new();
    let bytes = data(&f.v, "replacement_notes_hex");
    assert!(verify_field(&bytes, &f.first, &f.expected()).is_err());
    let parsed = parse_field(&bytes).unwrap();
    assert!(
        verify_field(
            &sign(&encode_field(&parsed.field).unwrap(), MUTATION_DOMAIN),
            &f.next,
            &f.expected()
        )
        .is_err()
    );
    let mut wrong = bytes;
    wrong[315] ^= 1;
    assert!(verify_field(&wrong, &f.next, &f.expected()).is_err());
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let replacement = f.field("replacement_notes_hex", true);
    let create = f.mutation("create_hex", false);
    let update = f.mutation("update_hex", true);
    let first = verify_transition(None, &create, &[&name, &notes]).unwrap();
    let second = verify_transition(Some(&first), &update, &[&replacement]).unwrap();
    let mut lower = create.parsed.mutation.clone();
    lower.operation = 2;
    lower.expected = 2;
    lower.revision = 3;
    lower.previous_digest = update.digest;
    lower.notes = update.parsed.mutation.notes.clone();
    assert!(verify_transition(Some(&second), &f.changed(&lower, false, 0), &[]).is_err());
}
#[test]
fn conversion_legacy_generation_zero_rules_and_max_are_closed() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let mut m = f.mutation("create_hex", false).parsed.mutation.clone();
    m.operation = 3;
    m.legacy_generation = 7;
    let conversion = f.changed(&m, false, 7);
    assert!(verify_transition(None, &conversion, &[&name, &notes]).is_ok());
    assert!(verify_mutation(&conversion.parsed.bytes, &f.first, &f.expected(), 6).is_err());
    m.legacy_generation = 0;
    assert!(encode_mutation(&m).is_err());
    m.operation = 1;
    m.legacy_generation = 1;
    assert!(encode_mutation(&m).is_err());
    m.operation = 2;
    m.expected = MAX;
    m.revision = MAX;
    m.previous_digest = [1; 32];
    m.legacy_generation = 0;
    assert!(encode_mutation(&m).is_err());
    let mut original = f.mutation("create_hex", false).parsed.mutation.clone();
    original.name.tag = 0;
    assert!(encode_mutation(&original).is_err());
    original.name = Slot {
        tag: 0,
        revision: 0,
        digest: [0; 32],
    };
    assert!(encode_mutation(&original).is_ok());
}
#[test]
fn accepted_manifest_fork_and_reused_reader_generation_cannot_advance_a_prior_brand() {
    let f = Fixture::new();
    let name = f.field("name_hex", false);
    let notes = f.field("notes_hex", false);
    let create = f.mutation("create_hex", false);
    let prior = verify_transition(None, &create, &[&name, &notes]).unwrap();
    let mut next = create.parsed.mutation.clone();
    next.operation = 2;
    next.expected = 1;
    next.revision = 2;
    next.previous_digest = create.digest;
    assert!(verify_transition(Some(&prior), &f.changed(&next, false, 0), &[]).is_ok());
    let source = &f.v["reader_statement"];
    let pin = data(source, "root_pin_hex");
    let account = data(source, "account_hex").try_into().unwrap();
    let fingerprint = data(source, "expected_root_fingerprint_hex")
        .try_into()
        .unwrap();
    let mut fork = data(source, "accepted_manifest_hex");
    fork.truncate(fork.len() - 64);
    let expiry = number(&fork, 45);
    fork[45..53].copy_from_slice(&(expiry - 1).to_be_bytes());
    let manifest = sealed_manifest::verify(
        &pin,
        &sign(&fork, b"ZTSE/manifest/v2\0"),
        &ManifestTrust {
            account_id: account,
            root_fingerprint: fingerprint,
            generation: 1,
            position: ChainPosition::After {
                version: 6,
                digest: [9; 32],
            },
        },
        2000,
    )
    .unwrap();
    let mut s = f.first.identity().parsed.statement();
    s.manifest_digest = *manifest.digest();
    let fork_statement = reader::verify(
        &sign(
            &reader::encode_unsigned(&s).unwrap(),
            b"ZT/contact-reader/authorization/v1\0",
        ),
        &manifest,
        &reader::ExpectedIdentity {
            account_id: &account,
            origin: "https://owner.invalid",
            root_fingerprint: &fingerprint,
        },
        reader::Comparison::DeclaredIssuedMs,
    )
    .unwrap();
    next.manifest_digest = s.manifest_digest;
    next.statement_digest = fork_statement.identity().digest;
    let fork_mutation = verify_mutation(
        &sign(&encode_mutation(&next).unwrap(), MUTATION_DOMAIN),
        &fork_statement,
        &f.expected(),
        0,
    )
    .unwrap();
    assert!(verify_transition(Some(&prior), &fork_mutation, &[]).is_err());
    let base_digest = f.first.identity().parsed.statement().manifest_digest;
    let accepted = sealed_manifest::verify(
        &pin,
        &data(&f.v, "successor_manifest_hex"),
        &ManifestTrust {
            account_id: account,
            root_fingerprint: fingerprint,
            generation: 1,
            position: ChainPosition::After {
                version: 7,
                digest: base_digest,
            },
        },
        2002,
    )
    .unwrap();
    let mut s = f.next.identity().parsed.statement();
    s.reader_generation = 1;
    let changed_reader = reader::verify(
        &sign(
            &reader::encode_unsigned(&s).unwrap(),
            b"ZT/contact-reader/authorization/v1\0",
        ),
        &accepted,
        &reader::ExpectedIdentity {
            account_id: &account,
            origin: "https://owner.invalid",
            root_fingerprint: &fingerprint,
        },
        reader::Comparison::DeclaredIssuedMs,
    )
    .unwrap();
    assert_ne!(s.reader_id, f.first.identity().parsed.statement().reader_id);
    next.manifest_version = s.manifest_version;
    next.manifest_digest = s.manifest_digest;
    next.statement_digest = changed_reader.identity().digest;
    let swapped = verify_mutation(
        &sign(&encode_mutation(&next).unwrap(), MUTATION_DOMAIN),
        &changed_reader,
        &f.expected(),
        0,
    )
    .unwrap();
    assert!(verify_transition(Some(&prior), &swapped, &[]).is_err());
}
#[test]
fn framing_lengths_membership_zero_bounds_and_low_s_aliases_refuse() {
    let f = Fixture::new();
    let bytes = data(&f.v, "name_hex");
    assert!(parse_field(&bytes[1..]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(parse_field(&trailing).is_err());
    let mut wrong = bytes.clone();
    wrong[311..315].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_field(&wrong).is_err());
    let mut q = parse_field(&bytes).unwrap().field;
    q.encapsulation = [0; 65];
    q.encapsulation[0] = 4;
    assert!(encode_field(&q).is_ok());
    assert!(parse_field(&sign(&encode_field(&q).unwrap(), FIELD_DOMAIN)).is_err());
    let m = data(&f.v, "create_hex");
    assert!(parse_mutation(&m[1..]).is_err());
    let mut trailing = m.clone();
    trailing.push(0);
    assert!(parse_mutation(&trailing).is_err());
    let mut alias = m.clone();
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(order[i]) - i16::from(alias[336 + i]) - borrow;
        alias[336 + i] = diff as u8;
        borrow = i16::from(diff < 0);
    }
    assert!(parse_mutation(&alias).is_err());
}
