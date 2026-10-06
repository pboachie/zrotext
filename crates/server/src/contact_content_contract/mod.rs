// SPDX-License-Identifier: AGPL-3.0-only
//! Pure historical field/mutation integrity. No authority, storage or private-key operation.
use crate::contact_reader_statement::{StatementIdentity, VerifiedContactReaderStatement};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
pub type Error = &'static str;
const FIELD_DOMAIN: &[u8] = b"ZT/contact-field/commitment/v1\0";
const MUTATION_DOMAIN: &[u8] = b"ZT/contact-field/mutation/v1\0";
const MAX: u64 = i64::MAX as u64;

#[derive(Clone, PartialEq, Eq)]
pub struct UnsignedField {
    pub kind: u8,
    pub account: [u8; 16],
    pub contact: [u8; 16],
    pub revision: u64,
    pub generation: u64,
    pub manifest_version: u64,
    pub reader_generation: u64,
    pub reader: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub routing_digest: [u8; 32],
    pub request: [u8; 16],
    pub writer: [u8; 32],
    pub encapsulation: [u8; 65],
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Slot {
    pub tag: u8,
    pub revision: u64,
    pub digest: [u8; 32],
}
impl Slot {
    fn validate(&self, revision: u64) -> Result<(), Error> {
        if self.revision > MAX || self.revision > revision {
            return Err("content slot revision");
        }
        match self.tag {
            0 if self.revision == 0 && self.digest == [0; 32] => Ok(()),
            1 if self.revision > 0 && self.digest != [0; 32] => Ok(()),
            _ => Err("content slot"),
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct UnsignedMutation {
    pub operation: u8,
    pub account: [u8; 16],
    pub contact: [u8; 16],
    pub expected: u64,
    pub revision: u64,
    pub request: [u8; 16],
    pub previous_digest: [u8; 32],
    pub generation: u64,
    pub manifest_version: u64,
    pub manifest_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub routing_digest: [u8; 32],
    pub legacy_generation: u64,
    pub name: Slot,
    pub notes: Slot,
}
fn positive(n: u64) -> Result<(), Error> {
    if n == 0 || n > MAX {
        Err("content integer")
    } else {
        Ok(())
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
/// Public unsigned framing only. Does not attest curve membership or trust.
pub fn encode_field(f: &UnsignedField) -> Result<Vec<u8>, Error> {
    for n in [
        f.revision,
        f.generation,
        f.manifest_version,
        f.reader_generation,
    ] {
        positive(n)?;
    }
    if f.generation != 1
        || f.account == [0; 16]
        || f.contact == [0; 16]
        || f.request == [0; 16]
        || [
            f.reader,
            f.manifest_digest,
            f.statement_digest,
            f.routing_digest,
            f.writer,
        ]
        .contains(&[0; 32])
        || f.encapsulation[0] != 4
        || !matches!(f.kind, 1 | 2)
        || f.ciphertext.len() < 17
        || f.ciphertext.len() > if f.kind == 1 { 272 } else { 2064 }
    {
        return Err("content field framing");
    }
    let mut b = b"ZTCO\x01".to_vec();
    b.push(f.kind);
    b.extend(f.account);
    b.extend(f.contact);
    for n in [
        f.revision,
        f.generation,
        f.manifest_version,
        f.reader_generation,
    ] {
        b.extend(n.to_be_bytes());
    }
    for d in [
        f.reader,
        f.manifest_digest,
        f.statement_digest,
        f.routing_digest,
    ] {
        b.extend(d);
    }
    b.extend(f.request);
    b.extend(f.writer);
    b.extend(f.encapsulation);
    b.extend((f.ciphertext.len() as u32).to_be_bytes());
    b.extend(&f.ciphertext);
    Ok(b)
}
pub fn encode_mutation(m: &UnsignedMutation) -> Result<Vec<u8>, Error> {
    for n in [m.revision, m.generation, m.manifest_version] {
        positive(n)?;
    }
    if m.generation != 1
        || m.expected > MAX
        || m.legacy_generation > MAX
        || m.account == [0; 16]
        || m.contact == [0; 16]
        || m.request == [0; 16]
        || [m.manifest_digest, m.statement_digest, m.routing_digest].contains(&[0; 32])
    {
        return Err("content mutation framing");
    }
    m.name.validate(m.revision)?;
    m.notes.validate(m.revision)?;
    match m.operation {
        1 | 3
            if m.expected == 0
                && m.revision == 1
                && m.previous_digest == [0; 32]
                && ((m.operation == 1 && m.legacy_generation == 0)
                    || (m.operation == 3 && m.legacy_generation > 0)) => {}
        2 if m.expected > 0
            && m.expected < MAX
            && m.revision == m.expected + 1
            && m.previous_digest != [0; 32]
            && m.legacy_generation == 0 => {}
        _ => return Err("content mutation semantics"),
    }
    let mut b = b"ZTCM\x01".to_vec();
    b.push(m.operation);
    b.extend(m.account);
    b.extend(m.contact);
    b.extend(m.expected.to_be_bytes());
    b.extend(m.revision.to_be_bytes());
    b.extend(m.request);
    b.extend(m.previous_digest);
    b.extend(m.generation.to_be_bytes());
    b.extend(m.manifest_version.to_be_bytes());
    for d in [m.manifest_digest, m.statement_digest, m.routing_digest] {
        b.extend(d);
    }
    b.extend(m.legacy_generation.to_be_bytes());
    for s in [&m.name, &m.notes] {
        b.push(s.tag);
        b.extend(s.revision.to_be_bytes());
        b.extend(s.digest);
    }
    Ok(b)
}
#[derive(Clone)]
pub struct ParsedField {
    field: UnsignedField,
    bytes: Vec<u8>,
    signature: Signature,
}
impl ParsedField {
    pub fn field(&self) -> UnsignedField {
        self.field.clone()
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
#[derive(Clone)]
pub struct ParsedMutation {
    mutation: UnsignedMutation,
    bytes: Vec<u8>,
    signature: Signature,
}
impl ParsedMutation {
    pub fn mutation(&self) -> UnsignedMutation {
        self.mutation.clone()
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
fn signed<'a>(
    b: &'a [u8],
    magic: &[u8],
    min: usize,
    max: usize,
) -> Result<(&'a [u8], Signature), Error> {
    if !(min..=max).contains(&b.len()) || &b[..5] != magic {
        return Err("content signed framing");
    }
    let at = b.len() - 64;
    let signature = Signature::from_slice(&b[at..]).map_err(|_| "content scalar")?;
    if signature.normalize_s().to_bytes().as_slice() != &b[at..] {
        return Err("content scalar alias");
    }
    Ok((&b[..at], signature))
}
fn fixed<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    b[at..at + N].try_into().unwrap()
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(fixed(b, at))
}
pub fn parse_field(b: &[u8]) -> Result<ParsedField, Error> {
    let (unsigned, signature) = signed(b, b"ZTCO\x01", 396, 2443)?;
    let n = u32::from_be_bytes(fixed(b, 311)) as usize;
    if n > 2064 || b.len() != 379 + n {
        return Err("content ciphertext length");
    }
    let f = UnsignedField {
        kind: b[5],
        account: fixed(b, 6),
        contact: fixed(b, 22),
        revision: number(b, 38),
        generation: number(b, 46),
        manifest_version: number(b, 54),
        reader_generation: number(b, 62),
        reader: fixed(b, 70),
        manifest_digest: fixed(b, 102),
        statement_digest: fixed(b, 134),
        routing_digest: fixed(b, 166),
        request: fixed(b, 198),
        writer: fixed(b, 214),
        encapsulation: fixed(b, 246),
        ciphertext: b[315..315 + n].to_vec(),
    };
    if encode_field(&f)? != unsigned {
        return Err("content field canonical");
    }
    VerifyingKey::from_sec1_bytes(&f.encapsulation).map_err(|_| "content encapsulation")?;
    Ok(ParsedField {
        field: f,
        bytes: b.to_vec(),
        signature,
    })
}
pub fn parse_mutation(b: &[u8]) -> Result<ParsedMutation, Error> {
    let (unsigned, signature) = signed(b, b"ZTCM\x01", 368, 368)?;
    let slot = |at| Slot {
        tag: b[at],
        revision: number(b, at + 1),
        digest: fixed(b, at + 9),
    };
    let m = UnsignedMutation {
        operation: b[5],
        account: fixed(b, 6),
        contact: fixed(b, 22),
        expected: number(b, 38),
        revision: number(b, 46),
        request: fixed(b, 54),
        previous_digest: fixed(b, 70),
        generation: number(b, 102),
        manifest_version: number(b, 110),
        manifest_digest: fixed(b, 118),
        statement_digest: fixed(b, 150),
        routing_digest: fixed(b, 182),
        legacy_generation: number(b, 214),
        name: slot(222),
        notes: slot(263),
    };
    if encode_mutation(&m)? != unsigned {
        return Err("content mutation canonical");
    }
    Ok(ParsedMutation {
        mutation: m,
        bytes: b.to_vec(),
        signature,
    })
}
pub struct ExpectedContent<'a> {
    pub contact: &'a [u8; 16],
    pub routing_digest: &'a [u8; 32],
}
fn verify_signature(
    bytes: &[u8],
    signature: &Signature,
    s: &StatementIdentity,
    domain: &[u8],
) -> Result<(), Error> {
    let unsigned = &bytes[..bytes.len() - 64];
    VerifyingKey::from_sec1_bytes(&s.root_point)
        .map_err(|_| "content root")?
        .verify(
            &[domain, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat(),
            signature,
        )
        .map_err(|_| "content signature")
}
#[derive(Clone)]
pub struct VerifiedHistoricalField {
    parsed: ParsedField,
    digest: [u8; 32],
    statement: StatementIdentity,
}
impl VerifiedHistoricalField {
    pub fn kind(&self) -> &'static str {
        "historical_integrity"
    }
    pub fn parsed(&self) -> ParsedField {
        self.parsed.clone()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Clone)]
pub struct VerifiedHistoricalMutation {
    parsed: ParsedMutation,
    digest: [u8; 32],
    statement: StatementIdentity,
}
impl VerifiedHistoricalMutation {
    pub fn kind(&self) -> &'static str {
        "historical_integrity"
    }
    pub fn parsed(&self) -> ParsedMutation {
        self.parsed.clone()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
pub struct VerifiedHistoricalTransition {
    mutation: VerifiedHistoricalMutation,
    fields: [Option<VerifiedHistoricalField>; 2],
}
impl VerifiedHistoricalTransition {
    pub fn kind(&self) -> &'static str {
        "historical_integrity"
    }
    pub fn mutation(&self) -> VerifiedHistoricalMutation {
        self.mutation.clone()
    }
}
macro_rules! redacted {($($ty:ty),*)=>{$(impl std::fmt::Debug for $ty {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_struct(stringify!($ty)).finish_non_exhaustive()}})*};}
redacted!(
    ParsedField,
    ParsedMutation,
    VerifiedHistoricalField,
    VerifiedHistoricalMutation,
    VerifiedHistoricalTransition
);
pub fn verify_field(
    b: &[u8],
    statement: &VerifiedContactReaderStatement,
    expected: &ExpectedContent<'_>,
) -> Result<VerifiedHistoricalField, Error> {
    let s = statement.identity();
    let identity = s.parsed.statement();
    let parsed = parse_field(b)?;
    let f = &parsed.field;
    if f.account != identity.account_id
        || f.contact != *expected.contact
        || f.routing_digest != *expected.routing_digest
        || f.generation != identity.trust_generation
        || f.manifest_version != identity.manifest_version
        || f.manifest_digest != identity.manifest_digest
        || f.statement_digest != s.digest
        || f.reader_generation != identity.reader_generation
        || f.reader != identity.reader_id
        || f.writer != s.root_writer_id
    {
        return Err("content field scope");
    }
    verify_signature(b, &parsed.signature, &s, FIELD_DOMAIN)?;
    Ok(VerifiedHistoricalField {
        parsed,
        digest: hash(b),
        statement: s,
    })
}
pub fn verify_mutation(
    b: &[u8],
    statement: &VerifiedContactReaderStatement,
    expected: &ExpectedContent<'_>,
    expected_legacy_generation: u64,
) -> Result<VerifiedHistoricalMutation, Error> {
    let s = statement.identity();
    let identity = s.parsed.statement();
    let parsed = parse_mutation(b)?;
    let m = &parsed.mutation;
    if m.account != identity.account_id
        || m.contact != *expected.contact
        || m.routing_digest != *expected.routing_digest
        || m.generation != identity.trust_generation
        || m.manifest_version != identity.manifest_version
        || m.manifest_digest != identity.manifest_digest
        || m.statement_digest != s.digest
        || m.legacy_generation != expected_legacy_generation
        || expected_legacy_generation > MAX
    {
        return Err("content mutation scope");
    }
    verify_signature(b, &parsed.signature, &s, MUTATION_DOMAIN)?;
    Ok(VerifiedHistoricalMutation {
        parsed,
        digest: hash(b),
        statement: s,
    })
}
pub fn verify_transition(
    previous: Option<&VerifiedHistoricalTransition>,
    next: &VerifiedHistoricalMutation,
    replacements: &[&VerifiedHistoricalField],
) -> Result<VerifiedHistoricalTransition, Error> {
    if replacements.len() > 2
        || replacements.len() == 2
            && replacements[0].parsed.field.kind == replacements[1].parsed.field.kind
    {
        return Err("content replacements");
    }
    let n = &next.parsed.mutation;
    let s = next.statement.parsed.statement();
    if let Some(p) = previous {
        let old = &p.mutation.parsed.mutation;
        let ps = p.mutation.statement.parsed.statement();
        if n.operation != 2
            || n.expected != old.revision
            || n.previous_digest != p.mutation.digest
            || n.account != old.account
            || n.contact != old.contact
            || n.routing_digest != old.routing_digest
            || n.generation != old.generation
            || s.origin != ps.origin
            || s.root_fingerprint != ps.root_fingerprint
            || n.manifest_version < old.manifest_version
            || n.manifest_version == old.manifest_version
                && n.manifest_digest != old.manifest_digest
            || s.reader_generation < ps.reader_generation
            || s.reader_generation == ps.reader_generation
                && (s.reader_id != ps.reader_id || s.reader_point != ps.reader_point)
        {
            return Err("content predecessor");
        }
    } else if n.operation == 2 {
        return Err("content genesis");
    }
    let mut current: [Option<VerifiedHistoricalField>; 2] = [None, None];
    let mut used = 0;
    for (index, slot) in [&n.name, &n.notes].into_iter().enumerate() {
        if slot.tag == 0 {
            continue;
        }
        if slot.revision == n.revision {
            let f = replacements
                .iter()
                .find(|f| usize::from(f.parsed.field.kind) == index + 1)
                .ok_or("content replacement absent")?;
            let q = &f.parsed.field;
            if f.digest != slot.digest
                || q.account != n.account
                || q.contact != n.contact
                || q.routing_digest != n.routing_digest
                || q.request != n.request
                || q.revision != n.revision
                || q.generation != n.generation
                || q.manifest_version != n.manifest_version
                || q.manifest_digest != n.manifest_digest
                || q.statement_digest != n.statement_digest
                || q.reader_generation != s.reader_generation
                || q.reader != s.reader_id
                || q.writer != next.statement.root_writer_id
                || f.statement.digest != next.statement.digest
            {
                return Err("content replacement scope");
            }
            current[index] = Some((**f).clone());
            used += 1;
        } else {
            let p = previous.ok_or("content retained genesis")?;
            let old = [
                &p.mutation.parsed.mutation.name,
                &p.mutation.parsed.mutation.notes,
            ][index];
            if slot != old {
                return Err("content retained substitution");
            }
            current[index] = Some(
                p.fields[index]
                    .as_ref()
                    .ok_or("content retained absent")?
                    .clone(),
            );
        }
    }
    if used != replacements.len() {
        return Err("content unused replacement");
    }
    Ok(VerifiedHistoricalTransition {
        mutation: next.clone(),
        fields: current,
    })
}
#[cfg(test)]
mod tests;
