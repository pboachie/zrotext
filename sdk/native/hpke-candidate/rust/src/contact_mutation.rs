//! Signed historical contact mutations and retained-field transitions.
//! No current grant, durable history or submission authority is inferred.
use super::*;
#[path = "contact_history.rs"]
pub mod history;

pub(crate) const DOMAIN: &str = "ZT/contact-field/mutation/v1";
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub tag: u8,
    pub seal_revision: u64,
    pub digest: [u8; 32],
}
#[derive(Clone)]
pub struct Input {
    pub operation: u8,
    pub expected_revision: u64,
    pub revision: u64,
    pub legacy_generation: u64,
    pub request_id: [u8; 16],
    pub previous_digest: [u8; 32],
    pub name: Slot,
    pub notes: Slot,
}
/// Private construction preserves genuine signature provenance.
#[derive(Clone)]
pub struct Mutation {
    raw: Vec<u8>,
    digest: [u8; 32],
    statement: Statement,
    input: Input,
}
impl Mutation {
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Clone)]
pub struct Transition {
    mutation: Mutation,
    fields: [Option<Field>; 2],
}
impl Transition {
    pub fn mutation(&self) -> &Mutation {
        &self.mutation
    }
    pub fn field(&self, kind: u8) -> Option<&Field> {
        match kind {
            1 | 2 => self.fields[usize::from(kind - 1)].as_ref(),
            _ => None,
        }
    }
}
fn slot_valid(s: Slot, revision: u64) -> bool {
    s.seal_revision <= revision
        && match s.tag {
            0 => s.seal_revision == 0 && s.digest == [0; 32],
            1 => positive(s.seal_revision) && s.digest != [0; 32],
            _ => false,
        }
}
fn unsigned(
    st: &Statement,
    e: &Expected,
    m: &Input,
    expected_legacy: u64,
) -> Result<Vec<u8>, Error> {
    need(
        scoped(st, e)
            && positive(m.revision)
            && m.expected_revision <= i64::MAX as u64
            && m.legacy_generation <= i64::MAX as u64
            && m.legacy_generation == expected_legacy
            && nonzero(&m.request_id, 16)
            && slot_valid(m.name, m.revision)
            && slot_valid(m.notes, m.revision),
    )?;
    need(match m.operation {
        1 | 3 => {
            m.expected_revision == 0
                && m.revision == 1
                && m.previous_digest == [0; 32]
                && if m.operation == 1 {
                    m.legacy_generation == 0
                } else {
                    m.legacy_generation > 0
                }
        }
        2 => {
            positive(m.expected_revision)
                && m.expected_revision < i64::MAX as u64
                && m.revision == m.expected_revision + 1
                && m.previous_digest != [0; 32]
                && m.legacy_generation == 0
        }
        _ => false,
    })?;
    let mut b = [
        b"ZTCM\x01".as_slice(),
        &[m.operation],
        &e.account,
        &e.contact,
        &m.expected_revision.to_be_bytes(),
        &m.revision.to_be_bytes(),
        &m.request_id,
        &m.previous_digest,
        &1u64.to_be_bytes(),
        &st.version.to_be_bytes(),
        &st.manifest_digest,
        &st.digest,
        &e.routing_digest,
        &m.legacy_generation.to_be_bytes(),
    ]
    .concat();
    for s in [m.name, m.notes] {
        b.push(s.tag);
        b.extend(s.seal_revision.to_be_bytes());
        b.extend(s.digest);
    }
    Ok(b)
}
fn input(b: &[u8]) -> Input {
    let slot = |at| Slot {
        tag: b[at],
        seal_revision: number(b, at + 1),
        digest: b[at + 9..at + 41].try_into().expect("bounded slot"),
    };
    Input {
        operation: b[5],
        expected_revision: number(b, 38),
        revision: number(b, 46),
        legacy_generation: number(b, 214),
        request_id: b[54..70].try_into().expect("bounded request"),
        previous_digest: b[70..102].try_into().expect("bounded predecessor"),
        name: slot(222),
        notes: slot(263),
    }
}
pub fn verify_mutation01(
    bytes: &[u8],
    st: &Statement,
    e: &Expected,
    expected_legacy: u64,
) -> Result<Mutation, Error> {
    need(bytes.len() == 368)?;
    let raw = bytes.to_vec();
    let m = input(&raw);
    need(unsigned(st, e, &m, expected_legacy)? == raw[..304])?;
    verify(&st.root_point, &raw, DOMAIN)?;
    Ok(Mutation {
        digest: Sha256::digest(&raw).into(),
        raw,
        statement: st.clone(),
        input: m,
    })
}
fn fields(
    previous: Option<&Transition>,
    next: &Mutation,
    replacements: &[Field],
) -> Result<[Option<Field>; 2], Error> {
    need(replacements.len() <= 2)?;
    let mut supplied: [Option<&Field>; 2] = [None, None];
    for f in replacements {
        let i = usize::from(f.raw[5] - 1);
        need(i < 2 && supplied[i].is_none())?;
        supplied[i] = Some(f);
    }
    let n = &next.input;
    let s = &next.statement;
    if let Some(prior) = previous {
        let p = &prior.mutation;
        let ps = &p.statement;
        need(
            n.operation == 2
                && n.expected_revision == p.input.revision
                && n.previous_digest == p.digest
                && next.raw[6..38] == p.raw[6..38]
                && next.raw[182..214] == p.raw[182..214]
                && s.origin == ps.origin
                && s.fingerprint == ps.fingerprint
                && s.version >= ps.version
                && (s.version != ps.version || s.manifest_digest == ps.manifest_digest)
                && s.reader_generation >= ps.reader_generation
                && (s.reader_generation != ps.reader_generation
                    || (s.reader_id == ps.reader_id && s.reader_point == ps.reader_point)),
        )?;
    } else {
        need(n.operation != 2)?;
    }
    let mut out = [None, None];
    let mut used = 0;
    for (i, sl) in [n.name, n.notes].into_iter().enumerate() {
        if sl.tag == 0 {
            continue;
        }
        if sl.seal_revision == n.revision {
            let f = supplied[i].ok_or(Error::Authentication)?;
            let b = &f.raw;
            need(
                f.digest == sl.digest
                    && number(b, 38) == n.revision
                    && b[198..214] == n.request_id
                    && b[6..38] == next.raw[6..38]
                    && number(b, 46) == 1
                    && number(b, 54) == s.version
                    && number(b, 62) == s.reader_generation
                    && b[70..102] == s.reader_id
                    && b[102..134] == s.manifest_digest
                    && b[134..166] == s.digest
                    && b[166..198] == next.raw[182..214]
                    && b[214..246] == s.root_writer_id,
            )?;
            out[i] = Some(f.clone());
            used += 1;
        } else {
            let p = previous.ok_or(Error::Authentication)?;
            need(
                sl == [p.mutation.input.name, p.mutation.input.notes][i] && p.fields[i].is_some(),
            )?;
            out[i] = p.fields[i].clone();
        }
    }
    need(used == replacements.len())?;
    Ok(out)
}
pub fn verify_transition01(
    previous: Option<&Transition>,
    next: &Mutation,
    replacements: &[Field],
) -> Result<Transition, Error> {
    Ok(Transition {
        mutation: next.clone(),
        fields: fields(previous, next, replacements)?,
    })
}

/// A complete captured proposal. A previous statement is independently supplied
/// and must match the genuine predecessor token exactly before signing.
#[derive(Clone)]
pub struct Proposal {
    pub statement: Statement,
    pub expected: Expected,
    pub input: Input,
    pub expected_legacy: u64,
    pub previous: Option<Transition>,
    pub previous_statement: Option<Statement>,
    pub replacements: Vec<Field>,
}
impl Proposal {
    fn plan(&self) -> Result<Vec<u8>, Error> {
        let b = unsigned(
            &self.statement,
            &self.expected,
            &self.input,
            self.expected_legacy,
        )?;
        match (&self.previous, &self.previous_statement) {
            (None, None) => {}
            (Some(p), Some(s)) => {
                need(scoped(s, &self.expected) && p.mutation.statement.raw == s.raw)?
            }
            _ => return Err(Error::Shape),
        }
        // This internal unsigned preview is never exposed as provenance.
        let preview = Mutation {
            raw: [b.as_slice(), &[0; 64]].concat(),
            digest: [0; 32],
            statement: self.statement.clone(),
            input: self.input.clone(),
        };
        fields(self.previous.as_ref(), &preview, &self.replacements)?;
        Ok(b)
    }
}
pub struct Production {
    transition: Transition,
}
impl Production {
    pub fn signed_bytes(&self) -> &[u8] {
        self.transition.mutation.signed_bytes()
    }
    pub fn verified(&self) -> &Transition {
        &self.transition
    }
}
fn produce<F>(
    proposal: &Proposal,
    unsigned: Vec<u8>,
    cancel: &Cancellation,
    sign: F,
) -> Result<Production, Error>
where
    F: FnOnce(&[u8], Instant, &Cancellation) -> Result<Vec<u8>, Error> + Send + 'static,
{
    let p = proposal.clone();
    super::execute(unsigned, cancel, sign, move |raw| {
        let mutation = verify_mutation01(raw, &p.statement, &p.expected, p.expected_legacy)?;
        let transition = verify_transition01(p.previous.as_ref(), &mutation, &p.replacements)?;
        Ok(Production { transition })
    })
}
pub fn produce_software_mutation01(
    scalar: &[u8],
    proposal: &Proposal,
    cancel: &Cancellation,
) -> Result<Production, Error> {
    use p256::ecdsa::{SigningKey, signature::Signer};
    let b = proposal.plan()?;
    let owned = zeroize::Zeroizing::new(scalar.to_vec());
    let key = SigningKey::from_slice(&owned).map_err(|_| Error::Shape)?;
    need(key.verifying_key().to_sec1_point(false).as_bytes() == proposal.statement.root_point)?;
    produce(proposal, b, cancel, move |b, _, _| {
        let _owned = owned;
        let sig: Signature = key.sign(&transcript(DOMAIN, b));
        Ok(sig.normalize_s().to_bytes().to_vec())
    })
}
#[cfg(windows)]
pub fn produce_protected_mutation01(
    signer: Arc<crate::cng::ContactRootSigner>,
    proposal: &Proposal,
    cancel: &Cancellation,
) -> Result<Production, Error> {
    let b = proposal.plan()?;
    let point = proposal.statement.root_point;
    produce(proposal, b, cancel, move |b, deadline, cancel| {
        signer
            .sign_contact_mutation(b, &point, || cancel.live() && Instant::now() < deadline)
            .map_err(|_| Error::ProtectedUnavailable)
    })
}
