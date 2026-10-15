//! Historical contact statement and opaque field integrity; never current permission.
use crate::{
    Error,
    manifest::{Manifest, enroll_root, verify_manifest},
    reader::{active, key},
};
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use sha2::{Digest, Sha256};

const STATEMENT_DOMAIN: &str = "ZT/contact-reader/authorization/v1";
#[path = "contact_mutation.rs"]
pub mod mutation;
#[cfg(test)]
#[path = "contact_tests.rs"]
mod tests;
/// Maintained canonical ASCII HTTPS origin grammar.
pub fn validate_origin01(value: &str) -> Result<(), Error> {
    need(origin(value))
}
pub(crate) const FIELD_DOMAIN: &str = "ZT/contact-field/commitment/v1";
fn need(v: bool) -> Result<(), Error> {
    if v { Ok(()) } else { Err(Error::Shape) }
}
fn positive(v: u64) -> bool {
    v > 0 && v <= i64::MAX as u64
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("bounded contact offset"))
}
fn nonzero(b: &[u8], n: usize) -> bool {
    b.len() == n && b.iter().any(|x| *x != 0)
}
pub(crate) fn origin(s: &str) -> bool {
    if !(9..=512).contains(&s.len()) || !s.bytes().all(|x| (0x21..=0x7e).contains(&x)) {
        return false;
    }
    let Ok(u) = url::Url::parse(s) else {
        return false;
    };
    // Preserve the maintained SDK's UTS46 decoded-label validity contract.
    // This is a general label rule, not a list of hostname exceptions.
    for label in u.host_str().unwrap_or("").split('.') {
        if let Some(encoded) = label.strip_prefix("xn--") {
            let Some(decoded) = idna::punycode::decode_to_string(encoded) else {
                return false;
            };
            if decoded.is_ascii() || decoded.starts_with("xn--") {
                return false;
            }
        }
    }
    u.scheme() == "https"
        && u.origin().ascii_serialization() == s
        && u.username().is_empty()
        && u.password().is_none()
        && u.path() == "/"
        && u.query().is_none()
        && u.fragment().is_none()
}
pub(crate) fn transcript(domain: &str, b: &[u8]) -> Vec<u8> {
    [domain.as_bytes(), &[0], &(b.len() as u32).to_be_bytes(), b].concat()
}
fn verify(point: &[u8], b: &[u8], domain: &str) -> Result<(), Error> {
    need(b.len() >= 64 && point.len() == 65)?;
    let signature = Signature::from_slice(&b[b.len() - 64..]).map_err(|_| Error::Authentication)?;
    need(signature.normalize_s() == signature)?;
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| Error::Shape)?
        .verify(&transcript(domain, &b[..b.len() - 64]), &signature)
        .map_err(|_| Error::Authentication)
}
/// Independent caller scope. No field is inferred from untrusted wire bytes.
#[derive(Clone)]
pub struct Expected {
    pub account: [u8; 16],
    pub origin: String,
    pub root_fingerprint: [u8; 32],
    pub contact: [u8; 16],
    pub routing_digest: [u8; 32],
}
/// Owned signature provenance with private construction, compared at declared issue time.
#[derive(Clone)]
pub struct Statement {
    raw: Vec<u8>,
    account: [u8; 16],
    origin: String,
    fingerprint: [u8; 32],
    manifest_digest: [u8; 32],
    reader_id: [u8; 32],
    digest: [u8; 32],
    root_writer_id: [u8; 32],
    reader_point: [u8; 65],
    pub(crate) root_point: [u8; 65],
    version: u64,
    reader_generation: u64,
}
impl Statement {
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn reader_point(&self) -> [u8; 65] {
        self.reader_point
    }
}
/// Verified commitment over opaque bytes, not ciphertext decryption or access authority.
#[derive(Clone)]
pub struct Field {
    raw: Vec<u8>,
    digest: [u8; 32],
}
impl Field {
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub fn verify_statement02(
    input: &[u8],
    accepted: &Manifest,
    account: &[u8],
    expected_origin: &str,
    fingerprint: &[u8],
) -> Result<Statement, Error> {
    need(
        (314..=817).contains(&input.len())
            && accepted.profile == 2
            && accepted.generation == 1
            && nonzero(account, 16)
            && nonzero(fingerprint, 32)
            && origin(expected_origin),
    )?;
    let b = input.to_vec();
    let n = u16::from_be_bytes([b[38], b[39]]) as usize;
    need(
        &b[..6] == b"ZTKA\x01\x03"
            && (9..=512).contains(&n)
            && b.len() == 305 + n
            && nonzero(&b[6..22], 16)
            && nonzero(&b[22..38], 16),
    )?;
    let mut at = 40 + n;
    let observed_origin = std::str::from_utf8(&b[40..at])
        .map_err(|_| Error::Shape)?
        .to_owned();
    need(origin(&observed_origin) && observed_origin == expected_origin && number(&b, at) == 1)?;
    let version = number(&b, at + 8);
    let reader_generation = number(&b, at + 16);
    at += 24;
    let fp: [u8; 32] = b[at..at + 32].try_into().map_err(|_| Error::Shape)?;
    at += 32;
    let md: [u8; 32] = b[at..at + 32].try_into().map_err(|_| Error::Shape)?;
    at += 32;
    let rid: [u8; 32] = b[at..at + 32].try_into().map_err(|_| Error::Shape)?;
    at += 32;
    let rp: [u8; 65] = b[at..at + 65].try_into().map_err(|_| Error::Shape)?;
    at += 65;
    let issued = number(&b, at);
    let until = number(&b, at + 8);
    need(
        [version, reader_generation, issued, until]
            .into_iter()
            .all(positive)
            && until > issued
            && until - issued <= 86400000
            && nonzero(&fp, 32)
            && nonzero(&md, 32)
            && nonzero(&rid, 32),
    )?;
    // Private historical replay of the exact already-accepted identity; the live
    // token is unchanged and no general comparison-floor reset is exported.
    let previous = Manifest {
        raw: accepted.raw.clone(),
        profile: accepted.profile,
        predecessor: accepted.predecessor,
        generation: accepted.generation,
        version: accepted.version,
        issued: accepted.issued,
        expires: accepted.expires,
        comparison: 0,
        digest: accepted.digest,
        account: accepted.account,
        root: accepted.root,
        enrolled: accepted.enrolled,
        lineage: accepted.lineage.clone(),
    };
    let pin = [
        b"ZTRP\x02".as_slice(),
        accepted.account.as_slice(),
        &1u64.to_be_bytes(),
        accepted.root.as_slice(),
    ]
    .concat();
    let compared = Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat());
    let root = enroll_root(&pin, &compared)?;
    let m = verify_manifest(&accepted.raw, &root, Some(&previous), 2, issued)?;
    let reader = key(&m, 2, &rid).ok_or(Error::Authentication)?;
    let writer = m.raw[151..m.raw.len() - 64]
        .chunks_exact(149)
        .find(|w| w[0] == 6)
        .ok_or(Error::Authentication)?;
    need(
        active(reader, issued, 12)
            && active(writer, issued, 0)
            && reader[130..132] == [0, 12]
            && writer[130..132] == [0, 0]
            && b[22..38] == m.account
            && m.account == account
            && version == m.version
            && md == m.digest
            && rp == reader[33..98]
            && issued >= m.issued
            && until <= m.expires
            && until <= number(reader, 140)
            && until <= number(writer, 140),
    )?;
    need(compared.as_slice() == fp && fp == fingerprint)?;
    verify(&writer[33..98], &b, STATEMENT_DOMAIN)?;
    Ok(Statement {
        account: m.account,
        origin: observed_origin,
        fingerprint: fp,
        manifest_digest: md,
        reader_id: rid,
        digest: Sha256::digest(&b).into(),
        root_writer_id: writer[1..33].try_into().map_err(|_| Error::Shape)?,
        reader_point: rp,
        root_point: writer[33..98].try_into().map_err(|_| Error::Shape)?,
        version,
        reader_generation,
        raw: b,
    })
}

#[derive(Clone)]
pub struct FieldInput {
    pub kind: u8,
    pub seal_revision: u64,
    pub request_id: [u8; 16],
    pub encapsulation: [u8; 65],
    pub ciphertext: Vec<u8>,
}
fn scoped(s: &Statement, e: &Expected) -> bool {
    nonzero(&e.account, 16)
        && nonzero(&e.root_fingerprint, 32)
        && nonzero(&e.contact, 16)
        && nonzero(&e.routing_digest, 32)
        && origin(&e.origin)
        && e.account == s.account
        && e.root_fingerprint == s.fingerprint
        && e.origin == s.origin
}
pub(crate) fn unsigned(s: &Statement, e: &Expected, f: &FieldInput) -> Result<Vec<u8>, Error> {
    need(
        scoped(s, e)
            && [1, 2].contains(&f.kind)
            && positive(f.seal_revision)
            && nonzero(&f.request_id, 16)
            && (17..=if f.kind == 1 { 272 } else { 2064 }).contains(&f.ciphertext.len()),
    )?;
    PublicKey::from_sec1_bytes(&f.encapsulation).map_err(|_| Error::Shape)?;
    let mut b = [b"ZTCO\x01".as_slice(), &[f.kind], &e.account, &e.contact].concat();
    for n in [f.seal_revision, 1, s.version, s.reader_generation] {
        b.extend(n.to_be_bytes())
    }
    for part in [
        &s.reader_id[..],
        &s.manifest_digest,
        &s.digest,
        &e.routing_digest,
        &f.request_id,
        &s.root_writer_id,
        &f.encapsulation,
    ] {
        b.extend(part)
    }
    b.extend((f.ciphertext.len() as u32).to_be_bytes());
    b.extend(&f.ciphertext);
    Ok(b)
}
pub fn verify_field01(input: &[u8], s: &Statement, e: &Expected) -> Result<Field, Error> {
    need((396..=2443).contains(&input.len()) && scoped(s, e))?;
    let b = input.to_vec();
    need(
        &b[..5] == b"ZTCO\x01"
            && b.len() as u64
                == 379
                    + u32::from_be_bytes(b[311..315].try_into().map_err(|_| Error::Shape)?) as u64,
    )?;
    let f = FieldInput {
        kind: b[5],
        seal_revision: number(&b, 38),
        request_id: b[198..214].try_into().map_err(|_| Error::Shape)?,
        encapsulation: b[246..311].try_into().map_err(|_| Error::Shape)?,
        ciphertext: b[315..b.len() - 64].to_vec(),
    };
    need(unsigned(s, e, &f)? == b[..b.len() - 64])?;
    verify(&s.root_point, &b, FIELD_DOMAIN)?;
    Ok(Field {
        digest: Sha256::digest(&b).into(),
        raw: b,
    })
}

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);
/// Explicit cancellation. Cancelled callers do not release an outstanding native operation's slot.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst)
    }
    fn live(&self) -> bool {
        !self.0.load(Ordering::SeqCst)
    }
}
struct Permit;
impl Drop for Permit {
    fn drop(&mut self) {
        OUTSTANDING.fetch_sub(1, Ordering::SeqCst);
    }
}
/// Historical commitment only. Persistence/submission are explicit caller decisions.
pub struct Production {
    field: Field,
}
impl Production {
    pub fn signed_bytes(&self) -> &[u8] {
        self.field.signed_bytes()
    }
    pub fn verified(&self) -> &Field {
        &self.field
    }
}
fn produce<F>(
    statement: &Statement,
    expected: &Expected,
    unsigned: Vec<u8>,
    cancel: &Cancellation,
    sign: F,
) -> Result<Production, Error>
where
    F: FnOnce(&[u8], Instant, &Cancellation) -> Result<Vec<u8>, Error> + Send + 'static,
{
    let st = statement.clone();
    let expected = expected.clone();
    execute(unsigned, cancel, sign, move |raw| {
        Ok(Production {
            field: verify_field01(raw, &st, &expected)?,
        })
    })
}
fn execute<F, V, T>(
    unsigned: Vec<u8>,
    cancel: &Cancellation,
    sign: F,
    verify: V,
) -> Result<T, Error>
where
    F: FnOnce(&[u8], Instant, &Cancellation) -> Result<Vec<u8>, Error> + Send + 'static,
    V: FnOnce(&[u8]) -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    need(cancel.live())?;
    OUTSTANDING
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            if n < 4 { Some(n + 1) } else { None }
        })
        .map_err(|_| Error::Shape)?;
    let permit = Permit;
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancellation = cancel.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("contact-field".into())
        .spawn(move || {
            let _permit = permit;
            let live = || need(cancellation.live() && Instant::now() < deadline);
            let result = (|| {
                live()?;
                let sig = sign(&unsigned, deadline, &cancellation)?;
                live()?;
                let raw = [unsigned, sig].concat();
                let value = verify(&raw)?;
                live()?;
                Ok(value)
            })();
            let _ = tx.send(result);
        })
        .map_err(|_| Error::Shape)?;
    loop {
        need(cancel.live() && Instant::now() < deadline)?;
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(result) => {
                need(cancel.live() && Instant::now() < deadline)?;
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(Error::Shape),
        }
    }
}
/// Explicit exportable software-key lane; never claims protected custody.
pub fn produce_software_field01(
    scalar: &[u8],
    statement: &Statement,
    expected: &Expected,
    field: &FieldInput,
    cancel: &Cancellation,
) -> Result<Production, Error> {
    use p256::ecdsa::{SigningKey, signature::Signer};
    let unsigned = unsigned(statement, expected, field)?;
    let owned = zeroize::Zeroizing::new(scalar.to_vec());
    let key = SigningKey::from_slice(&owned).map_err(|_| Error::Shape)?;
    need(key.verifying_key().to_sec1_point(false).as_bytes() == statement.root_point)?;
    produce(
        statement,
        expected,
        unsigned,
        cancel,
        move |unsigned, _, _| {
            let _owned = owned;
            let signature: Signature = key.sign(&transcript(FIELD_DOMAIN, unsigned));
            Ok(signature.normalize_s().to_bytes().to_vec())
        },
    )
}
#[cfg(windows)]
pub fn produce_protected_field01(
    signer: Arc<crate::cng::ContactRootSigner>,
    statement: &Statement,
    expected: &Expected,
    field: &FieldInput,
    cancel: &Cancellation,
) -> Result<Production, Error> {
    let unsigned = unsigned(statement, expected, field)?;
    let point = statement.root_point;
    produce(
        statement,
        expected,
        unsigned,
        cancel,
        move |b, deadline, cancel| {
            signer
                .sign_contact_field(b, &point, || cancel.live() && Instant::now() < deadline)
                .map_err(|_| Error::ProtectedUnavailable)
        },
    )
}
