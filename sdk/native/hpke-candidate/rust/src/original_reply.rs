//! Selected original role3 opening. HTTP grant provenance and durable authority
//! high-water integration are separate; callbacks must be independently trusted.
use crate::{
    Error,
    election::signature,
    envelope::verify_envelope,
    manifest::{Manifest, verify_manifest, window},
    reader::{active, key},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct OriginalScope {
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub interval: [u8; 16],
    pub connector: [u8; 16],
    pub read_grant: [u8; 16],
    pub reader: [u8; 32],
    pub peer: String,
}
/// Must come from independent authenticated grant integration, not event fields.
pub struct OriginalAuthority<'a> {
    pub scope: OriginalScope,
    pub revision: String,
    pub now: u64,
    pub expires: u64,
    pub manifest: &'a Manifest,
}
struct SelectedReader {
    connector: [u8; 16],
    grant: [u8; 16],
    reader: [u8; 32],
}
/// Owned opaque phone approval/installation; this does not create a live grant.
pub struct ReplySelection {
    scope: OriginalScope,
    archive: [u8; 32],
    readers: Vec<SelectedReader>,
    root: [u8; 65],
    enrolled: [u8; 65],
    generation: u64,
    version: u64,
    digest: [u8; 32],
}
const DISCLOSURE: &str = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
fn need(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}
struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let b = self.raw.get(self.at..self.at + n).ok_or(Error::Shape)?;
        self.at += n;
        Ok(b)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.take(N)?.try_into().map_err(|_| Error::Shape)?;
        need(b != [0; N])?;
        Ok(b)
    }
    fn number(&mut self) -> Result<u64, Error> {
        let n = number(self.take(8)?, 0);
        need(n > 0 && n <= i64::MAX as u64)?;
        Ok(n)
    }
    fn text(&mut self) -> Result<String, Error> {
        let n = self.take(1)?[0] as usize;
        Ok(std::str::from_utf8(self.take(n)?)
            .map_err(|_| Error::Shape)?
            .to_owned())
    }
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("internal checked width"))
}
pub(crate) fn valid_scope(s: &OriginalScope) -> bool {
    let p = s.peer.as_bytes();
    [
        s.account,
        s.device,
        s.line,
        s.interval,
        s.connector,
        s.read_grant,
    ]
    .iter()
    .all(|v| *v != [0; 16])
        && s.reader != [0; 32]
        && (3..=16).contains(&p.len())
        && p[0] == b'+'
        && (b'1'..=b'9').contains(&p[1])
        && p[2..].iter().all(u8::is_ascii_digit)
}
/// Accept only both phone signatures and independently accepted activation state.
pub fn verify_original_reply_selection02(
    input: &[u8],
    approval: &[u8],
    installation: &[u8],
    activation: &Manifest,
    accepted: u64,
    scope: &OriginalScope,
) -> Result<ReplySelection, Error> {
    need((380..=1536).contains(&input.len()) && activation.profile == 2 && valid_scope(scope))?;
    let mut p = Cursor { raw: input, at: 0 };
    need(p.take(5)? == b"ZTCA\x02")?;
    let account = p.fixed::<16>()?;
    let device = p.fixed::<16>()?;
    let line = p.fixed::<16>()?;
    p.number()?;
    let interval = p.fixed::<16>()?;
    p.fixed::<16>()?;
    p.fixed::<16>()?;
    p.fixed::<32>()?;
    let expires = p.number()?;
    let peer = p.text()?;
    need(p.text()? == "conversation-content-v1")?;
    need(p.take(32)? == Sha256::digest(DISCLOSURE.as_bytes()).as_slice())?;
    let archive = p.fixed::<32>()?;
    let signer = p.fixed::<32>()?;
    let generation = p.number()?;
    let previous = p.number()?;
    p.fixed::<32>()?;
    let version = p.number()?;
    let digest = p.fixed::<32>()?;
    p.number()?;
    p.number()?;
    for _ in 0..2 {
        let s = p.text()?;
        need((1..=64).contains(&s.len()) && s.bytes().all(|v| (33..=126).contains(&v)))?;
    }
    let count = p.take(1)?[0] as usize;
    need((1..=6).contains(&count))?;
    let mut readers: Vec<SelectedReader> = Vec::with_capacity(count);
    let mut chosen = false;
    for _ in 0..count {
        let r = SelectedReader {
            connector: p.fixed()?,
            grant: p.fixed()?,
            reader: p.fixed()?,
        };
        need(
            readers.last().is_none_or(|old| old.reader < r.reader)
                && readers.iter().all(|old| {
                    old.connector != r.connector && old.grant != r.grant && old.reader != r.reader
                }),
        )?;
        chosen |= r.connector == scope.connector
            && r.grant == scope.read_grant
            && r.reader == scope.reader;
        readers.push(r);
    }
    need(
        p.at == input.len()
            && chosen
            && accepted > 0
            && accepted < expires
            && account == scope.account
            && device == scope.device
            && line == scope.line
            && interval == scope.interval
            && peer == scope.peer
            && version == previous + 1,
    )?;
    let current = verify_manifest(
        &activation.raw,
        &activation.root_trust(),
        Some(activation),
        2,
        accepted,
    )?;
    need(
        current.account == account
            && current.generation == generation
            && current.version == version
            && current.digest == digest,
    )?;
    let signer = key(&current, 4, &signer).ok_or(Error::Authentication)?;
    need(active(signer, accepted, 2) && signer[98..114] == device && signer[114..130] == line)?;
    signature(
        &signer[33..98],
        approval,
        "zrotext/conversation/approve/v2",
        input,
    )?;
    signature(
        &signer[33..98],
        installation,
        "zrotext/conversation/install/v2",
        input,
    )?;
    Ok(ReplySelection {
        scope: scope.clone(),
        archive,
        readers,
        root: current.root,
        enrolled: current.enrolled,
        generation,
        version,
        digest,
    })
}
struct Checked {
    manifest: Manifest,
    revision: String,
    now: u64,
    expires: u64,
}
fn authority(value: OriginalAuthority<'_>, scope: &OriginalScope) -> Result<Checked, Error> {
    need(
        value.scope == *scope
            && !value.revision.is_empty()
            && value.revision.len() <= 128
            && value.now > 0
            && value.now < value.expires
            && value.expires <= i64::MAX as u64
            && value.manifest.profile == 2,
    )?;
    let m = value.manifest;
    let manifest = verify_manifest(&m.raw, &m.root_trust(), Some(m), 2, value.now)?;
    Ok(Checked {
        manifest,
        revision: value.revision,
        now: value.now,
        expires: value.expires,
    })
}
pub struct OriginalRead<'a> {
    pub event: [u8; 16],
    pub scope: &'a OriginalScope,
    pub historical: &'a Manifest,
    pub selection: &'a ReplySelection,
}
/// Explicit exportable-key reader; never silently replaces protected custody.
pub fn open_software_original_reply02<'a, F>(
    input: &[u8],
    options: &OriginalRead<'_>,
    scalar: &[u8],
    current: F,
) -> Result<Zeroizing<String>, Error>
where
    F: FnMut() -> Result<OriginalAuthority<'a>, Error>,
{
    open(input, options, current, |point, enc, info, aad, ct| {
        crate::open_software_cek(scalar, point, enc, info, aad, ct)
    })
}
#[cfg(windows)]
pub fn open_hardware_original_reply02<'a, F>(
    input: &[u8],
    options: &OriginalRead<'_>,
    custody: &crate::cng::HardwareRecipient,
    current: F,
) -> Result<Zeroizing<String>, Error>
where
    F: FnMut() -> Result<OriginalAuthority<'a>, Error>,
{
    open(input, options, current, |point, enc, info, aad, ct| {
        custody.open_cek(point, enc, info, aad, ct)
    })
}
fn open<'a, F, U>(
    b: &[u8],
    options: &OriginalRead<'_>,
    mut current: F,
    unwrap: U,
) -> Result<Zeroizing<String>, Error>
where
    F: FnMut() -> Result<OriginalAuthority<'a>, Error>,
    U: FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
{
    let OriginalRead {
        event,
        scope,
        historical,
        selection,
    } = options;
    need(
        (426..=34082).contains(&b.len())
            && *event != [0; 16]
            && historical.profile == 2
            && selection.scope == **scope
            && valid_scope(scope),
    )?;
    need(b[4] == 2 && b[5] == 2 && b[26..42] == *event)?;
    let initial = authority(current()?, scope)?;
    let m = &initial.manifest;
    need(
        historical.account == scope.account
            && m.account == scope.account
            && historical.root == m.root
            && historical.enrolled == m.enrolled
            && m.root == selection.root
            && m.enrolled == selection.enrolled
            && historical.generation == m.generation
            && m.generation == selection.generation
            && historical.version >= selection.version
            && historical.lineage.contains(&selection.digest)
            && m.lineage.contains(&historical.digest),
    )?;
    let observed = number(b, 146);
    need(
        observed > 0
            && observed <= initial.now
            && window(historical.issued, historical.expires, observed)
            && b[10..26] == scope.account
            && b[42..58] == scope.device
            && b[58..74] == scope.line
            && number(b, 74) == historical.version
            && b[82..114] == historical.digest,
    )?;
    let signer = key(historical, 4, &b[114..146]).ok_or(Error::Authentication)?;
    need(
        active(signer, observed, 2)
            && signer[98..114] == scope.device
            && signer[114..130] == scope.line,
    )?;
    let envelope = verify_envelope(b, &signer[33..98], 2)?;
    need(
        &b[179..envelope.prefix] == scope.peer.as_bytes()
            && b[envelope.body_end] as usize == 1 + selection.readers.len(),
    )?;
    let mut selected = None;
    for i in 0..b[envelope.body_end] as usize {
        let w = &b[envelope.body_end + 1 + i * 146..envelope.body_end + 1 + (i + 1) * 146];
        let (role, id) = if i == 0 {
            (2, &selection.archive)
        } else {
            (3, &selection.readers[i - 1].reader)
        };
        need(
            w[0] == role
                && &w[1..33] == id
                && active(
                    key(historical, role, id).ok_or(Error::Authentication)?,
                    observed,
                    8,
                ),
        )?;
        if role == 3 && *id == scope.reader {
            selected = Some(i)
        }
    }
    let index = selected.ok_or(Error::Authentication)?;
    let reader = key(m, 3, &scope.reader).ok_or(Error::Authentication)?;
    need(active(reader, initial.now, 8))?;
    let w = &b[envelope.body_end + 1 + index * 146..envelope.body_end + 1 + (index + 1) * 146];
    let (info, aad) = envelope.wrap_transcript(index)?;
    let cek = unwrap(&reader[33..98], &w[33..98], &info, &aad, &w[98..])?;
    need(cek.len() == 32)?;
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| Error::Shape)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::try_from(&b[envelope.prefix..envelope.prefix + 12])
                    .map_err(|_| Error::Shape)?,
                Payload {
                    msg: &b[envelope.prefix + 16..envelope.body_end],
                    aad: &envelope.body_aad(),
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let final_value = authority(current()?, scope)?;
    let f = &final_value.manifest;
    need(
        final_value.revision == initial.revision
            && final_value.now >= initial.now
            && final_value.now < initial.expires
            && final_value.now < number(reader, 140)
            && f.root == m.root
            && f.enrolled == m.enrolled
            && f.generation == m.generation
            && f.version == m.version
            && f.digest == m.digest,
    )?;
    need(
        !plain.is_empty()
            && plain.len() <= 32768
            && !plain.contains(&0)
            && !plain.starts_with(&[239, 187, 191]),
    )?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&plain)
            .map_err(|_| Error::Shape)?
            .to_owned(),
    ))
}
