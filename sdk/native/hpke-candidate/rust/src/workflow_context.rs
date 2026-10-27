//! ZTWC01 client encryption. Current owner/runtime authorization remains external.
use crate::{
    Error,
    manifest::{Manifest, window},
    reader::{active, key},
    template_crypto::seal,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
/// Explicit caller-selected reader role; ciphertext cannot select authority.
#[derive(Clone, Copy)]
pub enum WorkflowContextRole {
    Owner = 2,
    Integration = 3,
}
#[derive(Clone)]
pub struct WorkflowContextScope {
    pub kind: u8,
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub interval: [u8; 16],
    pub context: [u8; 16],
    pub binding_generation: u64,
    pub revision: u64,
    pub expires: u64,
    pub trust_generation: u64,
    pub manifest_version: u64,
    pub peer_digest: [u8; 32],
    pub reader: [u8; 32],
    pub manifest_digest: [u8; 32],
}
impl WorkflowContextScope {
    pub fn aad(&self) -> Result<Vec<u8>, Error> {
        if self.revision > 128 || !(1..=3).contains(&self.kind) {
            return Err(Error::Shape);
        };
        let mut out = b"ZTWC\x01".to_vec();
        out.push(self.kind);
        for id in [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.context,
        ] {
            if id == [0; 16] {
                return Err(Error::Shape);
            };
            out.extend(id)
        }
        for n in [
            self.binding_generation,
            self.revision,
            self.expires,
            self.trust_generation,
            self.manifest_version,
        ] {
            if n == 0 || n > i64::MAX as u64 {
                return Err(Error::Shape);
            };
            out.extend(n.to_be_bytes())
        }
        for digest in [self.peer_digest, self.reader, self.manifest_digest] {
            if digest == [0; 32] {
                return Err(Error::Shape);
            };
            out.extend(digest)
        }
        Ok(out)
    }
}
fn authority(
    m: &Manifest,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    now: u64,
) -> Result<Vec<u8>, Error> {
    if m.profile != 2
        || !window(m.issued, m.expires, now)
        || now < m.comparison
        || s.expires <= now
        || s.expires - now > 30 * 86400000
        || s.account != m.account
        || s.trust_generation != m.generation
        || s.manifest_version != m.version
        || s.manifest_digest != m.digest
    {
        return Err(Error::Authentication);
    }
    let reader = key(m, role as u8, &s.reader).ok_or(Error::Authentication)?;
    if !active(reader, now, 8) {
        return Err(Error::Authentication);
    }
    let signer = m.raw[151..m.raw.len() - 64]
        .as_chunks::<149>()
        .0
        .iter()
        .any(|w| {
            w[0] == 4
                && w[98..114] == s.device
                && w[114..130] == s.line
                && active(w.as_slice(), now, 2)
                && w[130..132] == [0, 2]
        });
    if !signer {
        return Err(Error::Authentication);
    };
    Ok(reader[33..98].to_vec())
}
pub fn seal_workflow_context(
    m: &Manifest,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    now: u64,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = s.aad()?;
    let point = authority(m, s, role, now)?;
    if !(1..=32768).contains(&content.len()) {
        return Err(Error::Shape);
    }
    let plain = Zeroizing::new(content.to_vec());
    if !(1..=32768).contains(&plain.len()) {
        return Err(Error::Shape);
    }
    let wrapped = seal(
        &point,
        &plain,
        &[b"ZT/workflow-context/hpke/v1\0", aad.as_slice()].concat(),
        &aad,
    )?;
    let mut out = [aad.as_slice(), &wrapped[..65]].concat();
    out.extend(
        u32::try_from(wrapped.len() - 65)
            .map_err(|_| Error::Shape)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&wrapped[65..]);
    Ok(out)
}
fn open(
    m: &Manifest,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    now: u64,
    envelope: &[u8],
    unwrap: impl FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(308..=33075).contains(&envelope.len()) {
        return Err(Error::Shape);
    };
    let wire = envelope.to_vec();
    let aad = s.aad()?;
    if wire[..222] != aad
        || u32::from_be_bytes(wire[287..291].try_into().map_err(|_| Error::Shape)?) as usize
            != wire.len() - 291
    {
        return Err(Error::Shape);
    };
    let point = authority(m, s, role, now)?;
    let plain = unwrap(
        &point,
        &wire[222..287],
        &[b"ZT/workflow-context/hpke/v1\0", aad.as_slice()].concat(),
        &aad,
        &wire[291..],
    )?;
    Ok(plain)
}
pub fn open_software_workflow_context(
    m: &Manifest,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    now: u64,
    scalar: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open(m, s, role, now, envelope, |point, enc, info, aad, ct| {
        crate::open_software_content(scalar, point, enc, info, aad, ct)
    })
}
#[cfg(windows)]
pub fn open_protected_workflow_context(
    m: &Manifest,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    now: u64,
    recipient: &crate::cng::HardwareRecipient,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open(m, s, role, now, envelope, |point, enc, info, aad, ct| {
        recipient.open_content(point, enc, info, aad, ct)
    })
}
pub fn workflow_context_digest(envelope: &[u8]) -> Result<[u8; 32], Error> {
    if !(308..=33075).contains(&envelope.len()) {
        return Err(Error::Shape);
    };
    Ok(Sha256::digest(envelope).into())
}

fn current<'a>(
    source: &mut impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    floor: u64,
) -> Result<(&'a Manifest, u64), Error> {
    let (m, now) = source()?;
    if now < floor {
        return Err(Error::Authentication);
    }
    authority(m, s, role, now)?;
    Ok((m, now))
}

/// Independent current authority is required before crypto and before return.
/// The callback is not a durable clock or an authenticated transport by itself.
pub fn seal_current_workflow_context<'a>(
    mut source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let (m, now) = current(&mut source, s, role, 0)?;
    let out = seal_workflow_context(m, s, role, now, content)?;
    let (latest, _) = current(&mut source, s, role, now)?;
    if latest.root != m.root || latest.enrolled != m.enrolled {
        return Err(Error::Authentication);
    }
    Ok(out)
}
fn open_current<'a>(
    mut source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    envelope: &[u8],
    unwrap: impl FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (m, now) = current(&mut source, s, role, 0)?;
    open(m, s, role, now, envelope, |point, enc, info, aad, ct| {
        let plain = unwrap(point, enc, info, aad, ct)?;
        let (latest, _) = current(&mut source, s, role, now)?;
        if latest.root != m.root || latest.enrolled != m.enrolled {
            return Err(Error::Authentication);
        }
        Ok(plain)
    })
}
pub fn open_current_software_workflow_context<'a>(
    source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    scalar: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_current(source, s, role, envelope, |point, enc, info, aad, ct| {
        crate::open_software_content(scalar, point, enc, info, aad, ct)
    })
}
#[cfg(windows)]
pub fn open_current_protected_workflow_context<'a>(
    source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &WorkflowContextScope,
    role: WorkflowContextRole,
    recipient: &crate::cng::HardwareRecipient,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut selected = Vec::new();
    let plain = open_current(source, s, role, envelope, |point, enc, info, aad, ct| {
        selected = point.to_vec();
        recipient.open_content(point, enc, info, aad, ct)
    })?;
    let point = recipient
        .public_point()
        .map_err(|_| Error::ProtectedUnavailable)?;
    if point != selected {
        return Err(Error::ProtectedUnavailable);
    }
    Ok(plain)
}

#[path = "workflow_context_bounded.rs"]
pub mod bounded;
