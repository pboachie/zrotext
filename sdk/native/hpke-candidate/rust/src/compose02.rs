//! Protected profile02 candidate composition, not live transport authority.
use crate::{
    Error,
    cng::HardwareSigner,
    compose::{Plan, Recipient, compose_profile},
    manifest::{Manifest, verify_manifest},
    reader::{active, key},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct ComposeRequest02<'a> {
    /// Required independently authenticated current selection for journal operations.
    pub current: Option<&'a dyn Fn() -> Result<(&'a Manifest, u64), Error>>,
    pub manifest: &'a Manifest,
    pub comparison: &'a dyn Fn() -> Result<u64, Error>,
    pub message: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub observed: u64,
    pub expires: u64,
    pub peer: &'a str,
    pub content: &'a str,
    pub signer: &'a HardwareSigner,
    pub recipients: Vec<Recipient>,
}
fn need(v: bool) -> Result<(), Error> {
    if v {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}
pub(crate) fn authorize(r: &ComposeRequest02<'_>) -> Result<Plan, Error> {
    need(
        r.manifest.profile == 2
            && r.observed <= i64::MAX as u64
            && r.expires <= i64::MAX as u64
            && r.expires > r.observed
            && r.expires - r.observed <= 900000,
    )?;
    let peer = r.peer.as_bytes();
    need(
        (3..=16).contains(&peer.len())
            && peer[0] == b'+'
            && (b'1'..=b'9').contains(&peer[1])
            && peer[2..].iter().all(u8::is_ascii_digit),
    )?;
    let bytes = r.content.as_bytes();
    need(
        (1..=32768).contains(&bytes.len())
            && !bytes.contains(&0)
            && !bytes.starts_with(&[239, 187, 191]),
    )?;
    let now = (r.comparison)()?;
    let m = verify_manifest(
        &r.manifest.raw,
        &r.manifest.root_trust(),
        Some(r.manifest),
        2,
        now,
    )?;
    let point = r
        .signer
        .public_point()
        .map_err(|_| Error::ProtectedUnavailable)?;
    let id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], &point].concat());
    let signer = key(&m, 5, &id).ok_or(Error::Authentication)?;
    need(active(signer, now, 1) && signer[114..130] == r.line && signer[33..98] == point)?;
    need((2..=8).contains(&r.recipients.len()))?;
    let mut requested = r.recipients.clone();
    requested.sort_by_key(|v| (v.role, v.id));
    let mut keys = Vec::new();
    let mut identity = Vec::new();
    let mut counts = [0u8; 4];
    for (i, k) in requested.iter().enumerate() {
        need(
            (1..=3).contains(&k.role)
                && (i == 0 || k.role != requested[i - 1].role || k.id != requested[i - 1].id),
        )?;
        counts[k.role as usize] += 1;
        let record = key(&m, k.role, &k.id).ok_or(Error::Authentication)?;
        need(active(record, now, 4))?;
        if k.role == 1 {
            need(record[98..114] == r.device && record[114..130] == r.line)?
        };
        identity.extend_from_slice(&record[..98]);
        keys.push(record.to_vec());
    }
    need(counts[1] == 1 && counts[2] == 1)?;
    let fields = [
        m.account.as_slice(),
        &r.message,
        &r.device,
        &r.line,
        &m.version.to_be_bytes(),
        &m.digest,
        &id,
        &r.observed.to_be_bytes(),
        &r.expires.to_be_bytes(),
        &[1, peer.len() as u8],
        peer,
    ]
    .concat();
    let prefix = [
        b"ZTSE\x02\x01\0\0".as_slice(),
        &(fields.len() as u16).to_be_bytes(),
        &fields,
    ]
    .concat();
    let text = Zeroizing::new(bytes.to_vec());
    let text_hash = Sha256::digest(&*text);
    let intent = Sha256::digest(
        [
            b"ZTSE/native-outbound-intent/v2\0".as_slice(),
            &prefix,
            &text_hash,
            &identity,
            &m.enrolled,
            &m.root,
            &m.generation.to_be_bytes(),
        ]
        .concat(),
    );
    Ok(Plan {
        prefix,
        text,
        public: point.to_vec(),
        intent: intent.to_vec(),
        recipients: keys,
        now,
    })
}
pub(crate) fn recheck(r: &ComposeRequest02<'_>, p: &mut Plan) -> Result<(), Error> {
    let fresh = authorize(r)?;
    need(fresh.now >= p.now && fresh.intent == p.intent)?;
    p.now = fresh.now;
    Ok(())
}
pub(crate) fn compose(r: &ComposeRequest02<'_>, p: &mut Plan) -> Result<Vec<u8>, Error> {
    let envelope = compose_profile(p, r.signer, 2)?;
    recheck(r, p)?;
    Ok(envelope)
}
/// Fresh candidate bytes only; use journal exact replay for retryable applications.
pub fn compose_protected02(r: &ComposeRequest02<'_>) -> Result<Vec<u8>, Error> {
    let mut p = authorize(r)?;
    compose(r, &mut p)
}

pub(crate) fn require_current(r: &ComposeRequest02<'_>, p: &mut Plan) -> Result<(), Error> {
    let (current, now) = (r.current.ok_or(Error::Authentication)?)()?;
    need(
        current.profile == 2
            && current.account == r.manifest.account
            && current.root == r.manifest.root
            && current.generation == r.manifest.generation
            && current.enrolled == r.manifest.enrolled
            && now >= p.now
            && r.observed > 0
            && r.observed <= now
            && now < r.expires
            && current.lineage.contains(&r.manifest.digest),
    )?;
    let comparison = || Ok(now);
    let request = ComposeRequest02 {
        manifest: current,
        comparison: &comparison,
        current: None,
        message: r.message,
        device: r.device,
        line: r.line,
        observed: r.observed,
        expires: r.expires,
        peer: r.peer,
        content: r.content,
        signer: r.signer,
        recipients: r.recipients.clone(),
    };
    let fresh = authorize(&request)?;
    need(fresh.public == p.public && fresh.recipients.len() == p.recipients.len())?;
    for (a, b) in fresh.recipients.iter().zip(&p.recipients) {
        need(a[..98] == b[..98])?;
    }
    p.now = now;
    Ok(())
}
