//! Root-pinned candidate manifest provenance; no live/durable authority.
use crate::Error;
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use sha2::{Digest, Sha256};
/// Independently compared initial root or verified profile02 successor trust.
pub struct RootTrust {
    account: [u8; 16],
    point: [u8; 65],
    generation: u64,
    anchor: [u8; 32],
    comparison: u64,
}
/// Owned signed evidence, never a mutable caller-provided trust structure.
pub struct Manifest {
    pub(crate) raw: Vec<u8>,
    pub(crate) profile: u8,
    pub(crate) predecessor: u8,
    pub(crate) generation: u64,
    pub(crate) version: u64,
    pub(crate) issued: u64,
    pub(crate) expires: u64,
    pub(crate) comparison: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) account: [u8; 16],
    pub(crate) root: [u8; 65],
    pub(crate) lineage: Vec<[u8; 32]>,
}
fn number(b: &[u8], at: usize) -> Result<u64, Error> {
    let n = u64::from_be_bytes(b[at..at + 8].try_into().map_err(|_| Error::Shape)?);
    if n > i64::MAX as u64 {
        return Err(Error::Shape);
    }
    Ok(n)
}
fn point(p: &[u8]) -> Result<(), Error> {
    if p.len() != 65 || p[0] != 4 {
        return Err(Error::Shape);
    }
    PublicKey::from_sec1_bytes(p).map_err(|_| Error::Shape)?;
    Ok(())
}
pub(crate) fn window(issued: u64, expires: u64, now: u64) -> bool {
    now > 0
        && now <= i64::MAX as u64
        && issued > 0
        && expires > issued
        && expires - issued <= 86400000
        && issued <= now + 300000
        && now < expires
}
pub fn enroll_root(pin: &[u8], compared: &[u8]) -> Result<RootTrust, Error> {
    if pin.len() != 94
        || compared.len() != 32
        || &pin[..5] != b"ZTRP\x02"
        || number(pin, 21)? != 1
        || pin[5..21] == [0; 16]
    {
        return Err(Error::Shape);
    }
    point(&pin[29..])?;
    let digest = Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), pin].concat());
    if digest.as_slice() != compared {
        return Err(Error::Authentication);
    }
    Ok(RootTrust {
        generation: 1,
        anchor: [0; 32],
        comparison: 0,
        account: pin[5..21].try_into().map_err(|_| Error::Shape)?,
        point: pin[29..].try_into().map_err(|_| Error::Shape)?,
    })
}
/// Verify genesis02, exact successors or a current unsigned identity with a fresh
/// valid signature. Caller must persist atomic selection before using authority.
pub fn verify_manifest(
    input: &[u8],
    root: &RootTrust,
    previous: Option<&Manifest>,
    expected: u8,
    now: u64,
) -> Result<Manifest, Error> {
    if ![2, 3].contains(&expected)
        || !(364..=9753).contains(&input.len())
        || now == 0
        || now > i64::MAX as u64
    {
        return Err(Error::Shape);
    }
    let b = input;
    if &b[..4] != b"ZTMA" || b[4] != expected {
        return Err(Error::Shape);
    }
    let offset = if expected == 3 { 2 } else { 0 };
    let predecessor = if expected == 3 {
        if b[5] != 3 || ![2, 3].contains(&b[6]) {
            return Err(Error::Shape);
        }
        b[6]
    } else {
        2
    };
    let count = b[150 + offset] as usize;
    if !(1..=64).contains(&count) || b.len() != 215 + offset + 149 * count {
        return Err(Error::Shape);
    }
    if number(b, 21 + offset)? != root.generation
        || now < root.comparison
        || (expected == 3 && root.generation != 1)
    {
        return Err(Error::Shape);
    }
    let version = number(b, 29 + offset)?;
    if version == 0 {
        return Err(Error::Shape);
    }
    let issued = number(b, 37 + offset)?;
    let expires = number(b, 45 + offset)?;
    if !window(issued, expires, now) {
        return Err(Error::Shape);
    }
    if b[5 + offset..21 + offset] != root.account || b[85 + offset..150 + offset] != root.point {
        return Err(Error::Authentication);
    }
    let mut roots = 0;
    let mut archives = 0;
    let mut seen = std::collections::HashSet::new();
    let mut last: Option<&[u8]> = None;
    for i in 0..count {
        let w = &b[151 + offset + i * 149..151 + offset + (i + 1) * 149];
        let role = w[0];
        if !(1..=6).contains(&role) {
            return Err(Error::Shape);
        }
        let scope = u16::from_be_bytes([w[130], w[131]]);
        let allowed = [0, 4, 12, 4, 2, 1, 0][role as usize];
        if (role == 3 && ![4, 8, 12].contains(&scope)) || (role != 3 && scope != allowed) {
            return Err(Error::Shape);
        }
        let device_bound = role == 1 || role == 4;
        let line_bound = device_bound || role == 5;
        if (w[98..114] == [0; 16]) == device_bound || (w[114..130] == [0; 16]) == line_bound {
            return Err(Error::Shape);
        }
        let from = number(w, 132)?;
        let until = number(w, 140)?;
        if from > until || ![1, 2].contains(&w[148]) || last.is_some_and(|old| old >= &w[..33]) {
            return Err(Error::Shape);
        }
        last = Some(&w[..33]);
        let public = &w[33..98];
        point(public)?;
        if !seen.insert(public) {
            return Err(Error::Shape);
        }
        let algorithm = if role <= 3 { b"\0\x10" } else { b"\x01\x01" };
        let id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), algorithm, public].concat());
        if id[..] != w[1..33] {
            return Err(Error::Authentication);
        }
        if role == 6 {
            roots += 1;
            if public != root.point || w[148] != 1 || from > issued || until < expires {
                return Err(Error::Shape);
            }
        }
        if role == 2 && w[148] == 1 {
            archives += 1
        }
    }
    if roots != 1 || archives != 1 {
        return Err(Error::Shape);
    }
    let unsigned = &b[..b.len() - 64];
    let signature = Signature::from_slice(&b[b.len() - 64..]).map_err(|_| Error::Authentication)?;
    if signature.normalize_s() != signature {
        return Err(Error::Authentication);
    }
    let label = if expected == 2 {
        b"ZTSE/manifest/v2\0"
    } else {
        b"ZTSE/manifest/v3\0"
    };
    let transcript = [
        label.as_slice(),
        &(unsigned.len() as u32).to_be_bytes(),
        unsigned,
    ]
    .concat();
    VerifyingKey::from_sec1_bytes(&root.point)
        .map_err(|_| Error::Shape)?
        .verify(&transcript, &signature)
        .map_err(|_| Error::Authentication)?;
    let digest: [u8; 32] = Sha256::digest(unsigned).into();
    let prev_digest = &b[53 + offset..85 + offset];
    if let Some(prior) = previous {
        if prior.account != root.account
            || prior.root != root.point
            || prior.generation != root.generation
            || now < prior.comparison
        {
            return Err(Error::Authentication);
        }
        if version == prior.version {
            if expected != prior.profile
                || predecessor != prior.predecessor
                || digest != prior.digest
            {
                return Err(Error::Authentication);
            }
        } else {
            if prior.version == i64::MAX as u64
                || version != prior.version + 1
                || prev_digest != prior.digest
                || expected < prior.profile
                || (expected == 3 && predecessor != prior.profile)
            {
                return Err(Error::Authentication);
            }
            if expected == 3 && prior.profile == 2 && !window(prior.issued, prior.expires, now) {
                return Err(Error::Authentication);
            }
        }
    } else if expected != 2 || version != 1 || prev_digest != root.anchor {
        return Err(Error::Authentication);
    }
    let mut lineage = previous.map(|m| m.lineage.clone()).unwrap_or_default();
    if previous.is_none_or(|m| m.version != version) {
        if lineage.len() >= 1024 {
            return Err(Error::Shape);
        }
        lineage.push(digest);
    }
    Ok(Manifest {
        lineage,
        generation: root.generation,
        raw: b.to_vec(),
        profile: expected,
        predecessor,
        version,
        issued,
        expires,
        comparison: now,
        digest,
        account: root.account,
        root: root.point,
    })
}
impl Manifest {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// Authenticate an exact profile02 root succession against current old history.
/// `expected_new_root` must be independently compared, never copied from the wire.
/// Persist this transition and its new genesis atomically before accepting effects.
pub fn verify_root_transition02(
    input: &[u8],
    old: &Manifest,
    expected_new_root: &[u8],
    now: u64,
) -> Result<RootTrust, Error> {
    if input.len() != 343
        || &input[..5] != b"ZTRT\x02"
        || old.profile != 2
        || expected_new_root.len() != 65
        || old.generation >= i64::MAX as u64
        || now < old.comparison
        || old.version == 0
    {
        return Err(Error::Shape);
    }
    let b = input;
    if b[5..21] != old.account
        || number(b, 21)? != old.generation
        || number(b, 29)? != old.generation + 1
        || b[37..102] != old.root
        || &b[102..167] != expected_new_root
        || b[102..167] == old.root
        || b[167..199] != old.digest
        || !window(number(b, 199)?, number(b, 207)?, now)
    {
        return Err(Error::Authentication);
    }
    point(expected_new_root)?;
    let transcript = [
        b"ZTSE/root-transition/v2\0".as_slice(),
        &215u32.to_be_bytes(),
        &b[..215],
    ]
    .concat();
    for (public, signature) in [(&b[37..102], &b[215..279]), (&b[102..167], &b[279..343])] {
        let signature = Signature::from_slice(signature).map_err(|_| Error::Shape)?;
        if signature.normalize_s() != signature {
            return Err(Error::Authentication);
        }
        VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| Error::Shape)?
            .verify(&transcript, &signature)
            .map_err(|_| Error::Authentication)?;
    }
    Ok(RootTrust {
        account: old.account,
        point: expected_new_root.try_into().map_err(|_| Error::Shape)?,
        generation: old.generation + 1,
        anchor: Sha256::digest(&b[..215]).into(),
        comparison: now,
    })
}
impl Manifest {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn root_trust(&self) -> RootTrust {
        RootTrust {
            account: self.account,
            point: self.root,
            generation: self.generation,
            anchor: [0; 32],
            comparison: self.comparison,
        }
    }
}
