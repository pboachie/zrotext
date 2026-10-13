//! Canonical candidate envelope integrity. This is not manifest authority.
use crate::Error;
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use sha2::{Digest, Sha256};

/// Owned, signature-verified syntax; signer authorization is a separate requirement.
pub struct IntegrityEnvelope {
    data: Vec<u8>,
    prefix: usize,
    body_end: usize,
    unsigned_end: usize,
}
fn number(p: &[u8], at: usize) -> Result<u64, Error> {
    let value = u64::from_be_bytes(p[at..at + 8].try_into().map_err(|_| Error::Shape)?);
    if value > i64::MAX as u64 {
        return Err(Error::Shape);
    }
    Ok(value)
}
fn point(p: &[u8]) -> Result<(), Error> {
    if p.len() != 65 || p[0] != 4 {
        return Err(Error::Shape);
    }
    PublicKey::from_sec1_bytes(p).map_err(|_| Error::Shape)?;
    Ok(())
}
/// Verify profiles 02 outbound/inbound and 03 outbound, without authorizing effects.
pub fn verify_envelope(
    input: &[u8],
    signer: &[u8],
    expected_profile: u8,
) -> Result<IntegrityEnvelope, Error> {
    if ![2, 3].contains(&expected_profile) || !(426..=36864).contains(&input.len()) {
        return Err(Error::Shape);
    }
    let b = input;
    if b[4] != expected_profile {
        return Err(Error::Shape);
    }
    let kind = b[5];
    if &b[..4] != b"ZTSE"
        || ![2, 3].contains(&b[4])
        || ![1, 2].contains(&kind)
        || (b[4] == 3 && kind != 1)
        || b[6] != 0
        || b[7] != 0
    {
        return Err(Error::Shape);
    }
    if kind == 2 && b.len() > 34082 {
        return Err(Error::Shape);
    }
    let base = if kind == 1 { 154 } else { 169 };
    let pl = u16::from_be_bytes([b[8], b[9]]) as usize;
    if !(base + 3..=base + 16).contains(&pl) {
        return Err(Error::Shape);
    }
    let end = 10 + pl;
    let p = &b[10..end];
    if p[base - 1] as usize + base != pl {
        return Err(Error::Shape);
    }
    let peer = &p[base..];
    if peer[0] != b'+'
        || !(b'1'..=b'9').contains(&peer[1])
        || !peer[2..].iter().all(u8::is_ascii_digit)
    {
        return Err(Error::Shape);
    }
    number(p, 64)?;
    let observed = number(p, 136)?;
    if kind == 1 {
        let expiry = number(p, 144)?;
        if expiry <= observed || expiry - observed > 900000 || p[152] != 1 {
            return Err(Error::Shape);
        }
    } else if number(p, 160)? == 0 || p[16..32] != p[144..160] {
        return Err(Error::Shape);
    }
    let size =
        u32::from_be_bytes(b[end + 12..end + 16].try_into().map_err(|_| Error::Shape)?) as usize;
    if !(17..=32784).contains(&size) {
        return Err(Error::Shape);
    }
    let body_end = end + 16 + size;
    if body_end >= b.len() {
        return Err(Error::Shape);
    }
    let count = b[body_end] as usize;
    let range = if kind == 1 { 2..=8 } else { 1..=7 };
    if !range.contains(&count) {
        return Err(Error::Shape);
    }
    let unsigned_end = body_end + 1 + count * 146;
    if unsigned_end + 64 != b.len() {
        return Err(Error::Shape);
    }
    let mut devices = 0;
    let mut archives = 0;
    let mut last: Option<&[u8]> = None;
    for i in 0..count {
        let w = &b[body_end + 1 + i * 146..body_end + 1 + (i + 1) * 146];
        if !(1..=3).contains(&w[0]) || last.is_some_and(|old| old >= &w[..33]) {
            return Err(Error::Shape);
        }
        last = Some(&w[..33]);
        point(&w[33..98])?;
        if w[0] == 1 {
            devices += 1
        }
        if w[0] == 2 {
            archives += 1
        }
    }
    if devices != usize::from(kind == 1) || archives != 1 {
        return Err(Error::Shape);
    }
    point(signer)?;
    let key_id = Sha256::digest([b"ZTSE/key/v1\0\x01\x01".as_slice(), signer].concat());
    if key_id[..] != p[104..136] {
        return Err(Error::Authentication);
    }
    let signature = Signature::from_slice(&b[unsigned_end..]).map_err(|_| Error::Authentication)?;
    if signature.normalize_s() != signature {
        return Err(Error::Authentication);
    }
    let label = if b[4] == 2 {
        b"ZTSE/sign/v2\0"
    } else {
        b"ZTSE/sign/v3\0"
    };
    let transcript = [
        label.as_slice(),
        &(unsigned_end as u32).to_be_bytes(),
        &b[..unsigned_end],
    ]
    .concat();
    VerifyingKey::from_sec1_bytes(signer)
        .map_err(|_| Error::Shape)?
        .verify(&transcript, &signature)
        .map_err(|_| Error::Authentication)?;
    Ok(IntegrityEnvelope {
        data: b.to_vec(),
        prefix: end,
        body_end,
        unsigned_end,
    })
}
impl IntegrityEnvelope {
    pub fn unsigned_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.data[..self.unsigned_end]).into()
    }
    pub fn body_aad(&self) -> Vec<u8> {
        let label = if self.data[4] == 2 {
            b"ZTSE/body/v2\0"
        } else {
            b"ZTSE/body/v3\0"
        };
        [label.as_slice(), &self.data[..self.prefix]].concat()
    }
    pub fn wrap_transcript(&self, index: usize) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if index >= self.data[self.body_end] as usize {
            return Err(Error::Shape);
        }
        let w = &self.data[self.body_end + 1 + index * 146..self.body_end + 1 + index * 146 + 33];
        let label = if self.data[4] == 2 {
            b"ZTSE/wrap/v2\0"
        } else {
            b"ZTSE/wrap/v3\0"
        };
        let aad = if self.data[4] == 3 {
            [
                b"ZTSE/wrap-aad/v3\0".as_slice(),
                &self.data[..self.prefix],
                w,
            ]
            .concat()
        } else {
            Vec::new()
        };
        Ok((
            [label.as_slice(), &self.data[..self.prefix], w].concat(),
            aad,
        ))
    }
}
