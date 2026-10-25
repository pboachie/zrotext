//! ZTWT01 client encryption. Current owner/runtime authorization remains external.
use crate::{
    Error, KEM, SUITE, expand, extract,
    manifest::{Manifest, window},
    reader::{active, key},
    template::TemplateContent,
};
use aes_gcm::{
    Aes128Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct EncryptedTemplateScope {
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub interval: [u8; 16],
    pub template: [u8; 16],
    pub binding_generation: u64,
    pub revision: u64,
    pub expires: u64,
    pub trust_generation: u64,
    pub manifest_version: u64,
    pub peer_digest: [u8; 32],
    pub reader: [u8; 32],
    pub manifest_digest: [u8; 32],
}
impl EncryptedTemplateScope {
    pub fn aad(&self) -> Result<Vec<u8>, Error> {
        if self.revision > 128 {
            return Err(Error::Shape);
        };
        let mut out = b"ZTWT\x01\x01".to_vec();
        for id in [
            self.account,
            self.device,
            self.line,
            self.interval,
            self.template,
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
fn authority(m: &Manifest, s: &EncryptedTemplateScope, now: u64) -> Result<Vec<u8>, Error> {
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
    let reader = key(m, 2, &s.reader).ok_or(Error::Authentication)?;
    if !active(reader, now, 8) {
        return Err(Error::Authentication);
    }
    let signer = m.raw[151..m.raw.len() - 64]
        .as_chunks::<149>()
        .0
        .iter()
        .map(|record| record.as_slice())
        .any(|w| {
            w[0] == 4
                && w[98..114] == s.device
                && w[114..130] == s.line
                && active(w, now, 2)
                && w[130..132] == [0, 2]
        });
    if !signer {
        return Err(Error::Authentication);
    };
    Ok(reader[33..98].to_vec())
}
pub(crate) fn seal(point: &[u8], plain: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let peer = PublicKey::from_sec1_bytes(point).map_err(|_| Error::Shape)?;
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::fill(entropy.as_mut()).map_err(|_| Error::ProtectedUnavailable)?;
    let ephemeral = SecretKey::from_slice(entropy.as_ref()).map_err(|_| Error::Shape)?;
    let enc = ephemeral.public_key().to_sec1_point(false);
    let dh = diffie_hellman(ephemeral.to_nonzero_scalar(), peer.as_affine());
    let prk = extract(&[], KEM, b"eae_prk", dh.raw_secret_bytes());
    let shared = expand(
        &prk,
        KEM,
        b"shared_secret",
        &[enc.as_bytes(), point].concat(),
        32,
    )?;
    let context = [
        &[0][..],
        &extract(&[], SUITE, b"psk_id_hash", &[]),
        &extract(&[], SUITE, b"info_hash", info),
    ]
    .concat();
    let secret = extract(&shared, SUITE, b"secret", &[]);
    let key = expand(&secret, SUITE, b"key", &context, 16)?;
    let nonce = expand(&secret, SUITE, b"base_nonce", &context, 12)?;
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| Error::Shape)?
        .encrypt(
            &Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Shape)?,
            Payload { msg: plain, aad },
        )
        .map_err(|_| Error::Authentication)?;
    Ok([enc.as_bytes(), &cipher].concat())
}
pub fn seal_encrypted_template(
    m: &Manifest,
    s: &EncryptedTemplateScope,
    now: u64,
    content: &TemplateContent,
) -> Result<Vec<u8>, Error> {
    let aad = s.aad()?;
    let point = authority(m, s, now)?;
    let plain = Zeroizing::new(content.canonical());
    if !(1..=32768).contains(&plain.len()) {
        return Err(Error::Shape);
    }
    let wrapped = seal(
        &point,
        &plain,
        &[b"ZT/workflow-template/hpke/v1\0", aad.as_slice()].concat(),
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
    s: &EncryptedTemplateScope,
    now: u64,
    envelope: &[u8],
    unwrap: impl FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
) -> Result<TemplateContent, Error> {
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
    let point = authority(m, s, now)?;
    let plain = unwrap(
        &point,
        &wire[222..287],
        &[b"ZT/workflow-template/hpke/v1\0", aad.as_slice()].concat(),
        &aad,
        &wire[291..],
    )?;
    TemplateContent::parse(&plain)
}
pub fn open_software_encrypted_template(
    m: &Manifest,
    s: &EncryptedTemplateScope,
    now: u64,
    scalar: &[u8],
    envelope: &[u8],
) -> Result<TemplateContent, Error> {
    open(m, s, now, envelope, |point, enc, info, aad, ct| {
        crate::open_software_content(scalar, point, enc, info, aad, ct)
    })
}
#[cfg(windows)]
pub fn open_protected_encrypted_template(
    m: &Manifest,
    s: &EncryptedTemplateScope,
    now: u64,
    recipient: &crate::cng::HardwareRecipient,
    envelope: &[u8],
) -> Result<TemplateContent, Error> {
    open(m, s, now, envelope, |point, enc, info, aad, ct| {
        recipient.open_content(point, enc, info, aad, ct)
    })
}
pub fn encrypted_template_digest(envelope: &[u8]) -> Result<[u8; 32], Error> {
    if !(308..=33075).contains(&envelope.len()) {
        return Err(Error::Shape);
    };
    Ok(Sha256::digest(envelope).into())
}

fn current<'a>(
    source: &mut impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &EncryptedTemplateScope,
    floor: u64,
) -> Result<(&'a Manifest, u64), Error> {
    let (m, now) = source()?;
    if now < floor {
        return Err(Error::Authentication);
    }
    authority(m, s, now)?;
    Ok((m, now))
}

/// Independent current authority is required before crypto and before return.
/// The callback is not a durable clock or an authenticated transport by itself.
pub fn seal_current_encrypted_template<'a>(
    mut source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &EncryptedTemplateScope,
    content: &TemplateContent,
) -> Result<Vec<u8>, Error> {
    let (m, now) = current(&mut source, s, 0)?;
    let out = seal_encrypted_template(m, s, now, content)?;
    let (latest, _) = current(&mut source, s, now)?;
    if latest.root != m.root || latest.enrolled != m.enrolled {
        return Err(Error::Authentication);
    }
    Ok(out)
}
fn open_current<'a>(
    mut source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &EncryptedTemplateScope,
    envelope: &[u8],
    unwrap: impl FnOnce(&[u8], &[u8], &[u8], &[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
) -> Result<TemplateContent, Error> {
    let (m, now) = current(&mut source, s, 0)?;
    open(m, s, now, envelope, |point, enc, info, aad, ct| {
        let plain = unwrap(point, enc, info, aad, ct)?;
        let (latest, _) = current(&mut source, s, now)?;
        if latest.root != m.root || latest.enrolled != m.enrolled {
            return Err(Error::Authentication);
        }
        Ok(plain)
    })
}
pub fn open_current_software_encrypted_template<'a>(
    source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &EncryptedTemplateScope,
    scalar: &[u8],
    envelope: &[u8],
) -> Result<TemplateContent, Error> {
    open_current(source, s, envelope, |point, enc, info, aad, ct| {
        crate::open_software_content(scalar, point, enc, info, aad, ct)
    })
}
#[cfg(windows)]
pub fn open_current_protected_encrypted_template<'a>(
    source: impl FnMut() -> Result<(&'a Manifest, u64), Error>,
    s: &EncryptedTemplateScope,
    recipient: &crate::cng::HardwareRecipient,
    envelope: &[u8],
) -> Result<TemplateContent, Error> {
    open_current(source, s, envelope, |point, enc, info, aad, ct| {
        recipient.open_content(point, enc, info, aad, ct)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_length_does_not_widen_cek() {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).unwrap();
        let key = SecretKey::from_slice(entropy.as_ref()).unwrap();
        let point = key.public_key().to_sec1_point(false);
        for size in [0, 1, 31, 32, 33, 32768, 32769] {
            let plain = vec![7; size];
            let wrapped = seal(
                point.as_bytes(),
                &plain,
                b"synthetic-info",
                b"synthetic-aad",
            )
            .unwrap();
            let opened = crate::open_software_content(
                entropy.as_ref(),
                point.as_bytes(),
                &wrapped[..65],
                b"synthetic-info",
                b"synthetic-aad",
                &wrapped[65..],
            );
            if size == 0 || size > 32768 {
                assert!(opened.is_err());
            } else {
                assert_eq!(*opened.unwrap(), plain);
            }
            let cek = crate::open_software_cek(
                entropy.as_ref(),
                point.as_bytes(),
                &wrapped[..65],
                b"synthetic-info",
                b"synthetic-aad",
                &wrapped[65..],
            );
            assert_eq!(cek.is_ok(), size == 32);
        }
    }
}
