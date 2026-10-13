//! Protected Windows profile03 candidate composition, never dispatch permission.
use crate::{
    Error, KEM, SUITE,
    cng::HardwareSigner,
    election::{ElectionProof, ElectionRecord, require_current_election03},
    envelope::verify_envelope,
    expand, extract,
    manifest::Manifest,
    reader::{active, key},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct Recipient {
    pub role: u8,
    pub id: [u8; 32],
}
#[derive(Clone)]
pub struct ComposeRequest<'a> {
    pub manifest: &'a Manifest,
    pub proof: &'a ElectionProof,
    pub authority: &'a dyn Fn() -> Result<(ElectionRecord, u64), Error>,
    pub message: [u8; 16],
    pub observed: u64,
    pub expires: u64,
    pub peer: &'a str,
    pub content: &'a str,
    pub signer: &'a HardwareSigner,
    pub recipients: Vec<Recipient>,
}
pub(crate) struct Plan {
    pub prefix: Vec<u8>,
    pub text: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
    pub intent: Vec<u8>,
    pub recipients: Vec<Vec<u8>>,
    pub now: u64,
}
fn need(v: bool) -> Result<(), Error> {
    if v {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("native validated width"))
}
pub(crate) fn authorize(r: &ComposeRequest<'_>) -> Result<Plan, Error> {
    let (current, now) = (r.authority)()?;
    let c = require_current_election03(r.proof, r.manifest, &current, now)?;
    let m = r.manifest;
    need(
        r.message != [0; 16]
            && r.observed > 0
            && r.observed >= m.issued
            && r.observed <= now
            && r.expires > now
            && r.expires <= i64::MAX as u64
            && r.expires - r.observed <= 900000,
    )?;
    let peer = r.peer.as_bytes();
    need(
        (3..=16).contains(&peer.len())
            && peer[0] == b'+'
            && (b'1'..=b'9').contains(&peer[1])
            && peer[2..].iter().all(u8::is_ascii_digit),
    )?;
    let body = r.content.as_bytes();
    need(
        (1..=32768).contains(&body.len())
            && !body.contains(&0)
            && !body.starts_with(&[239, 187, 191]),
    )?;
    let point = r
        .signer
        .public_point()
        .map_err(|_| Error::ProtectedUnavailable)?;
    let id = Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &[1, 1], &point].concat());
    let signer = key(m, 5, &id).ok_or(Error::Authentication)?;
    need(
        active(signer, now, 1)
            && active(signer, r.observed, 1)
            && &signer[114..130] == c.b("lineId")
            && signer[33..98] == point,
    )?;
    let mut deadline = m
        .expires
        .min(number(signer, 140))
        .min(c.n("permissionExpiresAtMs"));
    need((2..=8).contains(&r.recipients.len()))?;
    let mut recipients = r.recipients.clone();
    recipients.sort_by_key(|v| (v.role, v.id));
    let mut one = 0;
    let mut two = 0;
    let mut keys = Vec::new();
    let mut identity = Vec::new();
    for (i, v) in recipients.iter().enumerate() {
        need(
            (1..=3).contains(&v.role)
                && (i == 0 || v.role != recipients[i - 1].role || v.id != recipients[i - 1].id),
        )?;
        if v.role == 1 {
            one += 1;
        }
        if v.role == 2 {
            two += 1;
        }
        let k = key(m, v.role, &v.id).ok_or(Error::Authentication)?;
        need(active(k, now, 4) && active(k, r.observed, 4))?;
        if v.role == 1 {
            need(
                v.id == c.b("selectedReaderKeyId")
                    && &k[98..114] == c.b("deviceId")
                    && &k[114..130] == c.b("lineId"),
            )?;
        }
        deadline = deadline.min(number(k, 140));
        keys.push(k.to_vec());
        identity.extend_from_slice(&k[..98]);
    }
    need(one == 1 && two == 1 && r.expires <= deadline)?;
    let fields = [
        c.b("accountId"),
        &r.message,
        c.b("deviceId"),
        c.b("lineId"),
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
        &[90, 84, 83, 69, 3, 1, 0, 0][..],
        &(fields.len() as u16).to_be_bytes(),
        &fields,
    ]
    .concat();
    let intent = Sha256::digest(
        [
            b"ZTSE/native-outbound-intent/v1\0".as_slice(),
            &prefix,
            &Sha256::digest(body),
            &identity,
            c.b("bindingId"),
            &c.n("bindingGeneration").to_be_bytes(),
            c.b("electionCommitment"),
            c.b("electionBundleSha256"),
        ]
        .concat(),
    )
    .to_vec();
    Ok(Plan {
        prefix,
        text: Zeroizing::new(body.to_vec()),
        public: point,
        intent,
        recipients: keys,
        now,
    })
}
pub(crate) fn recheck(r: &ComposeRequest<'_>, p: &mut Plan) -> Result<(), Error> {
    let fresh = authorize(r)?;
    need(fresh.now >= p.now && fresh.intent == p.intent)?;
    p.now = fresh.now;
    Ok(())
}
fn wrap(point: &[u8], cek: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
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
    let schedule = extract(&shared, SUITE, b"secret", &[]);
    let key = expand(&schedule, SUITE, b"key", &context, 16)?;
    let nonce = expand(&schedule, SUITE, b"base_nonce", &context, 12)?;
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| Error::Shape)?
        .encrypt(
            &Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Shape)?,
            Payload { msg: cek, aad },
        )
        .map_err(|_| Error::Authentication)?;
    Ok([enc.as_bytes(), &cipher].concat())
}
pub(crate) fn compose_profile(
    p: &Plan,
    signer: &HardwareSigner,
    profile: u8,
) -> Result<Vec<u8>, Error> {
    let body_label = if profile == 2 {
        b"ZTSE/body/v2\0"
    } else {
        b"ZTSE/body/v3\0"
    };
    let wrap_label = if profile == 2 {
        b"ZTSE/wrap/v2\0"
    } else {
        b"ZTSE/wrap/v3\0"
    };
    let mut cek = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut *cek).map_err(|_| Error::ProtectedUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| Error::ProtectedUnavailable)?;
    let body = Aes256Gcm::new_from_slice(&*cek)
        .map_err(|_| Error::Shape)?
        .encrypt(
            &Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Shape)?,
            Payload {
                msg: &p.text,
                aad: &[body_label.as_slice(), &p.prefix].concat(),
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut unsigned = [
        p.prefix.as_slice(),
        &nonce,
        &(body.len() as u32).to_be_bytes(),
        &body,
        &[p.recipients.len() as u8],
    ]
    .concat();
    for k in &p.recipients {
        let suffix = [p.prefix.as_slice(), &k[..33]].concat();
        let wrapped = wrap(
            &k[33..98],
            &*cek,
            &[wrap_label.as_slice(), &suffix].concat(),
            &if profile == 3 {
                [b"ZTSE/wrap-aad/v3\0".as_slice(), &suffix].concat()
            } else {
                Vec::new()
            },
        )?;
        unsigned.extend_from_slice(&k[..33]);
        unsigned.extend_from_slice(&wrapped);
    }
    let signature = if profile == 2 {
        signer.sign_envelope02(&unsigned)
    } else {
        signer.sign_envelope03(&unsigned)
    }
    .map_err(|_| Error::ProtectedUnavailable)?;
    unsigned.extend_from_slice(&signature);
    verify_envelope(&unsigned, &p.public, profile)?;
    Ok(unsigned)
}
/// Fresh ciphertext only. Use durable exact replay for retryable requests.
pub fn compose_protected03(r: &ComposeRequest<'_>) -> Result<Vec<u8>, Error> {
    let mut p = authorize(r)?;
    compose(r, &mut p)
}

pub(crate) fn compose(r: &ComposeRequest<'_>, p: &mut Plan) -> Result<Vec<u8>, Error> {
    let envelope = compose_profile(p, r.signer, 3)?;
    recheck(r, p)?;
    Ok(envelope)
}
